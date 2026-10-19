# -*- coding: utf-8 -*-
"""Per-client application statistics from Zenarmor, reported as UniFi DPI.

Zenarmor (OPNsense's app-aware filtering plugin) writes one row per finished
connection to a local SQLite database, with the client's MAC address, the
application and category it identified, and bytes/packets in each direction.
This module tails that table and accumulates counters per client and
application, translated to UniFi's DPI ids so the controller's Insights /
Traffic Identification views populate.

Names are matched exactly against UniFi's application list first, then via
known aliases; anything else is reported as "other" within the closest
UniFi category.
"""
import logging
import json
import os
import re
import sqlite3
import threading
import time
import tempfile

from .unifi_dpi import APPLICATIONS
from .countries import country_code

logger = logging.getLogger('unifi-gateway')

DEFAULT_DB = '/usr/local/datastore/sqlite/conn_all.sqlite'
OTHER_APP = 0xffff          # "other" application within a category
UNKNOWN_CAT = 255

# Zenarmor category -> UniFi category id
CATEGORY_MAP = {
    'instant messaging': 0, 'chat': 0, 'messaging': 0,
    'peer to peer': 1, 'p2p': 1, 'file sharing': 1,
    'file transfer': 3, 'cloud storage': 3, 'file storage': 3,
    'media streaming': 4, 'video streaming': 4, 'music streaming': 4,
    'email': 5, 'mail': 5,
    'voip': 6, 'video conferencing': 6, 'conferencing': 6,
    'database': 7,
    'gaming': 8, 'games': 8,
    'network management': 9, 'network service': 9, 'network services': 9,
    'remote access': 10, 'remote control': 10,
    'vpn': 11, 'proxy': 11, 'anonymizer': 11, 'tunneling': 11,
    'finance': 12, 'investment': 12,
    'web browsing': 13, 'search': 13, 'online utility': 13, 'web services': 13,
    'cdn': 13, 'advertisement': 13, 'advertising': 13,
    'software updates': 14, 'software update': 14, 'security': 14,
    'business tools': 17, 'business': 17, 'productivity': 17,
    'collaboration': 17, 'a.i. tools': 17, 'ai tools': 17, 'education': 17,
    'storage & backup': 3, 'cloud services': 13, 'infrastructure services': 13,
    'generic tcpip': 19, 'ads': 13, 'ad tracker': 13,
    'secure web browsing': 20, 'dns over tls': 20, 'encrypted dns': 20,
    'adult': 22,
    'social network': 24, 'social networks': 24, 'social media': 24,
    'shopping': 41, 'news': 36, 'sports': 43, 'health': 33,
}

# Zenarmor application name -> UniFi application name, where they differ
APP_ALIASES = {
    'domain name resolution': 'DNS',
    'secure web browsing': 'SSL/TLS',
    'https': 'SSL/TLS',
    'tls': 'SSL/TLS',
    'web browsing': 'HTTP',
    'quic': 'QUIC',
    'quic udp connection': 'QUIC',
    'secure shell': 'Secure Shell (SSH)',
    'discord im': 'Discord',
    'microsoft defender': 'Windows Defender(MMPC)',
    'steam games': 'Valve Steam',
    'google apis': 'Google',
    'google services': 'Google',
    'apple services': 'Apple.com',
    'icloud services': 'iCloud',
    'microsoft services': 'Microsoft.com',
    'windows updates': 'Windows Update',
}


def _norm(name):
    return re.sub(r'[^a-z0-9]', '', (name or '').lower())


_BY_NAME = {}
_BY_WORD = {}
for _id, _name in APPLICATIONS.items():
    # keep the lowest id for duplicate names (the "home" category wins)
    _BY_NAME.setdefault(_norm(_name), _id)
    for _word in re.findall(r'[a-z0-9]+', _name.lower()):
        if len(_word) > 3:
            _BY_WORD.setdefault(_word, set()).add(_id)


def classify(app_name, app_category):
    """Return (cat, app) UniFi ids for a Zenarmor application/category."""
    for candidate in (app_name, APP_ALIASES.get((app_name or '').lower())):
        if candidate:
            app_id = _BY_NAME.get(_norm(candidate))
            if app_id is not None:
                return app_id >> 16, app_id & 0xffff
    # Only match a unique complete word when it is the entire source name.
    # Prefix guesses otherwise turn e.g. "Samsung Cloud" into SamsungPoP
    # (an investment app) or "Steam Tracker" into the Steam games client.
    words = re.findall(r'[a-z0-9]+', (app_name or '').lower())
    if len(words) == 1 and len(words[0]) > 3:
        matches = _BY_WORD.get(words[0], ())
        app_id = next(iter(matches)) if len(matches) == 1 else None
        if app_id is not None:
            return app_id >> 16, app_id & 0xffff
    cat = CATEGORY_MAP.get((app_category or '').strip().lower(), UNKNOWN_CAT)
    return cat, OTHER_APP


def _mac(raw):
    raw = (raw or '').lower().replace(':', '').replace('-', '')
    if not re.fullmatch(r'[0-9a-f]{12}', raw) or raw == '0' * 12:
        return None
    if int(raw[:2], 16) & 1:  # multicast/broadcast is not a client
        return None
    return ':'.join(raw[i:i + 2] for i in range(0, 12, 2))


class ZenarmorDPI:

    def __init__(self, db_path=DEFAULT_DB, state_file=None):
        self.db_path = db_path
        self.initialized = str(int(time.time()))
        self._last_id = None
        self._lock = threading.Lock()
        # mac -> (cat, app) -> [rx_bytes, tx_bytes, rx_packets, tx_packets]
        self._stats = {}
        self._countries = {}
        self._last_token = None
        self._state_file = state_file
        self._excluded_macs = set()
        self._mapping = {}
        self._load_state()

    def exclude_macs(self, macs):
        """Router interfaces must not appear as clients in DPI statistics."""
        with self._lock:
            self._excluded_macs = {m for raw in macs if (m := _mac(raw))}

    def _load_state(self):
        if not self._state_file:
            return
        try:
            with open(self._state_file, encoding='utf-8') as f:
                state = json.load(f)
            if state.get('db_path') != os.path.abspath(self.db_path):
                return
            stats, countries = {}, {}
            for client in state['clients']:
                mac = _mac(client['mac'])
                if not mac:
                    continue
                for row in client['stats']:
                    key = (int(row['cat']), int(row['app']))
                    stats.setdefault(mac, {})[key] = [int(row[k]) for k in (
                        'rx_bytes', 'tx_bytes', 'rx_packets', 'tx_packets')]
                    countries.setdefault(mac, {})[key] = {
                        c['iso']: [int(c[k]) for k in ('rx_bytes', 'tx_bytes')]
                        for c in row.get('countries', []) if country_code(c.get('iso'))}
            self.initialized = str(state['initialized'])
            self._last_id = int(state['last_id'])
            self._last_token = state.get('last_token')
            self._stats, self._countries = stats, countries
        except FileNotFoundError:
            pass
        except (OSError, ValueError, KeyError, TypeError) as e:
            logger.warning('Could not restore Zenarmor DPI state: %s', e)

    def _save_state(self):
        if not self._state_file:
            return
        path = os.path.abspath(self._state_file)
        tmp = None
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                    dir=os.path.dirname(path), delete=False) as f:
                tmp = f.name
                os.chmod(tmp, 0o600)
                json.dump({'db_path': os.path.abspath(self.db_path),
                           'initialized': self.initialized, 'last_id': self._last_id,
                           'last_token': self._last_token,
                           'clients': self.payload()}, f)
            os.replace(tmp, path)
        except OSError as e:
            logger.warning('Could not save Zenarmor DPI state: %s', e)
        finally:
            if tmp and os.path.exists(tmp):
                os.unlink(tmp)

    @property
    def available(self):
        return os.path.exists(self.db_path)

    def poll(self):
        """Fold connections finished since the last poll into the counters.

        The first poll only records the current position, so counters start
        at zero with the daemon instead of replaying Zenarmor's history."""
        conn = sqlite3.connect('file:%s?mode=ro' % self.db_path, uri=True, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            columns = {r[1] for r in conn.execute('pragma table_info(conn_all)')}
            max_id = conn.execute('select max(id) from conn_all').fetchone()[0] or 0
            if self._last_id is None:
                self._last_id = max_id
                if 'conn_uuid' in columns and max_id:
                    self._last_token = conn.execute(
                        'select conn_uuid from conn_all where id=?', (max_id,)).fetchone()[0]
                self._save_state()
                return 0
            anchor = conn.execute('select conn_uuid from conn_all where id=?',
                                  (self._last_id,)).fetchone() if 'conn_uuid' in columns else None
            if max_id < self._last_id or (self._last_token and anchor and
                                          anchor[0] != self._last_token):
                self._last_id = 0       # Zenarmor recreated its database
            optional = [c for c in ('direction', 'dst_hwaddr', 'dst_country_name',
                        'src_country_name', 'conn_uuid') if c in columns]
            rows = conn.execute(
                'select id, src_hwaddr, app_name, app_category, src_nbytes, '
                'dst_nbytes, src_npackets, dst_npackets' +
                ''.join(', ' + c for c in optional) + ' from conn_all '
                'where id > ? order by id limit 10000', (self._last_id,)).fetchall()
        finally:
            conn.close()
        with self._lock:
            for row in rows:
                self._last_id = row['id']
                self._last_token = row['conn_uuid'] if 'conn_uuid' in columns else None
                inbound = 'direction' in columns and row['direction'] == 'in'
                mac = _mac((row['dst_hwaddr'] if 'dst_hwaddr' in columns else None)
                           if inbound else row['src_hwaddr'])
                if not mac or mac in self._excluded_macs:
                    continue
                key = classify(row['app_name'], row['app_category'])
                counts = []
                try:
                    counts = [max(0, int(row[k] or 0)) for k in (
                        'src_nbytes', 'dst_nbytes', 'src_npackets', 'dst_npackets')]
                except (TypeError, ValueError):
                    continue
                sent, received, sent_p, received_p = counts
                if inbound:
                    received, sent, received_p, sent_p = sent, received, sent_p, received_p
                c = self._stats.setdefault(mac, {}).setdefault(key, [0, 0, 0, 0])
                c[0] += received
                c[1] += sent
                c[2] += received_p
                c[3] += sent_p
                field = 'src_country_name' if inbound else 'dst_country_name'
                iso = country_code(row[field]) if field in columns else None
                if iso:
                    countries = self._countries.setdefault(mac, {}).setdefault(key, {})
                    cs = countries.setdefault(iso, [0, 0])
                    cs[0] += received
                    cs[1] += sent
                label = (row['app_name'], row['app_category'], key)
                self._mapping[label] = self._mapping.get(label, 0) + received + sent
        self._save_state()
        return len(rows)

    def payload(self):
        """``dpi-stats`` entries in the UGW inform format."""
        with self._lock:
            return [{
                'initialized': self.initialized,
                'mac': mac,
                'stats': [{
                    'cat': cat, 'app': app,
                    'rx_bytes': c[0], 'tx_bytes': c[1],
                    'rx_packets': c[2], 'tx_packets': c[3],
                    **({'countries': [{'iso': iso, 'rx_bytes': n[0], 'tx_bytes': n[1]}
                        for iso, n in sorted(self._countries.get(mac, {}).get((cat, app), {}).items())]}
                       if self._countries.get(mac, {}).get((cat, app)) else {}),
                } for (cat, app), c in sorted(apps.items())],
            } for mac, apps in sorted(self._stats.items()) if mac not in self._excluded_macs]

    def mapping_report(self):
        """Classification coverage for diagnostics; never sent as invented apps."""
        with self._lock:
            return [{'name': name, 'category': category, 'cat': key[0],
                     'app': key[1], 'bytes': count}
                    for (name, category, key), count in
                    sorted(self._mapping.items(), key=lambda item: -item[1])]
