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
import os
import re
import sqlite3
import threading
import time

from .unifi_dpi import APPLICATIONS

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
    'steam games': 'Valve Steam',
    'google apis': 'Google',
    'google services': 'Google',
    'apple services': 'Apple.com',
    'icloud services': 'iCloud',
    'microsoft services': 'Microsoft.com',
    'windows updates': 'Windows Update',
    'openai': 'ChatGPT',
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
    # "Netflix Video" -> "Netflix"; "Steam Games" -> the only UniFi app
    # with "steam" in its name ("Valve Steam")
    first = (app_name or '').split(' ')[0]
    if first and len(first) > 3:
        app_id = _BY_NAME.get(_norm(first))
        if app_id is None:
            matches = _BY_WORD.get(first.lower(), ())
            app_id = next(iter(matches)) if len(matches) == 1 else None
        if app_id is not None:
            return app_id >> 16, app_id & 0xffff
    cat = CATEGORY_MAP.get((app_category or '').strip().lower(), UNKNOWN_CAT)
    return cat, OTHER_APP


def _mac(raw):
    raw = (raw or '').lower().replace(':', '').replace('-', '')
    if len(raw) != 12:
        return None
    return ':'.join(raw[i:i + 2] for i in range(0, 12, 2))


class ZenarmorDPI:

    def __init__(self, db_path=DEFAULT_DB):
        self.db_path = db_path
        self.initialized = str(int(time.time()))
        self._last_id = None
        self._lock = threading.Lock()
        # mac -> (cat, app) -> [rx_bytes, tx_bytes, rx_packets, tx_packets]
        self._stats = {}

    @property
    def available(self):
        return os.path.exists(self.db_path)

    def poll(self):
        """Fold connections finished since the last poll into the counters.

        The first poll only records the current position, so counters start
        at zero with the daemon instead of replaying Zenarmor's history."""
        conn = sqlite3.connect('file:%s?mode=ro' % self.db_path, uri=True, timeout=10)
        try:
            max_id = conn.execute('select max(id) from conn_all').fetchone()[0] or 0
            if self._last_id is None:
                self._last_id = max_id
                return 0
            if max_id < self._last_id:
                self._last_id = 0       # Zenarmor recreated its database
            rows = conn.execute(
                'select id, src_hwaddr, app_name, app_category, src_nbytes, '
                'dst_nbytes, src_npackets, dst_npackets from conn_all '
                'where id > ? order by id', (self._last_id,)).fetchall()
        finally:
            conn.close()
        with self._lock:
            for (row_id, hwaddr, app, category, src_b, dst_b, src_p, dst_p) in rows:
                self._last_id = row_id
                mac = _mac(hwaddr)
                if not mac:
                    continue
                key = classify(app, category)
                c = self._stats.setdefault(mac, {}).setdefault(key, [0, 0, 0, 0])
                # the client is the connection source: what it receives is
                # dst->src (rx), what it sends is src->dst (tx)
                c[0] += int(dst_b or 0)
                c[1] += int(src_b or 0)
                c[2] += int(dst_p or 0)
                c[3] += int(src_p or 0)
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
                } for (cat, app), c in sorted(apps.items())],
            } for mac, apps in sorted(self._stats.items())]
