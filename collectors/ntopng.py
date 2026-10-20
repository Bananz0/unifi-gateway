# -*- coding: utf-8 -*-
"""Per-client application statistics and Traffic Flows from ntopng (nDPI).

ntopng keeps live flows in memory, each with the nDPI application, bytes and
the client/server split. Each poll adds the growth of every flow since the
previous poll to the owning device's counters, so UniFi's DPI totals follow
live traffic instead of finished-connection batches. Flows ntopng stops
listing (finished or idle) are reported as allowed Traffic Flows.

Counters, payload format, state file and flow queue are ZenarmorDPI's; only
the data source differs. The first poll after start records the flows
already open without counting them, so history isn't replayed.
"""
import base64
import ipaddress
import json
import logging
import time
import urllib.error
import urllib.request

from .countries import country_code
from .zenarmor import (IP_PROTOCOLS, OTHER_APP, UNKNOWN_CAT, ZenarmorDPI,
                       _mac, classify)

logger = logging.getLogger('unifi-gateway')

PAGE = 1000
MAX_PAGES = 20

# nDPI protocol name (lower case) -> UniFi application name, where the
# generic name match in zenarmor.classify doesn't find it
NDPI_ALIASES = {
    'ntp': 'Network Time Protocol', 'bittorrent': 'BitTorrent Series',
    'http_proxy': 'HTTP Proxy Server', 'doh_dot': 'DNS over HTTPS (DoH)',
    'microsoft': 'Microsoft.com', 'imo': 'imo.im', 'microsoft365': 'Microsoft Office 365',
    'ms_onedrive': 'OneDrive', 'playstore': 'Google Play', 'googleservices': 'Google',
    'googlemaps': 'Google', 'whatsappfiles': 'WhatsApp', 'whatsappcall': 'WhatsApp',
    'fbookreelstory': 'Facebook', 'messenger': 'Facebook Messenger', 'apple': 'Apple.com',
    'appleicloud': 'iCloud', 'appleitunes': 'iTunes/App Store', 'applestore': 'Apple Store',
    'skype_teams': 'Skype', 'ssh': 'Secure Shell (SSH)',
    'rdp': 'MS Remote Desktop Protocol (RDP)', 'smbv1': 'SMB', 'smbv23': 'SMB2',
    'netbios': 'NetBIOS Name Service', 'dhcp': 'Dynamic Host Configuration Protocol (DHCP)',
    'dhcpv6': 'DHCPv6 Client', 'amazonvideo': 'Amazon Video', 'googledocs': 'Google Docs',
    'googledrive': 'Google Drive', 'gmail': 'Gmail',
}
# nDPI names with no UniFi application: report them as "other" in a category
NDPI_CATEGORIES = {
    'tailscale': 11, 'wireguard': 11, 'ipsec': 11, 'tor': 11, 'openvpn': 11,
    'cloudflare': 13, 'amazonaws': 13, 'azure': 13, 'googlecloud': 13, 'akamai': 13,
    'ubiquity': 9, 'ubntac2': 9, 'mdns': 9, 'llmnr': 9, 'wsd': 9, 'icmpv6': 9,
    'snmp': 9, 'syslog': 9, 'signal': 0, 'twitter': 24, 'openai': 17, 'claude': 17,
    'anthropic': 17, 'dazn': 4, 'supersport': 4, 'showmax': 4, 'amazonalexa': 13,
}


def classify_ndpi(l7):
    """(cat, app) UniFi ids for an nDPI name such as ``TLS.YouTube``: the
    application part first, then the transport/master protocol."""
    parts = [p for p in str(l7 or '').split('.') if p]
    candidates = list(reversed(parts)) if len(parts) > 1 else parts
    for part in candidates:
        if part.lower() == 'unknown':
            continue
        key = classify(NDPI_ALIASES.get(part.lower(), part), '')
        if key[1] != OTHER_APP:
            return key
        # a known app with no UniFi entry outranks its transport (TLS.Tailscale)
        if part.lower() in NDPI_CATEGORIES:
            return NDPI_CATEGORIES[part.lower()], OTHER_APP
    return UNKNOWN_CAT, OTHER_APP


class NtopngError(Exception):
    pass


class NtopngDPI(ZenarmorDPI):

    def __init__(self, url, username, password, mac_for_ip, state_file=None, timeout=10):
        self.url = url.rstrip('/')
        token = base64.b64encode(('%s:%s' % (username, password)).encode()).decode()
        self._auth = {'Authorization': 'Basic ' + token}
        self._timeout = timeout
        self._mac_for_ip = mac_for_ip
        self._flows = None          # flow id -> snapshot; None until baselined
        super().__init__(db_path='ntopng:' + self.url, state_file=state_file)
        if self._last_id is None:
            self._last_id = 0

    # ── ntopng REST ──────────────────────────────────────────────────────

    def _get(self, path):
        req = urllib.request.Request(self.url + path, headers=self._auth)
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read())
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise NtopngError('%s: %s' % (path, e))
        if not isinstance(data, dict) or data.get('rc') != 0:
            raise NtopngError('%s: %s' % (path, str(data)[:200]))
        return data['rsp']

    @property
    def available(self):
        try:
            return bool(self._get('/lua/rest/v2/get/ntopng/interfaces.lua'))
        except NtopngError as e:
            logger.warning('ntopng unavailable: %s', e)
            return False

    def _active_flows(self):
        for iface in self._get('/lua/rest/v2/get/ntopng/interfaces.lua'):
            ifid = iface.get('ifid')
            for page in range(1, MAX_PAGES + 1):
                rsp = self._get('/lua/rest/v2/get/flow/active.lua?ifid=%s&currentPage=%d'
                                '&perPage=%d' % (ifid, page, PAGE))
                rows = rsp.get('data') or []
                for row in rows:
                    yield ifid, row
                if len(rows) < PAGE or page * PAGE >= int(rsp.get('totalRows') or 0):
                    break

    # ── polling ──────────────────────────────────────────────────────────

    def _device(self, row):
        """(mac, device is the flow's client) for the LAN end of a flow."""
        client, server = row.get('client') or {}, row.get('server') or {}
        for end, is_client in ((client, True), (server, False)):
            mac = _mac(self._mac_for_ip(end.get('ip')))
            if mac and mac not in self._excluded_macs:
                return mac, is_client
        return None, True

    def poll(self):
        flows = {}
        for ifid, row in self._active_flows():
            fid = (ifid, str(row.get('key')), str(row.get('hash_id')), row.get('first_seen'))
            total = max(0, int(row.get('bytes') or 0))
            share = (row.get('breakdown') or {}).get('cli2srv')
            cli = int(round(total * float(share) / 100)) if share is not None else total // 2
            flows[fid] = {'row': row, 'cli': cli, 'srv': total - cli}
        counted = 0
        with self._lock:
            previous, baseline = self._flows, self._flows is None
            for fid, snap in flows.items():
                old = (previous or {}).get(fid)
                if baseline:
                    continue
                d_cli = snap['cli'] - (old['cli'] if old else 0)
                d_srv = snap['srv'] - (old['srv'] if old else 0)
                if d_cli < 0 or d_srv < 0:        # flow id reused: count afresh
                    d_cli, d_srv = snap['cli'], snap['srv']
                if not (d_cli or d_srv):
                    continue
                mac, is_client = self._device(snap['row'])
                if not mac:
                    continue
                sent, received = (d_cli, d_srv) if is_client else (d_srv, d_cli)
                l7 = (snap['row'].get('protocol') or {}).get('l7')
                key = classify_ndpi(l7)
                c = self._stats.setdefault(mac, {}).setdefault(key, [0, 0, 0, 0])
                c[0] += received
                c[1] += sent
                remote = snap['row'].get('server' if is_client else 'client') or {}
                iso = country_code(remote.get('country'))
                if iso:
                    cs = self._countries.setdefault(mac, {}).setdefault(key, {}).setdefault(iso, [0, 0])
                    cs[0] += received
                    cs[1] += sent
                label = (l7, '', key)
                self._mapping[label] = self._mapping.get(label, 0) + received + sent
                counted += 1
            if self.flows and previous:
                for fid, snap in previous.items():
                    if fid not in flows:
                        flow = self._connection(snap)
                        if flow:
                            self._connections.append(flow)
            self._flows = flows
        self._save_state()
        return counted

    def _connection(self, snap):
        """A finished ntopng flow as a UXG ``connections`` (Traffic Flows)
        entry; the device is always the source."""
        row = snap['row']
        mac, is_client = self._device(row)
        if not mac:
            return None
        device, remote = ((row.get('client'), row.get('server')) if is_client
                          else (row.get('server'), row.get('client')))
        device, remote = device or {}, remote or {}
        sent, received = (snap['cli'], snap['srv']) if is_client else (snap['srv'], snap['cli'])
        try:
            version = ipaddress.ip_address(device.get('ip')).version
            local = not ipaddress.ip_address(remote.get('ip')).is_global
        except (TypeError, ValueError):
            return None
        protocol = IP_PROTOCOLS.get(str((row.get('protocol') or {}).get('l4') or '').lower())
        if protocol is None:
            return None
        ended = int(row.get('last_seen') or time.time())
        flow = {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime(ended)),
            'ip': {'saddr': device.get('ip'), 'daddr': remote.get('ip'),
                   'protocol': protocol, 'version': 'v%d' % version,
                   **({'sport': int(device['port']), 'dport': int(remote['port'])}
                      if protocol in (6, 17, 132) and device.get('port') and remote.get('port')
                      else {})},
            'stats': {'rxBytes': received, 'rxPackets': 0, 'txBytes': sent, 'txPackets': 0},
            'in': 'lan' if is_client or local else 'wan',
            'out': 'wan' if is_client and not local else 'lan',
        }
        name = str(remote.get('name') or '')
        if name and name != remote.get('ip'):
            flow['hostnames'] = [name]
        iso = country_code(remote.get('country'))
        if iso and not local:
            flow['country'] = iso
            flow['region'] = {'dst': iso}
        return flow
