# -*- coding: utf-8 -*-
"""OPNsense-specific data collection and control via the REST API (26.x).

Reads:
- Interface counters / addresses / MACs (diagnostics/traffic, interfaces/overview)
- Clients: ARP table + hostwatch discovery + DHCP leases (ISC, Kea or Dnsmasq)
- Per-client traffic: sampled from diagnostics/traffic/top (iftop) and
  accumulated into byte counters
- WAN gateway latency (routes/gateway/status), DNS servers, CPU/memory,
  uptime, Dynamic DNS (os-ddclient) and speedtest results (os-speedtest-community)

Writes (see opnsense_sync.py): client blocking, firewall rules, port forwards,
DHCP reservations, DNS host overrides, static routes, reboot, speed test.

Every API read falls back to the FreeBSD/psutil implementation when the API
is unreachable, so a misconfigured key degrades to the old behaviour instead
of breaking informs.
"""
import calendar
import hashlib
import json
import logging
import re
import os
import threading
import time
import sqlite3
from datetime import datetime

from . import base
from .freebsd import FreeBSDCollector
from .opnsense_api import OPNsenseAPI, OPNsenseAPIError
from .opnsense_sync import OPNsenseConfigSync, normalize_mac
from .opnsense_udapi import UDAPIConfigSync, is_udapi_config
from .zenarmor import ZenarmorDPI
from .netflow import NetflowTotals
from .unifi_mirror import OPNsenseMirror, UniFiController

logger = logging.getLogger('unifi-gateway')

SECTION = 'opnsense'

DEFAULTS = {
    'url': 'https://127.0.0.1',
    'api_key': '',
    'api_secret': '',
    'verify_ssl': 'false',
    'timeout': '30',
    'apply_firewall': 'true',
    'apply_port_forward': 'true',
    'apply_dhcp': 'true',
    'apply_dns': 'true',
    'apply_routes': 'true',
    'block_clients': 'true',
    'allow_reboot': 'false',
    'traffic_interval': '30',
    'host_active_window': '300',
    'state_file': '',
    'dpi': 'auto',
    'flows': 'false',
    'zenarmor_db': '/usr/local/datastore/sqlite/conn_all.sqlite',
    'netflow_db': '/var/netflow/src_addr_000300.sqlite',
}

LOCAL_HOSTS = ('127.0.0.1', 'localhost', '::1')

UNIFI_SECTION = 'unifi'
UNIFI_DEFAULTS = {
    'url': '', 'username': '', 'password': '', 'site': 'default',
    'verify_ssl': 'false', 'mirror': 'true', 'mirror_interval': '300',
}


class OPNSenseCollector(FreeBSDCollector):

    def __init__(self, config):
        self.opts = self._read_options(config)
        self.api = None
        if self.opts['api_key'] and self.opts['api_secret']:
            self.api = OPNsenseAPI(
                self.opts['url'], self.opts['api_key'], self.opts['api_secret'],
                verify_ssl=self._bool('verify_ssl'),
                timeout=int(self.opts['timeout']),
            )
        else:
            logger.warning(
                'OPNsense API key/secret not configured ([opnsense] api_key, '
                'api_secret); using local FreeBSD collection only'
            )
        # "local" means host stats (CPU, memory, uptime) can come from psutil
        # on this machine instead of the API.
        self.local = base.psutil is not None and (
            self.api is None or self.api.host in LOCAL_HOSTS or
            os.path.exists('/usr/local/opnsense'))

        self._cache = {}
        self._api_errors = {}
        self._prev_counters = {}
        self._host_traffic = {}
        self._host_seen = {}
        self._traffic_lock = threading.Lock()
        self._traffic_thread = None
        self._blocked_refresh = None
        self._insight_start = None
        self.dpi = None
        self.netflow = None
        self._traffic_source = None
        if os.path.isfile(self.opts['netflow_db']):
            self.netflow = NetflowTotals(self.opts['netflow_db'],
                state_file=os.path.join(os.path.dirname(self._state_path()), 'netflow-accounting.json'))
            if self.netflow.restored:
                self._traffic_source = 'netflow-buckets'
        self.mirror = None
        self._mirror_thread = None
        self._init_mirror(config)
        if str(self.opts['dpi']).lower() not in ('0', 'false', 'no', 'off'):
            dpi = ZenarmorDPI(self.opts['zenarmor_db'],
                state_file=os.path.join(os.path.dirname(self._state_path()), 'zenarmor-dpi.json'))
            if dpi.available:
                self.dpi = dpi
                dpi.flows = self._bool('flows')
                if dpi.flows:
                    logger.info('Reporting Zenarmor connections as Traffic Flows')
                logger.info('Reporting DPI statistics from Zenarmor (%s)', dpi.db_path)
            elif str(self.opts['dpi']).lower() not in ('auto',):
                logger.warning('Zenarmor database %s not found, DPI disabled', dpi.db_path)
        self._state = self._load_state()
        self.sync = None
        self.udapi_sync = None
        if self.api:
            options = {k: self._bool(k) for k in (
                'apply_firewall', 'apply_port_forward', 'apply_dhcp',
                'apply_dns', 'apply_routes')}
            self.sync = OPNsenseConfigSync(
                self.api, self.port_identifier, self.lan_identifiers,
                options=options)
            # UXG-class devices are provisioned with a UDAPI tree instead.
            self.udapi_sync = UDAPIConfigSync(
                self.api, self.port_identifier, self.lan_identifiers,
                options=options)
        super().__init__(config)

    # ── Options / state ──────────────────────────────────────────────────

    @staticmethod
    def _read_options(config):
        opts = dict(DEFAULTS)
        if config.has_section(SECTION):
            for key in DEFAULTS:
                if config.has_option(SECTION, key):
                    opts[key] = config.get(SECTION, key)
        opts['api_key'] = os.environ.get('OPNSENSE_API_KEY', opts['api_key'])
        opts['api_secret'] = os.environ.get('OPNSENSE_API_SECRET', opts['api_secret'])
        opts['url'] = os.environ.get('OPNSENSE_URL', opts['url'])
        return opts

    def _init_mirror(self, config):
        opts = dict(UNIFI_DEFAULTS)
        if config.has_section(UNIFI_SECTION):
            opts.update({k: config.get(UNIFI_SECTION, k) for k in UNIFI_DEFAULTS
                         if config.has_option(UNIFI_SECTION, k)})
        self.unifi_opts = opts
        enabled = str(opts['mirror']).lower() in ('1', 'true', 'yes', 'on')
        if not (self.api and enabled and opts['username'] and opts['password']):
            return
        url = opts['url'] or self._controller_url(config)
        if not url:
            logger.warning('UniFi mirror: set [unifi] url to enable it')
            return
        controller = UniFiController(
            url, opts['username'], opts['password'], site=opts['site'],
            verify_ssl=str(opts['verify_ssl']).lower() in ('1', 'true', 'yes'))
        self.mirror = OPNsenseMirror(self.api, controller, self.lan_identifiers,
                                     self.wan_identifiers)
        logger.info('Mirroring OPNsense config into the UniFi controller at %s', url)

    @staticmethod
    def _controller_url(config):
        """Derive https://<controller> from the inform URL."""
        inform = config.get('gateway', 'url', fallback='')
        host = re.sub(r'^https?://', '', inform).split('/')[0].split(':')[0]
        return 'https://%s' % host if host else ''

    def wan_identifiers(self):
        idents = [self.port_identifier(p['ifname']) for p in self.ports
                  if p['type'].lower().startswith('wan')]
        return [i for i in idents if i] or ['wan']

    def _ensure_mirror(self):
        if not self.mirror or (self._mirror_thread and self._mirror_thread.is_alive()):
            return
        self._mirror_thread = threading.Thread(
            target=self._mirror_loop, args=(int(self.unifi_opts['mirror_interval']),),
            daemon=True, name='unifi-mirror')
        self._mirror_thread.start()

    def _mirror_loop(self, interval):
        last_warnings = None
        while True:
            try:
                summary = self.mirror.run()
                warnings = summary.pop('warnings', [])
                if warnings != last_warnings:
                    logger.info('UniFi mirror: %s', json.dumps(summary))
                    for w in warnings:
                        logger.warning('UniFi mirror: %s', w)
                    last_warnings = warnings
            except Exception as e:  # never let the mirror thread die
                logger.warning('UniFi mirror failed: %s', e)
            time.sleep(max(60, interval))

    def _bool(self, key):
        return str(self.opts.get(key, '')).strip().lower() in ('1', 'true', 'yes', 'on')

    def _state_path(self):
        if self.opts['state_file']:
            return self.opts['state_file']
        cfg = os.environ.get('UNIFI_GW_CONFIG', 'conf/unifi-gateway.conf')
        return os.path.join(os.path.dirname(cfg) or '.', 'opnsense_state.json')

    def _load_state(self):
        try:
            with open(self._state_path(), 'r') as f:
                state = json.load(f)
                if isinstance(state, dict):
                    return state
        except (IOError, OSError, ValueError):
            pass
        return {'blocked': [], 'system_cfg_hash': None}

    def _save_state(self):
        try:
            with open(self._state_path(), 'w') as f:
                json.dump(self._state, f, indent=2, sort_keys=True)
        except (IOError, OSError) as e:
            logger.warning('Failed to save OPNsense state: %s', e)

    # ── API helpers ──────────────────────────────────────────────────────

    def _call(self, name, fn, ttl=0, max_stale=None):
        """Run an API read with caching and de-duplicated error logging.
        Returns None on failure."""
        if self.api is None:
            return None
        now = time.time()
        cached = self._cache.get(name)
        if ttl and cached and now - cached[0] < ttl:
            return cached[1]
        try:
            value = fn()
        except (OPNsenseAPIError, ValueError, KeyError, TypeError) as e:
            if self._api_errors.get(name) != str(e):
                logger.warning('OPNsense API %s failed: %s', name, e)
            self._api_errors[name] = str(e)
            return cached[1] if cached and (max_stale is None or now - cached[0] <= max_stale) else None
        if name in self._api_errors:
            logger.info('OPNsense API %s recovered', name)
            del self._api_errors[name]
        self._cache[name] = (now, value)
        return value

    def _overview(self):
        """Interface overview rows keyed by device name (refreshed every 5 min)."""
        rows = self._call(
            'interfaces', lambda: self.api.search('interfaces/overview/interfaces_info'),
            ttl=300) or []
        return {r['device']: r for r in rows if r.get('device')}

    def port_identifier(self, ifname):
        """OPNsense identifier (wan/lan/optN) for an emulated UniFi port."""
        for port in self.ports:
            if port['ifname'] != ifname:
                continue
            if port.get('opnif'):
                return port['opnif']
            row = self._overview().get(port['realif'])
            return row.get('identifier') if row else None
        return None

    def lan_identifiers(self):
        idents = [self.port_identifier(p['ifname']) for p in self.ports
                  if p['type'].lower().startswith('lan')]
        return [i for i in idents if i] or ['lan']

    def _wan_port(self):
        return next((p for p in self.ports if p['type'].lower() == 'wan'), None)

    def _lan_devices(self):
        return {p['realif'] for p in self.ports if p['type'].lower().startswith('lan')}

    # ── Inform data ──────────────────────────────────────────────────────

    def update(self):
        super().update()
        if self.api is None:
            return
        self._ensure_traffic_sampler()
        self._ensure_mirror()
        # Refresh counters for every inform, independently of discovery's
        # cached API reads (the base class otherwise refreshes hosts at 120s).
        self.data['host_table'] = self._build_host_table()
        if self.updated.get('host_table') != self._blocked_refresh:
            self._blocked_refresh = self.updated.get('host_table')
            try:
                self.refresh_blocked_ips()
            except OPNsenseAPIError as e:
                logger.warning('Failed to refresh blocked client addresses: %s', e)
        self.data['ddns'] = self._get_ddns()
        wan = self._wan_port()
        if wan:
            row = self._overview().get(wan['realif'])
            if row and row.get('link_type'):
                self.data['wan_type'] = row['link_type']
        if self.dpi:
            self.data['dpi_stats'] = self.dpi.payload()
            if self.dpi.flows:
                self.data['connections'] = self.dpi.take_connections()
        if not self.local:
            uptime = self._get_uptime()
            if uptime:
                self.data['uptime'] = uptime

    def _get_ifstat(self):
        traffic = self._call(
            'traffic', lambda: self.api.get('diagnostics/traffic/interface'))
        if not traffic or not traffic.get('interfaces'):
            return super()._get_ifstat()
        by_device = {v.get('device'): v for v in traffic['interfaces'].values()}
        now = time.time()
        ret = {}
        for port in self.ports:
            stats = by_device.get(port['realif'])
            if not stats:
                continue
            ifname = port['ifname']
            num = lambda k: int(stats.get(k, 0) or 0)
            rx, tx = num('bytes received'), num('bytes transmitted')
            info = {
                'rx_bytes': str(rx),
                'rx_packets': str(num('packets received')),
                'rx_errors': str(num('input errors')),
                'rx_dropped': str(num('input queue drops')),
                'rx_fifo': '0', 'rx_frame': '0', 'rx_compressed': '0',
                'rx_multicast': str(num('multicasts received')),
                'tx_bytes': str(tx),
                'tx_packets': str(num('packets transmitted')),
                'tx_errors': str(num('output errors')),
                'tx_dropped': str(num('send queue drops')),
                'tx_fifo': '0', 'tx_frame': '0', 'tx_compressed': '0',
                'tx_multicast': str(num('multicasts transmitted')),
                'rx_bps': 0, 'tx_bps': 0,
            }
            prev = self._prev_counters.get(ifname)
            if prev and now > prev[0] and rx >= prev[1] and tx >= prev[2]:
                elapsed = now - prev[0]
                info['rx_bps'] = int((rx - prev[1]) / elapsed)
                info['tx_bps'] = int((tx - prev[2]) / elapsed)
            self._prev_counters[ifname] = (now, rx, tx)
            line_rate = str(stats.get('line rate', '')).split(' ')[0]
            if line_rate.isdigit() and int(line_rate) > 0:
                info['speed'] = int(line_rate) // 1000000
            ret[ifname] = info
        missing = [p for p in self.ports if p['ifname'] not in ret]
        if missing and self.local:
            fallback = super()._get_ifstat()
            for p in missing:
                if p['ifname'] in fallback:
                    ret[p['ifname']] = fallback[p['ifname']]
        return ret

    def _get_interface_macs(self):
        overview = self._overview()
        if not overview:
            return super()._get_interface_macs()
        ret = {}
        fallback = None
        for port in self.ports:
            row = overview.get(port['realif'])
            mac = (row or {}).get('macaddr', '')
            if mac and mac != '00:00:00:00:00:00':
                ret[port['ifname']] = mac.lower()
            else:
                if fallback is None:
                    fallback = super()._get_interface_macs()
                ret[port['ifname']] = fallback.get(port['ifname'], '00:00:00:00:00:00')
        return ret

    def _get_interface_addresses(self):
        overview = self._overview()
        if not overview:
            return super()._get_interface_addresses()
        ret = {}
        for port in self.ports:
            row = overview.get(port['realif'])
            addr = (row or {}).get('addr4') or ''
            if '/' not in addr:
                continue
            ip_addr, bits = addr.split('/', 1)
            mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
            netmask = '.'.join(str((mask >> s) & 0xff) for s in (24, 16, 8, 0))
            entry = {'address': ip_addr, 'netmask': netmask}
            if port['type'].lower() == 'wan':
                gws = row.get('gateways') or []
                gw = gws[0] if gws else self._get_default_gateway()
                if gw:
                    entry['gateway'] = gw
            ret[port['ifname']] = entry
        return ret

    def _get_default_gateway(self):
        status = self._gateway_status()
        if status and status.get('address') not in (None, '', '~'):
            return status['address']
        return super()._get_default_gateway()

    def _wan_gateway_name(self):
        def find():
            wan = self._wan_port()
            ident = self.port_identifier(wan['ifname']) if wan else 'wan'
            rows = self.api.search('routing/settings/search_gateway')
            candidates = [r for r in rows if r.get('interface') == ident
                          and r.get('ipprotocol') == 'inet' and not r.get('disabled')]
            candidates.sort(key=lambda r: (not r.get('defaultgw'), not r.get('upstream')))
            return candidates[0]['name'] if candidates else None
        return self._call('wan_gateway', find, ttl=600)

    def _gateway_status(self):
        name = self._wan_gateway_name()
        items = self._call(
            'gateway_status',
            lambda: self.api.get('routes/gateway/status').get('items', []), ttl=10)
        if not items:
            return None
        if name:
            return next((i for i in items if i.get('name') == name), None)
        return None

    def _get_latency(self):
        status = self._gateway_status()
        if status:
            delay = str(status.get('delay', '')).split(' ')[0]
            try:
                return float(delay)
            except ValueError:
                pass
        return super()._get_latency()

    def _get_nameservers(self):
        if not self.local:
            servers = self._call(
                'nameservers',
                lambda: self.api.get('unbound/settings/get_nameservers'), ttl=600)
            if isinstance(servers, list) and servers:
                return [s for s in servers if s]
        return super()._get_nameservers()

    def _get_system_stats(self):
        if self.local:
            return super()._get_system_stats()
        stats = {'cpu': '0', 'mem': '0'}
        resources = self._call(
            'resources', lambda: self.api.get('diagnostics/system/system_resources'),
            ttl=30)
        mem = (resources or {}).get('memory', {})
        try:
            stats['mem'] = str(int(float(mem['used']) * 100 / float(mem['total'])))
        except (KeyError, ValueError, TypeError, ZeroDivisionError):
            pass
        activity = self._call(
            'activity', lambda: self.api.get('diagnostics/activity/get_activity'),
            ttl=60)
        for line in (activity or {}).get('headers', []):
            if line.startswith('CPU:') and 'idle' in line:
                idle = line.split(',')[-1].strip().split('%')[0]
                try:
                    stats['cpu'] = str(int(100 - float(idle)))
                except ValueError:
                    pass
        return stats

    def _get_uptime(self):
        info = self._call(
            'system_time', lambda: self.api.get('diagnostics/system/system_time'),
            ttl=60)
        return _parse_uptime((info or {}).get('uptime'))

    def _get_speedtest_results(self):
        recent = self._call(
            'speedtest', lambda: self.api.get('speedtest/service/showrecent'), ttl=300)
        if isinstance(recent, dict) and recent.get('date'):
            try:
                lastrun = int(time.mktime(
                    datetime.strptime(recent['date'][:19], '%Y-%m-%dT%H:%M:%S').timetuple()))
                return {
                    'lastrun': lastrun,
                    'ping': float(recent.get('latency', 0)),
                    'download': float(recent.get('download', 0)),
                    'upload': float(recent.get('upload', 0)),
                }
            except (ValueError, TypeError):
                pass
        return super()._get_speedtest_results()

    def _get_ddns(self):
        rows = self._call(
            'ddns', lambda: self.api.search('dyndns/accounts/search_item'), ttl=300)
        result = []
        for row in rows or []:
            if row.get('enabled') != '1':
                continue
            mtime = 0
            try:
                mtime = int(float(row.get('current_mtime') or 0))
            except ValueError:
                pass
            for host in str(row.get('hostnames', '')).split(','):
                if not host:
                    continue
                result.append({
                    'host_name': host,
                    'ip': row.get('current_ip', ''),
                    'status': 'good' if row.get('current_ip') else 'unknown',
                    'atime': 0, 'mtime': mtime, 'wtime': 30,
                    'warned_min_error_interval': 0, 'warned_min_interval': 0,
                })
        return result

    # ── DHCP leases ──────────────────────────────────────────────────────

    def _get_dhcp_leases(self):
        if self.api is None:
            return super()._get_dhcp_leases()
        leases = self._call('leases', self._fetch_leases, ttl=60)
        if leases is None:
            return super()._get_dhcp_leases()
        return leases

    def _fetch_leases(self):
        """Try ISC (os-isc-dhcp), Kea and Dnsmasq; return active IPv4 leases."""
        leases = []
        errors = 0
        sources = (
            # ISC also lists static mappings; only count those seen online
            ('dhcpv4/leases/search_lease', 'mac', 'ends',
             lambda r: r.get('state') == 'active' and (
                 r.get('type') != 'static' or r.get('status') == 'online')),
            ('kea/leases4/search', 'hwaddr', 'expire',
             lambda r: str(r.get('state', '0')) == '0'),
            ('dnsmasq/leases/search', 'hwaddr', 'expire', lambda r: True),
        )
        for path, mac_key, expiry_key, active in sources:
            try:
                rows = self.api.search(path)
            except OPNsenseAPIError:
                errors += 1
                continue
            for row in rows:
                if not row.get(mac_key) or not row.get('address') or not active(row):
                    continue
                if ':' in row['address']:
                    continue
                lease = {'mac': normalize_mac(row[mac_key]), 'ip': row['address'],
                         'expiry': str(row.get(expiry_key, ''))}
                if row.get('hostname'):
                    lease['hostname'] = row['hostname']
                if row.get('type'):
                    lease['type'] = row['type']
                leases.append(lease)
        if errors == len(sources):
            raise OPNsenseAPIError('no DHCP lease API answered')
        return leases

    # ── Clients / host table ─────────────────────────────────────────────

    def _get_neighbors_raw(self):
        if self.api is None:
            return super()._get_neighbors_raw()
        arp = self._call('arp', lambda: self.api.search('diagnostics/interface/search_arp'),
                         ttl=30, max_stale=30)
        if arp is None:
            result = super()._get_neighbors_raw()
            if self.netflow:
                self.netflow.bind(result)
            return result

        lan_devices = self._lan_devices()
        overview = self._overview()
        lan_descr = {(overview.get(d) or {}).get('description') for d in lan_devices}
        descr_device = {(overview.get(d) or {}).get('description'): d for d in lan_devices}
        now = time.time()
        window = int(self.opts['host_active_window'])
        neighbors = {}

        for row in arp:
            if row.get('intf') not in lan_devices or row.get('permanent'):
                continue
            mac = normalize_mac(row.get('mac'))
            if not mac or row.get('expired'):
                continue
            acquired = self._cache.get('arp', (now,))[0]
            neighbors[mac] = {'mac': mac, 'ip': row['ip'], 'realif': row['intf'],
                              'last_seen': acquired}
            if row.get('hostname'):
                neighbors[mac]['hostname'] = row['hostname']
            if row.get('manufacturer'):
                neighbors[mac]['oui'] = row['manufacturer']

        discovered = self._call(
            'hostwatch', lambda: self.api.search('hostdiscovery/service/search'),
            ttl=60, max_stale=300) or []
        for row in discovered:
            if row.get('interface_name') not in lan_descr:
                continue
            mac = normalize_mac(row.get('ether_address'))
            ip = row.get('ip_address', '')
            if not mac or ':' in ip:
                continue
            last_seen = _parse_iso(row.get('last_seen'))
            first_seen = _parse_iso(row.get('first_seen'))
            if mac in neighbors:
                if first_seen:
                    neighbors[mac]['first_seen'] = first_seen
                if last_seen and neighbors[mac]['ip'] == ip:
                    neighbors[mac]['last_seen'] = last_seen
            elif last_seen and now - last_seen <= window:
                neighbors[mac] = {'mac': mac, 'ip': ip, 'last_seen': last_seen,
                                  'realif': descr_device.get(row['interface_name'])}
                if first_seen:
                    neighbors[mac]['first_seen'] = first_seen
                if row.get('organization_name'):
                    neighbors[mac]['oui'] = row['organization_name']

        leases = {l['mac']: l for l in self.data.get('dhcp_leases', [])}
        for mac, entry in neighbors.items():
            if 'hostname' not in entry and leases.get(mac, {}).get('hostname'):
                entry['hostname'] = leases[mac]['hostname']
        result = list(neighbors.values())
        if self.netflow:
            self.netflow.bind(result)
        return result

    def _build_host_table(self):
        if self.api is None:
            return super()._build_host_table()
        now = time.time()
        blocked = set(self._state.get('blocked', []))
        with self._traffic_lock:
            traffic = {ip: dict(c) for ip, c in self._host_traffic.items()}
        use_netflow = self.netflow and self._traffic_source == 'netflow-buckets'
        by_mac = self.netflow.snapshot() if use_netflow else {}
        hosts = []
        for entry in self._get_neighbors_raw():
            mac = entry['mac']
            first = self._host_seen.setdefault(mac, now)
            counters = by_mac.get(mac, {}) if use_netflow else traffic.get(entry['ip'], {})
            host = {
                'mac': mac,
                'ip': entry['ip'],
                'authorized': mac not in blocked,
                'age': max(0, int(now - entry.get('last_seen', now))),
                'uptime': int(now - first),
                'rx_bytes': int(counters.get('rx_bytes', 0)),
                'tx_bytes': int(counters.get('tx_bytes', 0)),
                'rx_packets': int(counters.get('rx_packets', 0)),
                'tx_packets': int(counters.get('tx_packets', 0)),
                'bc_bytes': 0,
                'mc_bytes': 0,
            }
            if entry.get('hostname'):
                host['hostname'] = entry['hostname']
            if entry.get('realif'):
                host['realif'] = entry['realif']
            if entry.get('oui'):
                host['oui'] = entry['oui']
            hosts.append(host)
        return hosts

    # ── Per-client traffic sampling ──────────────────────────────────────

    def _ensure_traffic_sampler(self):
        interval = int(self.opts['traffic_interval'])
        if interval <= 0 or (self._traffic_thread and self._traffic_thread.is_alive()):
            return
        self._traffic_thread = threading.Thread(
            target=self._traffic_loop, args=(interval,), daemon=True,
            name='opnsense-traffic')
        self._traffic_thread.start()

    def _traffic_loop(self, interval):
        last = None
        while True:
            started = time.time()
            elapsed = (started - last) if last else interval
            last = started
            try:
                self.sample_traffic(elapsed)
            except Exception as e:  # never let the sampler die
                logger.debug('Traffic sample failed: %s', e)
            if self.dpi:
                try:
                    self.dpi.exclude_macs(self.data.get('macs', {}).values())
                    self.dpi.poll()
                except Exception as e:
                    logger.debug('Zenarmor DPI poll failed: %s', e)
            time.sleep(max(1, interval - (time.time() - started)))

    def sample_traffic(self, elapsed):
        """Fold Netflow observations, otherwise estimate from iftop samples."""
        if self._insight_enabled():
            try:
                if self.netflow:
                    self.netflow.poll(self._lan_devices())
                    if self._traffic_source != 'netflow-buckets':
                        logger.info('Client traffic accounting: local Netflow LAN buckets')
                    self._traffic_source = 'netflow-buckets'
                    return
                self._sample_insight()
                self._traffic_source = 'insight-api'
                return
            except (OPNsenseAPIError, sqlite3.Error, OSError, ValueError, TypeError) as e:
                logger.warning('Netflow sample failed; retaining confirmed counters: %s', e)
                return
        # Once real counters are in use, estimates must not contaminate them.
        if self._traffic_source in ('netflow-buckets', 'insight-api'):
            return
        self._sample_iftop(elapsed)
        self._traffic_source = 'iftop-estimate'

    def _insight_enabled(self):
        status = self._call(
            'netflow_enabled', lambda: self.api.get('diagnostics/netflow/is_enabled'),
            ttl=600)
        return bool(status) and str(status.get('local')) == '1'

    def _sample_insight(self):
        """Byte/packet totals per client since the daemon started.

        FlowSourceAddrTotals books a flow under its source address with
        direction 'in' (client sent: tx) and under its destination with
        direction 'out' (client received: rx). With WAN capture set to
        egress-only, LAN addresses are only seen on the LAN side, so nothing
        is counted twice."""
        if self._insight_start is None:
            self._insight_start = int(time.time())
        now = int(time.time()) + 1
        totals = {}
        for measure, suffix in (('octets', 'bytes'), ('packets', 'packets')):
            path = 'diagnostics/networkinsight/top/FlowSourceAddrTotals/%d/%d/' \
                   'src_addr,direction/%s/5000' % (self._insight_start, now, measure)
            for rec in self.api.get(path) or []:
                ip = rec.get('src_addr')
                key = {'in': 'tx_', 'out': 'rx_'}.get(rec.get('direction'))
                if not ip or not key:
                    continue
                totals.setdefault(ip, {})[key + suffix] = int(rec.get('total') or 0)
        with self._traffic_lock:
            for ip, values in totals.items():
                c = self._host_traffic.setdefault(ip, {})
                for key, value in values.items():
                    # Insight re-buckets at coarser resolutions as the window
                    # grows; never let a counter go backwards.
                    c[key] = max(c.get(key, 0), value)

    def _sample_iftop(self, elapsed):
        """Accumulate estimated byte counters from one iftop sample.

        ``rate_bits_in`` is traffic towards the client (its download, reported
        as rx_bytes), ``rate_bits_out`` traffic from it (tx_bytes)."""
        idents = ','.join(self.lan_identifiers())
        data = self.api.get('diagnostics/traffic/top/' + idents, timeout=30)
        if not isinstance(data, dict):
            return
        with self._traffic_lock:
            for content in data.values():
                for rec in (content or {}).get('records', []):
                    tags = rec.get('tags', [])
                    if 'local' in tags or 'private' not in tags:
                        continue
                    c = self._host_traffic.setdefault(rec['address'], {})
                    c['rx_bytes'] = c.get('rx_bytes', 0) +                         rec.get('rate_bits_in', 0) / 8.0 * elapsed
                    c['tx_bytes'] = c.get('tx_bytes', 0) +                         rec.get('rate_bits_out', 0) / 8.0 * elapsed

    # ── Controller actions ───────────────────────────────────────────────

    def _ips_for(self, macs):
        macs = {normalize_mac(m) for m in macs}
        ips = set()
        for host in self.data.get('host_table', []):
            if host['mac'] in macs:
                ips.add(host['ip'])
        for lease in self.data.get('dhcp_leases', []):
            if lease['mac'] in macs:
                ips.add(lease['ip'])
        return ips

    def _apply_blocked(self, kill_macs=()):
        if not self.sync or not self._bool('block_clients'):
            return False
        macs = self._state.get('blocked', [])
        self.sync.sync_blocked(macs, self._ips_for(macs))
        for ip in self._ips_for(kill_macs):
            self.sync.kill_states(ip)
        return True

    def block_client(self, mac):
        mac = normalize_mac(mac)
        blocked = set(self._state.get('blocked', []))
        blocked.add(mac)
        self._state['blocked'] = sorted(blocked)
        self._save_state()
        logger.info('Blocking client %s', mac)
        return self._apply_blocked(kill_macs=[mac])

    def unblock_client(self, mac):
        mac = normalize_mac(mac)
        blocked = set(self._state.get('blocked', []))
        blocked.discard(mac)
        self._state['blocked'] = sorted(blocked)
        self._save_state()
        logger.info('Unblocking client %s', mac)
        return self._apply_blocked()

    def set_blocked_clients(self, macs):
        macs = sorted({normalize_mac(m) for m in macs if m})
        new = set(macs) - set(self._state.get('blocked', []))
        self._state['blocked'] = macs
        self._save_state()
        return self._apply_blocked(kill_macs=new)

    def kick_client(self, mac):
        if not self.sync:
            return False
        for ip in self._ips_for([mac]):
            self.sync.kill_states(ip)
        return True

    def refresh_blocked_ips(self):
        """Keep the blocked-IP alias current as blocked clients change address."""
        if self._state.get('blocked'):
            self._apply_blocked()

    def apply_system_cfg(self, cfg, force=False):
        if not self.sync:
            return False
        digest = _digest(cfg)
        if not force and digest == self._state.get('system_cfg_hash'):
            return True
        sync = self.udapi_sync if is_udapi_config(cfg) else self.sync
        summary = sync.apply_system_cfg(cfg)
        logger.info('Applied controller config to OPNsense: %s', json.dumps(summary))
        self._state['system_cfg_hash'] = digest
        self._save_state()
        return True

    def reboot(self):
        if not self.api or not self._bool('allow_reboot'):
            return False
        logger.warning('Rebooting OPNsense on controller request')
        self.api.post('core/system/reboot')
        return True

    def run_speedtest(self):
        if not self.api:
            return False
        try:
            result = self.api.get('speedtest/service/run/0', timeout=180)
        except OPNsenseAPIError as e:
            logger.warning('OPNsense speedtest failed: %s', e)
            return False
        if isinstance(result, dict) and result.get('version') == 'none':
            # the plugin is installed but has no speedtest backend to run
            logger.warning('OPNsense speedtest unavailable: %s', result.get('message'))
            return False
        self._cache.pop('speedtest', None)
        logger.info('Speed test complete: %s', result)
        return True


def _parse_iso(value):
    """Parse hostwatch's UTC timestamps (2026-10-19T18:19:40Z)."""
    if not value:
        return None
    try:
        dt = datetime.strptime(value.rstrip('Z')[:19], '%Y-%m-%dT%H:%M:%S')
    except ValueError:
        return None
    return calendar.timegm(dt.timetuple())


def _parse_uptime(value):
    """Parse OPNsense's '3 days, 02:03:04' / '06:54:07' uptime string."""
    match = re.match(r'(?:(\d+)\s+\w+,\s*)?(\d+):(\d+):(\d+)$', (value or '').strip())
    if not match:
        return None
    days, hours, minutes, seconds = (int(g or 0) for g in match.groups())
    return ((days * 24 + hours) * 60 + minutes) * 60 + seconds


def _digest(cfg):
    return hashlib.sha256(json.dumps(cfg, sort_keys=True).encode('utf-8')).hexdigest()
