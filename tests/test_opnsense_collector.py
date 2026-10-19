# -*- coding: utf-8 -*-
"""Tests for OPNSenseCollector reading data through the REST API.

Canned responses are trimmed from a live OPNsense 26.7.7 box."""
import io
import time
from unittest.mock import patch

import pytest

from collectors.opnsense import OPNSenseCollector, _parse_iso, _parse_uptime
from collectors.opnsense_api import OPNsenseAPIError

NOW = time.time()


def _iso(ts):
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(ts))


RESPONSES = {
    'interfaces/overview/interfaces_info': [
        {'identifier': 'wan', 'device': 'vmx0', 'macaddr': '80:2a:a8:98:76:51',
         'addr4': '102.140.218.150/24', 'link_type': 'dhcp',
         'gateways': ['102.140.218.1'], 'ipv4': [{'ipaddr': '102.140.218.150/24'}]},
        {'identifier': 'lan', 'device': 'vmx1', 'macaddr': '80:2a:a8:98:76:53',
         'description': 'LAN', 'addr4': '10.0.5.1/24', 'link_type': 'static',
         'gateways': [], 'ipv4': [{'ipaddr': '10.0.5.1/24'}]},
    ],
    'diagnostics/traffic/interface': {'interfaces': {
        'wan': {'device': 'vmx0', 'bytes received': '3567929068',
                'bytes transmitted': '329376780', 'packets received': '100',
                'packets transmitted': '200', 'input errors': '1',
                'output errors': '0', 'line rate': '1000000000 bit/s'},
        'lan': {'device': 'vmx1', 'bytes received': '311977884',
                'bytes transmitted': '3429329881', 'line rate': '100000000 bit/s'},
    }},
    'routing/settings/search_gateway': [
        {'name': 'WAN_GWv6', 'interface': 'wan', 'ipprotocol': 'inet6', 'defaultgw': True},
        {'name': 'WAN_GWv4', 'interface': 'wan', 'ipprotocol': 'inet',
         'defaultgw': True, 'upstream': True, 'disabled': False},
    ],
    'routes/gateway/status': {'items': [
        {'name': 'WAN_GWv4', 'address': '102.140.218.1', 'delay': '172.0 ms'},
    ]},
    'dhcpv4/leases/search_lease': [
        {'address': '10.0.5.2', 'type': 'static', 'mac': '8C:73:A0:A2:5D:20',
         'hostname': 'MumAP', 'state': 'active', 'status': 'offline'},
        {'address': '10.0.5.101', 'type': 'dynamic', 'mac': 'b8:81:98:67:48:5f',
         'hostname': 'bmm', 'state': 'active', 'ends': '2026/10/20 01:00:00'},
        {'address': '10.0.5.172', 'type': 'static', 'mac': 'd4:94:a9:f4:e1:24',
         'hostname': 'Phoenix', 'state': 'active', 'status': 'online'},
        {'address': '10.0.5.9', 'type': 'dynamic', 'mac': '00:11:22:33:44:55',
         'state': 'expired'},
    ],
    'diagnostics/interface/search_arp': [
        {'mac': '80:2a:a8:98:76:53', 'ip': '10.0.5.1', 'intf': 'vmx1', 'permanent': True},
        {'mac': 'b8:81:98:67:48:5f', 'ip': '10.0.5.101', 'intf': 'vmx1',
         'permanent': False, 'expired': False, 'hostname': ''},
        {'mac': 'd4:94:a9:f4:e1:24', 'ip': '10.0.5.172', 'intf': 'vmx1',
         'permanent': False, 'expired': False},
        {'mac': '54:89:98:f1:91:be', 'ip': '102.140.218.1', 'intf': 'vmx0',
         'permanent': False},
    ],
    'hostdiscovery/service/search': [
        {'interface_name': 'LAN', 'ether_address': 'b8:81:98:67:48:5f',
         'ip_address': '10.0.5.101', 'first_seen': _iso(NOW - 86400),
         'last_seen': _iso(NOW - 60)},
        {'interface_name': 'LAN', 'ether_address': 'c4:aa:c4:1f:0c:d6',
         'ip_address': '10.0.5.44', 'first_seen': _iso(NOW - 3600),
         'last_seen': _iso(NOW - 30)},
        {'interface_name': 'LAN', 'ether_address': 'c4:aa:c4:1f:11:b6',
         'ip_address': '10.0.5.43', 'last_seen': _iso(NOW - 86400)},
    ],
    'speedtest/service/showrecent': {
        'date': '2026-07-16T01:59:00', 'download': '44.54', 'upload': '42.24',
        'latency': '3.75'},
    'dyndns/accounts/search_item': [
        {'enabled': '1', 'hostnames': 'bananz0.dedyn.io', 'current_ip': '102.140.218.150',
         'password': 'secret'},
        {'enabled': '0', 'hostnames': 'old.example', 'current_ip': ''},
    ],
    'diagnostics/system/system_resources': {'memory': {'total': '1000', 'used': 250}},
    'diagnostics/activity/get_activity': {'headers': [
        'CPU:  2.0% user,  0.0% nice,  1.0% system,  0.0% interrupt, 97.0% idle']},
    'diagnostics/system/system_time': {'uptime': '1 day, 02:00:05'},
    'unbound/settings/get_nameservers': ['9.9.9.9', '149.112.112.112'],
    'diagnostics/traffic/top/lan': {'lan': {'records': [
        {'address': '10.0.5.101', 'rate_bits_in': 80000, 'rate_bits_out': 8000,
         'tags': ['private']},
        {'address': '10.0.5.1', 'rate_bits_in': 1, 'rate_bits_out': 1,
         'tags': ['local', 'private']},
        {'address': '17.248.151.230', 'rate_bits_in': 5, 'rate_bits_out': 5, 'tags': []},
    ]}},
}


class FakeReadAPI:

    def __init__(self, url, key, secret, verify_ssl=False, timeout=30):
        self.host = url.split('//')[1].split(':')[0].split('/')[0]
        self.responses = dict(RESPONSES)
        self.posts = []

    def _lookup(self, path):
        if path not in self.responses:
            raise OPNsenseAPIError('GET %s: HTTP 404' % path)
        value = self.responses[path]
        if isinstance(value, Exception):
            raise value
        return value

    def get(self, path, params=None, timeout=None):
        return self._lookup(path)

    def search(self, path, params=None, timeout=None):
        value = self._lookup(path)
        return value if isinstance(value, list) else value.get('rows', [])

    def post(self, path, payload=None, timeout=None):
        self.posts.append((path, payload))
        return {'status': 'ok', 'result': 'saved', 'uuid': 'u', 'dropped_states': 1}


@pytest.fixture
def opn_config(freebsd_config, tmp_path):
    freebsd_config.read_dict({'opnsense': {
        'url': 'https://192.0.2.1:20443', 'api_key': 'k', 'api_secret': 's',
        'traffic_interval': '0', 'state_file': str(tmp_path / 'state.json'),
    }})
    return freebsd_config


@pytest.fixture
def collector(opn_config, bsd_patches):
    with patch('collectors.opnsense.OPNsenseAPI', FakeReadAPI), \
            patch('collectors.opnsense.os.path.exists', return_value=False):
        dc = OPNSenseCollector(opn_config)
    dc.data['host_table'] = dc._build_host_table()
    return dc


class TestParsing:

    def test_parse_uptime(self):
        assert _parse_uptime('06:54:07') == 6 * 3600 + 54 * 60 + 7
        assert _parse_uptime('3 days, 01:00:00') == 3 * 86400 + 3600
        assert _parse_uptime('garbage') is None

    def test_parse_iso_is_utc(self):
        assert _parse_iso('1970-01-02T00:00:00Z') == 86400
        assert _parse_iso('') is None


def test_failed_arp_read_cannot_keep_old_clients_fresh(collector):
    collector._cache['arp'] = (time.time() - 90, ['stale'])
    def fail():
        raise OPNsenseAPIError('unavailable')
    assert collector._call('arp', fail, ttl=30, max_stale=30) is None


def test_unused_netflow_database_does_not_hide_estimates(collector):
    from unittest.mock import Mock
    collector.netflow = Mock()
    collector.netflow.snapshot.return_value = {}
    collector._traffic_source = 'iftop-estimate'
    collector._host_traffic['10.0.5.101'] = {'rx_bytes': 123}
    hosts = {h['ip']: h for h in collector._build_host_table()}
    assert hosts['10.0.5.101']['rx_bytes'] == 123
    collector._traffic_source = 'netflow-buckets'
    collector.netflow.snapshot.return_value = {
        'b8:81:98:67:48:5f': {'rx_bytes': 456, 'tx_packets': 7}}
    hosts = {h['ip']: h for h in collector._build_host_table()}
    assert hosts['10.0.5.101']['rx_bytes'] == 456
    assert hosts['10.0.5.101']['tx_packets'] == 7


class TestReads:

    def test_remote_mode(self, collector):
        assert collector.local is False
        assert collector.port_identifier('eth0') == 'wan'
        assert collector.lan_identifiers() == ['lan']

    def test_interfaces(self, collector):
        assert collector.data['macs'] == {'eth0': '80:2a:a8:98:76:51', 'eth1': '80:2a:a8:98:76:53'}
        assert collector.data['ip']['eth0'] == {
            'address': '102.140.218.150', 'netmask': '255.255.255.0',
            'gateway': '102.140.218.1'}
        assert collector.data['ip']['eth1']['netmask'] == '255.255.255.0'
        wan = collector.data['ifstat']['eth0']
        assert wan['rx_bytes'] == '3567929068'
        assert wan['rx_errors'] == '1'
        assert wan['speed'] == 1000
        assert collector.data['ifstat']['eth1']['speed'] == 100

    def test_wan_and_system(self, collector):
        assert collector.data['latency'] == 172.0
        assert collector.data['nameservers'] == ['9.9.9.9', '149.112.112.112']
        assert collector.data['system_stats'] == {'cpu': '3', 'mem': '25'}
        assert collector.data['uptime'] == 86400 + 7205
        assert collector.data['wan_type'] == 'dhcp'
        assert collector.data['speedtest']['download'] == 44.54

    def test_ddns_never_leaks_credentials(self, collector):
        assert collector.data['ddns'] == [{
            'host_name': 'bananz0.dedyn.io', 'ip': '102.140.218.150', 'status': 'good',
            'atime': 0, 'mtime': 0, 'wtime': 30,
            'warned_min_error_interval': 0, 'warned_min_interval': 0}]
        assert 'secret' not in repr(collector.data)

    def test_leases_skip_offline_static_and_expired(self, collector):
        ips = sorted(l['ip'] for l in collector.data['dhcp_leases'])
        assert ips == ['10.0.5.101', '10.0.5.172']

    def test_host_table(self, collector):
        hosts = {h['ip']: h for h in collector.data['host_table']}
        # ARP LAN entries + hostwatch hosts seen within the window
        assert sorted(hosts) == ['10.0.5.101', '10.0.5.172', '10.0.5.44']
        assert hosts['10.0.5.101']['hostname'] == 'bmm'
        assert 50 <= hosts['10.0.5.101']['age'] <= 120
        assert hosts['10.0.5.172']['hostname'] == 'Phoenix'
        assert all(h['authorized'] for h in hosts.values())

    def test_traffic_accumulates_per_client(self, collector):
        collector.sample_traffic(10)
        collector.sample_traffic(10)
        hosts = {h['ip']: h for h in collector._build_host_table()}
        assert hosts['10.0.5.101']['rx_bytes'] == 200000  # 80 kbit/s * 20 s / 8
        assert hosts['10.0.5.101']['tx_bytes'] == 20000
        assert '10.0.5.1' not in collector._host_traffic
        assert '17.248.151.230' not in collector._host_traffic

    def test_insight_totals_preferred_and_monotonic(self, collector):
        collector.api.responses['diagnostics/netflow/is_enabled'] = {'netflow': 1, 'local': 1}
        rows = [
            {'src_addr': '10.0.5.101', 'direction': 'out', 'total': 5000},
            {'src_addr': '10.0.5.101', 'direction': 'in', 'total': 700},
            {'src_addr': '', 'direction': '', 'total': 3},  # Insight's "(other)" row
        ]
        packets = [
            {'src_addr': '10.0.5.101', 'direction': 'out', 'total': 9},
            {'src_addr': '10.0.5.101', 'direction': 'in', 'total': 4},
        ]

        def fake_get(path, params=None, timeout=None):
            if path.startswith('diagnostics/networkinsight/top/FlowSourceAddrTotals/'):
                return rows if '/octets/' in path else packets
            return FakeReadAPI._lookup(collector.api, path)

        collector.api.get = fake_get
        collector.sample_traffic(30)
        host = {h['ip']: h for h in collector._build_host_table()}['10.0.5.101']
        assert (host['rx_bytes'], host['tx_bytes']) == (5000, 700)
        assert (host['rx_packets'], host['tx_packets']) == (9, 4)

        rows[0]['total'] = 4000  # coarser bucket returned less: keep the max
        collector.sample_traffic(30)
        host = {h['ip']: h for h in collector._build_host_table()}['10.0.5.101']
        assert host['rx_bytes'] == 5000

    def test_without_psutil_uses_api_for_host_stats(self, opn_config, bsd_patches):
        with patch('collectors.opnsense.OPNsenseAPI', FakeReadAPI), \
                patch('collectors.base.psutil', None), \
                patch('collectors.opnsense.os.path.exists', return_value=True):
            dc = OPNSenseCollector(opn_config)
        assert dc.local is False
        assert dc.data['system_stats'] == {'cpu': '3', 'mem': '25'}
        assert dc.data['uptime'] == 86400 + 7205

    def test_api_failure_falls_back(self, opn_config, bsd_patches):
        with patch('collectors.opnsense.OPNsenseAPI', FakeReadAPI), \
                patch('collectors.opnsense.os.path.exists', return_value=False), \
                patch.object(FakeReadAPI, '_lookup',
                             side_effect=OPNsenseAPIError('down')):
            dc = OPNSenseCollector(opn_config)
        # psutil-based fallback still produced interface data
        assert dc.data['macs']['eth0'] == '00:0c:29:a3:6d:9e'
        assert dc.data['dhcp_leases'] == []

    def test_without_credentials_is_plain_freebsd(self, freebsd_config, bsd_patches):
        dc = OPNSenseCollector(freebsd_config)
        assert dc.api is None and dc.sync is None
        assert dc.block_client('aa:bb:cc:dd:ee:ff') is False


class TestActions:

    def test_block_and_unblock_persist(self, collector):
        # bsd_patches stubs out open(); the state file needs the real one
        with patch('builtins.open', io.open),                 patch.object(collector.sync, 'sync_blocked') as sync_blocked, \
                patch.object(collector.sync, 'kill_states') as kill:
            assert collector.block_client('B8-81-98-67-48-5F') is True
            sync_blocked.assert_called_with(['b8:81:98:67:48:5f'], {'10.0.5.101'})
            kill.assert_called_once_with('10.0.5.101')
            assert collector._load_state()['blocked'] == ['b8:81:98:67:48:5f']
            assert collector.unblock_client('b8:81:98:67:48:5f') is True
            sync_blocked.assert_called_with([], set())
            assert collector._load_state()['blocked'] == []

    def test_blocked_host_is_unauthorized(self, collector):
        collector._state['blocked'] = ['b8:81:98:67:48:5f']
        hosts = {h['ip']: h for h in collector._build_host_table()}
        assert hosts['10.0.5.101']['authorized'] is False

    def test_system_cfg_applied_once_per_change(self, collector):
        with patch.object(collector.sync, 'apply_system_cfg', return_value={}) as apply:
            assert collector.apply_system_cfg({'a': 1}) is True
            assert collector.apply_system_cfg({'a': 1}) is True
            assert apply.call_count == 1
            collector.apply_system_cfg({'a': 2})
            assert apply.call_count == 2

    def test_reboot_is_opt_in(self, collector):
        assert collector.reboot() is False
        collector.opts['allow_reboot'] = 'true'
        assert collector.reboot() is True
        assert ('core/system/reboot', None) in collector.api.posts
