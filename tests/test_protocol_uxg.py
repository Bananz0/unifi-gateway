# -*- coding: utf-8 -*-
"""Tests for the UXG (device = UXGB) inform payload."""
import configparser
import json
from unittest.mock import patch

import pytest

import unifi_protocol
from unifi_protocol import UDAPI_VERSION, create_inform, is_uxg

PORTS = ('[{"ifname":"eth4","name":"WAN","type":"wan","realif":"igb0"},'
         '{"ifname":"eth1","name":"LAN","type":"lan","realif":"igb1"},'
         '{"ifname":"eth2","name":"IOT","type":"lan2","realif":"igb2","network":"br20","vlan":20}]')


def make_config(device='UXGB', adopted=True):
    cfg = configparser.RawConfigParser()
    cfg.read_dict({
        'gateway': {
            'ports': PORTS, 'is_adopted': str(adopted), 'lan_ip': '192.168.1.1',
            'lan_mac': '74:ac:b9:5e:00:01', 'firmware': '5.1.26.33914',
            'device': device, 'device_display': 'UniFi Gateway Max',
            'url': 'http://unifi:8080/inform', 'hostname': 'gw',
        },
        'provisioned': {'cfgversion': 'd939f9148878909d'},
    })
    return cfg


def stats(rx):
    return {'rx_bytes': rx, 'tx_bytes': rx // 2, 'rx_packets': 10, 'tx_packets': 5,
            'rx_errors': 0, 'tx_errors': 0, 'rx_dropped': 0, 'tx_dropped': 0,
            'rx_multicast': 0, 'rx_bps': 0, 'tx_bps': 0}


class DC:
    def __init__(self, **extra):
        self.data = {
            'ifstat': {'eth4': stats(1000), 'eth1': stats(2000), 'eth2': stats(3000)},
            'ip': {'eth4': {'address': '203.0.113.2', 'netmask': '255.255.255.0',
                            'gateway': '203.0.113.1'},
                   'eth1': {'address': '192.168.1.1', 'netmask': '255.255.255.0'},
                   'eth2': {'address': '192.168.20.1', 'netmask': '255.255.255.0'}},
            'macs': {'eth4': '74:ac:b9:5e:00:05', 'eth1': '74:ac:b9:5e:00:01',
                     'eth2': '74:ac:b9:5e:00:02'},
            'host_table': [
                {'mac': 'aa:bb:cc:00:00:01', 'ip': '192.168.1.50', 'hostname': 'laptop',
                 'age': 3, 'uptime': 600, 'rx_bytes': 10, 'tx_bytes': 5, 'realif': 'igb1',
                 'oui': 'Acme'},
                {'mac': 'aa:bb:cc:00:00:02', 'ip': '192.168.20.9', 'realif': 'igb2'},
                {'mac': 'aa:bb:cc:00:00:03', 'ip': '192.168.1.60'},
            ],
            'dhcp_leases': [
                {'mac': 'aa:bb:cc:00:00:01', 'ip': '192.168.1.50', 'hostname': 'laptop',
                 'expiry': '1792444000'},
                {'mac': 'aa:bb:cc:00:00:02', 'ip': '192.168.20.9',
                 'expiry': '2026/10/20 01:00:00'},
            ],
            'speedtest': {'download': 90, 'upload': 20, 'ping': 7, 'lastrun': 1792440000},
            'ddns': [{'host_name': 'x.example.net', 'status': 'good'}],
            'system_stats': {'cpu': '3', 'mem': '40'},
            'uptime': 1234,
        }
        self.data.update(extra)


def inform(config=None, dc=None, **kw):
    with patch('unifi_protocol.uptime', return_value=99):
        return json.loads(create_inform(config or make_config(), dc or DC(), **kw))


def test_secondary_wan_without_ip_still_reports_real_port_and_down_state():
    import ast
    config = make_config()
    ports = ast.literal_eval(config.get('gateway', 'ports'))
    ports.append({'ifname': 'eth3', 'realif': 're1', 'type': 'wan2',
                  'name': 'WAN2', 'port_idx': 4})
    config.set('gateway', 'ports', json.dumps(ports))
    dc = DC()
    dc.data['ifstat']['eth3'] = {**stats(0), 'up': False, 'enable': False}
    dc.data['macs']['eth3'] = '00:11:22:33:44:55'
    port = next(p for p in inform(config, dc)['port_table'] if p['port_idx'] == 4)
    assert port['name'] == 'eth3'
    assert port['is_uplink'] is True
    assert port['up'] is False
    assert port['enable'] is False
    assert port['mac'] == '00:11:22:33:44:55'


class TestSelection:

    @pytest.mark.parametrize('device,expected', [
        ('UXGB', True), ('uxgb', True), ('UXGPRO', True), ('UGW3', False), ('', False)])
    def test_is_uxg(self, device, expected):
        assert is_uxg(make_config(device)) is expected

    def test_usg_mode_unchanged(self):
        payload = inform(make_config('UGW3'))
        assert 'udapi_version' not in payload and 'port_table' not in payload
        assert 'host_table' in payload['network_table'][1]

    def test_unadopted_uxg_sends_partial_inform(self):
        payload = inform(make_config(adopted=False))
        assert payload['model'] == 'UXGB' and payload['state'] == 0
        assert 'port_table' not in payload


class TestPayload:

    def test_identity_and_required_blocks(self):
        p = inform()
        assert p['model'] == 'UXGB' and p['version'] == '5.1.26.33914'
        assert p['state'] == 2 and p['default'] is False
        assert p['cfgversion'] == 'd939f9148878909d'
        assert p['udapi_version'] == UDAPI_VERSION
        assert p['uplink'] == 'eth4'
        assert p['mac'] == '74:ac:b9:5e:00:01' and p['ip'] == '192.168.1.1'
        for key in ('if_table', 'network_table', 'routes', 'speedtest-status',
                    'ddns-status', 'system-stats', 'ipv4_active_leases', 'port_table'):
            assert key in p
        assert p['speedtest-status']['xput_download'] == 90
        assert p['ddns-status'] == {'dyndns': [{'host_name': 'x.example.net', 'status': 'good'}]}

    def test_port_table_carries_clients(self):
        ports = {p['ifname']: p for p in inform()['port_table']}
        # front-panel numbering, as the controller seeds a UXG-Max: ethN = port N+1
        assert {name: p['port_idx'] for name, p in ports.items()} == {'eth4': 5, 'eth1': 2, 'eth2': 3}
        wan = ports['eth4']
        assert wan['is_uplink'] is True and wan['mac_table'] == []
        lan = ports['eth1']
        assert lan['mac'] == '74:ac:b9:5e:00:01' and lan['num_port'] == 1
        assert lan['rx_bytes'] == 2000 and lan['up'] is True
        macs = {h['mac']: h for h in lan['mac_table']}
        # realif-matched host plus the one without realif (primary LAN)
        assert set(macs) == {'aa:bb:cc:00:00:01', 'aa:bb:cc:00:00:03'}
        laptop = macs['aa:bb:cc:00:00:01']
        assert laptop['hostname'] == 'laptop' and laptop['static'] is False
        assert laptop['vlan'] == 1 and 'realif' not in laptop and 'oui' not in laptop
        iot = ports['eth2']['mac_table']
        assert [h['mac'] for h in iot] == ['aa:bb:cc:00:00:02'] and iot[0]['vlan'] == 20

    def test_active_leases(self):
        leases = {lease['mac']: lease for lease in inform()['ipv4_active_leases']}
        assert leases['aa:bb:cc:00:00:01'] == {
            'mac': 'aa:bb:cc:00:00:01', 'ip': '192.168.1.50', 'hostname': 'laptop',
            'network': 'br0', 'expiration': 1792444000}
        # non-epoch expiry is omitted rather than guessed
        assert leases['aa:bb:cc:00:00:02'] == {
            'mac': 'aa:bb:cc:00:00:02', 'ip': '192.168.20.9', 'network': 'br20'}

    def test_network_table_uses_udapi_names_without_host_table(self):
        nets = {n['name']: n for n in inform()['network_table']}
        assert set(nets) == {'eth4', 'br0', 'br20'}
        assert all('host_table' not in n for n in nets.values())
        assert nets['br0']['address'] == '192.168.1.1/24'
        assert nets['eth4']['gateways'] == ['203.0.113.1']

    def test_dpi_uses_modern_schema_only(self):
        dpi = [{'mac': 'aa:bb:cc:00:00:01', 'initialized': '1', 'stats': [
            {'app': 112, 'cat': 4, 'rx_bytes': 10, 'tx_bytes': 5}]}]
        p = inform(dc=DC(dpi_stats=dpi))
        assert p['has_dpi'] is True
        assert p['dpi_stats'][0]['stats'][0] == {'app': 112, 'cat': 4, 'rxBytes': 10, 'txBytes': 5}
        assert 'dpi-stats' not in p and 'dpi-clients' not in p
        assert inform()['has_dpi'] is False and 'dpi_stats' not in inform()

    def test_include_blocks(self):
        assert 'gw_caps' not in inform()
        p = inform(include_blocks=['ipv4_active_leases', 'gw_caps'])
        assert p['gw_caps'] == unifi_protocol.GW_CAPS
        assert p['ipv4_active_leases']  # always sent, requested or not

    def test_encodes_with_inform_protocol(self):
        cfg = make_config()
        cfg.set('gateway', 'key', '0' * 32)
        cfg.set('gateway', 'use_aes_gcm', 'True')
        with patch('unifi_protocol.uptime', return_value=99):
            data = create_inform(cfg, DC())
        packet = unifi_protocol.encode_inform(cfg, data)
        assert unifi_protocol.decode_inform(cfg, packet)['model'] == 'UXGB'


def test_connections_use_udapi_interface_names():
    flow = {'ip': {'saddr': '192.168.1.50', 'daddr': '1.1.1.1', 'protocol': 17,
                   'version': 'v4', 'sport': 5000, 'dport': 53},
            'stats': {'rxBytes': 1, 'rxPackets': 1, 'txBytes': 1, 'txPackets': 1},
            'in': 'lan', 'out': 'wan'}
    p = inform(dc=DC(connections=[flow]))
    assert p['connections'][0]['in'] == 'br0' and p['connections'][0]['out'] == 'eth4'
    assert p['connections'][0]['ip'] == flow['ip']
    assert 'connections' not in inform()


def test_capabilities_advertise_only_implemented_features():
    caps = inform()['usg_caps']
    assert caps & 0x20000000            # trigger logs -> blocked Traffic Flows
    assert caps & 1                     # DPI
    for unsupported in (128, 0x40000000, 64, 32):   # IPS, ad block, GeoIP, schedules
        assert not caps & unsupported
    # region blocking only once OPNsense has a GeoIP database
    assert inform(dc=DC(geoip_ready=True))['usg_caps'] & 64
    # threat management only when the operator opts in
    assert inform(dc=DC(ids_available=True))['usg_caps'] & 0x2080 == 0x2080


def test_triggers_use_udapi_interface_names():
    trig = {'id': '000000000000000000000001', 'type': 'FIREWALL_RULE', 'in': 'wan',
            'ip': {'saddr': '79.124.62.230', 'daddr': '203.0.113.2', 'protocol': 6}}
    p = inform(dc=DC(triggers=[trig]))
    assert p['triggers'][0]['in'] == 'eth4' and 'out' not in p['triggers'][0]


def test_port_throughput_rates():
    """The dashboard's Throughput reads the uplink's *-r rates; a UXG has to
    report them (the controller showed 0 bps without)."""
    st = stats(1000)
    st.update(rx_bps=5000, tx_bps=700)
    dc = DC()
    dc.data['ifstat']['eth4'] = st
    wan = {p['ifname']: p for p in inform(dc=dc)['port_table']}['eth4']
    assert (wan['rx_bytes-r'], wan['tx_bytes-r'], wan['bytes-r']) == (5000, 700, 5700)
