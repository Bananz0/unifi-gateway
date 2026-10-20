# -*- coding: utf-8 -*-
"""Tests for mirroring OPNsense objects into the UniFi controller."""
import copy
import itertools

import pytest

from collectors.opnsense_api import OPNsenseAPIError
from collectors.unifi_mirror import OPNsenseMirror, UniFiAPIError

OPN = {
    'firewall/alias/search_item': [
        {'name': 'HomeServer', 'type': 'host', 'content': '10.0.5.245', 'enabled': '1'},
        {'name': 'HoneyPotSSHPorts', 'type': 'port', 'content': '22\n2222\n22222', 'enabled': '1'},
        {'name': 'Countries', 'type': 'geoip', 'content': 'KE', 'enabled': '1'},
        {'name': 'ufg_blocked', 'type': 'mac', 'content': 'aa:bb:cc:dd:ee:ff', 'enabled': '1'},
    ],
    'firewall/d_nat/search_rule': [
        {'uuid': 'automatic_pf_1', 'is_automatic': True, 'interface': 'lan'},
        {'interface': 'wan', 'protocol': 'tcp', 'destination.port': '32400',
         'target': 'HomeServer', 'local-port': '32400', 'descr': 'Plex', 'disabled': '0'},
        {'interface': 'wan', 'protocol': 'tcp/udp', 'destination.port': '13290',
         'target': '10.0.5.9', 'local-port': '', 'descr': 'Torrent', 'disabled': '1'},
        {'interface': 'opt1,wan', 'protocol': 'tcp', 'destination.port': 'HoneyPotSSHPorts',
         'target': 'HomeServer', 'local-port': '2222', 'descr': 'Honeypot'},
        {'interface': 'lan', 'protocol': 'udp', 'destination.port': '123',
         'target': '127.0.0.1', 'local-port': '123', 'descr': 'NTP redirect'},
        {'interface': 'wan', 'protocol': 'tcp', 'destination.port': '8080',
         'target': '10.0.5.210', 'descr': 'unifi-gw:pf-3001-wan from UniFi'},
    ],
    'interfaces/overview/interfaces_info': [
        {'identifier': 'wan', 'description': 'WAN1'},
        {'identifier': 'lan', 'description': 'LAN'},
    ],
    'firewall/filter/search_rule': [
        {'description': 'Default allow LAN to any rule', 'interface': 'LAN', 'enabled': '1',
         'action': 'pass', 'protocol': '', 'ipprotocol': 'inet', 'source_net': 'lan',
         'destination_net': 'any', 'sort_order': '1'},
        {'description': 'OpenVPN', 'interface': 'WAN1', 'enabled': '1', 'action': 'pass',
         'protocol': 'udp', 'ipprotocol': 'inet', 'source_net': 'any',
         'destination_net': '(self)', 'destination_port': '1194', 'sort_order': '2'},
        {'description': 'To home server web', 'interface': 'lan', 'enabled': '0',
         'action': 'block', 'protocol': 'TCP', 'ipprotocol': 'inet', 'source_net': 'any',
         'destination_net': 'HomeServer', 'destination_port': '443', 'sort_order': '3'},
        {'description': 'Tailnet', 'interface': 'opt4', 'enabled': '1', 'action': 'pass',
         'protocol': 'any', 'ipprotocol': 'inet', 'source_net': 'any', 'destination_net': 'any'},
        {'description': 'unifi-gw:block-clients', 'interface': 'lan', 'action': 'block'},
        {'description': 'auto', 'is_automatic': True, 'interface': 'lan'},
    ],
    'dnsmasq/settings/search_host': [
        {'host': 'MeridianHub', 'ip': '10.0.5.210', 'hwaddr': '9c:05:d6:62:10:83', 'descr': 'x'},
        {'host': 'oldLink16', 'ip': '10.0.5.200', 'hwaddr': 'd0:21:f9:72:bb:c4', 'descr': ''},
        {'host': 'StaceyAP', 'ip': '10.0.5.4', 'hwaddr': 'cc:32:e5:1d:c3:b7,ce:32:e5:0d:c3:b7'},
        {'host': 'denied', 'hwaddr': 'c8:be:19:3a:cb:b1', 'ignore': '1'},
        {'host': 'nas', 'ip': '10.0.5.20', 'hwaddr': 'aa:aa:aa:aa:aa:01',
         'descr': 'unifi-gw:dhcp-aaaaaaaaaa01 from UniFi'},
    ],
    'routing/settings/search_gateway': [{'name': 'LAB_GW', 'gateway': '10.0.5.254'},
                                        {'name': 'SAFB_DHCP', 'gateway': None}],
    'routes/gateway/status': {'items': []},
    'routes/routes/searchroute': [
        {'network': '198.51.100.0/24', 'gateway': 'LAB_GW', 'descr': 'Lab', 'enabled': '1'},
        {'network': '192.168.8.0/24', 'gateway': 'SAFB_DHCP', 'descr': 'Dead', 'enabled': '1'},
    ],
}


class FakeOPN:
    def __init__(self):
        self.data = copy.deepcopy(OPN)

    def search(self, path, params=None, timeout=None):
        if path not in self.data:
            raise OPNsenseAPIError(path)
        return self.data[path]

    def get(self, path, params=None, timeout=None):
        return self.search(path)


class FakeController:
    def __init__(self):
        ids = itertools.count(1)
        self.next_id = lambda: 'id%d' % next(ids)
        self.store = {'firewallgroup': [], 'portforward': [], 'firewallrule': [],
                      'routing': [], 'user': [
                          {'_id': 'u1', 'mac': '9c:05:d6:62:10:83', 'name': '',
                           'note': 'my own note'},
                          {'_id': 'u2', 'mac': '11:11:11:11:11:11', 'use_fixedip': True,
                           'fixed_ip': '10.0.5.99', 'note': '[OPNsense] DHCP reservation'}]}
        self.writes = []

    def call(self, method, path, payload=None):
        if path == 'rest/networkconf':
            return [{'_id': 'lan-net', 'purpose': 'corporate', 'ip_subnet': '10.0.5.1/24'}]
        if path == 'stat/device':
            return [{'mac': 'd0:21:f9:72:bb:c4'}]
        parts = path.split('/')
        coll = self.store[parts[1]]
        if method == 'GET':
            return copy.deepcopy(coll)
        self.writes.append((method, path))
        if method == 'POST':
            obj = dict(payload, _id=self.next_id())
            coll.append(obj)
            return [obj]
        target = next(o for o in coll if o['_id'] == parts[2])
        if method == 'PUT':
            target.update(payload)
        else:
            coll.remove(target)
        return []


@pytest.fixture
def mirror():
    return OPNsenseMirror(FakeOPN(), FakeController(), lambda: ['lan'], lambda: ['wan'])


def by_name(ctl, coll):
    return {o['name']: o for o in ctl.store[coll]}


class TestMirror:

    def test_groups_only_for_expressible_aliases(self, mirror):
        mirror.run()
        groups = by_name(mirror.ctl, 'firewallgroup')
        assert groups['[OPNsense] HomeServer']['group_type'] == 'address-group'
        assert groups['[OPNsense] HomeServer']['group_members'] == ['10.0.5.245']
        assert groups['[OPNsense] HoneyPotSSHPorts']['group_members'] == ['22', '2222', '22222']
        assert set(groups) == {'[OPNsense] HomeServer', '[OPNsense] HoneyPotSSHPorts'}

    def test_port_forwards(self, mirror):
        summary = mirror.run()
        fwds = by_name(mirror.ctl, 'portforward')
        assert set(fwds) == {'[OPNsense] Plex', '[OPNsense] Torrent'}
        plex = fwds['[OPNsense] Plex']
        assert (plex['fwd'], plex['dst_port'], plex['fwd_port'], plex['proto']) == \
            ('10.0.5.245', '32400', '32400', 'tcp')
        torrent = fwds['[OPNsense] Torrent']
        assert torrent['enabled'] is False and torrent['proto'] == 'tcp_udp'
        assert torrent['fwd_port'] == '13290'
        assert any('Honeypot' in w for w in summary['warnings'])

    def test_firewall_rules(self, mirror):
        mirror.run()
        rules = by_name(mirror.ctl, 'firewallrule')
        assert set(rules) == {'[OPNsense] Default allow LAN to any rule',
                              '[OPNsense] OpenVPN', '[OPNsense] To home server web'}
        lan = rules['[OPNsense] Default allow LAN to any rule']
        assert (lan['ruleset'], lan['action'], lan['protocol']) == ('LAN_IN', 'accept', 'all')
        assert lan['src_networkconf_id'] == 'lan-net' and lan['rule_index'] == 2000
        vpn = rules['[OPNsense] OpenVPN']
        assert (vpn['ruleset'], vpn['dst_port']) == ('WAN_LOCAL', '1194')
        web = rules['[OPNsense] To home server web']
        groups = by_name(mirror.ctl, 'firewallgroup')
        assert web['dst_firewallgroup_ids'] == [groups['[OPNsense] HomeServer']['_id']]
        assert web['enabled'] is False and web['action'] == 'drop'
        assert web['rule_index'] == 2001

    def test_fixed_ips(self, mirror):
        mirror.run()
        users = {u['mac']: u for u in mirror.ctl.store['user']}
        hub = users['9c:05:d6:62:10:83']
        assert hub['fixed_ip'] == '10.0.5.210' and hub['use_fixedip'] is True
        assert hub['note'] == 'my own note'           # user's note kept
        assert hub['name'] == 'MeridianHub'
        assert users['cc:32:e5:1d:c3:b7']['fixed_ip'] == '10.0.5.4'
        assert 'd0:21:f9:72:bb:c4' not in users        # UniFi switch, not a client
        assert 'c8:be:19:3a:cb:b1' not in users        # ignored host
        assert 'aa:aa:aa:aa:aa:01' not in users        # came from UniFi itself
        assert users['11:11:11:11:11:11']['use_fixedip'] is False   # stale mirror cleared

    def test_routes(self, mirror):
        summary = mirror.run()
        routes = by_name(mirror.ctl, 'routing')
        assert routes['[OPNsense] Lab']['static-route_nexthop'] == '10.0.5.254'
        assert any('192.168.8.0/24' in w for w in summary['warnings'])

    def test_second_run_writes_nothing(self, mirror):
        mirror.run()
        mirror.ctl.writes.clear()
        mirror.run()
        assert mirror.ctl.writes == []

    def test_removed_on_opnsense_is_removed_in_unifi(self, mirror):
        mirror.run()
        mirror.api.data['firewall/d_nat/search_rule'] = [
            r for r in mirror.api.data['firewall/d_nat/search_rule'] if r.get('descr') != 'Plex']
        mirror.run()
        assert '[OPNsense] Plex' not in by_name(mirror.ctl, 'portforward')

    def test_controller_rejection_is_isolated(self, mirror):
        real = mirror.ctl.call

        def call(method, path, payload=None):
            if method == 'POST' and path == 'rest/portforward' and payload['name'].endswith('Plex'):
                raise UniFiAPIError('HTTP 400 api.err.Something')
            return real(method, path, payload)

        mirror.ctl.call = call
        summary = mirror.run()
        assert '[OPNsense] Torrent' in by_name(mirror.ctl, 'portforward')
        assert any('api.err.Something' in w for w in summary['warnings'])


def test_rule_numbers_follow_gateway_type(mirror):
    """UniFi OS gateways only accept user rules from 20000 upwards."""
    real = mirror.ctl.call

    def call(method, path, payload=None):
        if path == 'stat/device':
            return [{'mac': 'd0:21:f9:72:bb:c4', 'type': 'usw'}, {'mac': '74:ac:b9:5e:00:01', 'type': 'uxg'}]
        return real(method, path, payload)

    mirror.ctl.call = call
    mirror.run()
    indexes = sorted(r['rule_index'] for r in mirror.ctl.store['firewallrule'])
    assert indexes[0] == 20000 and all(i >= 20000 for i in indexes)
