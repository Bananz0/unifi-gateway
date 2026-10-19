# -*- coding: utf-8 -*-
"""Tests for translating controller system_cfg into OPNsense API objects."""
import copy
import uuid

import pytest

from collectors.opnsense_api import OPNsenseAPIError
from collectors.opnsense_sync import (
    ALIASES, DNAT_RULES, FILTER_RULES, KEA_RESERVATIONS, ROUTES, UNBOUND_HOSTS,
    GATEWAYS, OPNsenseConfigSync, alias_name, differs, make_tag, parse_tag,
)


class FakeAPI:
    """In-memory stand-in for the MVC endpoints the sync module uses."""

    def __init__(self):
        self.store = {}     # search path -> {uuid: flattened row}
        self.posts = []
        self.gets = {}      # path -> canned GET response
        self.fail_add = set()

    def _spec_for(self, path):
        for spec in (FILTER_RULES, DNAT_RULES, ALIASES, UNBOUND_HOSTS,
                     KEA_RESERVATIONS, ROUTES, GATEWAYS):
            if path in (spec.add,) or path.startswith(spec.set) or \
                    path.startswith(spec.delete):
                return spec
        return None

    @staticmethod
    def _flatten(payload, prefix=''):
        out = {}
        for k, v in payload.items():
            if isinstance(v, dict):
                out.update(FakeAPI._flatten(v, prefix + k + '.'))
            elif isinstance(v, str) and '\n' in v:
                out[prefix + k] = ','.join(v.split('\n'))
            else:
                out[prefix + k] = v
        return out

    def search(self, path, params=None, timeout=None):
        if path in self.gets:
            return self.gets[path]
        return [dict(row, uuid=u) for u, row in self.store.get(path, {}).items()]

    def get(self, path, params=None, timeout=None):
        return self.gets.get(path, {})

    def post(self, path, payload=None, timeout=None):
        self.posts.append(path)
        spec = self._spec_for(path)
        if spec is None:
            return {'status': 'ok'}
        rows = self.store.setdefault(spec.search, {})
        if path == spec.add:
            if spec.name in self.fail_add:
                return {'result': 'failed', 'validations': {'x': 'y'}}
            new = str(uuid.uuid4())
            rows[new] = self._flatten(payload[spec.wrapper])
            return {'result': 'saved', 'uuid': new}
        if path.startswith(spec.set):
            rows[path[len(spec.set):]] = self._flatten(payload[spec.wrapper])
            return {'result': 'saved'}
        rows.pop(path[len(spec.delete):], None)
        return {'result': 'deleted'}

    def writes(self):
        return [p for p in self.posts if not p.endswith(('apply', 'reconfigure'))]


PORT_MAP = {'eth0': 'wan', 'eth1': 'lan'}


@pytest.fixture
def api():
    return FakeAPI()


@pytest.fixture
def sync(api):
    return OPNsenseConfigSync(api, PORT_MAP.get, lambda: ['lan'])


# Trimmed from a real UniFi Network 9.x system_cfg captured from a live UGW3
# emulation, plus user rules in the 2000/4000 ranges.
SYSTEM_CFG = {
    'firewall': {
        'group': {
            'address-group': {
                'guest_portal_address': {'address': ['10.0.5.210']},
                'nas_hosts': {'description': 'NAS', 'address': ['10.0.5.20', '10.0.5.21']},
            },
            'network-group': {
                'corporate_network': {'network': ['10.0.5.0/24']},
            },
            'port-group': {
                'web_ports': {'port': [80, 443]},
            },
        },
        'name': {
            'WAN_IN': {
                'default-action': 'drop',
                'rule': {
                    '3001': {'action': 'accept', 'state': {
                        'established': 'enable', 'related': 'enable',
                        'new': 'disable', 'invalid': 'disable'}},
                },
            },
            'WAN_LOCAL': {
                'default-action': 'drop',
                'rule': {
                    '2000': {'action': 'accept', 'description': 'ping from office',
                             'protocol': 'icmp', 'source': {'address': '198.51.100.7'}},
                },
            },
            'LAN_IN': {
                'default-action': 'accept',
                'rule': {
                    '2001': {'action': 'drop', 'description': 'no NAS web',
                             'protocol': 'tcp', 'log': 'enable',
                             'destination': {'group': {'address-group': 'nas_hosts',
                                                       'port-group': 'web_ports'}}},
                    '2002': {'action': 'reject', 'protocol': 'tcp_udp',
                             'destination': {'address': '192.0.2.1', 'port': '53,853'}},
                    '2003': {'action': 'accept', 'state': {'established': 'enable'}},
                    '4000': {'action': 'drop', 'disable': "''",
                             'source': {'mac-address': 'AA:BB:CC:DD:EE:FF'}},
                    '6001': {'action': 'accept', 'source': {'address': '10.0.5.0/24'}},
                },
            },
            'GUEST_IN': {'rule': {'2000': {'action': 'drop'}}},
        },
    },
    'interfaces': {'ethernet': {
        'eth0': {'firewall': {'in': {'name': 'WAN_IN'}, 'local': {'name': 'WAN_LOCAL'}}},
        'eth1': {'firewall': {'in': {'name': 'LAN_IN'}, 'local': {'name': 'LAN_LOCAL'}}},
    }},
    'port-forward': {
        'wan-interface': 'eth0',
        'rule': {
            '3001': {'description': 'web', 'forward-to': {'address': '10.0.5.20', 'port': '8080'},
                     'original-port': '80', 'protocol': 'tcp_udp', 'src': 'any'},
            '3002': {'description': 'restricted', 'forward-to': {'address': '10.0.5.21'},
                     'original-port': '2222', 'protocol': 'tcp', 'src': '!203.0.113.9'},
        },
    },
    'system': {
        'domain-name': 'localdomain',
        'static-host-mapping': {'host-name': {
            'setup.ubnt.com': {'inet': ['10.0.5.1']},
            'nas': {'inet': ['10.0.5.20'], 'alias': ['files']},
        }},
    },
    'service': {},
}


class TestHelpers:

    def test_tag_roundtrip(self):
        assert parse_tag(make_tag('fw-LAN_IN-2001-lan', 'hello')) == 'fw-LAN_IN-2001-lan'
        assert parse_tag('some user rule') is None

    def test_alias_name_sanitized_and_bounded(self):
        assert alias_name('unifi_controller_ports-tcp') == 'ufg_unifi_controller_ports_tcp'
        long = alias_name('x' * 60)
        assert len(long) <= 32 and long.startswith('ufg_')
        assert long != alias_name('x' * 59)

    def test_differs_ignores_list_order(self):
        row = {'content': 'b,a', 'enabled': '1', 'source.network': 'any'}
        assert not differs(row, {'content': 'a\nb', 'enabled': '1',
                                 'source': {'network': 'any'}})
        assert differs(row, {'content': 'a\nc', 'enabled': '1'})


class TestFirewallTranslation:

    def test_only_user_rules_are_translated(self, sync):
        rules, _ = sync._translate_rules(SYSTEM_CFG, sync._collect_groups(SYSTEM_CFG['firewall']))
        assert sorted(rules) == [
            'fw-LAN_IN-2001-lan', 'fw-LAN_IN-2002-lan', 'fw-LAN_IN-4000-lan',
            'fw-WAN_LOCAL-2000-wan',
        ]

    def test_local_ruleset_targets_firewall_itself(self, sync):
        rules, _ = sync._translate_rules(SYSTEM_CFG, sync._collect_groups(SYSTEM_CFG['firewall']))
        rule = rules['fw-WAN_LOCAL-2000-wan']
        assert rule['interface'] == 'wan'
        assert rule['direction'] == 'in'
        assert rule['destination_net'] == '(self)'
        assert rule['source_net'] == '198.51.100.7'
        assert rule['protocol'] == 'ICMP'
        assert rule['action'] == 'pass'

    def test_groups_become_aliases(self, sync):
        rules, aliases = sync._translate_rules(SYSTEM_CFG, sync._collect_groups(SYSTEM_CFG['firewall']))
        rule = rules['fw-LAN_IN-2001-lan']
        assert rule['destination_net'] == 'ufg_nas_hosts'
        assert rule['destination_port'] == 'ufg_web_ports'
        assert rule['action'] == 'block'
        assert rule['log'] == '1'
        assert aliases['ufg_nas_hosts']['type'] == 'host'
        assert aliases['ufg_nas_hosts']['content'] == '10.0.5.20\n10.0.5.21'
        assert aliases['ufg_web_ports']['type'] == 'port'
        assert 'ufg_guest_portal_address' not in aliases  # unreferenced

    def test_port_list_becomes_port_alias(self, sync):
        rules, aliases = sync._translate_rules(SYSTEM_CFG, sync._collect_groups(SYSTEM_CFG['firewall']))
        rule = rules['fw-LAN_IN-2002-lan']
        assert rule['protocol'] == 'TCP/UDP'
        assert rule['action'] == 'reject'
        assert aliases[rule['destination_port']]['content'] == '53\n853'

    def test_mac_source_and_disabled_flag(self, sync):
        rules, aliases = sync._translate_rules(SYSTEM_CFG, sync._collect_groups(SYSTEM_CFG['firewall']))
        rule = rules['fw-LAN_IN-4000-lan']
        assert rule['enabled'] == '0'
        assert aliases[rule['source_net']] == {
            'enabled': '1', 'name': rule['source_net'], 'type': 'mac',
            'content': 'aa:bb:cc:dd:ee:ff', 'description': aliases[rule['source_net']]['description'],
        }

    def test_unbound_and_state_only_rules_warn(self, sync):
        sync._translate_rules(SYSTEM_CFG, sync._collect_groups(SYSTEM_CFG['firewall']))
        assert any('GUEST_IN' in w for w in sync.warnings)
        assert any('2003' in w and 'existing connections' in w for w in sync.warnings)

    def test_port_forwards(self, sync):
        forwards, _ = sync._translate_port_forwards(SYSTEM_CFG, {})
        web = forwards['pf-3001-wan']
        assert web['protocol'] == 'tcp/udp'
        assert web['destination'] == {'network': 'wanip', 'port': '80'}
        assert web['target'] == '10.0.5.20'
        assert web['local-port'] == '8080'
        assert web['pass'] == 'pass'
        restricted = forwards['pf-3002-wan']
        assert restricted['source'] == {'network': '203.0.113.9', 'not': '1'}
        assert restricted['local-port'] == ''


class TestApply:

    def test_apply_creates_everything_once(self, api, sync):
        api.gets['unbound/settings/get'] = {'unbound': {'general': {'enabled': '1'}}}
        summary = sync.apply_system_cfg(copy.deepcopy(SYSTEM_CFG))
        assert summary['firewall_rules'] == 4
        assert summary['port_forwards'] == 2
        assert summary['dns_hosts'] == 2  # setup.ubnt.com skipped, alias added
        assert 'firewall/filter/apply' in api.posts
        assert 'unbound/service/reconfigure' in api.posts

        # second run with identical config writes nothing
        api.posts.clear()
        sync.apply_system_cfg(copy.deepcopy(SYSTEM_CFG))
        assert api.writes() == []

    def test_removed_rules_are_deleted(self, api, sync):
        sync.apply_system_cfg(copy.deepcopy(SYSTEM_CFG))
        cfg = copy.deepcopy(SYSTEM_CFG)
        del cfg['firewall']['name']['LAN_IN']['rule']['2001']
        cfg['port-forward']['rule'].pop('3002')
        sync.apply_system_cfg(cfg)
        keys = {parse_tag(r['description']) for r in api.search(FILTER_RULES.search)}
        assert 'fw-LAN_IN-2001-lan' not in keys
        names = {r['name'] for r in api.search(ALIASES.search)}
        assert 'ufg_nas_hosts' not in names  # no longer referenced
        assert len(api.search(DNAT_RULES.search)) == 1

    def test_untagged_objects_are_never_touched(self, api, sync):
        api.store[FILTER_RULES.search] = {'user-1': {'description': 'my own rule'}}
        api.store[ALIASES.search] = {'user-2': {'name': 'bogons', 'description': ''}}
        sync.apply_system_cfg({})
        assert 'user-1' in api.store[FILTER_RULES.search]
        assert 'user-2' in api.store[ALIASES.search]

    def test_isc_dhcp_reservations_warn(self, api, sync):
        cfg = {'service': {'dhcp-server': {'shared-network-name': {'LAN': {'subnet': {
            '10.0.5.0/24': {'static-mapping': {'nas': {
                'ip-address': '10.0.5.20', 'mac-address': 'AA:BB:CC:00:00:01'}}}}}}}}}
        summary = sync.apply_system_cfg(cfg)
        assert summary['dhcp_reservations'] == 0
        assert any('ISC DHCP' in w for w in summary['warnings'])

    def test_kea_reservations(self, api, sync):
        api.gets['kea/dhcpv4/get'] = {'dhcpv4': {'general': {'enabled': '1'}}}
        api.gets['kea/dhcpv4/search_subnet'] = [{'uuid': 'sub-1', 'subnet': '10.0.5.0/24'}]
        cfg = {'service': {'dhcp-server': {'shared-network-name': {'LAN': {'subnet': {
            '10.0.5.0/24': {'static-mapping': {'my nas': {
                'ip-address': '10.0.5.20', 'mac-address': 'AA:BB:CC:00:00:01'}}}}}}}}}
        assert sync.apply_system_cfg(cfg)['dhcp_reservations'] == 1
        row = api.search(KEA_RESERVATIONS.search)[0]
        assert row['subnet'] == 'sub-1'
        assert row['hw_address'] == 'aa:bb:cc:00:00:01'
        assert row['hostname'] == 'my-nas'
        assert 'kea/service/reconfigure' in api.posts

    def test_static_route_creates_gateway(self, api, sync):
        api.gets['interfaces/overview/interfaces_info'] = [
            {'identifier': 'lan', 'ipv4': [{'ipaddr': '10.0.5.1/24'}],
             'ipv6': [{'ipaddr': 'fe80::1%em0/64'}]},
        ]
        cfg = {'protocols': {'static': {'route': {
            '198.51.100.0/24': {'next-hop': {'10.0.5.254': {'description': 'lab'}}}}}}}
        assert sync.apply_system_cfg(cfg)['static_routes'] == 1
        gw = api.search(GATEWAYS.search)[0]
        assert gw['interface'] == 'lan' and gw['gateway'] == '10.0.5.254'
        route = api.search(ROUTES.search)[0]
        assert route['gateway'] == gw['name']

    def test_route_retries_after_new_gateway(self, api, sync, monkeypatch):
        """configd caches the gateway list, so the first route add after
        creating a gateway fails validation; it must retry, not give up."""
        api.gets['interfaces/overview/interfaces_info'] = [
            {'identifier': 'lan', 'ipv4': [{'ipaddr': '10.0.5.1/24'}]}]
        sleeps = []
        monkeypatch.setattr('collectors.opnsense_sync.time.sleep', sleeps.append)
        real_post = api.post
        failures = []

        def post(path, payload=None, timeout=None):
            if path == ROUTES.add and not failures:
                failures.append(path)
                return {'result': 'failed', 'validations': {'route.gateway': 'x'}}
            return real_post(path, payload, timeout)

        api.post = post
        cfg = {'protocols': {'static': {'route': {
            '198.51.100.0/24': {'next-hop': {'10.0.5.254': {}}}}}}}
        summary = sync.apply_system_cfg(cfg)
        assert summary['static_routes'] == 1 and summary['warnings'] == []
        assert sleeps and len(api.search(ROUTES.search)) == 1

    def test_mirrored_objects_are_not_applied_back(self, api, sync):
        """Objects mirrored from OPNsense into UniFi come back in system_cfg
        and must not be duplicated."""
        cfg = copy.deepcopy(SYSTEM_CFG)
        cfg['firewall']['name']['LAN_IN']['rule']['2005'] = {
            'action': 'accept', 'description': '[OPNsense] Default allow LAN'}
        cfg['port-forward']['rule']['3003'] = {
            'description': '[OPNsense] Plex', 'forward-to': {'address': '10.0.5.245'},
            'original-port': '32400', 'protocol': 'tcp'}
        cfg['service']['dhcp-server'] = {'shared-network-name': {'LAN': {'subnet': {
            '10.0.5.0/24': {'static-mapping': {'hub': {
                'ip-address': '10.0.5.210', 'mac-address': '9C:05:D6:62:10:83'}}}}}}}
        api.gets['dnsmasq/settings/get'] = {'dnsmasq': {'enable': '1'}}
        api.gets['dnsmasq/settings/search_host'] = [
            {'uuid': 'own', 'host': 'MeridianHub', 'hwaddr': '9c:05:d6:62:10:83', 'descr': ''}]
        summary = sync.apply_system_cfg(cfg)
        keys = {parse_tag(r['description']) for r in api.search(FILTER_RULES.search)}
        assert 'fw-LAN_IN-2005-lan' not in keys
        assert summary['port_forwards'] == 2
        assert summary['dhcp_reservations'] == 0

    def test_section_failure_does_not_stop_others(self, api, sync):
        api.gets['unbound/settings/get'] = {'unbound': {'general': {'enabled': '1'}}}
        api.fail_add.add('DNS host override')
        summary = sync.apply_system_cfg(copy.deepcopy(SYSTEM_CFG))
        assert summary['firewall_rules'] == 4
        assert 'dns_hosts' not in summary
        assert any('dns_hosts not applied' in w for w in summary['warnings'])


class TestBlocking:

    def test_block_creates_alias_and_rule(self, api, sync):
        sync.sync_blocked(['AA:BB:CC:DD:EE:01'], ['10.0.5.50'])
        aliases = {r['name']: r for r in api.search(ALIASES.search)}
        assert aliases['ufg_blocked']['content'] == 'aa:bb:cc:dd:ee:01'
        assert aliases['ufg_blocked']['type'] == 'mac'
        assert aliases['ufg_blocked_ip']['content'] == '10.0.5.50'
        rule = api.search(FILTER_RULES.search)[0]
        assert rule['enabled'] == '1'
        assert rule['action'] == 'block'
        assert rule['interface'] == 'lan'
        assert rule['source_net'] == 'ufg_blocked,ufg_blocked_ip'

    def test_empty_block_list_disables_rule(self, api, sync):
        sync.sync_blocked(['aa:bb:cc:dd:ee:01'], [])
        sync.sync_blocked([], [])
        assert api.search(FILTER_RULES.search)[0]['enabled'] == '0'

    def test_block_rule_survives_config_sync(self, api, sync):
        sync.sync_blocked(['aa:bb:cc:dd:ee:01'], [])
        sync.apply_system_cfg({})
        assert len(api.search(FILTER_RULES.search)) == 1
        assert {r['name'] for r in api.search(ALIASES.search)} == {'ufg_blocked', 'ufg_blocked_ip'}

    def test_kill_states_uses_exact_host_network(self, api, sync):
        calls = []
        api.post = lambda path, payload=None, timeout=None: (
            calls.append((path, payload)), {'result': 'ok', 'dropped_states': 3})[1]
        assert sync.kill_states('10.0.5.17') == 3
        assert calls == [('diagnostics/firewall/kill_states', {'filter': '10.0.5.17'})]
        assert sync.kill_states('fe80::1') == 0  # sanitizer would mangle IPv6
        assert sync.kill_states('not-an-ip') == 0

    def test_failed_add_raises(self, api, sync):
        api.fail_add.add('alias')
        with pytest.raises(OPNsenseAPIError):
            sync.sync_blocked(['aa:bb:cc:dd:ee:01'], [])
