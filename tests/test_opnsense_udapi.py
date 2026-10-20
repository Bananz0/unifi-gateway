# -*- coding: utf-8 -*-
"""Tests for translating a UXG (UDAPI) system_cfg into OPNsense API objects."""
import copy
import json
import os
import re

import pytest

from collectors.opnsense_sync import (
    ALIASES, DNAT_RULES, FILTER_RULES, GATEWAYS, KEA_RESERVATIONS, ROUTES,
    UNBOUND_HOSTS, OPNsenseConfigSync, make_tag, parse_tag,
)
from collectors.opnsense_udapi import UDAPIConfigSync, is_udapi_config
from tests.test_opnsense_sync import FakeAPI

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')


def load(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return json.load(f)['system_cfg']


REAL = load('uxg_setparam_10.6.106.json')
SYNTHETIC = load('uxg_system_cfg_synthetic.json')

PORT_MAP = {'eth4': 'wan'}


@pytest.fixture
def api():
    api = FakeAPI()
    api.gets['interfaces/overview/interfaces_info'] = [
        {'identifier': 'lan', 'ipv4': [{'ipaddr': '192.168.1.1/24'}]},
        {'identifier': 'wan', 'ipv4': [{'ipaddr': '203.0.113.2/24'}]},
    ]
    api.gets['unbound/settings/get'] = {'unbound': {'general': {'enabled': '1'}}}
    api.gets['kea/dhcpv4/get'] = {'dhcpv4': {'general': {'enabled': '1'}}}
    api.gets['kea/dhcpv4/search_subnet'] = [{'uuid': 'sub-1', 'subnet': '192.168.1.0/24'}]
    return api


@pytest.fixture
def sync(api):
    return UDAPIConfigSync(api, PORT_MAP.get, lambda: ['lan'])


def rows(api, spec):
    return {parse_tag(r.get(spec.descr_field)) or r.get('name'): r
            for r in api.search(spec.search)}


def chain(cfg, name):
    return next(c for c in cfg['udapi']['firewall/filter'] if c['config']['name'] == name)


class TestShape:

    def test_detection(self):
        assert is_udapi_config(REAL)
        assert not is_udapi_config({'firewall': {}})
        assert not is_udapi_config({'ubntconf': 'x'})  # no tree: never "empty"

    def test_edgeos_sync_still_rejects_udapi(self, api):
        with pytest.raises(ValueError):
            OPNsenseConfigSync(api, PORT_MAP.get, lambda: ['lan']).apply_system_cfg(REAL)

    def test_udapi_sync_rejects_edgeos(self, sync):
        with pytest.raises(ValueError):
            sync.apply_system_cfg({'firewall': {}})


class TestRealCapture:
    """The lab capture holds only controller built-ins."""

    def test_builtins_produce_no_firewall_objects(self, api, sync):
        summary = sync.apply_system_cfg(copy.deepcopy(REAL))
        assert summary['firewall_rules'] == 0
        assert summary['port_forwards'] == 0
        assert summary['aliases'] == 0
        assert api.search(FILTER_RULES.search) == []
        assert api.search(ALIASES.search) == []

    def test_chain_bindings_follow_jumps(self, sync):
        sync._udapi_ifs = {}
        bindings = sync._chain_bindings(
            [(c['config']['name'], c.get('rules', []))
             for c in REAL['udapi']['firewall/filter']])
        assert bindings['LAN_IN'] == [('br0', None, False)]
        assert bindings['LAN_OUT'] == [(None, 'br0', False)]
        assert bindings['LAN_LOCAL'] == [('br0', None, True)]

    def test_bridge_resolves_by_subnet(self, sync):
        sync.apply_system_cfg(copy.deepcopy(REAL))
        assert sync.resolve_interface('br0') == 'lan'
        assert sync.resolve_interface('eth9') is None

    def test_dns_skips_controller_and_own_records(self, api, sync):
        summary = sync.apply_system_cfg(copy.deepcopy(REAL))
        hosts = {(r['hostname'], r['domain']) for r in api.search(UNBOUND_HOSTS.search)}
        # setup.ui.com, the wildcard and the gateway's own name are skipped
        assert hosts == {('unifi', 'localdomain')}
        assert summary['dns_hosts'] == 1

    def test_redacted_zero_mac_lease_is_skipped(self, sync):
        summary = sync.apply_system_cfg(copy.deepcopy(REAL))
        assert summary['dhcp_reservations'] == 0
        assert any('DHCP static lease' in w for w in summary['warnings'])


class TestSyntheticRules:

    def test_user_rules_translated(self, api, sync):
        summary = sync.apply_system_cfg(copy.deepcopy(SYNTHETIC))
        rules = rows(api, FILTER_RULES)
        assert set(rules) == {
            'ufw-LAN_IN-20001-lan', 'ufw-LAN_IN-20002-lan',
            'ufw-LAN_IN-40000-lan', 'ufw-WAN_LOCAL-20000-wan'}
        assert summary['firewall_rules'] == 4

        nas = rules['ufw-LAN_IN-20001-lan']
        assert nas['action'] == 'block' and nas['log'] == '1'
        assert nas['direction'] == 'in' and nas['ipprotocol'] == 'inet'
        assert nas['destination_net'] == 'ufg_nas_hosts'
        assert nas['destination_port'] == 'ufg_web_ports'
        assert nas['sequence'] == '20001'

        dns = rules['ufw-LAN_IN-20002-lan']
        assert dns['action'] == 'reject' and dns['protocol'] == 'TCP/UDP'
        assert dns['destination_net'] == '192.168.1.1' and dns['destination_not'] == '1'
        assert dns['ipprotocol'] == 'inet'  # narrowed from both by the v4 literal
        assert dns['destination_port'].startswith('ufg_ports_')

        assert rules['ufw-LAN_IN-40000-lan']['enabled'] == '0'
        assert rules['ufw-LAN_IN-40000-lan']['source_net'] == 'ufg_kids_devices'

        local = rules['ufw-WAN_LOCAL-20000-wan']
        assert local['destination_net'] == '(self)' and local['protocol'] == 'ICMP'

    def test_unsupported_rules_warn_and_are_not_broadened(self, sync):
        summary = sync.apply_system_cfg(copy.deepcopy(SYNTHETIC))
        warnings = '\n'.join(summary['warnings'])
        assert 'LAN_IN/20003 skipped: matches only existing connections' in warnings
        assert 'LAN_IN/20004 skipped: unsupported field schedule' in warnings

    def test_aliases_only_for_referenced_sets(self, api, sync):
        sync.apply_system_cfg(copy.deepcopy(SYNTHETIC))
        aliases = rows(api, ALIASES)
        assert aliases['ufg_nas_hosts']['type'] == 'host'
        assert aliases['ufg_web_ports']['type'] == 'port'
        assert aliases['ufg_kids_devices']['content'] == 'aa:bb:cc:00:00:99'
        assert 'ufg_corporate_network' not in aliases  # built-in rules only

    def test_mirrored_and_builtin_rules_skipped(self, api, sync):
        sync.apply_system_cfg(copy.deepcopy(SYNTHETIC))
        keys = set(rows(api, FILTER_RULES))
        assert not any(k.startswith('ufw-WAN_IN-') for k in keys)  # [OPNsense]
        assert not any('-6000' in k or '-3000' in k for k in keys)

    @pytest.mark.parametrize('descr,mirrored', [
        ('[OPNsense] Allow Plex', True),
        ('[WAN_IN][OPNsense] Allow Plex', True),
        ('[LANv6_OUT][OPNsense] x', True),
        ('[LAN_IN]Allow Network 192.168.1.0/24 Traffic', False),
        ('Allow [OPNsense] later', False),
    ])
    def test_mirror_detection_ignores_ruleset_prefix(self, descr, mirrored):
        from collectors.opnsense_udapi import _mirrored
        assert _mirrored({'description': descr}) is mirrored

    def test_idempotent(self, api, sync):
        sync.apply_system_cfg(copy.deepcopy(SYNTHETIC))
        api.posts.clear()
        sync.apply_system_cfg(copy.deepcopy(SYNTHETIC))
        assert api.writes() == []

    def test_removed_rule_is_deleted(self, api, sync):
        sync.apply_system_cfg(copy.deepcopy(SYNTHETIC))
        cfg = copy.deepcopy(SYNTHETIC)
        lan_in = chain(cfg, 'LAN_IN')
        lan_in['rules'] = [r for r in lan_in['rules'] if r['id'] != 20001]
        sync.apply_system_cfg(cfg)
        assert 'ufw-LAN_IN-20001-lan' not in rows(api, FILTER_RULES)
        assert 'ufg_nas_hosts' not in rows(api, ALIASES)

    def test_rule_that_becomes_untranslatable_keeps_its_object(self, api, sync):
        sync.apply_system_cfg(copy.deepcopy(SYNTHETIC))
        cfg = copy.deepcopy(SYNTHETIC)
        rule = next(r for r in chain(cfg, 'LAN_IN')['rules'] if r['id'] == 20001)
        rule['ipsec'] = {'match': 'in'}
        summary = sync.apply_system_cfg(cfg)
        assert any('unsupported field ipsec' in w for w in summary['warnings'])
        # never broadened, never silently dropped: last good version stays
        assert rows(api, FILTER_RULES)['ufw-LAN_IN-20001-lan']['action'] == 'block'
        assert 'ufg_nas_hosts' in rows(api, ALIASES)

    def test_combined_matches_are_refused(self, sync):
        side = {'address': '10.0.0.1', 'sets': ['nas_hosts']}
        sets = sync._collect_sets(SYNTHETIC['udapi']['firewall/sets'])
        with pytest.raises(ValueError, match='combined'):
            sync._udapi_endpoint(side, 'k', sets, {})

    def test_unknown_set_is_refused(self, sync):
        with pytest.raises(ValueError, match='unknown set'):
            sync._udapi_endpoint({'sets': ['nope']}, 'k', {}, {})

    def test_port_range_object(self, sync):
        aliases = {}
        net, neg, port = sync._udapi_endpoint(
            {'port': {'start': 1000, 'stop': 2000}}, 'k', {}, aliases)
        assert (net, neg, port) == ('any', False, '1000-2000')

    def test_unbound_chain_warns(self, sync):
        cfg = copy.deepcopy(SYNTHETIC)
        cfg['udapi']['firewall/filter'].append({
            'config': {'name': 'GUEST_IN'},
            'rules': [{'id': 20001, 'target': 'DROP', 'ipVersion': 'both'}]})
        summary = sync.apply_system_cfg(cfg)
        assert any('chain GUEST_IN is not bound' in w for w in summary['warnings'])

    def test_block_rule_and_untagged_objects_survive(self, api, sync):
        sync.sync_blocked(['aa:bb:cc:dd:ee:01'], [])
        api.store[FILTER_RULES.search]['user-1'] = {'description': 'my own rule'}
        sync.apply_system_cfg(copy.deepcopy(REAL))
        keys = {parse_tag(r['description']) for r in api.search(FILTER_RULES.search)}
        assert 'block-clients' in keys
        assert 'user-1' in api.store[FILTER_RULES.search]

    def test_missing_section_is_left_alone(self, api, sync):
        sync.apply_system_cfg(copy.deepcopy(SYNTHETIC))
        cfg = copy.deepcopy(SYNTHETIC)
        del cfg['udapi']['firewall/filter']
        del cfg['udapi']['firewall/nat']
        summary = sync.apply_system_cfg(cfg)
        assert 'firewall_rules' not in summary and 'port_forwards' not in summary
        assert len(rows(api, FILTER_RULES)) == 4
        assert len(rows(api, DNAT_RULES)) == 2

    def test_usg_era_rules_are_replaced(self, api, sync):
        """Migrating from the USG identity: the EdgeOS translator's rules are
        owned by the controller config, which no longer contains them."""
        api.store[FILTER_RULES.search] = {'old': {
            'description': make_tag('fw-LAN_IN-2001-lan', 'from USG')}}
        sync.apply_system_cfg(copy.deepcopy(SYNTHETIC))
        assert 'fw-LAN_IN-2001-lan' not in rows(api, FILTER_RULES)

    def test_options_disable_sections(self, api):
        sync = UDAPIConfigSync(api, PORT_MAP.get, lambda: ['lan'],
                               options={'apply_firewall': False, 'apply_dns': False})
        summary = sync.apply_system_cfg(copy.deepcopy(SYNTHETIC))
        assert 'firewall_rules' not in summary and 'dns_hosts' not in summary
        assert summary['port_forwards'] == 2


class TestSyntheticPortForwards:

    def test_dnat_rules(self, api, sync):
        sync.apply_system_cfg(copy.deepcopy(SYNTHETIC))
        forwards = rows(api, DNAT_RULES)
        assert set(forwards) == {'upf-PREROUTING-20001-wan', 'upf-PREROUTING-20002-wan'}
        web = forwards['upf-PREROUTING-20001-wan']
        assert web['protocol'] == 'tcp/udp'
        assert web['destination.network'] == 'wanip'
        assert web['destination.port'] == '80'
        assert web['target'] == '192.168.1.20' and web['local-port'] == '8080'
        ssh = forwards['upf-PREROUTING-20002-wan']
        assert ssh['source.network'] == '203.0.113.9' and ssh['source.not'] == '1'
        assert ssh['local-port'] == '' and ssh['log'] == '1'

    def test_guest_portal_masquerade_and_mirrored_skipped(self, api, sync):
        summary = sync.apply_system_cfg(copy.deepcopy(SYNTHETIC))
        assert summary['port_forwards'] == 2
        assert not any('port forward' in w for w in summary['warnings'])

    def test_unmapped_wan_warns(self, api):
        sync = UDAPIConfigSync(api, {}.get, lambda: ['lan'])
        summary = sync.apply_system_cfg(copy.deepcopy(SYNTHETIC))
        assert summary['port_forwards'] == 0
        assert any('WAN eth4 is not mapped' in w for w in summary['warnings'])

    def test_pppoe_wan_resolves_through_parent(self, sync):
        sync._udapi_ifs = {'ppp0': {'identification': {'id': 'ppp0', 'type': 'pppoe'},
                                    'pppoe': {'interface': {'id': 'eth4'}}}}
        sync._if_networks = {}
        assert sync.resolve_interface('ppp0') == 'wan'


class TestSyntheticServices:

    def test_kea_reservations(self, api, sync):
        summary = sync.apply_system_cfg(copy.deepcopy(SYNTHETIC))
        assert summary['dhcp_reservations'] == 2
        res = {r['hw_address']: r for r in api.search(KEA_RESERVATIONS.search)}
        assert res['aa:bb:cc:00:00:10']['hostname'] == 'nas'
        assert res['aa:bb:cc:00:00:10']['subnet'] == 'sub-1'
        assert res['aa:bb:cc:00:00:11']['hostname'] == 'host-aabbcc000011'

    def test_dns_records(self, api, sync):
        sync.apply_system_cfg(copy.deepcopy(SYNTHETIC))
        hosts = {(r['hostname'], r['domain'], r['server'])
                 for r in api.search(UNBOUND_HOSTS.search)}
        assert ('nas', 'localdomain', '192.168.1.20') in hosts
        assert ('files', 'localdomain', '192.168.1.20') in hosts

    def test_static_routes(self, api, sync):
        summary = sync.apply_system_cfg(copy.deepcopy(SYNTHETIC))
        assert summary['static_routes'] == 1  # disabled one ignored
        route = api.search(ROUTES.search)[0]
        assert route['network'] == '10.9.0.0/16'
        gw = api.search(GATEWAYS.search)[0]
        assert gw['gateway'] == '192.168.1.254' and gw['interface'] == 'lan'
        assert any('blackhole route 10.66.0.0/16' in w for w in summary['warnings'])

    def test_empty_present_section_removes_tagged(self, api, sync):
        sync.apply_system_cfg(copy.deepcopy(SYNTHETIC))
        cfg = copy.deepcopy(SYNTHETIC)
        cfg['udapi']['routes/static'] = []
        cfg['udapi']['services']['dhcpServers'][0]['staticLeases'] = []
        sync.apply_system_cfg(cfg)
        assert api.search(ROUTES.search) == []
        assert api.search(KEA_RESERVATIONS.search) == []


# A real Network 10.6.106 capture with a WAN network and user objects (lab,
# secrets and the operator's own data removed): port forwards are flat NAT
# entries carrying their chain, with the WAN given as the ADDRv4_eth4 set.
WAN_CAPTURE = load('uxg_setparam_10.6.106_objects.json')


@pytest.fixture
def wan_api():
    api = FakeAPI()
    api.gets['interfaces/overview/interfaces_info'] = [
        {'identifier': 'lan', 'ipv4': [{'ipaddr': '10.0.5.1/24'}]},
        {'identifier': 'wan', 'ipv4': [{'ipaddr': '203.0.113.2/24'}]},
    ]
    api.gets['unbound/settings/get'] = {'unbound': {'general': {'enabled': '1'}}}
    api.gets['kea/dhcpv4/get'] = {'dhcpv4': {'general': {'enabled': '1'}}}
    api.gets['kea/dhcpv4/search_subnet'] = [{'uuid': 'sub-1', 'subnet': '10.0.5.0/24'}]
    return api


@pytest.fixture
def wan_sync(wan_api):
    return UDAPIConfigSync(wan_api, {'eth4': 'wan', 'eth0': 'lan'}.get, lambda: ['lan'])


class TestRealWanCapture:

    def test_port_forwards_from_flat_dnat(self, wan_api, wan_sync):
        summary = wan_sync.apply_system_cfg(copy.deepcopy(WAN_CAPTURE))
        assert summary['port_forwards'] == 2 and summary['warnings'] == []
        fwds = {r['target']: r for r in wan_api.search(DNAT_RULES.search)}
        web = fwds['10.0.5.50']
        assert (web['interface'], web['destination.network'], web['destination.port'],
                web['local-port'], web['protocol']) == ('wan', 'wanip', '8080', '80', 'tcp/udp')
        multi = fwds['10.0.5.51']
        assert multi['source.network'] == '203.0.113.9' and multi['log'] == '1'
        assert multi['destination.port'] == '9000-9005'
        assert all('PREROUTING' in parse_tag(r['descr']) for r in fwds.values())

    def test_wan_local_icmp_and_lan_group_rules(self, wan_api, wan_sync):
        wan_sync.apply_system_cfg(copy.deepcopy(WAN_CAPTURE))
        rules = {r['description'].split(' ', 1)[1]: r for r in wan_api.search(FILTER_RULES.search)}
        ping = rules['lab allow ping']
        assert (ping['interface'], ping['action'], ping['protocol'], ping['source_net'],
                ping['destination_net']) == ('wan', 'pass', 'ICMP', '198.51.100.7', '(self)')
        nas = rules['lab block nas web']
        assert nas['destination_net'].startswith('ufg_') and nas['destination_port'].startswith('ufg_')

    def test_reservation_named_from_dns_record(self, wan_api, wan_sync):
        """UDAPI static leases are nameless; the nas.lab record for the same
        address names the reservation instead of host-<mac>."""
        wan_sync.apply_system_cfg(copy.deepcopy(WAN_CAPTURE))
        res = {r['hw_address']: r for r in wan_api.search(KEA_RESERVATIONS.search)}
        assert res['aa:bb:cc:00:00:01']['hostname'] == 'nas'

    def test_controller_and_mirrored_entries_skipped(self, wan_api, wan_sync):
        cfg = copy.deepcopy(WAN_CAPTURE)
        nat = cfg['udapi']['firewall/nat']
        mirrored = dict(next(r for r in nat if r.get('target') == 'DNAT'),
                        id=99, description='PortForward DNAT [[OPNsense] Plex]')
        nat.append(mirrored)
        wan_sync.apply_system_cfg(cfg)
        assert len(wan_api.search(DNAT_RULES.search)) == 2
        names = {r['hostname'] for r in wan_api.search(UNBOUND_HOSTS.search)}
        # the controller's own "unifi" name is kept: UniFi devices find the
        # controller through it, as they would via a real UXG's DNS
        assert names == {'unifi', 'nas'}

    def test_icmp_type_maps_to_opnsense(self, wan_api, wan_sync):
        cfg = copy.deepcopy(WAN_CAPTURE)
        chain('udapi' and cfg, 'WAN_LOCAL')['rules'][0]['icmpType'] = 'echo-request'
        wan_sync.apply_system_cfg(cfg)
        ping = [r for r in wan_api.search(FILTER_RULES.search) if 'lab allow ping' in r['description']][0]
        assert ping['icmptype'] == 'echoreq'


class TestRegionBlocking:
    """services.geoipFiltering as captured from Network 10.6.106 after
    enabling Region Blocking for CN and RU."""

    def apply(self, wan_api, wan_sync, **geo):
        cfg = copy.deepcopy(WAN_CAPTURE)
        cfg['udapi'].setdefault('services', {})['geoipFiltering'] = {
            'enabled': True, 'action': 'block', 'countryList': ['CN', 'RU'],
            'direction': 'both', 'interfaces': [{'id': 'eth4'}], **geo}
        summary = wan_sync.apply_system_cfg(cfg)
        rules = {r['description'].split()[0]: r for r in wan_api.search(FILTER_RULES.search)
                 if 'ugeo-' in r.get('description', '')}
        aliases = {a['name']: a for a in wan_api.search(ALIASES.search)}
        return summary, rules, aliases

    def test_block_both_directions(self, wan_api, wan_sync):
        summary, rules, aliases = self.apply(wan_api, wan_sync)
        assert not summary['warnings']
        assert aliases['ufg_geoip']['type'] == 'geoip'
        assert set(re.split(r'[,\n]', aliases['ufg_geoip']['content'])) == {'CN', 'RU'}
        inbound = rules['unifi-gw:ugeo-in-wan']
        assert (inbound['interface'], inbound['direction'], inbound['action']) == ('wan', 'in', 'block')
        assert inbound['source_net'] == 'ufg_geoip' and inbound['source_not'] == '0'
        outbound = rules['unifi-gw:ugeo-out-wan']
        assert outbound['direction'] == 'out' and outbound['destination_net'] == 'ufg_geoip'

    def test_allow_list_negates_and_ingress_only(self, wan_api, wan_sync):
        _, rules, _ = self.apply(wan_api, wan_sync, action='allow', direction='ingress')
        assert set(rules) == {'unifi-gw:ugeo-in-wan'}
        assert rules['unifi-gw:ugeo-in-wan']['source_not'] == '1'

    def test_disabled_removes_rules(self, wan_api, wan_sync):
        self.apply(wan_api, wan_sync)
        _, rules, _ = self.apply(wan_api, wan_sync, enabled=False)
        assert rules == {}


def test_trigger_tagged_rules_are_still_translated(wan_api, wan_sync):
    """With trigger logs advertised, Network 10.6 adds triggerTag to every
    user rule and port forward; they must not be skipped as unknown."""
    cfg = copy.deepcopy(WAN_CAPTURE)
    for chain in cfg['udapi']['firewall/filter']:
        for rule in chain.get('rules') or []:
            rule['triggerTag'] = {'id': '6ad6addb3b3b84feb42f9f7d', 'type': 'FIREWALL_RULE'}
    for rule in cfg['udapi']['firewall/nat']:
        rule['triggerTag'] = {'id': '6ad6adc83b3b84feb42f9f68', 'type': 'PORT_FORWARDING'}
    summary = wan_sync.apply_system_cfg(cfg)
    assert not [w for w in summary['warnings'] if 'triggerTag' in w]
    assert summary['port_forwards'] == 2
