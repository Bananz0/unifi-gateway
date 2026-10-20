import copy

import pytest

from collectors.opnsense_api import OPNsenseAPIError
from collectors.opnsense_sync import ALIASES, FILTER_RULES, make_tag
from collectors.opnsense_udapi import UDAPIConfigSync
from collectors.opnsense_wireguard import plan_servers
from collectors.opnsense_wireguard_sync import PEERS, SERVERS, SOURCE_NAT, WireGuardSync
from tests.test_opnsense_sync import FakeAPI
from tests.test_opnsense_wireguard import PUBLIC, SERVER


WAN_BOUND = dict(SERVER, address={'source': 'wan', 'ipVersion': 'v4'})


class WireGuardAPI(FakeAPI):
    def __init__(self, snat_mode='hybrid'):
        super().__init__()
        self.gets['wireguard/general/get'] = {'general': {'enabled': '0'}}
        self.gets['firewall/source_nat/get'] = {'filter': {'general': {'snat_mode': {
            mode: {'value': mode, 'selected': int(mode == snat_mode)}
            for mode in ('automatic', 'hybrid', 'advanced', 'disabled')}}}}
        self.down = set()   # instance names that fail to come up

    def _spec_for(self, path):
        for spec in (SERVERS, PEERS, SOURCE_NAT):
            if path == spec.add or path.startswith((spec.set, spec.delete)):
                return spec
        return super()._spec_for(path)

    def post(self, path, payload=None, timeout=None):
        if path == 'wireguard/general/set':
            self.posts.append(path)
            self.gets['wireguard/general/get']['general'].update(payload['general'])
            return {'result': 'saved'}
        spec = self._spec_for(path)
        if spec in (SERVERS, PEERS) and path.startswith(spec.set):
            # OPNsense merges a partial set into the stored record
            self.posts.append(path)
            self.store[spec.search][path[len(spec.set):]].update(payload[spec.wrapper])
            return {'result': 'saved'}
        return super().post(path, payload, timeout)

    def get(self, path, params=None, timeout=None):
        for spec in (SERVERS, PEERS):
            get = spec.set.replace('/set_', '/get_')
            if path.startswith(get):
                row = self.store.get(spec.search, {}).get(path[len(get):])
                return {spec.wrapper: dict(row)} if row else {}
        if path == 'wireguard/service/show':
            servers = self.store.get(SERVERS.search, {})
            rows = [{'type': 'interface', 'ifname': s['name'],
                     'status': 'down' if s['name'] in self.down else 'up'}
                    for s in servers.values() if s.get('enabled') == '1']
            for peer in self.store.get(PEERS.search, {}).values():
                for ref in str(peer.get('servers') or '').split(','):
                    if ref in servers and peer.get('enabled') == '1':
                        rows.append({'type': 'peer', 'ifname': servers[ref]['name'],
                                     'name': peer['name']})
            return {'rows': rows}
        return super().get(path, params, timeout)


def setup(snat_mode='hybrid'):
    api = WireGuardAPI(snat_mode)
    sync = UDAPIConfigSync(api, {'eth4': 'wan'}.get, lambda: ['lan'])
    sync.resolve_interface = {'eth4': 'wan', 'eth5': 'opt3'}.get
    return api, sync


def run(sync, section):
    wireguard = WireGuardSync(sync)
    rules = wireguard.prepare(section)
    if sync.sync_items(FILTER_RULES, rules, keep=lambda k: not k.startswith('wg-'))[0]:
        sync.apply_filter()
    return wireguard.finish()


def owned(api, spec):
    return [r for r in api.search(spec.search) if spec.key_fn(r)]


def test_lifecycle_create_repeat_and_remove():
    api, sync = setup()
    assert run(sync, [WAN_BOUND]) == 1
    [server], [peer] = owned(api, SERVERS), owned(api, PEERS)
    assert peer['servers'] == server['uuid']
    assert api.gets['wireguard/general/get']['general']['enabled'] == '1'
    rules = {r['description'].split()[0]: r for r in api.search(FILTER_RULES.search)}
    listen = next(r for k, r in rules.items() if k.endswith('-in'))
    assert (listen['interface'], listen['destination_net'], listen['destination_port'],
            listen['protocol'], listen['ipprotocol']) == ('wan', 'wanip', '51890', 'UDP', 'inet')
    tunnel = next(r for k, r in rules.items() if k.endswith('-tun'))
    assert tunnel['interface'] == 'wireguard'
    [alias] = [a for a in api.search(ALIASES.search) if a['name'].startswith('ufg_wg_')]
    assert tunnel['source_net'] == alias['name']
    assert alias['content'] == '10.253.0.0/24,fd00:253::/64'
    [nat] = api.search(SOURCE_NAT.search)
    assert nat['source_net'] == '10.253.0.0/24' and nat['interface'] == 'wan'
    assert api.posts.count('wireguard/service/reconfigure') == 1

    api.posts.clear()
    run(sync, [WAN_BOUND])
    assert api.posts == []

    run(sync, [])
    assert owned(api, SERVERS) == owned(api, PEERS) == []
    assert api.search(FILTER_RULES.search) == api.search(SOURCE_NAT.search) == []
    assert not [a for a in api.search(ALIASES.search) if a['name'].startswith('ufg_wg_')]
    # retired tunnels are disabled and stopped before their records go
    disable = api.posts.index('wireguard/service/reconfigure')
    assert all(p.startswith((SERVERS.set, PEERS.set)) for p in api.posts[:disable]
               if p.startswith('wireguard/'))
    assert disable < min(i for i, p in enumerate(api.posts) if p.startswith(SERVERS.delete))


def test_key_change_is_detected_from_detail_not_search_rows():
    api, sync = setup()
    run(sync, [WAN_BOUND])
    rotated = copy.deepcopy(WAN_BOUND)
    rotated['privateKey'] = PUBLIC
    api.posts.clear()
    run(sync, [rotated])
    assert any(p.startswith(SERVERS.set) for p in api.posts)
    assert owned(api, SERVERS)[0]['privkey'] == PUBLIC


def test_unmanaged_objects_survive_and_block_port_collisions():
    api, sync = setup()
    api.store[SERVERS.search] = {'manual': {'name': 'office', 'enabled': '1', 'port': '51820'}}
    api.store[FILTER_RULES.search] = {'r1': {'description': 'manual rule'}}
    run(sync, [WAN_BOUND])
    run(sync, [])
    assert api.search(SERVERS.search)[0]['name'] == 'office'
    assert api.search(FILTER_RULES.search)[0]['description'] == 'manual rule'
    api.posts.clear()
    with pytest.raises(ValueError, match='unmanaged'):
        run(sync, [dict(WAN_BOUND, port=51820)])
    assert api.posts == []


def test_automatic_outbound_nat_warns_instead_of_changing_mode():
    api, sync = setup(snat_mode='automatic')
    run(sync, [WAN_BOUND])
    assert api.search(SOURCE_NAT.search) == []
    assert any('outbound NAT mode is automatic' in w for w in sync.warnings)
    assert 'firewall/source_nat/set' not in api.posts


def test_instance_that_does_not_come_up_fails_for_retry():
    api, sync = setup()
    [name] = plan_servers([WAN_BOUND])[0]
    api.down.add(name)
    with pytest.raises(OPNsenseAPIError, match='not up'):
        run(sync, [WAN_BOUND])


@pytest.mark.parametrize('address,expected', [
    (None, ('wan', 'wanip', 'inet46')),
    ({'source': 'any'}, ('wan', 'wanip', 'inet46')),
    ({'source': 'wan', 'ipVersion': 'v6'}, ('wan', 'wanip', 'inet6')),
    ({'source': 'interface', 'id': 'eth5', 'ipVersion': 'v4'}, ('opt3', 'opt3ip', 'inet')),
    ({'source': 'static', 'address': '203.0.113.7'}, ('wan', '203.0.113.7', 'inet')),
])
def test_controller_listen_bindings_scope_the_listen_rule(address, expected):
    api, sync = setup()
    body = dict(SERVER, address=address) if address else dict(SERVER)
    rules = WireGuardSync(sync).prepare([body])
    listen = next(r for k, r in rules.items() if k.endswith('-in'))
    assert (listen['interface'], listen['destination_net'], listen['ipprotocol']) == expected


@pytest.mark.parametrize('address', [
    {'source': 'interface', 'id': 'eth9'},
    {'source': 'static', 'address': '0.0.0.0'}, {'source': 'static'},
    {'source': 'wan', 'address': '203.0.113.7'}, {'source': 'teleport'},
    {'source': 'any', 'ipVersion': 'v5'}, {'source': 'any', 'mystery': 1},
])
def test_unusable_listen_bindings_write_nothing(address):
    api, sync = setup()
    with pytest.raises(ValueError):
        WireGuardSync(sync).prepare([dict(SERVER, address=address)])
    assert api.posts == []


def test_routes_only_for_peer_prefixes_outside_the_tunnel():
    servers, _ = plan_servers([SERVER])
    assert next(iter(servers.values()))['payload']['disableroutes'] == '1'
    site = copy.deepcopy(SERVER)
    site['remotePeers'][0]['allowedIPs'].append('192.168.50.0/24')
    server = next(iter(plan_servers([site])[0].values()))
    assert server['payload']['disableroutes'] == '0'
    assert '192.168.50.0/24' in server['networks']
    site['remotePeers'][0]['allowedIPs'].append('0.0.0.0/0')
    with pytest.raises(ValueError, match='default route'):
        plan_servers([site])


def udapi(servers=None):
    tree = {'firewall/filter': [], 'interfaces': []}
    if servers is not None:
        tree['vpn/wireguard/servers'] = servers
    return {'udapi': tree}


def test_provisioning_is_opt_in():
    api, sync = setup()
    summary = sync.apply_system_cfg(udapi([WAN_BOUND]))
    assert not any(p.startswith('wireguard/') for p in api.posts)
    assert 'vpn/wireguard/servers' in summary['untranslated_settings']


def test_provisioning_applies_and_absent_section_retires():
    api, sync = setup()
    sync.options = {'apply_vpn': True}
    summary = sync.apply_system_cfg(udapi([WAN_BOUND]))
    assert summary['wireguard_servers'] == 1
    assert 'vpn/wireguard/servers' not in summary['untranslated_settings']
    assert len([r for r in api.search(FILTER_RULES.search)
                if 'wg-' in r['description']]) == 2
    api.posts.clear()
    sync.apply_system_cfg(udapi([WAN_BOUND]))
    assert [p for p in api.posts if not p.endswith(('apply', 'reconfigure'))] == []
    sync.apply_system_cfg(udapi())
    assert owned(api, SERVERS) == []
    assert not [r for r in api.search(FILTER_RULES.search) if 'wg-' in r['description']]


def test_failed_translation_keeps_the_last_applied_rules():
    api, sync = setup()
    sync.options = {'apply_vpn': True}
    sync.apply_system_cfg(udapi([WAN_BOUND]))
    bad = dict(WAN_BOUND, dnsServers=['1.1.1.1'])
    summary = sync.apply_system_cfg(udapi([bad]))
    assert any('WireGuard not applied' in w for w in summary['warnings'])
    assert len(owned(api, SERVERS)) == 1
    assert len([r for r in api.search(FILTER_RULES.search)
                if 'wg-' in r['description']]) == 2
