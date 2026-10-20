import pytest

from collectors.adguard_appblocks import (
    PREFIX, AdGuardAppBlockSync, AdGuardError, resolve_services, neighbor_addresses,
)

SERVICES = [{'id': 'instagram', 'name': 'Instagram'}, {'id': 'tiktok', 'name': 'TikTok'},
            {'id': 'youtube', 'name': 'YouTube'}]
RULE = {'_id': 'r1', 'name': 'No Instagram', 'type': 'DEVICE', 'target_type': 'APP_ID',
        'client_macs': ['AA:BB:CC:00:00:02'], 'app_ids': [1573022], 'schedule': {'mode': 'ALWAYS'}}


class Controller:
    def __init__(self, rules, networks=()):
        self.rules, self.networks = rules, list(networks)

    def call(self, method, path):
        return self.rules if path == 'v2/firewall-app-blocks' else self.networks


class FakeAdGuard:
    def __init__(self, clients=(), global_services=('gambling',)):
        self.clients = {c['name']: dict(c) for c in clients}
        self.global_services = list(global_services)
        self.global_schedule = {}
        self.posts = []

    def get(self, path):
        if path == 'control/blocked_services/all':
            return {'blocked_services': SERVICES}
        if path == 'control/blocked_services/get':
            return {'ids': self.global_services, 'schedule': self.global_schedule}
        if path == 'control/clients':
            return {'clients': list(self.clients.values())}
        raise AdGuardError(path)

    def post(self, path, payload):
        self.posts.append(path)
        if path == 'control/clients/add':
            self.clients[payload['name']] = dict(payload)
        elif path == 'control/clients/update':
            self.clients.pop(payload['name'])
            self.clients[payload['data']['name']] = dict(payload['data'])
        elif path == 'control/clients/delete':
            self.clients.pop(payload['name'])
        return 'OK'


def test_unifi_apps_resolve_to_adguard_services_by_name():
    assert resolve_services([1573022, 262256], SERVICES) == ['instagram', 'youtube']
    with pytest.raises(ValueError, match='no AdGuard'):
        resolve_services([1572867], SERVICES)        # Facebook not in this catalog


def test_device_block_lifecycle_keeps_global_services_and_operator_clients():
    agh = FakeAdGuard(clients=[{'name': 'kids tablet', 'ids': ['10.0.0.9']}])
    sync = AdGuardAppBlockSync(agh, Controller([RULE]),
                              lambda: {'aa:bb:cc:00:00:02': ['10.0.0.8']})
    summary = sync.run()
    assert (summary['clients'], summary['changed']) == (1, 1)
    [client] = [c for n, c in agh.clients.items() if n.startswith(PREFIX)]
    assert client['ids'] == ['10.0.0.8']
    assert client['blocked_services'] == ['gambling', 'instagram']
    assert client['use_global_blocked_services'] is False and client['use_global_settings'] is True
    agh.posts.clear()
    assert sync.run()['changed'] == 0 and agh.posts == []
    sync.controller.rules = [dict(RULE, app_ids=[1573022, 262392])]
    sync.run()
    assert agh.posts == ['control/clients/update']
    sync.controller.rules = []
    sync.run()
    assert list(agh.clients) == ['kids tablet']


def test_network_block_uses_the_lan_subnet():
    rule = dict(RULE, type='NETWORK', client_macs=[], network_ids=['n1'])
    net = {'_id': 'n1', 'purpose': 'corporate', 'ip_subnet': '10.20.0.1/24'}
    agh = FakeAdGuard()
    AdGuardAppBlockSync(agh, Controller([rule], [net])).run()
    [client] = agh.clients.values()
    assert client['ids'] == ['10.20.0.0/24']


@pytest.mark.parametrize('change', [
    {'schedule': {'mode': 'CUSTOM'}}, {'app_ids': [999999999]}, {'client_macs': []},
    {'target_type': 'APP_CATEGORY'},
])
def test_unsupported_rules_write_nothing(change):
    agh = FakeAdGuard()
    with pytest.raises(ValueError):
        AdGuardAppBlockSync(agh, Controller([dict(RULE, **change)])).run()
    assert agh.posts == []


def test_dual_stack_device_rules_follow_current_address_ownership():
    addresses = {'aa:bb:cc:00:00:02': ['10.0.0.8', 'fd00::123']}
    agh = FakeAdGuard()
    sync = AdGuardAppBlockSync(agh, Controller([RULE]), lambda: addresses)
    assert sync.run()['clients'] == 2
    assert {c['ids'][0] for c in agh.clients.values()} == {'10.0.0.8', 'fd00::123'}
    addresses['aa:bb:cc:00:00:02'] = ['10.0.0.20']
    agh.posts.clear()
    sync.run()
    assert [c['ids'] for c in agh.clients.values()] == [['10.0.0.20']]
    assert agh.posts == ['control/clients/delete', 'control/clients/delete', 'control/clients/add']


def test_offline_device_is_pending_and_cannot_keep_an_old_ip_blocked():
    addresses = {'aa:bb:cc:00:00:02': ['10.0.0.8']}
    agh = FakeAdGuard()
    sync = AdGuardAppBlockSync(agh, Controller([RULE]), lambda: addresses)
    sync.run()
    addresses.clear()
    result = sync.run()
    assert result['pending_devices'] == 1 and result['clients'] == 0
    assert agh.clients == {}


def test_device_policy_inherits_containing_network_blocks():
    agh = FakeAdGuard()
    network_rule = dict(RULE, _id='network', type='NETWORK', client_macs=[],
                        network_ids=['n1'], app_ids=[262392])
    net = {'_id': 'n1', 'purpose': 'corporate', 'ip_subnet': '10.20.0.1/24'}
    sync = AdGuardAppBlockSync(agh, Controller([RULE, network_rule], [net]),
                              lambda: {'aa:bb:cc:00:00:02': ['10.20.0.8']})
    sync.run()
    exact = next(c for c in agh.clients.values() if c['ids'] == ['10.20.0.8'])
    assert exact['blocked_services'] == ['gambling', 'instagram', 'tiktok']


def test_manual_overlapping_client_is_not_overridden_or_silently_bypassed():
    agh = FakeAdGuard(clients=[{'name': 'operator client', 'ids': ['10.20.0.8']}])
    network_rule = dict(RULE, type='NETWORK', client_macs=[], network_ids=['n1'])
    net = {'_id': 'n1', 'purpose': 'corporate', 'ip_subnet': '10.20.0.1/24'}
    with pytest.raises(ValueError, match='unmanaged AdGuard client'):
        AdGuardAppBlockSync(agh, Controller([network_rule], [net])).run()
    assert agh.posts == []


def test_neighbor_snapshot_uses_all_current_lan_ips_but_not_wan_expired_or_ambiguous_entries():
    mac = 'aa:bb:cc:00:00:02'
    arp = [{'mac': mac, 'ip': '10.0.0.8', 'intf': 'em0'},
           {'mac': mac, 'ip': '10.0.0.9', 'intf': 'em0', 'expired': True},
           {'mac': mac, 'ip': '198.51.100.2', 'intf': 're0'},
           {'mac': mac, 'ip': '10.0.0.10', 'intf': 'em0'},
           {'mac': 'aa:bb:cc:00:00:04', 'ip': '10.0.0.10', 'intf': 'em0'}]
    ndp = [{'mac': mac, 'ip': 'fd00::1', 'intf': 'em0'},
           {'mac': mac, 'ip': 'fd00::2', 'intf': 'em0'},
           {'mac': mac, 'ip': 'fe80::2%em0', 'intf': 'em0'},
           {'mac': '(incomplete)', 'ip': 'fd00::3', 'intf': 'em0'}]
    assert neighbor_addresses(arp, ndp, {'em0'}) == {mac: ['10.0.0.8', 'fd00::1', 'fd00::2']}


def test_unknown_neighbor_snapshot_is_not_treated_as_all_devices_offline():
    with pytest.raises(ValueError, match='snapshot unavailable'):
        neighbor_addresses(None, [], {'em0'})


def test_scheduled_global_blocks_are_not_silently_promoted_to_always():
    agh = FakeAdGuard()
    agh.global_schedule = {'time_zone': 'Local', 'sun': {'start': 3600000, 'end': 7200000}}
    sync = AdGuardAppBlockSync(agh, Controller([RULE]),
                              lambda: {'aa:bb:cc:00:00:02': ['10.0.0.8']})
    with pytest.raises(ValueError, match='schedule inheritance'):
        sync.run()
    assert agh.posts == []
