import pytest

from collectors.adguard_appblocks import (
    PREFIX, AdGuardAppBlockSync, AdGuardError, resolve_services,
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
        self.posts = []

    def get(self, path):
        if path == 'control/blocked_services/all':
            return {'blocked_services': SERVICES}
        if path == 'control/blocked_services/get':
            return {'ids': self.global_services, 'schedule': {}}
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
    sync = AdGuardAppBlockSync(agh, Controller([RULE]))
    summary = sync.run()
    assert (summary['clients'], summary['changed']) == (1, 1)
    [client] = [c for n, c in agh.clients.items() if n.startswith(PREFIX)]
    assert client['ids'] == ['aa:bb:cc:00:00:02']
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
