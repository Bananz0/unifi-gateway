"""DDNS, Smart Queue and MAC override translation, from a real Network
10.6.106 push (tests/fixtures/uxg_features_10.6.106.json)."""
import copy
import json
import os

import pytest

from collectors.opnsense_coverage import untranslated_paths
from collectors.opnsense_ddns import ACCOUNTS, plan_ddns, sync_ddns
from collectors.opnsense_macclone import MACOverrideSync, plan_overrides
from collectors.opnsense_shaper import PIPES, RULES, plan_shaper, sync_shaper
from collectors.opnsense_udapi import UDAPIConfigSync
from tests.test_opnsense_sync import FakeAPI

FIXTURE = json.load(open(os.path.join(os.path.dirname(__file__), 'fixtures',
                                      'uxg_features_10.6.106.json')))
RESOLVE = {'eth4': 'wan', 'br0': 'lan'}.get


class ServicesAPI(FakeAPI):
    def __init__(self):
        super().__init__()
        self.gets['dyndns/settings/get'] = {'ddclient': {'general': {'enabled': '0'}}}
        self.gets['interfaces/assignment/pending'] = {'status': 'ok'}
        self.store['interfaces/assignment/search_item'] = {
            'wan-uuid': {'identifier': 'wan', 'spoofmac': ''},
            'lan-uuid': {'identifier': 'lan', 'spoofmac': ''}}

    def _spec_for(self, path):
        for spec in (ACCOUNTS, PIPES, RULES):
            if path == spec.add or path.startswith((spec.set, spec.delete)):
                return spec
        return super()._spec_for(path)

    def get(self, path, params=None, timeout=None):
        if path.startswith('dyndns/accounts/get_item/'):
            row = self.store[ACCOUNTS.search].get(path.rsplit('/', 1)[1])
            return {'account': dict(row, password='')} if row else {}
        if path.startswith('interfaces/assignment/get_item/'):
            return {'interface': self.store['interfaces/assignment/search_item'][path.rsplit('/', 1)[1]]}
        return super().get(path, params, timeout)

    def post(self, path, payload=None, timeout=None):
        if path == 'dyndns/settings/set':
            self.posts.append(path)
            self.gets['dyndns/settings/get']['ddclient']['general'].update(
                payload['ddclient']['general'])
            return {'result': 'saved'}
        if path.startswith('interfaces/assignment/set_item/'):
            self.posts.append(path)
            self.store['interfaces/assignment/search_item'][path.rsplit('/', 1)[1]].update(
                payload['interface'])
            return {'result': 'saved'}
        return super().post(path, payload, timeout)


def setup():
    api = ServicesAPI()
    sync = UDAPIConfigSync(api, RESOLVE, lambda: ['lan'])
    sync.resolve_interface = RESOLVE
    return api, sync


# ── DDNS ─────────────────────────────────────────────────────────────────

def test_captured_custom_server_becomes_a_dyndns2_account():
    [account] = plan_ddns(FIXTURE['services']['ddns'], RESOLVE).values()
    assert (account['service'], account['protocol'], account['server']) == (
        'custom', 'dyndns2', 'members.dyndns.org')
    assert (account['hostnames'], account['interface'], account['checkip']) == (
        'lab.example.test', 'wan', 'if')


@pytest.mark.parametrize('client,service', [
    ({'service': 'dyndns'}, 'dyndns2'), ({'service': 'no-ip'}, 'noip'),
    ({'service': 'custom', 'customName': 'namecheap.0', 'server': 'dynamicdns.park-your-domain.com',
      'serverPath': '/update?domain=x&password=y&host='}, 'namecheap'),
])
def test_controller_service_names_map_to_ddclient(client, service):
    body = dict({'hostname': 'h.example.test', 'username': 'u', 'password': 'p',
                 'interface': {'id': 'eth4'}}, **client)
    [account] = plan_ddns({'enabled': True, 'clients': [body]}, RESOLVE).values()
    assert account['service'] == service


@pytest.mark.parametrize('change', [
    {'service': 'cloudflare'}, {'service': 'custom', 'server': 'x.test', 'serverPath': '/p'},
    {'service': 'custom', 'server': ''}, {'interface': {'id': 'eth9'}}, {'mystery': 1},
    {'hostname': ''},
])
def test_unrepresentable_ddns_clients_reject_the_section(change):
    body = dict(FIXTURE['services']['ddns']['clients'][0], **change)
    with pytest.raises(ValueError):
        plan_ddns({'enabled': True, 'clients': [body]}, RESOLVE)


def test_ddns_lifecycle_preserves_unmanaged_accounts():
    api, sync = setup()
    api.store[ACCOUNTS.search] = {'mine': {'description': 'home', 'service': 'cloudflare'}}
    assert sync_ddns(sync, FIXTURE['services']['ddns']) == 1
    assert api.gets['dyndns/settings/get']['ddclient']['general']['enabled'] == '1'
    api.posts.clear()
    sync_ddns(sync, FIXTURE['services']['ddns'])
    assert api.posts == []   # masked get_item password doesn't cause rewrites
    sync_ddns(sync, None)
    assert [r['description'] for r in api.search(ACCOUNTS.search)] == ['home']


# ── Smart Queues ─────────────────────────────────────────────────────────

def test_captured_smart_queue_plan():
    assert plan_shaper(FIXTURE['qos/ip'], RESOLVE) == ('wan', {'in': '50000', 'out': '20000'})
    off = copy.deepcopy(FIXTURE['qos/ip'])
    off['global']['enabled'] = False
    assert plan_shaper(off, RESOLVE) is None


@pytest.mark.parametrize('change', [
    lambda q: q.update(queues=[{'id': 1}]),
    lambda q: q['global']['connectivity'].update(downloadSpeed=0),
    lambda q: q['global']['connectivity'].update(interfaceID='eth9'),
    lambda q: q['global'].update(mystery=True),
])
def test_unrepresentable_smart_queues_are_rejected(change):
    section = copy.deepcopy(FIXTURE['qos/ip'])
    change(section)
    with pytest.raises(ValueError):
        plan_shaper(section, RESOLVE)


def test_smart_queue_lifecycle():
    api, sync = setup()
    assert sync_shaper(sync, FIXTURE['qos/ip']) == 1
    pipes = {p['description'].split()[0]: p for p in api.search(PIPES.search)}
    assert {(p['bandwidth'], p['bandwidthMetric'], p['scheduler']) for p in pipes.values()} == {
        ('50000', 'Kbit', 'fq_codel'), ('20000', 'Kbit', 'fq_codel')}
    rules = api.search(RULES.search)
    by_direction = {r['direction']: r['target'] for r in rules}
    assert by_direction['in'] == next(u for u, p in api.store[PIPES.search].items()
                                      if p['bandwidth'] == '50000')
    api.posts.clear()
    sync_shaper(sync, FIXTURE['qos/ip'])
    assert api.posts == []
    sync_shaper(sync, {})
    assert api.search(PIPES.search) == api.search(RULES.search) == []
    assert api.posts.index(next(p for p in api.posts if p.startswith(RULES.delete))) < \
        api.posts.index(next(p for p in api.posts if p.startswith(PIPES.delete)))


def test_operator_shaper_on_the_interface_blocks_a_second_one():
    api, sync = setup()
    api.store[RULES.search] = {'r': {'description': 'my shaping', 'interface': 'wan', 'enabled': '1'}}
    with pytest.raises(ValueError, match='unmanaged'):
        sync_shaper(sync, FIXTURE['qos/ip'])
    assert api.posts == []


# ── MAC override ─────────────────────────────────────────────────────────

def test_mac_override_applies_and_restores_the_original(tmp_path):
    api, _ = setup()
    rows = api.store['interfaces/assignment/search_item']
    rows['wan-uuid']['spoofmac'] = '02:aa:bb:cc:dd:ee'
    mac = MACOverrideSync(api, str(tmp_path / 'mac.json'))
    desired = plan_overrides(FIXTURE['interfaces'], RESOLVE)
    assert desired == {'wan': '02:11:22:33:44:55'}
    mac.sync(desired)
    assert rows['wan-uuid']['spoofmac'] == '02:11:22:33:44:55'
    api.posts.clear()
    mac.sync(desired)
    assert api.posts == []
    mac.sync({})
    assert rows['wan-uuid']['spoofmac'] == '02:aa:bb:cc:dd:ee'
    assert json.load(open(tmp_path / 'mac.json')) == {}


def test_mac_changed_in_opnsense_meanwhile_is_left_alone(tmp_path):
    api, _ = setup()
    rows = api.store['interfaces/assignment/search_item']
    mac = MACOverrideSync(api, str(tmp_path / 'mac.json'))
    mac.sync({'wan': '02:11:22:33:44:55'})
    rows['wan-uuid']['spoofmac'] = '02:99:99:99:99:99'
    mac.sync({})
    assert rows['wan-uuid']['spoofmac'] == '02:99:99:99:99:99'


@pytest.mark.parametrize('value', ['01:00:5e:00:00:01', '00:00:00:00:00:00', 'nonsense'])
def test_invalid_override_rejected(value):
    iface = {'identification': {'id': 'eth4', 'type': 'ethernet', 'macOverride': value}}
    with pytest.raises(ValueError):
        plan_overrides([iface], RESOLVE)


def test_pending_interface_changes_block_mac_writes(tmp_path):
    api, _ = setup()
    api.gets['interfaces/assignment/pending'] = {'status': 'pending'}
    with pytest.raises(Exception, match='pending'):
        MACOverrideSync(api, str(tmp_path / 'm.json')).sync({'wan': '02:11:22:33:44:55'})


# ── provisioning + coverage ──────────────────────────────────────────────

def tree():
    return {'udapi': {'interfaces': copy.deepcopy(FIXTURE['interfaces']),
                      'qos/ip': FIXTURE['qos/ip'],
                      'services': {'ddns': FIXTURE['services']['ddns']}}}


def test_opt_in_options_and_coverage(tmp_path):
    api, sync = setup()
    sync.options = {'apply_interfaces': False}
    summary = sync.apply_system_cfg(tree())
    assert {'qos/ip', 'services/ddns', 'interfaces/*/identification/macOverride'} <= set(
        summary['untranslated_settings'])
    assert api.posts == []
    sync.options = {'apply_interfaces': False, 'apply_ddns': True, 'apply_shaper': True,
                    'apply_mac_override': True, 'mac_state_file': str(tmp_path / 'm.json')}
    summary = sync.apply_system_cfg(tree())
    assert (summary['ddns_accounts'], summary['smart_queues'], summary['mac_overrides']) == (1, 1, 1)
    assert not {'qos/ip', 'services/ddns', 'interfaces/*/identification/macOverride'} & set(
        summary['untranslated_settings'])


def test_coverage_reports_the_captured_untranslated_services():
    paths = untranslated_paths({'services': FIXTURE['services'], 'qos/ip': {}})
    assert {'services/upnp', 'services/wanFailover', 'services/ddns', 'qos/ip'} <= set(paths)


def test_uxg_inform_declares_only_applied_udapi_features():
    from unifi_protocol import _udapi_version

    class Collector:
        udapi_features = {}
    assert 'versionDetail' not in _udapi_version(Collector())
    Collector.udapi_features = {'vpn/wireguard/servers': 7}
    assert _udapi_version(Collector())['versionDetail'] == {'vpn/wireguard/servers': 7}


# ── WAN failover ─────────────────────────────────────────────────────────

from collectors.opnsense_failover import FailoverSync, plan_failover  # noqa: E402

FAILOVER_RESOLVE = {'eth4': 'wan', 'eth3': 'opt1'}.get


class GatewayAPI:
    def __init__(self, rows):
        self.rows = {r['uuid']: r for r in rows}
        self.posts = []

    def get(self, path, params=None, timeout=None):
        if path == 'routing/settings/search_gateway':
            return {'rows': [dict(r) for r in self.rows.values()]}
        if path.startswith('routing/settings/get_gateway/'):
            return {'gateway_item': dict(self.rows[path.rsplit('/', 1)[1]])}
        return {}

    def post(self, path, payload=None, timeout=None):
        self.posts.append(path)
        if path == 'routing/settings/add_gateway':
            row = dict(payload['gateway_item'], uuid='persisted-' + payload['gateway_item']['name'])
            self.rows = {u: r for u, r in self.rows.items() if r['name'] != row['name']}
            self.rows[row['uuid']] = row
            return {'result': 'saved', 'uuid': row['uuid']}
        if path.startswith('routing/settings/set_gateway/'):
            self.rows[path.rsplit('/', 1)[1]].update(payload['gateway_item'])
            return {'result': 'saved'}
        if path.startswith('routing/settings/del_gateway/'):
            row = self.rows.pop(path.rsplit('/', 1)[1])
            self.rows[row['name']] = {'uuid': row['name'], 'name': row['name'], 'virtual': True,
                                      'interface': row['interface'], 'ipprotocol': 'inet',
                                      'priority': 254}
            return {'result': 'deleted'}
        return {'status': 'ok'}


def test_captured_failover_plan():
    plan = plan_failover(FIXTURE['services']['wanFailover'], FAILOVER_RESOLVE)
    assert plan == {
        'wan': {'priority': '1', 'interval': '3000', 'time_period': '60000', 'losshigh': '50',
                'monitor_disable': '0'},
        'opt1': {'priority': '2', 'interval': '3000', 'time_period': '60000', 'losshigh': '50',
                 'monitor_disable': '0'}}


def test_single_wan_writes_nothing():
    section = copy.deepcopy(FIXTURE['services']['wanFailover'])
    section['wanInterfaces'] = section['wanInterfaces'][:1]
    assert plan_failover(section, FAILOVER_RESOLVE) == {}


@pytest.mark.parametrize('change', [
    lambda s: s.update(loadBalance={'weights': 1}),
    lambda s: s['wanInterfaces'][0].update(weight=50),
    lambda s: s['wanInterfaces'][0].update(metric=0),
    lambda s: s['wanInterfaces'][1].update(interface={'id': 'eth9'}),
    lambda s: s['wanInterfaces'][0]['monitors'][0]['alert'].update(lossThreshold=101),
])
def test_unrepresentable_failover_is_rejected(change):
    section = copy.deepcopy(FIXTURE['services']['wanFailover'])
    change(section)
    with pytest.raises(ValueError):
        plan_failover(section, FAILOVER_RESOLVE)


def test_failover_lifecycle_restores_operator_and_dynamic_gateways(tmp_path):
    api = GatewayAPI([
        {'uuid': 'u-wan', 'name': 'WAN_GW', 'interface': 'wan', 'ipprotocol': 'inet',
         'priority': '100', 'interval': '', 'time_period': '', 'losshigh': '', 'monitor_disable': '1'},
        {'uuid': 'OPT1_DHCP', 'name': 'OPT1_DHCP', 'interface': 'opt1', 'ipprotocol': 'inet',
         'priority': 254, 'virtual': True}])
    sync = FailoverSync(api, str(tmp_path / 'f.json'))
    plan = plan_failover(FIXTURE['services']['wanFailover'], FAILOVER_RESOLVE)
    assert sync.sync(plan) == 2
    assert api.rows['u-wan']['priority'] == '1' and api.rows['u-wan']['monitor_disable'] == '0'
    assert api.rows['persisted-OPT1_DHCP']['priority'] == '2'
    api.posts.clear()
    sync.sync(plan)
    assert api.posts == []
    sync.sync({})
    assert (api.rows['u-wan']['priority'], api.rows['u-wan']['monitor_disable']) == ('100', '1')
    assert api.rows['OPT1_DHCP'].get('virtual')


def test_gateway_edited_in_opnsense_is_not_restored(tmp_path):
    api = GatewayAPI([{'uuid': 'u', 'name': 'WAN_GW', 'interface': 'wan', 'ipprotocol': 'inet',
                       'priority': '100'}, {'uuid': 'v', 'name': 'B', 'interface': 'opt1',
                                            'ipprotocol': 'inet', 'priority': '200'}])
    sync = FailoverSync(api, str(tmp_path / 'f.json'))
    sync.sync(plan_failover(FIXTURE['services']['wanFailover'], FAILOVER_RESOLVE))
    api.rows['u']['priority'] = '7'
    sync.sync({})
    assert api.rows['u']['priority'] == '7'
    assert api.rows['v']['priority'] == '200'


def test_ambiguous_gateways_reject(tmp_path):
    api = GatewayAPI([{'uuid': 'a', 'name': 'A', 'interface': 'wan', 'ipprotocol': 'inet'},
                      {'uuid': 'b', 'name': 'B', 'interface': 'wan', 'ipprotocol': 'inet'}])
    with pytest.raises(ValueError, match='exactly one'):
        FailoverSync(api, str(tmp_path / 'f.json')).sync({'wan': {'priority': '1'}})
    assert api.posts == []
