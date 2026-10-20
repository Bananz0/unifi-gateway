import copy

import pytest

from collectors.opnsense_api import OPNsenseAPIError
from collectors.opnsense_appblocks import PREFIX, SimpleAppBlockSync, plan_blocks
from tests.test_opnsense_appcontrol import CATALOG, INSTAGRAM


MAC = '02:11:22:33:44:55'
RULE = {'_id': 'rule1', 'name': 'Block Instagram', 'type': 'DEVICE',
        'target_type': 'APP_ID', 'client_macs': [MAC], 'network_ids': [],
        'app_ids': [INSTAGRAM], 'app_category_ids': [], 'schedule': {'mode': 'ALWAYS'}}


class Controller:
    def __init__(self):
        self.rules = [copy.deepcopy(RULE)]
        self.networks = []

    def call(self, method, path):
        assert method == 'GET'
        return copy.deepcopy(self.rules if path == 'v2/firewall-app-blocks' else self.networks)


class Plugin:
    def __init__(self):
        self.policies = {0: {'id': 0, 'name': 'Default', 'isActive': True,
            'app_controls': [100], 'isCentralized': False,
            'mac_addresses': [], 'networks': [],
            'configs': {'directions': {'inbound': False, 'outbound': False},
                        'sort_number': 100, 'groups': [], 'usernames': [],
                        'vlans': [], 'webcategory_type': 'permissive', 'decision_is_block': False}}}
        self.writes = []
        self.license_rejected = False
        self.ignore_selectors = False

    def get(self, path, params=None):
        if path.endswith('/index'):
            return {'policies': [copy.deepcopy(p) for p in self.policies.values()]}
        if path.endswith('/applicationDatabase'):
            return {'success': True, 'applicationDatabase': {'applications': copy.deepcopy(CATALOG)}}
        assert path.endswith('/detail')
        return copy.deepcopy(self.policies[params['id']])

    def post(self, path, payload):
        self.writes.append(('POST', path, copy.deepcopy(payload)))
        if path == 'zenarmor/policy/clone?id=0':
            pid = max(self.policies) + 1
            self.policies[pid] = dict(copy.deepcopy(self.policies[0]), id=pid,
                                     name=payload['name'], isActive=False)
            return {'success': True, 'nodePolicy': {'id': pid}}
        assert path == 'zenarmor/policy/delete'
        del self.policies[payload['cloud_id']]
        return {'success': True}

    def put(self, path, payload, params=None):
        self.writes.append(('PUT', path, copy.deepcopy(payload)))
        policy = self.policies[params['id']]
        if path.endswith('/config'):
            if payload['operation'] == 'set-configs':
                policy['configs'] = copy.deepcopy(payload['configs'])
            elif payload['status'] and self.license_rejected:
                return {'success': False, 'message': 'Upgrade to premium'}
            else:
                policy['isActive'] = payload['status']
        elif path.endswith('/macAddresses'):
            if not self.ignore_selectors:
                policy['mac_addresses'] = copy.deepcopy(payload['macAddresses'])
        elif path.endswith('/networks'):
            if not self.ignore_selectors:
                policy['networks'] = copy.deepcopy(payload['networks'])
        else:
            assert path.endswith('/appControls')
            apps = set(policy['app_controls'])
            for row in payload['apps']:
                (apps.add if row['value'] else apps.discard)(row['id'])
            policy['app_controls'] = sorted(apps)
        return {'success': True}


def test_client_rule_lifecycle_preserves_default_and_manual_controls():
    api, ctl = Plugin(), Controller()
    before = copy.deepcopy(api.policies[0])
    sync = SimpleAppBlockSync(api, ctl)
    assert sync.run() == {'requested': 1, 'policies': 1, 'changed': 1}
    policy = api.policies[1]
    assert policy['app_controls'] == [100, 10745]
    assert policy['mac_addresses'][0]['value'] == MAC
    assert policy['networks'] == []
    assert policy['isActive'] is True
    assert policy['configs']['directions'] == {'inbound': True, 'outbound': True}
    assert api.policies[0] == before
    api.writes.clear()
    assert sync.run()['changed'] == 0
    assert api.writes == []
    ctl.rules = []
    assert sync.run()['changed'] == 1
    assert list(api.policies) == [0]
    assert api.policies[0] == before


def test_multiple_rules_for_same_device_merge_apps_into_one_policy():
    ctl, api = Controller(), Plugin()
    ctl.rules.append(dict(RULE, _id='rule2'))
    assert SimpleAppBlockSync(api, ctl).run()['policies'] == 1
    ctl.rules.pop()
    api.writes.clear()
    assert SimpleAppBlockSync(api, ctl).run()['changed'] == 0


def test_license_rejection_leaves_scoped_policy_disabled_without_global_fallback():
    api = Plugin()
    api.license_rejected = True
    with pytest.raises(OPNsenseAPIError, match='premium'):
        SimpleAppBlockSync(api, Controller()).run()
    assert api.policies[1]['isActive'] is False
    assert api.policies[0]['app_controls'] == [100]
    assert all(not (method == 'PUT' and payload.get('id') == 0)
               for method, path, payload in api.writes)


def test_selector_readback_failure_does_not_activate_policy():
    api = Plugin()
    api.ignore_selectors = True
    with pytest.raises(OPNsenseAPIError, match='selectors'):
        SimpleAppBlockSync(api, Controller()).run()
    assert api.policies[1]['isActive'] is False
    assert not any(payload.get('status') is True for _, _, payload in api.writes)


@pytest.mark.parametrize('change', [
    {'client_macs': []}, {'client_macs': ['ff:ff:ff:ff:ff:ff']},
    {'client_macs': ['00:00:00:00:00:00']}, {'schedule': {'mode': 'CUSTOM'}},
    {'target_type': 'APP_CATEGORY'}, {'app_ids': [99999999]},
    {'unknown_filter': 'restrict'}, {'type': 'ALL'}, {'network_ids': ['network1']},
])
def test_unsupported_rule_never_writes_or_becomes_global(change):
    api, ctl = Plugin(), Controller()
    ctl.rules = [dict(RULE, **change)]
    with pytest.raises(ValueError):
        SimpleAppBlockSync(api, ctl).run()
    assert api.writes == []


def test_network_scope_is_explicit_and_ipv6_is_not_silently_omitted():
    ctl, api = Controller(), Plugin()
    ctl.rules = [dict(RULE, type='NETWORK', client_macs=[], network_ids=['lan1'])]
    ctl.networks = [{'_id': 'lan1', 'purpose': 'corporate', 'ip_subnet': '10.20.0.1/24',
                     'ipv6_interface_type': 'none'}]
    assert SimpleAppBlockSync(api, ctl).run()['policies'] == 1
    assert api.policies[1]['networks'][0]['value'] == '10.20.0.0/24'
    assert api.policies[1]['mac_addresses'] == []
    ctl.networks[0]['ipv6_interface_type'] = 'pd'
    api.writes.clear()
    with pytest.raises(ValueError, match='IPv6'):
        SimpleAppBlockSync(api, ctl).run()
    assert api.writes == []
    assert api.policies[1]['isActive'] is True


def test_existing_custom_security_policy_is_not_shadowed():
    api = Plugin()
    api.policies[5] = dict(copy.deepcopy(api.policies[0]), id=5, name='manual security')
    with pytest.raises(ValueError, match='inheritance'):
        SimpleAppBlockSync(api, Controller()).run()
    assert api.writes == []


def test_controller_failure_is_not_an_authoritative_empty_rule_list():
    ctl, api = Controller(), Plugin()
    sync = SimpleAppBlockSync(api, ctl)
    sync.run()
    api.writes.clear()
    ctl.rules = {'error': 'not available'}
    with pytest.raises(ValueError, match='snapshot'):
        sync.run()
    assert api.writes == []
    assert api.policies[1]['isActive'] is True


def test_mac_scope_does_not_depend_on_mutable_client_ip():
    plan = plan_blocks([RULE], [], CATALOG)
    name, policy = next(iter(plan.items()))
    assert name.startswith(PREFIX)
    assert policy == {'macs': [MAC], 'networks': [], 'apps': [10745]}


def test_license_backoff_avoids_repeat_writes_but_allows_cleanup():
    api, ctl = Plugin(), Controller()
    api.license_rejected = True
    sync = SimpleAppBlockSync(api, ctl)
    with pytest.raises(OPNsenseAPIError):
        sync.run()
    api.writes.clear()
    with pytest.raises(OPNsenseAPIError, match='premium'):
        sync.run()
    assert api.writes == []
    ctl.rules = []
    assert sync.run()['changed'] == 1
    assert list(api.policies) == [0]


def test_unblock_cleanup_does_not_depend_on_default_remaining_active():
    api, ctl = Plugin(), Controller()
    sync = SimpleAppBlockSync(api, ctl)
    sync.run()
    ctl.rules = []
    api.policies[0]['isActive'] = False
    assert sync.run()['changed'] == 1
    assert list(api.policies) == [0]


def test_changed_default_security_cannot_be_shadowed_by_old_clone():
    api, ctl = Plugin(), Controller()
    sync = SimpleAppBlockSync(api, ctl)
    sync.run()
    api.policies[0]['advanced_security'] = [123]
    with pytest.raises(OPNsenseAPIError, match='security controls changed'):
        sync.run()
    assert api.policies[1]['isActive'] is False
    assert api.policies[0]['advanced_security'] == [123]


def test_polling_integration_is_independent_of_mirroring():
    import configparser
    from unittest.mock import patch
    from collectors.opnsense import OPNSenseCollector
    config = configparser.ConfigParser()
    config.read_dict({'unifi': {'url': 'https://controller.example', 'username': 'test',
                              'password': 'test', 'mirror': 'false', 'app_control': 'true'}})
    collector = OPNSenseCollector.__new__(OPNSenseCollector)
    collector.api = object()
    collector.mirror = None
    collector.appcontrol = None
    with patch('collectors.opnsense.UniFiController') as ctl:
        collector._init_mirror(config)
    assert collector.mirror is None
    assert isinstance(collector.appcontrol, SimpleAppBlockSync)
    assert ctl.call_count == 1


def test_mirror_and_enforcement_use_separate_controller_sessions():
    import configparser
    from unittest.mock import patch
    from collectors.opnsense import OPNSenseCollector
    config = configparser.ConfigParser()
    config.read_dict({'unifi': {'url': 'https://controller.example', 'username': 'test',
                              'password': 'test'}})
    collector = OPNSenseCollector.__new__(OPNSenseCollector)
    collector.api = object()
    with patch('collectors.opnsense.UniFiController', side_effect=[object(), object()]):
        collector._init_mirror(config)
    assert collector.mirror.ctl is not collector.appcontrol.controller
