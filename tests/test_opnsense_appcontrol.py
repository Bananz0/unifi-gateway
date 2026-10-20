import copy
import json
from unittest.mock import patch

import pytest

from collectors.opnsense_api import OPNsenseAPI, OPNsenseAPIError
from collectors.opnsense_appcontrol import ZenarmorAppPolicy, resolve_app_ids


INSTAGRAM = 1573022
CATALOG = [{'id': 10745, 'name': 'Instagram', 'parent_id': 36, 'children': []},
           {'id': 100, 'name': 'Unrelated app'}]


class PolicyAPI:
    def __init__(self):
        self.policy = {'id': 0, 'name': 'Default', 'app_controls': [100]}
        self.puts = []
        self.reject = False
        self.no_effect = False

    def get(self, path, params=None):
        if path.endswith('/applicationDatabase'):
            return {'success': True, 'applicationDatabase': {'applications': copy.deepcopy(CATALOG)}}
        assert path == 'zenarmor/policy/detail'
        assert params == {'id': 0}
        return copy.deepcopy(self.policy)

    def put(self, path, payload, params=None):
        assert path == 'zenarmor/policy/appControls'
        assert params == {'id': 0}
        self.puts.append(copy.deepcopy(payload))
        if self.reject:
            return {'success': False, 'message': 'rejected'}
        if not self.no_effect:
            controls = set(self.policy['app_controls'])
            for app in payload['apps']:
                if app['value']:
                    controls.add(app['id'])
                else:
                    controls.discard(app['id'])
            self.policy['app_controls'] = sorted(controls)
        return {'success': True}


def test_instagram_ids_are_translated_between_independent_catalogs():
    assert resolve_app_ids([INSTAGRAM], CATALOG) == [10745]


@pytest.mark.parametrize('catalog', [[], [{'id': 1, 'name': 'Instagram CDN'}],
    [{'id': 1, 'name': 'Instagram'}, {'id': 2, 'name': 'Instagram'}]])
def test_missing_and_ambiguous_matches_never_expand_to_a_category(catalog):
    with pytest.raises(ValueError, match='unambiguous'):
        resolve_app_ids([INSTAGRAM], catalog)


def test_app_deltas_preserve_manual_blocks_and_are_idempotent():
    api = PolicyAPI()
    policy = ZenarmorAppPolicy(api)
    assert policy.set_apps(0, blocked=[10745], expected_name='Default')
    assert api.policy['app_controls'] == [100, 10745]
    assert not policy.set_apps(0, blocked=[10745])
    assert len(api.puts) == 1
    assert policy.set_apps(0, allowed=[10745])
    assert api.policy['app_controls'] == [100]


def test_missing_catalog_id_and_changed_identity_do_not_write():
    api = PolicyAPI()
    policy = ZenarmorAppPolicy(api)
    with pytest.raises(ValueError, match='identity'):
        policy.set_apps(0, blocked=[10745], expected_name='another policy')
    with pytest.raises(ValueError, match='catalog'):
        policy.set_apps(0, blocked=[999999])
    assert api.puts == []


@pytest.mark.parametrize('failure', ['reject', 'no_effect'])
def test_backend_failure_is_never_reported_as_success(failure):
    api = PolicyAPI()
    setattr(api, failure, True)
    with pytest.raises(OPNsenseAPIError):
        ZenarmorAppPolicy(api).set_apps(0, blocked=[10745])


def test_put_sends_json_body_and_encodes_query_parameters():
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return b'{"success": true}'

    api = OPNsenseAPI('https://router.example', 'key', 'secret')
    with patch('urllib.request.urlopen', return_value=Response()) as request:
        assert api.put('zenarmor/policy/appControls', {'apps': []}, params={'id': 0}) == {'success': True}
    sent = request.call_args.args[0]
    assert sent.get_method() == 'PUT'
    assert sent.full_url == 'https://router.example/api/zenarmor/policy/appControls?id=0'
    assert json.loads(sent.data) == {'apps': []}
