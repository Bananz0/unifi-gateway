import copy
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('unifi_app_rules_tool', Path(__file__).parents[1] / 'tools/unifi_app_rules.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class Controller:
    def __init__(self):
        self.rules = []
        self.calls = []

    def call(self, method, path, payload=None):
        self.calls.append((method, path))
        assert 'trafficrules' not in path
        if method == 'POST':
            assert path == 'v2/firewall-app-blocks/create'
            row = dict(copy.deepcopy(payload), _id='new-id')
            self.rules.append(row)
            return row
        return copy.deepcopy(self.rules)


def test_current_api_saves_and_reads_back_an_instagram_rule_without_deprecated_endpoint():
    api = Controller()
    body = tool.build_rule('No Instagram', ['Instagram'], ['02:00:00:00:00:01'])
    rule, changed = tool.save_rule(api, body)
    assert rule['app_ids'] == [1573022] and changed
    assert api.calls == [('GET', tool.ENDPOINT), ('POST', tool.ENDPOINT + '/create'), ('GET', tool.ENDPOINT)]
    api.calls.clear()
    same, changed = tool.save_rule(api, body)
    assert not changed and same['_id'] == rule['_id']
    assert api.calls == [('GET', tool.ENDPOINT)]


def test_conflicting_same_name_does_not_overwrite_the_existing_rule():
    api = Controller()
    body = tool.build_rule('No Instagram', ['Instagram'], ['02:00:00:00:00:01'])
    tool.save_rule(api, body)
    body['client_macs'] = ['02:00:00:00:00:02']
    with pytest.raises(ValueError, match='different rule'):
        tool.save_rule(api, body)
    assert len(api.rules) == 1


@pytest.mark.parametrize('mac', ['ff:ff:ff:ff:ff:ff', 'not-a-mac', '00:00:00:00:00:00'])
def test_invalid_device_scope_never_creates_a_rule(mac):
    api = Controller()
    with pytest.raises(ValueError):
        tool.save_rule(api, tool.build_rule('Block', ['Instagram'], [mac]))
    assert api.calls == []


def test_unknown_application_and_unscoped_rule_are_not_saved():
    with pytest.raises(ValueError, match='unknown'):
        tool.build_rule('Block', ['not-a-real-application'], ['02:00:00:00:00:01'])
    with pytest.raises(ValueError, match='select devices'):
        tool.build_rule('Block', ['Instagram'])


def test_cli_argparse_none_for_the_unused_scope_is_supported(tmp_path, monkeypatch, capsys):
    config = tmp_path / 'gateway.conf'
    config.write_text('[unifi]\nurl=https://controller.invalid\nusername=test\npassword=test\n')
    api = Controller()
    monkeypatch.setattr(tool, 'UniFiController', lambda *args, **kwargs: api)
    assert tool.main(['--config', str(config), 'create', '--name', 'No Instagram',
                      '--app', 'Instagram', '--mac', '02:00:00:00:00:01']) == 0
    assert 'new-id' in capsys.readouterr().out
    assert len(api.rules) == 1
