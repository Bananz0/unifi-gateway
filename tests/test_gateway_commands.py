# -*- coding: utf-8 -*-
"""Tests for dispatching controller responses to the platform collector."""
import json
import sys
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def gw_module():
    class FakeDaemon:
        def __init__(self, pidfile='_.pid', **kw):
            self.pidfile = pidfile

    with patch.dict(sys.modules, {'daemon': MagicMock(Daemon=FakeDaemon)}):
        sys.modules.pop('unifi_gateway', None)
        import unifi_gateway
        yield unifi_gateway
    sys.modules.pop('unifi_gateway', None)


@pytest.fixture
def gateway(gw_module, tmp_path):
    conf = tmp_path / 'gw.conf'
    conf.write_text(
        '[global]\npid_file = %s\n[gateway]\nis_adopted = True\n' % (tmp_path / 'x.pid'))
    with patch.object(gw_module, 'CONFIG_FILE', str(conf)), \
            patch.object(gw_module, 'UNHANDLED_LOG', str(tmp_path / 'unhandled.json')):
        gw = gw_module.UnifiGateway()
        gw.datacollector = MagicMock()
        yield gw


class TestCommands:

    @pytest.mark.parametrize('cmd,method', [
        ('block-sta', 'block_client'),
        ('unblock-sta', 'unblock_client'),
        ('kick-sta', 'kick_client'),
    ])
    def test_client_commands(self, gateway, cmd, method):
        getattr(gateway.datacollector, method).return_value = True
        gateway._handle_response({'_type': 'cmd', 'cmd': cmd, 'mac': '72:ea:9e:2b:ef:c5'})
        getattr(gateway.datacollector, method).assert_called_once_with('72:ea:9e:2b:ef:c5')
        assert gateway._unhandled == {}

    def test_unsupported_platform_records_unhandled(self, gateway):
        gateway.datacollector.block_client.return_value = False
        gateway._handle_response({'_type': 'cmd', 'cmd': 'block-sta', 'mac': 'aa:bb:cc:dd:ee:ff'})
        assert 'command/block-sta' in gateway._unhandled

    def test_collector_exception_does_not_crash(self, gateway):
        gateway.datacollector.block_client.side_effect = RuntimeError('boom')
        gateway._handle_response({'_type': 'cmd', 'cmd': 'block-sta', 'mac': 'aa:bb:cc:dd:ee:ff'})
        assert 'command/block-sta' in gateway._unhandled

    def test_speedtest_prefers_platform(self, gateway):
        gateway.datacollector.run_speedtest.return_value = True
        with patch.object(gateway, '_run_speedtest') as local:
            gateway._handle_response({'_type': 'cmd', 'cmd': 'speed-test'})
        local.assert_not_called()

    def test_reboot_delegates(self, gateway):
        gateway._handle_response({'_type': 'reboot'})
        gateway.datacollector.reboot.assert_called_once_with()


class TestSetparam:

    def test_system_cfg_is_applied(self, gateway):
        gateway.datacollector.apply_system_cfg.return_value = True
        cfg = {'firewall': {'name': {}}}
        gateway._handle_response({'_type': 'setparam', 'system_cfg': json.dumps(cfg)})
        gateway.datacollector.apply_system_cfg.assert_called_once_with(cfg)
        assert gateway._unhandled == {}
        assert gateway.config.get('provisioned', 'system_cfg') == json.dumps(cfg)

    def test_system_cfg_unhandled_without_platform_support(self, gateway):
        gateway.datacollector.apply_system_cfg.return_value = False
        gateway._handle_response({'_type': 'setparam', 'system_cfg': '{}'})
        assert 'setparam/system_cfg' in gateway._unhandled

    def test_interval_and_cfgversion_are_handled(self, gateway):
        gateway._handle_response({'_type': 'setparam', 'interval': 26, 'cfgversion': 'abc'})
        assert gateway.interval == 26
        assert gateway._unhandled == {}

    @pytest.mark.parametrize('value', [
        ['aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:02'],
        [{'mac': 'aa:bb:cc:dd:ee:01'}, {'mac': 'aa:bb:cc:dd:ee:02'}],
        'aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:02',
    ])
    def test_blocked_sta_formats(self, gateway, value):
        gateway.datacollector.set_blocked_clients.return_value = True
        gateway._handle_response({'_type': 'setparam', 'blocked_sta': value})
        gateway.datacollector.set_blocked_clients.assert_called_once_with(
            ['aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:02'])
        assert gateway._unhandled == {}
