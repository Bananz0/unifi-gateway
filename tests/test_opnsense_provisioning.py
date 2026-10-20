import copy
import threading
from unittest.mock import Mock

import pytest

from collectors.opnsense import OPNSenseCollector
from collectors.opnsense_api import OPNsenseAPIError
from collectors.opnsense_dhcp import RANGES
from collectors.opnsense_interfaces import ASSIGN, VLANS
from collectors.opnsense_udapi import UDAPIConfigSync
from tests.test_opnsense_dhcp import DHCPAPI, SERVER
from tests.test_opnsense_interfaces import InterfaceAPI, INTERFACES


class CombinedAPI(DHCPAPI):
    def __init__(self):
        super().__init__()
        self.interfaces = InterfaceAPI()
        self.events = []

    def get(self, path, *args, **kwargs):
        if path.startswith('interfaces/'):
            return self.interfaces.get(path)
        return super().get(path, *args, **kwargs)

    def search(self, path, *args, **kwargs):
        if path in (VLANS.search, ASSIGN + 'search_item'):
            return self.interfaces.search(path)
        return super().search(path, *args, **kwargs)

    def post(self, path, payload=None, **kwargs):
        self.events.append(path)
        if path.startswith('interfaces/'):
            return self.interfaces.post(path, payload)
        return super().post(path, payload, **kwargs)


def config():
    server = dict(SERVER, interfaces=[{'id': 'br208'}], gatewayAddress='10.208.0.1',
                  rangeStart='10.208.0.20', rangeStop='10.208.0.40')
    return {'udapi': {'interfaces': copy.deepcopy(INTERFACES), 'services': {'dhcpServers': [server]}}}


def test_interfaces_are_assigned_before_dhcp_and_retired_after_pool_removal():
    api = CombinedAPI()
    sync = UDAPIConfigSync(api, {'eth0': 'lan'}.get, lambda: ['lan'])
    summary = sync.apply_system_cfg(config())
    assert summary['vlans'] == 1 and summary['dhcp_pools'] == 1
    assert api.search(RANGES.search)[0]['interface'] == 'opt1'
    assert sync.resolve_interface('br208') == 'opt1'
    api.events.clear()
    removed = {'udapi': {'interfaces': [], 'services': {'dhcpServers': []}}}
    summary = sync.apply_system_cfg(removed)
    assert summary['retired_vlans'] == 1
    removed_pool = next(i for i, path in enumerate(api.events) if path.startswith(RANGES.delete))
    disabled_interface = next(i for i, path in enumerate(api.events) if path.startswith(ASSIGN + 'set_item/'))
    assert removed_pool < disabled_interface
    assert api.interfaces.assignments['lan']['enable'] == '1'


def test_unassigned_vlan_never_falls_back_to_parent_lan_for_dhcp():
    api = CombinedAPI()
    sync = UDAPIConfigSync(api, {'eth0': 'lan'}.get, lambda: ['lan'], options={'apply_interfaces': False})
    summary = sync.apply_system_cfg(config())
    assert sync.resolve_interface('eth0.208') is None
    assert sync.resolve_interface('br208') is None
    assert api.search(RANGES.search) == []
    assert any('interface is not assigned' in warning for warning in summary['warnings'])
    assert api.interfaces.assignments['lan']['enable'] == '1'


def collector():
    result = OPNSenseCollector.__new__(OPNSenseCollector)
    result.sync = Mock()
    result.udapi_sync = Mock()
    result._provision_lock = threading.RLock()
    result._pending_system_cfg = None
    result._provision_retry_thread = Mock()
    result._provision_retry_thread.is_alive.return_value = True
    result._state = {}
    result._save_state = Mock()
    return result


def test_transient_failure_does_not_cache_success_and_retains_retry_snapshot():
    c = collector()
    cfg = {'udapi': {'services': {}}}
    c.udapi_sync.apply_system_cfg.side_effect = [OPNsenseAPIError('temporary failure'), {'vlans': 1}]
    with pytest.raises(OPNsenseAPIError):
        c.apply_system_cfg(cfg)
    assert 'system_cfg_hash' not in c._state
    assert c._pending_system_cfg == cfg and c._pending_system_cfg is not cfg
    assert c.apply_system_cfg(cfg)
    assert c._pending_system_cfg is None
    assert c._state['system_cfg_hash']
    assert c.apply_system_cfg(cfg)
    assert c.udapi_sync.apply_system_cfg.call_count == 2


def test_new_invalid_config_cancels_an_older_pending_request():
    c = collector()
    c._pending_system_cfg = {'udapi': {'old': True}}
    c.udapi_sync.apply_system_cfg.side_effect = ValueError('invalid VLAN')
    with pytest.raises(ValueError):
        c.apply_system_cfg({'udapi': {'new': True}})
    assert c._pending_system_cfg is None
    assert 'system_cfg_hash' not in c._state


def test_latest_request_can_cancel_failed_update_and_return_to_cached_config():
    c = collector()
    first = {'udapi': {'version': 'first'}}
    c.udapi_sync.apply_system_cfg.return_value = {}
    assert c.apply_system_cfg(first)
    c.udapi_sync.apply_system_cfg.side_effect = OPNsenseAPIError('temporary failure')
    with pytest.raises(OPNsenseAPIError):
        c.apply_system_cfg({'udapi': {'version': 'second'}})
    assert c._pending_system_cfg is not None
    assert c.apply_system_cfg(first)
    assert c._pending_system_cfg is None
    assert c.udapi_sync.apply_system_cfg.call_count == 2
