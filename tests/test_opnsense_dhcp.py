import copy

import pytest

from collectors.opnsense_dhcp import OPTIONS, RANGES, plan_servers, sync_servers
from collectors.opnsense_udapi import UDAPIConfigSync
from tests.test_opnsense_sync import FakeAPI


SERVER = {'name': 'guest', 'enabled': True, 'interfaces': [{'id': 'br1'}],
          'ipVersion': 'v4', 'gatewayAddress': '10.20.0.1', 'ipv4Netmask': 24,
          'rangeStart': '10.20.0.20', 'rangeStop': '10.20.0.200',
          'leaseTime': 7200, 'dnsServers': ['1.1.1.1'], 'domain': 'guest.home'}


class DHCPAPI(FakeAPI):
    def __init__(self):
        super().__init__()
        self.gets['dnsmasq/settings/get'] = {'dnsmasq': {
            'enable': '1', 'strictbind': '1', 'interface': '', 'port': '53053',
            'dhcp': {'no_interface': ''}}}
        self.gets['dnsmasq/service/status'] = {'status': 'running'}

    def post(self, path, payload=None, **kwargs):
        if path == 'dnsmasq/settings/set':
            self.posts.append(path)
            self.gets['dnsmasq/settings/get']['dnsmasq'].update(payload['dnsmasq'])
            return {'result': 'saved'}
        return super().post(path, payload, **kwargs)

    def _spec_for(self, path):
        for spec in (RANGES, OPTIONS):
            if path == spec.add or path.startswith((spec.set, spec.delete)):
                return spec
        return super()._spec_for(path)


def setup():
    api = DHCPAPI()
    sync = UDAPIConfigSync(api, {'br1': 'opt5'}.get, lambda: ['lan'])
    sync.resolve_interface = {'br1': 'opt5'}.get
    return api, sync


def test_pool_options_idempotence_and_removal():
    api, sync = setup()
    assert sync_servers(sync, [SERVER]) == 1
    pool = api.search(RANGES.search)[0]
    assert pool['subnet_mask'] == '255.255.255.0'
    assert pool['lease_time'] == '7200'
    assert {r['option']: r['value'] for r in api.search(OPTIONS.search)} == {
        '3': '10.20.0.1', '6': '1.1.1.1'}
    api.posts.clear()
    sync_servers(sync, [SERVER])
    assert api.posts == []
    sync_servers(sync, [])
    assert api.search(RANGES.search) == []
    assert api.search(OPTIONS.search) == []


@pytest.mark.parametrize('change', [
    {'rangeStart': '10.19.0.20'}, {'rangeStop': '10.20.0.255'},
    {'rangeStart': '10.20.0.1'}, {'rangeStart': '10.20.0.201'},
    {'dnsServers': ['bad']}, {'leaseTime': 30}, {'ipVersion': 'v6'},
    {'mysteryOption': True}, {'interfaces': [{'id': 'unknown'}]},
])
def test_invalid_section_has_no_writes(change):
    api, sync = setup()
    invalid = dict(SERVER, **change)
    with pytest.raises((ValueError, KeyError)):
        sync_servers(sync, [SERVER, invalid])
    assert api.posts == []


def test_unmanaged_pool_is_preserved_and_prevents_competing_options():
    api, sync = setup()
    original = {'interface': 'opt5', 'start_addr': '10.20.0.210',
                'end_addr': '10.20.0.220', 'description': 'manual'}
    api.store[RANGES.search] = {'manual': copy.deepcopy(original)}
    with pytest.raises(ValueError, match='unmanaged DHCP pool'):
        sync_servers(sync, [SERVER])
    assert api.posts == []
    assert api.store[RANGES.search]['manual'] == original


def test_global_manual_dns_option_prevents_override():
    api, sync = setup()
    api.store[OPTIONS.search] = {'manual': {'option': '6', 'interface': '',
                                          'description': 'manual DNS'}}
    with pytest.raises(ValueError, match='unmanaged DHCP option'):
        sync_servers(sync, [SERVER])
    assert api.posts == []


def test_self_relay_does_not_create_relay_or_pool():
    api, sync = setup()
    server = {'name': 'local', 'enabled': True,
              'relay': {'ipPair': [{'localIp': '10.20.0.1', 'serverIp': '10.20.0.1'}]}}
    assert sync_servers(sync, [server]) == 0
    assert api.posts == []


def test_remote_relay_is_not_created_as_a_local_pool():
    api, sync = setup()
    assert sync_servers(sync, [dict(SERVER, relay={'ipPair': [
        {'localIp': '10.20.0.1', 'serverIp': '10.30.0.1'}]})]) == 0
    assert api.posts == []


def test_multiple_pools_cannot_leak_interface_options():
    other = dict(SERVER, name='other', rangeStart='10.20.0.210', rangeStop='10.20.0.220')
    with pytest.raises(ValueError, match='range-specific'):
        plan_servers([SERVER, other], {'br1': 'opt5'}.get)


def test_disabled_pool_removes_only_controller_owned_objects():
    api, sync = setup()
    sync_servers(sync, [SERVER])
    api.store[RANGES.search]['manual'] = {'interface': 'lan', 'description': 'manual'}
    sync_servers(sync, [dict(SERVER, enabled=False)])
    assert list(api.store[RANGES.search]) == ['manual']


def test_local_pool_refuses_existing_relay():
    from tests.test_opnsense_relay import RelayAPI, RELAYS
    _, sync = setup()
    sync.api = api = RelayAPI()
    api.store[RELAYS.search] = {'existing': {'interface': 'opt5', 'destination': 'd'}}
    with pytest.raises(ValueError, match='existing relay'):
        sync_servers(sync, [SERVER])
    assert api.posts == []


def test_managed_vlan_is_added_to_explicit_listeners_without_changing_dns_port():
    api, sync = setup()
    api.gets['dnsmasq/settings/get']['dnsmasq']['interface'] = 'lan'
    api.gets['interfaces/assignment/get_item/opt5'] = {'interface': {'descr': 'ufg_vlan_example'}}
    sync_servers(sync, [SERVER])
    assert api.gets['dnsmasq/settings/get']['dnsmasq']['interface'] == 'lan,opt5'
    assert api.gets['dnsmasq/settings/get']['dnsmasq']['port'] == '53053'
    api.posts.clear()
    sync_servers(sync, [SERVER])
    assert api.posts == []


def test_unmanaged_listener_scope_or_explicit_dhcp_exclusion_is_not_overridden():
    api, sync = setup()
    api.gets['dnsmasq/settings/get']['dnsmasq']['interface'] = 'lan'
    with pytest.raises(ValueError, match='managed VLAN'):
        sync_servers(sync, [SERVER])
    assert api.posts == []
    api.gets['dnsmasq/settings/get']['dnsmasq']['interface'] = ''
    api.gets['dnsmasq/settings/get']['dnsmasq']['dhcp']['no_interface'] = 'opt5'
    with pytest.raises(ValueError, match='explicitly disabled'):
        sync_servers(sync, [SERVER])
    assert api.posts == []
