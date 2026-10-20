import pytest

from collectors.opnsense_relay import DESTINATIONS, RELAY_ROOT, plan_relays, sync_relays
from collectors.opnsense_sync import ItemSpec
from tests.test_opnsense_dhcp import DHCPAPI, SERVER, setup


RELAYS = ItemSpec('DHCP relay', RELAY_ROOT + 'search_relay',
                  RELAY_ROOT + 'add_relay', RELAY_ROOT + 'set_relay/',
                  RELAY_ROOT + 'del_relay/', 'relay', 'destination')
REMOTE = dict(SERVER, relay={'ipPair': [
    {'localIp': '10.20.0.1', 'serverIp': '10.30.0.1'}]})


class RelayAPI(DHCPAPI):
    def _spec_for(self, path):
        for spec in (DESTINATIONS, RELAYS):
            if path == spec.add or path.startswith((spec.set, spec.delete)):
                return spec
        return super()._spec_for(path)

    def get(self, path, **kwargs):
        if path.startswith(RELAY_ROOT + 'get_relay/'):
            row = self.store.get(RELAYS.search, {}).get(path.rsplit('/', 1)[-1])
            return {'relay': row} if row else {}
        return super().get(path, **kwargs)


def test_relay_lifecycle_preserves_unmanaged_objects():
    _, sync = setup()
    sync.api = api = RelayAPI()
    api.store[DESTINATIONS.search] = {'manual-dest': {'name': 'manual', 'server': '10.40.0.1'}}
    api.store[RELAYS.search] = {'manual': {'destination': 'manual-dest', 'interface': 'opt6',
                                         'enabled': '1', 'agent_info': '0'}}
    assert sync_relays(sync, [REMOTE]) == 1
    assert len(api.search(RELAYS.search)) == 2
    assert api.posts[-1] == 'dhcrelay/service/reconfigure'
    api.posts.clear()
    sync_relays(sync, [REMOTE])
    assert api.posts == []
    sync_relays(sync, [])
    assert list(api.store[RELAYS.search]) == ['manual']
    assert list(api.store[DESTINATIONS.search]) == ['manual-dest']
    relay_delete = next(i for i, p in enumerate(api.posts) if p.startswith(RELAYS.delete))
    destination_delete = next(i for i, p in enumerate(api.posts) if p.startswith(DESTINATIONS.delete))
    assert relay_delete < destination_delete


def test_existing_unmanaged_relay_prevents_duplicate():
    _, sync = setup()
    sync.api = api = RelayAPI()
    api.store[RELAYS.search] = {'manual': {'destination': 'manual', 'interface': 'opt5'}}
    with pytest.raises(ValueError, match='unmanaged'):
        sync_relays(sync, [REMOTE])
    assert api.posts == []


def test_relay_cannot_compete_with_local_dnsmasq():
    from collectors.opnsense_dhcp import RANGES
    _, sync = setup()
    sync.api = api = RelayAPI()
    api.store[RANGES.search] = {'manual': {'interface': 'opt5'}}
    with pytest.raises(ValueError, match='local DHCP pool'):
        sync_relays(sync, [REMOTE])
    assert api.posts == []


@pytest.mark.parametrize('pairs', [
    [{'localIp': '10.20.0.1', 'serverIp': '::1'}],
    [{'localIp': '10.20.0.1', 'serverIp': '224.0.0.1'}],
    [{'localIp': '10.20.0.1', 'serverIp': '127.0.0.1'}],
    [{'localIp': '10.20.0.1', 'serverIp': '10.20.0.1'},
     {'localIp': '10.20.0.1', 'serverIp': '10.30.0.1'}],
    [],
])
def test_invalid_relay_settings_fail_closed(pairs):
    with pytest.raises(ValueError):
        plan_relays([dict(REMOTE, relay={'ipPair': pairs})], {'br1': 'opt5'}.get)


def test_ipv6_relay_destination_family():
    server = dict(REMOTE, ipVersion='v6', relay={'ipPair': [
        {'localIp': 'fd00:20::1', 'serverIp': 'fd00:30::1'}]})
    rows = plan_relays([server], {'br1': 'opt5'}.get)
    assert next(iter(rows.values()))['server'] == 'fd00:30::1'
