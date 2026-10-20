import copy

import pytest

from collectors.opnsense_api import OPNsenseAPIError
from collectors.opnsense_dhcp import OPTIONS, RANGES
from collectors.opnsense_dhcp_roles import sync_dhcp_roles
from collectors.opnsense_relay import DESTINATIONS
from tests.test_opnsense_dhcp import SERVER, setup
from tests.test_opnsense_relay import RELAYS, REMOTE, RelayAPI


def context():
    _, sync = setup()
    sync.api = api = RelayAPI()
    return api, sync


def first(posts, prefix):
    return next(i for i, path in enumerate(posts) if path.startswith(prefix))


def test_server_to_relay_stops_dnsmasq_before_creating_relay():
    api, sync = context()
    sync_dhcp_roles(sync, [SERVER])
    api.posts.clear()
    assert sync_dhcp_roles(sync, [REMOTE]) == {'dhcp_relays': 1, 'dhcp_pools': 0}
    assert api.search(RANGES.search) == api.search(OPTIONS.search) == []
    assert len(api.search(RELAYS.search)) == 1
    assert first(api.posts, RANGES.delete) < first(api.posts, 'dnsmasq/service/reconfigure')
    assert first(api.posts, 'dnsmasq/service/reconfigure') < first(api.posts, RELAYS.add)
    api.posts.clear()
    sync_dhcp_roles(sync, [REMOTE])
    assert api.posts == []


def test_relay_to_server_stops_relay_before_creating_pool():
    api, sync = context()
    sync_dhcp_roles(sync, [REMOTE])
    api.posts.clear()
    sync_dhcp_roles(sync, [SERVER])
    assert api.search(RELAYS.search) == api.search(DESTINATIONS.search) == []
    assert len(api.search(RANGES.search)) == 1
    assert first(api.posts, RELAYS.set) < first(api.posts, 'dhcrelay/service/reconfigure')
    assert first(api.posts, 'dhcrelay/service/reconfigure') < first(api.posts, RELAYS.delete)
    assert first(api.posts, 'dhcrelay/service/reconfigure') < first(api.posts, RANGES.add)


@pytest.mark.parametrize('role,collection', [(SERVER, RELAYS), (REMOTE, RANGES)])
def test_manual_conflicts_are_rejected_before_any_service_write(role, collection):
    api, sync = context()
    api.store[collection.search] = {'manual': {'interface': 'opt5', 'description': 'manual',
                                             'destination': 'not-owned'}}
    original = copy.deepcopy(api.store)
    with pytest.raises(ValueError):
        sync_dhcp_roles(sync, [role])
    assert api.posts == [] and api.store == original


@pytest.mark.parametrize('old,new,service,new_spec', [
    (SERVER, REMOTE, 'dnsmasq', RELAYS), (REMOTE, SERVER, 'dhcrelay', RANGES),
])
def test_failed_stop_is_retried_before_opposite_role_start(old, new, service, new_spec):
    api, sync = context()
    sync_dhcp_roles(sync, [old])
    post = api.post
    fail_path = service + '/service/reconfigure'

    def fail(path, payload=None, **kwargs):
        if path == fail_path:
            api.posts.append(path)
            return {'status': 'failed'}
        return post(path, payload, **kwargs)

    api.post = fail
    api.posts.clear()
    with pytest.raises(OPNsenseAPIError, match='reconfigure failed'):
        sync_dhcp_roles(sync, [new])
    assert new_spec.add not in api.posts
    api.posts.clear()
    # The old records are already deleted, but the running service has not
    # acknowledged that deletion. The retry must still stop it first.
    with pytest.raises(OPNsenseAPIError):
        sync_dhcp_roles(sync, [new])
    assert fail_path in api.posts and new_spec.add not in api.posts
    api.post = post
    api.posts.clear()
    sync_dhcp_roles(sync, [new])
    assert first(api.posts, fail_path) < first(api.posts, new_spec.add)
    assert sync.api is api


def test_new_process_applies_saved_configuration_even_when_no_objects_change():
    api, sync = context()
    sync_dhcp_roles(sync, [SERVER])
    _, restarted = setup()
    restarted.api = api
    api.posts.clear()
    sync_dhcp_roles(restarted, [SERVER])
    assert api.posts == ['dnsmasq/service/reconfigure', 'dhcrelay/service/reconfigure']
    api.posts.clear()
    sync_dhcp_roles(restarted, [SERVER])
    assert api.posts == []


def test_success_response_with_dead_dnsmasq_is_not_accepted_or_cached():
    api, sync = context()
    api.gets['dnsmasq/service/status'] = {'status': 'stopped'}
    for attempt in range(2):
        with pytest.raises(OPNsenseAPIError, match='did not start'):
            sync_dhcp_roles(sync, [SERVER])
        assert sync.api is api
        assert 'dnsmasq' in sync._dhcp_pending_services
    api.gets['dnsmasq/service/status'] = {'status': 'running'}
    sync_dhcp_roles(sync, [SERVER])
    assert sync._dhcp_pending_services == set()


def test_both_roles_in_one_request_are_rejected_before_writes():
    api, sync = context()
    with pytest.raises(ValueError, match='cannot share'):
        sync_dhcp_roles(sync, [SERVER, dict(REMOTE, name='relay')])
    assert api.posts == []


def test_mixed_roles_require_strict_binding_without_modifying_global_settings():
    api, sync = context()
    api.store[RANGES.search] = {'manual': {'interface': 'lan', 'description': 'manual',
                                         'start_addr': '192.168.1.100'}}
    api.gets['dnsmasq/settings/get']['dnsmasq']['strictbind'] = '0'
    with pytest.raises(ValueError, match='strict interface binding'):
        sync_dhcp_roles(sync, [REMOTE])
    assert api.posts == []


def test_lost_delete_response_still_stops_saved_old_role_on_retry():
    api, sync = context()
    sync_dhcp_roles(sync, [SERVER])
    post = api.post

    def lost_response(path, payload=None, **kwargs):
        result = post(path, payload, **kwargs)
        if path.startswith(RANGES.delete):
            raise OPNsenseAPIError('connection lost after deleting range')
        return result

    api.post = lost_response
    with pytest.raises(OPNsenseAPIError, match='connection lost'):
        sync_dhcp_roles(sync, [REMOTE])
    assert not api.search(RANGES.search)
    assert not api.search(RELAYS.search)
    api.post = post
    api.posts.clear()
    sync_dhcp_roles(sync, [REMOTE])
    assert first(api.posts, 'dnsmasq/service/reconfigure') < first(api.posts, RELAYS.add)


def test_unrelated_manual_services_survive_both_role_transitions():
    api, sync = context()
    api.store[RANGES.search] = {'manual-pool': {'interface': 'lan', 'description': 'manual'}}
    api.store[RELAYS.search] = {'manual-relay': {'interface': 'opt6', 'destination': 'manual-dest'}}
    api.store[DESTINATIONS.search] = {'manual-dest': {'name': 'manual', 'server': '10.40.0.1'}}
    for request in ([SERVER], [REMOTE], [SERVER], []):
        sync_dhcp_roles(sync, request)
        assert api.store[RANGES.search]['manual-pool']['description'] == 'manual'
        assert api.store[RELAYS.search]['manual-relay']['destination'] == 'manual-dest'
        assert api.store[DESTINATIONS.search]['manual-dest']['server'] == '10.40.0.1'
