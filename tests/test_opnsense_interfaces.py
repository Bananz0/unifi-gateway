import copy

import pytest

from collectors.opnsense_api import OPNsenseAPIError
from collectors.opnsense_interfaces import ASSIGN, VLANS, VLANProvisioner, address_payload


INTERFACES = [
    {'identification': {'id': 'eth0', 'type': 'ethernet'}},
    {'identification': {'id': 'eth0.208', 'type': 'vlan'},
     'vlan': {'id': 208, 'interface': {'id': 'eth0'}}, 'status': {'enabled': True}},
    {'identification': {'id': 'br208', 'type': 'bridge'},
     'bridge': {'id': 208, 'interfaces': [{'id': 'eth0.208'}]},
     'addresses': [{'type': 'static', 'version': 'v4', 'cidr': '10.208.0.1/24'},
                   {'type': 'static', 'version': 'v6', 'cidr': 'fd00:208::1/64'}],
     'status': {'enabled': True, 'mtu': 1500, 'comment': 'Guest'}}]


class InterfaceAPI:
    def __init__(self):
        self.vlans = {}
        self.assignments = {'lan': {'if': 'vtnet1', 'descr': 'LAN', 'enable': '1',
            'type4': 'staticv4', 'ipaddr': '192.168.1.1/24', 'type6': '', 'ipaddrv6': '', 'mtu': ''}}
        self.posts = []
        self.full_model = True
        self.fail_apply_once = False

    def search(self, path):
        if path == VLANS.search:
            return [dict(v, uuid=k, vlanif=v['vlanif'] + ' [display name]') for k, v in self.vlans.items()]
        assert path == ASSIGN + 'search_item'
        return [dict(v, uuid=k) for k, v in self.assignments.items()]

    def get(self, path):
        if path == ASSIGN + 'pending':
            return {'status': 'ok'}
        if path == 'interfaces/overview/interfaces_info':
            return [{'identifier': 'lan', 'ipv4': [{'ipaddr': '192.168.1.1/24'}]}]
        if path.startswith('interfaces/vlan_settings/get_item/'):
            return {'vlan': copy.deepcopy(self.vlans[path.rsplit('/', 1)[-1]])}
        if path == ASSIGN + 'get_item':
            fields = {'if': {v['vlanif']: {} for v in self.vlans.values()}}
            if self.full_model:
                fields.update({key: '' for key in ('type4', 'type6', 'ipaddr', 'ipaddrv6', 'enable')})
            return {'interface': fields}
        assert path.startswith(ASSIGN + 'get_item/')
        return {'interface': copy.deepcopy(self.assignments[path.rsplit('/', 1)[-1]])}

    def post(self, path, payload=None):
        self.posts.append((path, copy.deepcopy(payload)))
        if path.endswith('/reconfigure'):
            if path == ASSIGN + 'reconfigure' and self.fail_apply_once:
                self.fail_apply_once = False
                return {'status': 'failed'}
            return {'status': 'ok'}
        if path == VLANS.add:
            uuid = 'v' + str(len(self.vlans) + 1)
            self.vlans[uuid] = dict(payload['vlan'], vlanif='vlan0' + str(len(self.vlans) + 1))
            return {'result': 'saved', 'uuid': uuid}
        if path.startswith(VLANS.set):
            self.vlans[path[len(VLANS.set):]].update(payload['vlan'])
            return {'result': 'saved'}
        if path == ASSIGN + 'add_item':
            identifier = 'opt' + str(len(self.assignments))
            self.assignments[identifier] = dict(type4='', type6='', ipaddr='', ipaddrv6='', mtu='',
                                                **payload['interface'])
            return {'result': 'saved', 'uuid': 'temporary-uuid-not-the-identifier'}
        assert path.startswith(ASSIGN + 'set_item/')
        self.assignments[path.rsplit('/', 1)[-1]].update(payload['interface'])
        return {'result': 'saved'}


def provisioner():
    api = InterfaceAPI()
    return api, VLANProvisioner(api, {'eth0': 'lan'}.get)


def test_create_dual_stack_vlan_uses_stable_assignment_and_preserves_lan():
    api, sync = provisioner()
    before = copy.deepcopy(api.assignments['lan'])
    bindings, count = sync.prepare(copy.deepcopy(INTERFACES))
    assert bindings == {'eth0.208': 'opt1', 'br208': 'opt1'} and count == 1
    row = api.assignments['opt1']
    assert row['ipaddr'] == '10.208.0.1/24'
    assert row['ipaddrv6'] == 'fd00:208::1/64'
    assert row['mtu'] == '1500' and row['enable'] == '1'
    assert api.assignments['lan'] == before
    api.posts.clear()
    sync.prepare(copy.deepcopy(INTERFACES))
    assert api.posts == []  # search's decorated vlanif never causes an update


def test_existing_native_switch_vlan_bridge_is_collapsed_without_writes():
    api, sync = provisioner()
    interfaces = copy.deepcopy(INTERFACES)
    interfaces[1]['vlan']['id'] = 1
    interfaces[2]['addresses'] = [{'version': 'v4', 'type': 'static', 'cidr': '192.168.1.1/24'}]
    bindings, count = sync.prepare(interfaces)
    assert bindings == {'eth0.208': 'lan', 'br208': 'lan'} and count == 0
    assert api.posts == []


def test_old_assignment_model_rejected_before_creating_vlan():
    api, sync = provisioner()
    api.full_model = False
    with pytest.raises(ValueError, match='26.7.7'):
        sync.prepare(INTERFACES)
    assert api.posts == []


def test_unmanaged_vlan_collision_is_not_adopted():
    api, sync = provisioner()
    api.vlans['manual'] = {'if': 'vtnet1', 'tag': '208', 'descr': 'manual', 'vlanif': 'vlan10'}
    with pytest.raises(ValueError, match='unmanaged VLAN'):
        sync.prepare(INTERFACES)
    assert api.posts == []


def test_unmanaged_assignment_is_detected_before_vlan_edit():
    api, sync = provisioner()
    sync.prepare(INTERFACES)
    api.assignments['opt1']['descr'] = 'manual takeover'
    changed = copy.deepcopy(INTERFACES)
    changed[1]['vlan']['id'] = 209
    api.posts.clear()
    with pytest.raises(ValueError, match='unmanaged assignment'):
        sync.prepare(changed)
    assert api.posts == []


def test_apply_failure_restores_owned_vlan_and_l3_preimages():
    api, sync = provisioner()
    sync.prepare(INTERFACES)
    before_vlans, before_assignments = copy.deepcopy(api.vlans), copy.deepcopy(api.assignments)
    changed = copy.deepcopy(INTERFACES)
    changed[1]['vlan']['id'] = 209
    changed[2]['addresses'][0]['cidr'] = '10.209.0.1/24'
    api.fail_apply_once = True
    with pytest.raises(OPNsenseAPIError, match='apply failed'):
        sync.prepare(changed)
    assert api.vlans == before_vlans
    assert api.assignments == before_assignments
    with pytest.raises(ValueError, match='preparation must succeed'):
        sync.retire()


def test_new_assignment_stays_disabled_after_failed_apply():
    api, sync = provisioner()
    api.fail_apply_once = True
    with pytest.raises(OPNsenseAPIError):
        sync.prepare(INTERFACES)
    assert api.assignments['opt1']['enable'] == '0'
    assert api.assignments['opt1']['ipaddr'] == ''


def test_removed_owned_network_is_disabled_without_deleting_legacy_rules():
    api, sync = provisioner()
    sync.prepare(INTERFACES)
    sync.prepare([])
    assert sync.retire() == 1
    assert api.assignments['opt1']['enable'] == '0'
    assert api.assignments['lan']['enable'] == '1'
    assert len(api.vlans) == 1
    assert not any('/del_item/' in path for path, _ in api.posts)
    api.posts.clear()
    assert sync.retire() == 0
    assert api.posts == []


@pytest.mark.parametrize('address', [
    {'type': 'static', 'version': 'v4', 'cidr': 'fd00::1/64'},
    {'type': 'dynamic', 'version': 'v6', 'origin': 'dhcp'},
    {'type': 'static', 'version': 'v4', 'cidr': '10.20.0.1/24', 'unknown': True},
])
def test_unsupported_address_semantics_fail_closed(address):
    with pytest.raises(ValueError):
        address_payload({'addresses': [address]})


def test_multiple_primary_addresses_require_vips():
    with pytest.raises(ValueError, match='multiple'):
        address_payload({'addresses': [{'type': 'static', 'version': 'v4', 'cidr': ip}
                                      for ip in ['10.20.0.1/24', '10.21.0.1/24']]})


def test_unknown_vlan_fields_do_not_disappear():
    api, sync = provisioner()
    interfaces = copy.deepcopy(INTERFACES)
    interfaces[1]['vlan']['qinq'] = True
    with pytest.raises(ValueError, match='unsupported VLAN options'):
        sync.prepare(interfaces)
    assert api.posts == []


class PendingInterfaceAPI(InterfaceAPI):
    """Model the vendor adapter's committed config plus separate todo file."""
    def __init__(self):
        super().__init__()
        self.pending = {}

    def get(self, path):
        if path == ASSIGN + 'pending':
            return {'status': 'pending' if self.pending else 'ok'}
        if path.startswith(ASSIGN + 'get_item/'):
            identifier = path.rsplit('/', 1)[-1]
            return {'interface': copy.deepcopy(self.pending.get(identifier, self.assignments[identifier]))}
        return super().get(path)

    def post(self, path, payload=None):
        if path.startswith(ASSIGN + 'set_item/'):
            self.posts.append((path, copy.deepcopy(payload)))
            identifier = path.rsplit('/', 1)[-1]
            merged = dict(self.pending.get(identifier, self.assignments[identifier]), **payload['interface'])
            if merged != self.assignments[identifier]:
                self.pending[identifier] = merged
            # Deliberately do not clear a previous todo when equal to the
            # committed state: this is the failure observed on real 26.7.7.
            return {'result': 'saved'}
        if path == ASSIGN + 'reconfigure':
            self.posts.append((path, copy.deepcopy(payload)))
            if self.fail_apply_once:
                self.fail_apply_once = False
                return {'status': 'failed'}
            self.assignments.update(self.pending)
            self.pending.clear()
            return {'status': 'ok'}
        return super().post(path, payload)


def test_rollback_replaces_vendor_pending_edit_even_when_preimage_matches_committed_state():
    api = PendingInterfaceAPI()
    sync = VLANProvisioner(api, {'eth0': 'lan'}.get)
    sync.prepare(INTERFACES)
    before = copy.deepcopy(api.assignments)
    changed = copy.deepcopy(INTERFACES)
    changed[2]['addresses'][0]['cidr'] = '10.218.0.1/24'
    api.fail_apply_once = True
    with pytest.raises(OPNsenseAPIError, match='apply failed'):
        sync.prepare(changed)
    assert api.assignments == before
    assert api.pending == {}


def test_unrelated_pending_interface_change_prevents_global_apply():
    api = PendingInterfaceAPI()
    api.pending['lan'] = dict(api.assignments['lan'], ipaddr='192.168.9.1/24')
    sync = VLANProvisioner(api, {'eth0': 'lan'}.get)
    with pytest.raises(OPNsenseAPIError, match='pending OPNsense'):
        sync.prepare(INTERFACES)
    assert api.posts == []


def test_retirement_cannot_commit_an_unrelated_pending_lan_change():
    api = PendingInterfaceAPI()
    sync = VLANProvisioner(api, {'eth0': 'lan'}.get)
    sync.prepare(INTERFACES)
    sync.prepare([])
    api.pending['lan'] = dict(api.assignments['lan'], ipaddr='192.168.9.1/24')
    api.posts.clear()
    with pytest.raises(OPNsenseAPIError, match='pending OPNsense'):
        sync.retire()
    assert api.posts == []
    assert api.assignments['opt1']['enable'] == '1'


def test_failed_retirement_restores_original_active_profile_and_clears_todo():
    api = PendingInterfaceAPI()
    sync = VLANProvisioner(api, {'eth0': 'lan'}.get)
    sync.prepare(INTERFACES)
    before = copy.deepcopy(api.assignments)
    sync.prepare([])
    api.fail_apply_once = True
    with pytest.raises(OPNsenseAPIError):
        sync.retire()
    assert api.assignments == before
    assert api.pending == {}


@pytest.mark.parametrize('change', ['bridge_option', 'conflicting_mtu', 'invalid_enabled'])
def test_bridge_and_vlan_constraints_are_not_silently_dropped(change):
    api, sync = provisioner()
    cfg = copy.deepcopy(INTERFACES)
    if change == 'bridge_option':
        cfg[2]['bridge']['stp'] = True
    elif change == 'conflicting_mtu':
        cfg[1]['status']['mtu'] = 1400
    else:
        cfg[1]['status']['enabled'] = 'false'
    with pytest.raises(ValueError):
        sync.prepare(cfg)
    assert api.posts == []


def test_native_lan_address_edit_cannot_accidentally_create_a_duplicate_tagged_lan():
    api, sync = provisioner()
    cfg = copy.deepcopy(INTERFACES)
    cfg[1]['vlan']['id'] = 1
    cfg[2]['addresses'] = [{'type': 'static', 'version': 'v4', 'cidr': '192.168.1.254/24'}]
    with pytest.raises(ValueError, match='overlaps an existing interface'):
        sync.prepare(cfg)
    assert api.posts == []


def test_new_tagged_network_cannot_duplicate_an_existing_lan_subnet():
    api, sync = provisioner()
    cfg = copy.deepcopy(INTERFACES)
    cfg[2]['addresses'][0]['cidr'] = '192.168.1.1/24'
    with pytest.raises(ValueError, match='overlaps an existing interface'):
        sync.prepare(cfg)
    assert api.posts == []


def test_wan_vlan_is_not_configured_as_a_lan_without_gateway_translation():
    api = InterfaceAPI()
    api.assignments['wan'] = dict(api.assignments['lan'], **{'if': 'vtnet0', 'descr': 'WAN'})
    sync = VLANProvisioner(api, {'eth0': 'wan'}.get, lambda: ['lan'])
    with pytest.raises(ValueError, match='WAN VLAN'):
        sync.prepare(INTERFACES)
    assert api.posts == []
