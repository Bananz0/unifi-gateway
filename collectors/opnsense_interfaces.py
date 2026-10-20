"""Owned VLAN/interface provisioning through OPNsense 26.7.7 MVC APIs.

The controller's default switch/VLAN/bridge stack is collapsed onto an existing
LAN only when its configured addresses match. New tagged networks get separate
owned VLANs and assignments. Unmanaged interfaces are never reconfigured here.
"""
import hashlib
import ipaddress
import time

from .opnsense_api import OPNsenseAPI, OPNsenseAPIError
from .opnsense_sync import ItemSpec, OPNsenseConfigSync, _row_value, differs, make_tag, parse_tag


VLANS = ItemSpec('VLAN', 'interfaces/vlan_settings/search_item',
                 'interfaces/vlan_settings/add_item', 'interfaces/vlan_settings/set_item/',
                 'interfaces/vlan_settings/del_item/', 'vlan', 'descr')
ASSIGN = 'interfaces/assignment/'


def address_payload(body):
    result = {'type4': '', 'ipaddr': '', 'type6': '', 'ipaddrv6': ''}
    seen = set()
    for address in body.get('addresses') or []:
        version = address.get('version')
        if version not in ('v4', 'v6') or version in seen:
            raise ValueError('multiple or unknown address families require VIP translation')
        seen.add(version)
        type_key, addr_key = ('type4', 'ipaddr') if version == 'v4' else ('type6', 'ipaddrv6')
        kind = address.get('type')
        if kind == 'static':
            value = ipaddress.ip_interface(address['cidr'])
            if value.version != (4 if version == 'v4' else 6):
                raise ValueError('interface address family mismatch')
            result.update({type_key: 'staticv4' if version == 'v4' else 'staticv6', addr_key: str(value)})
        elif kind == 'dhcp' or (kind == 'dynamic' and address.get('origin') == 'dhcp'):
            if version != 'v4':
                raise ValueError('DHCPv6 requires explicit prefix-delegation translation')
            result[type_key] = 'dhcp'
        elif kind == 'dynamic' and address.get('origin') == 'slaac' and version == 'v6':
            result[type_key] = 'slaac'
        else:
            raise ValueError('unsupported interface address mode')
        if set(address) - {'version', 'type', 'cidr', 'origin'}:
            raise ValueError('unsupported interface address options')
    status = body.get('status') or {}
    enabled = status.get('enabled', True)
    if not isinstance(enabled, bool):
        raise ValueError('interface enabled state must be boolean')
    result['enable'] = '1' if enabled else '0'
    if 'mtu' in status:
        mtu = int(status['mtu'])
        if not 576 <= mtu <= 65535:
            raise ValueError('invalid interface MTU')
        result['mtu'] = str(mtu)
    return result


def compile_vlans(interfaces, port_map, overview):
    bodies = {b.get('identification', {}).get('id'): b for b in interfaces}
    aliases, desired = {}, {}

    def parent(ident, visited=()):
        if not ident or ident in visited:
            raise ValueError('cyclic or missing VLAN parent')
        mapped = port_map(ident)
        if mapped:
            return mapped
        body = bodies.get(ident) or {}
        if (body.get('identification') or {}).get('type') == 'switch':
            ports = (body.get('switch') or {}).get('ports') or []
            parents = {parent(p.get('interface', {}).get('id'), visited + (ident,))
                       for p in ports if p.get('enabled', True)}
            if len(parents) == 1:
                return next(iter(parents))
        raise ValueError('VLAN parent requires an explicit physical-port mapping')

    for ident, body in bodies.items():
        if (body.get('identification') or {}).get('type') != 'vlan':
            continue
        vlan = body.get('vlan') or {}
        if set(vlan) - {'id', 'interface'}:
            raise ValueError('unsupported VLAN options')
        tag = int(vlan['id'])
        if not 1 <= tag <= 4094:
            raise ValueError('VLAN tag must be between 1 and 4094')
        wrappers = [b for b in bodies.values() if any(
            member.get('id') == ident for member in (b.get('bridge') or {}).get('interfaces') or [])]
        if len(wrappers) > 1 or any(len(b['bridge']['interfaces']) != 1 for b in wrappers):
            raise ValueError('VLAN bridge requires full bridge-membership translation')
        if any(set(b['bridge']) - {'id', 'interfaces'} for b in wrappers):
            raise ValueError('unsupported VLAN bridge options')
        layer3 = wrappers[0] if wrappers else body
        logical_ids = [ident] + [b['identification']['id'] for b in wrappers]
        addresses = address_payload(layer3)
        # The native LAN stack is an existing resource, not a request to create
        # a tagged VLAN 1. Exact host/prefix matches avoid guessing by subnet.
        static = {addresses[k] for k in ('ipaddr', 'ipaddrv6') if addresses[k]}
        native = []
        if tag == 1 and static:
            for row in overview:
                actual = set()
                for entry in (row.get('ipv4') or []) + (row.get('ipv6') or []):
                    try:
                        actual.add(str(ipaddress.ip_interface(entry['ipaddr'])))
                    except (KeyError, ValueError):
                        pass
                if static <= actual and row.get('identifier'):
                    native.append(row['identifier'])
        if len(native) == 1:
            aliases.update({key: native[0] for key in logical_ids})
            continue
        if body.get('addresses') and wrappers:
            raise ValueError('both VLAN and bridge carry addresses')
        for candidate in (body, layer3):
            if set(candidate) - {'identification', 'vlan', 'bridge', 'addresses', 'status'}:
                raise ValueError('unsupported VLAN interface settings')
            if set(candidate.get('status') or {}) - {'enabled', 'mtu', 'comment'}:
                raise ValueError('unsupported VLAN status settings')
            if not isinstance((candidate.get('status') or {}).get('enabled', True), bool):
                raise ValueError('interface enabled state must be boolean')
        if wrappers and 'mtu' in (body.get('status') or {}):
            vlan_mtu = address_payload(body)['mtu']
            if 'mtu' in addresses and addresses['mtu'] != vlan_mtu:
                raise ValueError('distinct VLAN/bridge MTUs require separate bridge interfaces')
            addresses['mtu'] = vlan_mtu
        if (body.get('status') or {}).get('enabled') is False:
            addresses['enable'] = '0'
        key = 'vlan-' + hashlib.sha256(ident.encode()).hexdigest()[:20]
        desired[key] = {'parent': parent((vlan.get('interface') or {}).get('id')),
                        'tag': str(tag), 'addresses': addresses, 'ids': logical_ids,
                        'descr': 'ufg_' + key.replace('-', '_'),
                        'label': str((layer3.get('status') or {}).get('comment') or ident)}
    return desired, aliases


class VLANProvisioner:
    def __init__(self, api, port_map, lan_identifiers=None):
        self.api, self.port_map = api, port_map
        self.lan_identifiers = lan_identifiers
        self.sync = OPNsenseConfigSync(api, port_map, lambda: [])
        self._wanted_keys = None

    def _apply(self, path):
        result = self.api.post(path)
        if not isinstance(result, dict) or result.get('status') != 'ok':
            raise OPNsenseAPIError('interface apply failed: ' + path)

    def prepare(self, interfaces):
        self._rollback = []
        try:
            return self._prepare(interfaces)
        except Exception as error:
            self._wanted_keys = None
            try:
                self._restore_preimages()
            except Exception as restore_error:
                raise OPNsenseAPIError('%s; interface rollback failed: %s' % (
                    error, restore_error)) from error
            raise
        finally:
            self._rollback = []

    def _restore_preimages(self):
        vlans = [(uuid, payload) for kind, uuid, payload in self._rollback if kind == 'vlan']
        assignments = [(uuid, payload) for kind, uuid, payload in self._rollback if kind == 'assignment']
        for uuid, payload in vlans:
            result = self.api.post(VLANS.set + uuid, {'vlan': payload})
            OPNsenseAPI.check_saved(result, 'restore VLAN preimage')
        # NetworkInterface's legacy adapter leaves an old todo entry intact
        # when a set equals the committed configuration. Force a distinct,
        # disabled IPv6 mode first, verify the staged values, then commit and
        # restore the exact original profile in a second step. No temporary
        # address is activated and the primary LAN is never part of this list.
        for uuid, payload in assignments:
            temporary = dict(payload, enable='0', ipaddrv6='',
                             type6='' if payload.get('type6') == 'linklocal' else 'linklocal')
            result = self.api.post(ASSIGN + 'set_item/' + uuid, {'interface': temporary})
            OPNsenseAPI.check_saved(result, 'stage disabled interface rollback')
            raw = self.api.get(ASSIGN + 'get_item/' + uuid).get('interface') or {}
            if differs(raw, temporary):
                raise OPNsenseAPIError('rollback did not replace the pending interface edit')
        if vlans:
            self._apply('interfaces/vlan_settings/reconfigure')
        if assignments:
            self._apply(ASSIGN + 'reconfigure')
            for uuid, payload in assignments:
                result = self.api.post(ASSIGN + 'set_item/' + uuid, {'interface': payload})
                OPNsenseAPI.check_saved(result, 'restore interface preimage')
                raw = self.api.get(ASSIGN + 'get_item/' + uuid).get('interface') or {}
                if differs(raw, payload):
                    raise OPNsenseAPIError('restored interface profile did not stage correctly')
            self._apply(ASSIGN + 'reconfigure')
            for uuid, payload in assignments:
                raw = self.api.get(ASSIGN + 'get_item/' + uuid).get('interface') or {}
                if differs(raw, payload):
                    raise OPNsenseAPIError('restored interface profile differs after apply')

    def _prepare(self, interfaces):
        self._wanted_keys = None
        overview = self.api.get('interfaces/overview/interfaces_info')
        if isinstance(overview, dict):
            overview = overview.get('rows', [])
        if not isinstance(overview, list):
            raise OPNsenseAPIError('interface inventory unavailable')
        plans, bindings = compile_vlans(interfaces, self.port_map, overview)
        if not plans:
            self._wanted_keys = set()
            return bindings, 0
        template = self.api.get(ASSIGN + 'get_item').get('interface') or {}
        required = {'enable', 'type4', 'type6', 'ipaddr', 'ipaddrv6'}
        if not required <= template.keys():
            raise ValueError('interface addressing requires the OPNsense 26.7.7 assignment model')
        if self.api.get(ASSIGN + 'pending').get('status') != 'ok':
            raise OPNsenseAPIError('finish pending OPNsense interface changes before provisioning VLANs')
        assignments = self.api.search(ASSIGN + 'search_item')
        if any(r.get('pending_action') for r in assignments):
            raise OPNsenseAPIError('finish pending OPNsense interface changes before provisioning VLANs')
        by_identifier = {r['uuid']: r for r in assignments}
        existing = self.api.search(VLANS.search)
        owned_identifiers = {}
        for vlan in existing:
            key = parse_tag(vlan.get('descr'))
            if key in plans:
                raw = self.api.get('interfaces/vlan_settings/get_item/' + vlan['uuid']).get('vlan') or {}
                device = _row_value(raw, 'vlanif')
                if any(_row_value(r, 'if') == device and r.get('descr') != plans[key]['descr'] for r in assignments):
                    raise ValueError('managed VLAN has an unmanaged assignment')
                for assignment in assignments:
                    if _row_value(assignment, 'if') == device:
                        owned_identifiers[key] = assignment['uuid']
        planned_networks = []
        for key, plan in plans.items():
            for field in ('ipaddr', 'ipaddrv6'):
                if not plan['addresses'].get(field):
                    continue
                proposed = ipaddress.ip_interface(plan['addresses'][field])
                if proposed.ip.is_link_local:
                    continue
                for other_key, other in planned_networks:
                    if other_key != key and proposed.version == other.version and proposed.network.overlaps(other):
                        raise ValueError('requested VLAN networks overlap')
                planned_networks.append((key, proposed.network))
                for row in overview:
                    if row.get('identifier') == owned_identifiers.get(key):
                        continue
                    for entry in (row.get('ipv4') or []) + (row.get('ipv6') or []):
                        try:
                            actual = ipaddress.ip_interface(entry['ipaddr'])
                        except (KeyError, ValueError):
                            continue
                        if (not actual.ip.is_link_local and actual.version == proposed.version
                                and proposed.network.overlaps(actual.network)):
                            raise ValueError('requested VLAN subnet overlaps an existing interface')
        payloads = {}
        pairs = set()
        for key, plan in plans.items():
            if plan['parent'] == 'wan' or (self.lan_identifiers is not None
                    and plan['parent'] not in self.lan_identifiers()):
                raise ValueError('WAN VLAN provisioning requires gateway/client translation')
            row = by_identifier.get(plan['parent'])
            device = _row_value(row, 'if') if row else ''
            if not device:
                raise ValueError('VLAN physical parent is not assigned in OPNsense')
            pair = (device, plan['tag'])
            if pair in pairs:
                raise ValueError('duplicate VLAN parent/tag in controller configuration')
            pairs.add(pair)
            for vlan in existing:
                if _row_value(vlan, 'if') == device and str(vlan.get('tag')) == plan['tag'] and parse_tag(vlan.get('descr')) != key:
                    raise ValueError('an unmanaged VLAN already uses this parent/tag')
            payloads[key] = {'if': device, 'tag': plan['tag'], 'pcp': '0',
                             'proto': '802.1q', 'descr': make_tag(key, plan['label'])}
        for row in existing:
            key = parse_tag(row.get('descr'))
            if key in payloads and differs(row, payloads[key]):
                raw = self.api.get('interfaces/vlan_settings/get_item/' + row['uuid']).get('vlan') or {}
                self._rollback.append(('vlan', row['uuid'], {
                    field: _row_value(raw, field) for field in ('if', 'tag', 'pcp', 'proto', 'descr', 'vlanif')}))
        changed, uuids = self.sync.sync_items(VLANS, payloads, delete_stale=False)
        if changed:
            self._apply('interfaces/vlan_settings/reconfigure')
        assignment_changed = False
        expected = []
        for key, plan in plans.items():
            uuid = uuids[key]
            if not uuid:
                raise OPNsenseAPIError('VLAN add response has no UUID')
            raw = self.api.get('interfaces/vlan_settings/get_item/' + uuid).get('vlan') or {}
            device = _row_value(raw, 'vlanif')
            if not device:
                raise OPNsenseAPIError('VLAN device name unavailable')
            rows = self.api.search(ASSIGN + 'search_item')
            assigned = next((r for r in rows if _row_value(r, 'if') == device), None)
            if assigned is None:
                # configd caches available devices. Wait only on creation,
                # with a bounded deadline, instead of posting an invalid NIC.
                deadline = time.monotonic() + 24
                while device not in (self.api.get(ASSIGN + 'get_item').get('interface') or {}).get('if', {}):
                    if time.monotonic() >= deadline:
                        raise OPNsenseAPIError('new VLAN is not yet in the assignment inventory; retry provisioning')
                    time.sleep(2)
                result = self.api.post(ASSIGN + 'add_item', {'interface': {
                    'if': device, 'descr': plan['descr'], 'lock': '0', 'enable': '0'}})
                OPNsenseAPI.check_saved(result, 'assign VLAN')
                # Assignment add returns a temporary UUID; search returns the
                # stable optN identifier required by subsequent set/get calls.
                assigned = next((r for r in self.api.search(ASSIGN + 'search_item')
                                 if _row_value(r, 'if') == device), None)
                assignment_changed = True
            if not assigned or assigned.get('descr') != plan['descr']:
                raise ValueError('refusing to modify an unmanaged VLAN assignment')
            identifier = assigned['uuid']
            current = self.api.get(ASSIGN + 'get_item/' + identifier).get('interface') or {}
            if differs(current, plan['addresses']):
                self._rollback.append(('assignment', identifier, {
                    field: _row_value(current, field) for field in plan['addresses']}))
                result = self.api.post(ASSIGN + 'set_item/' + identifier,
                                       {'interface': plan['addresses']})
                OPNsenseAPI.check_saved(result, 'configure VLAN addresses')
                assignment_changed = True
            expected.append((identifier, plan['addresses']))
            bindings.update({name: identifier for name in plan['ids']})
        if assignment_changed:
            self._apply(ASSIGN + 'reconfigure')
        for identifier, payload in expected:
            raw = self.api.get(ASSIGN + 'get_item/' + identifier).get('interface') or {}
            if differs(raw, payload):
                raise OPNsenseAPIError('VLAN interface readback differs from requested configuration')
        self._wanted_keys = set(plans)
        return bindings, len(plans)

    def retire(self):
        """Disable removed owned networks after dependent service reconciliation.

        Assignments are retained: the vendor deletion endpoint can silently
        delete unrelated legacy firewall rules. Full safe reference auditing is
        required before automatic garbage collection may remove assignments.
        """
        if self._wanted_keys is None:
            raise ValueError('VLAN preparation must succeed before retirement')
        targets = []
        assignments = self.api.search(ASSIGN + 'search_item')
        for vlan in self.api.search(VLANS.search):
            key = parse_tag(vlan.get('descr'))
            if not str(key or '').startswith('vlan-') or key in self._wanted_keys:
                continue
            raw = self.api.get('interfaces/vlan_settings/get_item/' + vlan['uuid']).get('vlan') or {}
            device = _row_value(raw, 'vlanif')
            for row in assignments:
                if _row_value(row, 'if') != device:
                    continue
                if row.get('descr') != 'ufg_' + key.replace('-', '_'):
                    raise ValueError('stale managed VLAN has an unmanaged assignment')
                current = self.api.get(ASSIGN + 'get_item/' + row['uuid']).get('interface') or {}
                if _row_value(current, 'enable') != '0':
                    fields = ('enable', 'type4', 'ipaddr', 'type6', 'ipaddrv6', 'mtu')
                    if not set(fields[:-1]) <= current.keys():
                        raise ValueError('interface retirement requires the 26.7.7 assignment model')
                    targets.append((row['uuid'], {field: _row_value(current, field) for field in fields}))
        if not targets:
            return 0
        if self.api.get(ASSIGN + 'pending').get('status') != 'ok':
            raise OPNsenseAPIError('finish pending OPNsense interface changes before retiring VLANs')
        self._rollback = []
        try:
            for identifier, preimage in targets:
                self._rollback.append(('assignment', identifier, preimage))
                result = self.api.post(ASSIGN + 'set_item/' + identifier, {'interface': {'enable': '0'}})
                OPNsenseAPI.check_saved(result, 'disable retired VLAN')
            self._apply(ASSIGN + 'reconfigure')
            for identifier, _ in targets:
                raw = self.api.get(ASSIGN + 'get_item/' + identifier).get('interface') or {}
                if _row_value(raw, 'enable') != '0':
                    raise OPNsenseAPIError('retired VLAN remains enabled after apply')
        except Exception as error:
            try:
                self._restore_preimages()
            except Exception as restore_error:
                raise OPNsenseAPIError('%s; interface retirement rollback failed: %s' % (
                    error, restore_error)) from error
            raise
        finally:
            self._rollback = []
        return len(targets)
