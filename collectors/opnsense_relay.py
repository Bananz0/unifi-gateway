"""DHCP relay planning against OPNsense 26.7's DHCRelay model.

Relays have no description field. Ownership is therefore derived exclusively
from their reference to a tagged destination, never from an interface match.
"""
import hashlib
import ipaddress

from .opnsense_api import OPNsenseAPI, OPNsenseAPIError
from .opnsense_sync import ItemSpec, make_tag, parse_tag, _row_value


DESTINATIONS = ItemSpec('relay destination', 'dhcrelay/settings/search_dest',
                        'dhcrelay/settings/add_dest', 'dhcrelay/settings/set_dest/',
                        'dhcrelay/settings/del_dest/', 'destination', 'name')
RELAY_ROOT = 'dhcrelay/settings/'


def plan_relays(servers, resolve):
    desired = {}
    for server in servers:
        if server.get('enabled') is False or not server.get('relay'):
            continue
        body = server['relay']
        if set(body) != {'ipPair'} or not body['ipPair']:
            raise ValueError('unsupported DHCP relay settings')
        pairs = body['ipPair']
        addresses = []
        self_pairs = 0
        version = {'v4': 4, 'v6': 6}.get(server.get('ipVersion', 'v4'))
        if version is None:
            raise ValueError('unsupported DHCP relay IP version')
        for pair in pairs:
            if set(pair) != {'localIp', 'serverIp'}:
                raise ValueError('unsupported DHCP relay IP pair')
            local = ipaddress.ip_address(pair['localIp'])
            remote = ipaddress.ip_address(pair['serverIp'])
            if local.version != version or remote.version != version:
                raise ValueError('DHCP relay address family mismatch')
            if remote.is_unspecified or remote.is_multicast or remote.is_loopback:
                raise ValueError('DHCP relay destination must be a unicast server')
            if local == remote:
                self_pairs += 1
            else:
                addresses.append(str(remote))
        if self_pairs == len(pairs):
            continue
        if self_pairs:
            raise ValueError('mixed local and remote DHCP relay roles')
        interfaces = server.get('interfaces') or []
        if len(interfaces) != 1:
            raise ValueError('DHCP relay requires exactly one interface')
        interface = resolve(interfaces[0].get('id'))
        if not interface:
            raise ValueError('DHCP relay interface is not assigned')
        if not server.get('name'):
            raise ValueError('DHCP relay requires a stable name')
        key = 'relay-' + hashlib.sha256(server['name'].encode()).hexdigest()[:20]
        if key in desired or any(r['interface'] == interface for r in desired.values()):
            raise ValueError('duplicate DHCP relay name or interface')
        desired[key] = {'interface': interface, 'server': ','.join(sorted(set(addresses)))}
    return desired


def relay_inventory(sync):
    # Read raw relay records: search results replace destination UUIDs with
    # display names, which must never be used to infer ownership.
    destinations = sync.api.search(DESTINATIONS.search)
    owned = {r['uuid']: parse_tag(r.get('name')) for r in destinations
             if str(parse_tag(r.get('name')) or '').startswith('relay-')}
    relays = []
    for row in sync.api.search(RELAY_ROOT + 'search_relay'):
        detail = sync.api.get(RELAY_ROOT + 'get_relay/' + row['uuid']).get('relay')
        if not isinstance(detail, dict):
            raise OPNsenseAPIError('could not read relay configuration')
        relays.append(dict(detail, uuid=row['uuid']))
    return owned, relays


def preflight_relays(sync, desired, retiring_pools=()):
    """Check unmanaged collisions without changing either DHCP service."""
    owned, relays = relay_inventory(sync)
    for row in relays:
        if _row_value(row, 'destination') not in owned:
            if any(r['interface'] == _row_value(row, 'interface') for r in desired.values()):
                raise ValueError('unmanaged DHCP relay already uses interface')
    if desired:
        # A relay must not compete with a local DHCP server, including a
        # controller-owned pool. Role transitions require explicit cleanup.
        from .opnsense_dhcp import RANGES
        for row in sync.api.search(RANGES.search):
            if row['uuid'] in retiring_pools:
                continue
            if any(r['interface'] in _row_value(row, 'interface').split(',') for r in desired.values()):
                raise ValueError('DHCP relay conflicts with a local DHCP pool')
    return owned, relays


def sync_relays(sync, servers):
    desired = plan_relays(servers, sync.resolve_interface)
    owned, relays = preflight_relays(sync, desired)
    # configd only stops PIDs for UUIDs still present in the model. Deleting
    # an active record first leaves an orphan relay holding UDP/67 indefinitely.
    stop_relays(sync, [row for row in relays
                      if _row_value(row, 'destination') in owned
                      and owned[_row_value(row, 'destination')] not in desired])
    payloads = {key: {'name': make_tag(key), 'server': row['server']}
                for key, row in desired.items()}
    changed, uuids = sync.sync_items(DESTINATIONS, payloads, delete_stale=False)
    # Present raw values to the common comparison/tagging engine; no custom
    # ownership state file is necessary.
    class RelayAPI:
        def search(self, path):
            return relays

        def post(self, path, payload=None):
            return sync.api.post(path, payload)

    by_destination = dict(owned)
    by_destination.update({uuid: key for key, uuid in uuids.items() if uuid})
    if any(not uuid for uuid in uuids.values()):
        raise OPNsenseAPIError('relay destination API did not return UUID')
    spec = ItemSpec('DHCP relay', RELAY_ROOT + 'search_relay',
                    RELAY_ROOT + 'add_relay', RELAY_ROOT + 'set_relay/',
                    RELAY_ROOT + 'del_relay/', 'relay', 'destination',
                    key_fn=lambda row: by_destination.get(_row_value(row, 'destination')))
    from .opnsense_sync import OPNsenseConfigSync
    relay_sync = OPNsenseConfigSync(RelayAPI(), sync.port_map, sync.lan_identifiers)
    relay_changed, _ = relay_sync.sync_items(spec, {
        key: {'enabled': '1', 'interface': row['interface'],
              'destination': uuids[key], 'agent_info': '0'}
        for key, row in desired.items()})
    # Delete stale destinations only after their relays have been removed.
    deleted, _ = sync.sync_items(DESTINATIONS, payloads,
                                 keep=lambda key: not key.startswith('relay-'))
    if changed or relay_changed or deleted:
        result = sync.api.post('dhcrelay/service/reconfigure')
        if not isinstance(result, dict) or result.get('status') != 'ok':
            raise OPNsenseAPIError('DHCP relay reconfigure failed')
    return len(desired)


def stop_relays(sync, rows):
    """Disable and apply while UUIDs remain addressable, before deleting."""
    for row in rows:
        if _row_value(row, 'enabled') != '0':
            result = sync.api.post(RELAY_ROOT + 'set_relay/' + row['uuid'],
                                   {'relay': {'enabled': '0'}})
            OPNsenseAPI.check_saved(result, 'disable retiring DHCP relay')
    if rows:
        # Also retry this when records are already disabled: the previous
        # request may have saved them but failed before stopping the process.
        result = sync.api.post('dhcrelay/service/reconfigure')
        if not isinstance(result, dict) or result.get('status') != 'ok':
            raise OPNsenseAPIError('DHCP relay stop failed')
