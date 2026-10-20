"""Translate authoritative UXG DHCP pools into scoped Dnsmasq objects.

Planning validates the complete section before writes. Unmanaged ranges and
options are never adopted, overwritten, or competed with implicitly.
"""
import hashlib
import ipaddress

from .opnsense_sync import ItemSpec, make_tag, parse_tag, _row_value
from .opnsense_api import OPNsenseAPI, OPNsenseAPIError


def _spec(kind, wrapper):
    root = 'dnsmasq/settings/'
    return ItemSpec('Dnsmasq ' + kind, root + 'search_' + kind,
                    root + 'add_' + kind, root + 'set_' + kind + '/',
                    root + 'del_' + kind + '/', wrapper, 'description')


RANGES = _spec('range', 'range')
OPTIONS = _spec('option', 'option')
SERVER_KEYS = {'name', 'enabled', 'interfaces', 'ipVersion', 'gatewayAddress',
               'ipv4Netmask', 'rangeStart', 'rangeStop', 'leaseTime',
               'dnsServers', 'domain', 'staticLeases', 'relay'}


def plan_servers(servers, resolve):
    ranges, options = {}, {}
    for server in servers:
        name = str(server.get('name') or '')
        key = 'pool-' + hashlib.sha256(name.encode()).hexdigest()[:20]
        if not name:
            raise ValueError('DHCP server requires a stable name')
        if set(server) - SERVER_KEYS:
            raise ValueError('unsupported DHCP fields: ' + ','.join(sorted(set(server) - SERVER_KEYS)))
        if server.get('enabled') is False:
            continue
        if server.get('relay'):
            # The controller also emits local-IP -> same local-IP "relays"
            # for externally managed DHCP. They must not enable a real relay.
            from .opnsense_relay import plan_relays
            plan_relays([server], resolve)
            continue
        if server.get('ipVersion', 'v4') != 'v4':
            raise ValueError('IPv6 DHCP pools are not translated by the IPv4 backend')
        interfaces = server.get('interfaces') or []
        if len(interfaces) != 1:
            raise ValueError('DHCP pool requires exactly one interface')
        interface = resolve(interfaces[0].get('id'))
        if not interface:
            raise ValueError('DHCP pool interface is not assigned')
        gateway = ipaddress.IPv4Address(server['gatewayAddress'])
        network = ipaddress.IPv4Network('%s/%s' % (gateway, server['ipv4Netmask']), strict=False)
        start, stop = (ipaddress.IPv4Address(server[k]) for k in ('rangeStart', 'rangeStop'))
        if (start not in network or stop not in network or start > stop
                or start <= network.network_address or stop >= network.broadcast_address
                or start <= gateway <= stop):
            raise ValueError('DHCP range is invalid or contains the gateway')
        lease = int(server.get('leaseTime', 86400))
        if lease < 120:
            raise ValueError('DHCP lease must be at least 120 seconds')
        domain = str(server.get('domain') or '')
        if any(c in domain for c in ',\r\n '):
            raise ValueError('invalid DHCP domain')
        if key in ranges:
            raise ValueError('duplicate DHCP server name')
        for row in ranges.values():
            if row['interface'] == interface:
                raise ValueError('multiple DHCP pools on one interface need range-specific option tags')
        ranges[key] = {'interface': interface, 'start_addr': str(start),
                       'end_addr': str(stop), 'subnet_mask': str(network.netmask),
                       'lease_time': str(lease), 'domain_type': 'range',
                       'domain': domain, 'description': make_tag(key, name)}
        dns = [str(ipaddress.IPv4Address(ip)) for ip in server.get('dnsServers') or []]
        for code, value in ((3, str(gateway)), (6, ','.join(dns))):
            # An empty option 6 intentionally suppresses Dnsmasq's implicit
            # advertisement of itself when the controller supplies no DNS.
            option_key = key + '-o' + str(code)
            options[option_key] = {'type': 'set', 'option': str(code),
                                   'option6': '', 'interface': interface,
                                   'value': value, 'force': '0',
                                   'description': make_tag(option_key, name)}
    return ranges, options


def sync_servers(sync, servers):
    """Apply a complete, prevalidated IPv4 section; return managed pool count."""
    ranges, options = plan_servers(servers, sync.resolve_interface)
    if ranges:
        for row in sync.api.search('dhcrelay/settings/search_relay'):
            detail = sync.api.get('dhcrelay/settings/get_relay/' + row['uuid']).get('relay')
            if not isinstance(detail, dict):
                raise ValueError('could not check existing DHCP relay')
            if any(r['interface'] == _row_value(detail, 'interface') for r in ranges.values()):
                raise ValueError('local DHCP pool conflicts with an existing relay')
    existing = sync.api.search(RANGES.search)
    existing_options = sync.api.search(OPTIONS.search)
    listeners = None
    if ranges:
        settings = sync.api.get('dnsmasq/settings/get').get('dnsmasq') or {}
        if str(settings.get('enable')) != '1':
            raise ValueError('Dnsmasq must be enabled before adding server pools')
        selected = set(filter(None, _row_value(settings, 'interface').split(',')))
        excluded = set(filter(None, _row_value(settings.get('dhcp') or {}, 'no_interface').split(',')))
        required = {p['interface'] for p in ranges.values()}
        if required & excluded:
            raise ValueError('DHCP is explicitly disabled on a requested interface')
        if selected and not required <= selected:
            for interface in required - selected:
                detail = sync.api.get('interfaces/assignment/get_item/' + interface).get('interface') or {}
                if not str(detail.get('descr') or '').startswith('ufg_vlan_'):
                    raise ValueError('Dnsmasq listener expansion requires a managed VLAN assignment')
            listeners = ','.join(sorted(selected | required))
    for row in existing:
        if str(parse_tag(row.get('description')) or '').startswith('pool-'):
            continue
        for payload in ranges.values():
            # Dnsmasq scopes options to an interface. Even disjoint unmanaged
            # pools on that interface could receive the controller's options.
            if payload['interface'] in _row_value(row, 'interface').split(','):
                raise ValueError('unmanaged DHCP pool on interface ' + payload['interface'])
    for row in existing_options:
        if str(parse_tag(row.get('description')) or '').startswith('pool-'):
            continue
        scopes = _row_value(row, 'interface').split(',')
        for payload in options.values():
            if (not any(scopes) or payload['interface'] in scopes) and _row_value(row, 'option') == payload['option']:
                raise ValueError('unmanaged DHCP option conflicts with controller settings')
    # Keep unrelated tagged objects if this backend grows more collections.
    changed, _ = sync.sync_items(RANGES, ranges, keep=lambda key: not key.startswith('pool-'))
    option_changed, _ = sync.sync_items(OPTIONS, options, keep=lambda key: not key.startswith('pool-'))
    if listeners is not None:
        result = sync.api.post('dnsmasq/settings/set', {'dnsmasq': {'interface': listeners}})
        OPNsenseAPI.check_saved(result, 'include managed VLAN DHCP listener')
    if changed or option_changed or listeners is not None:
        result = sync.api.post('dnsmasq/service/reconfigure')
        if not isinstance(result, dict) or result.get('status') != 'ok':
            raise OPNsenseAPIError('Dnsmasq reconfigure failed')
    return len(ranges)
