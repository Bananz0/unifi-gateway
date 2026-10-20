"""Coordinate owned DHCP server/relay changes with break-before-make ordering.

There is no multi-service transaction in OPNsense. Preflight both roles, stop
the old role, then converge the new one. A failed apply must be retried before
the opposite role can start, even when the preceding write already persisted.
"""
from .opnsense_api import OPNsenseAPIError
from .opnsense_dhcp import OPTIONS, RANGES, plan_servers, preflight_servers, sync_servers
from .opnsense_relay import (
    plan_relays, preflight_relays, relay_inventory, sync_relays, stop_relays, RELAY_ROOT,
)
from .opnsense_sync import ItemSpec, _row_value, parse_tag


def sync_dhcp_roles(sync, servers):
    ranges, options = plan_servers(servers, sync.resolve_interface)
    desired_relays = plan_relays(servers, sync.resolve_interface)
    pool_interfaces = {row['interface'] for row in ranges.values()}
    relay_interfaces = {row['interface'] for row in desired_relays.values()}
    if pool_interfaces & relay_interfaces:
        raise ValueError('DHCP server and relay cannot share an interface')

    # Only remove records whose ownership is established by tags/references.
    owned, relays = relay_inventory(sync)
    retiring_relays = [row for row in relays
                       if _row_value(row, 'destination') in owned
                       and _row_value(row, 'interface') in pool_interfaces]
    existing_pools = sync.api.search(RANGES.search)
    retiring_pools = [row for row in existing_pools
                      if str(parse_tag(row.get('description')) or '').startswith('pool-')
                      and relay_interfaces & set(_row_value(row, 'interface').split(','))]
    preflight_servers(sync, ranges, options, {row['uuid'] for row in retiring_relays})
    preflight_relays(sync, desired_relays, {row['uuid'] for row in retiring_pools})
    retiring_ids = {row['uuid'] for row in retiring_pools}
    retained_v4 = any(row['uuid'] not in retiring_ids
                      and ':' not in str(row.get('start_addr') or '')
                      for row in existing_pools)
    if desired_relays and (ranges or retained_v4):
        settings = sync.api.get('dnsmasq/settings/get').get('dnsmasq') or {}
        if str(settings.get('enable')) == '1' and str(settings.get('strictbind')) != '1':
            raise ValueError('mixed Dnsmasq server and relay roles require strict interface binding')

    # The first reconciliation after daemon restart applies saved configuration
    # once, covering a crash between an API write and service reconfigure. Later
    # identical reconciliations issue no writes or service restarts.
    pending = getattr(sync, '_dhcp_pending_services', None)
    if pending is None:
        pending = sync._dhcp_pending_services = {'dnsmasq', 'dhcrelay'}
    api = sync.api

    class TrackingAPI:
        def __getattr__(self, name):
            return getattr(api, name)

        def post(self, path, payload=None, **kwargs):
            service = path.split('/', 1)[0]
            reconfigure = path == service + '/service/reconfigure'
            if service in ('dnsmasq', 'dhcrelay') and '/settings/' in path:
                pending.add(service)  # before a possibly ambiguous failed write
            result = api.post(path, payload, **kwargs)
            if reconfigure and service in ('dnsmasq', 'dhcrelay'):
                if not isinstance(result, dict) or result.get('status') != 'ok':
                    raise OPNsenseAPIError(service + ' reconfigure failed')
                if service == 'dnsmasq':
                    settings = api.get('dnsmasq/settings/get').get('dnsmasq') or {}
                    if str(settings.get('enable')) == '1':
                        status = api.get('dnsmasq/service/status')
                        if not isinstance(status, dict) or status.get('status') != 'running':
                            raise OPNsenseAPIError('Dnsmasq did not start after reconfigure')
                pending.discard(service)
            return result

    def flush(service):
        if service in pending:
            sync.api.post(service + '/service/reconfigure')

    sync.api = TrackingAPI()
    try:
        retired_keys = {parse_tag(row.get('description')) for row in retiring_pools}
        # Options disappear before their ranges; no orphan interface-wide
        # router/DNS option is left behind for a future unrelated pool.
        for row in api.search(OPTIONS.search):
            key = parse_tag(row.get('description')) or ''
            if any(key.startswith(pool + '-o') for pool in retired_keys):
                sync._delete(OPTIONS, row['uuid'])
        for row in retiring_pools:
            sync._delete(RANGES, row['uuid'])
        flush('dnsmasq')

        relay_spec = ItemSpec('DHCP relay', '', '', '', RELAY_ROOT + 'del_relay/',
                              'relay', 'destination')
        stop_relays(sync, retiring_relays)
        for row in retiring_relays:
            sync._delete(relay_spec, row['uuid'])
        flush('dhcrelay')

        relay_count = sync_relays(sync, servers)
        flush('dhcrelay')
        pool_count = sync_servers(sync, servers)
        flush('dnsmasq')
        return {'dhcp_relays': relay_count, 'dhcp_pools': pool_count}
    finally:
        sync.api = api
