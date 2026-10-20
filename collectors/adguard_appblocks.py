"""UniFi simple app blocks enforced by AdGuard Home's per-client blocked
services, a FOSS alternative to Zenarmor policies.

Each blocked scope (current device IPs or LAN subnets, from ``plan_blocks``)
becomes AdGuard Home persistent clients named ``unifi-gw-app-<hash>``
whose blocked services are AdGuard's global ones plus the UniFi apps. A
client's own list replaces the global one, hence the union. UniFi apps are
matched to AdGuard services by exact name; a missing match fails closed.

This is DNS-level blocking: a device using its own DNS-over-HTTPS or
hard-coded addresses is not covered, and cached answers expire by TTL.
"""
import base64
import hashlib
import ipaddress
import json
import re
import urllib.error
import urllib.request

from .opnsense_appblocks import plan_blocks
from .unifi_dpi import APPLICATIONS

PREFIX = 'unifi-gw-app-'


def neighbor_addresses(arp, ndp, interfaces):
    """Fresh LAN neighbor ownership; historical discovery/leases are not proof.

    Include every observed IPv6 privacy address and discard ambiguous addresses
    instead of applying one device's policy to a different device.
    """
    if not isinstance(arp, list) or not isinstance(ndp, list):
        raise ValueError('current neighbor snapshot unavailable')
    owners = {}
    for row in arp + ndp:
        if row.get('intf') not in interfaces or row.get('expired'):
            continue
        mac = str(row.get('mac') or '').lower().replace('-', ':')
        if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac) or int(mac[:2], 16) & 1 or mac == '00:00:00:00:00:00':
            continue
        try:
            addr = ipaddress.ip_address(str(row.get('ip') or '').split('%', 1)[0])
        except ValueError:
            continue
        if addr.is_unspecified or addr.is_multicast or addr.is_loopback or addr.is_link_local:
            continue
        owners.setdefault(str(addr), set()).add(mac)
    result = {}
    for address, macs in owners.items():
        if len(macs) == 1:
            result.setdefault(next(iter(macs)), []).append(address)
    return {mac: sorted(ips) for mac, ips in result.items()}


class AdGuardError(Exception):
    pass


class AdGuardHome:
    """Minimal AdGuard Home REST client (Basic auth)."""

    def __init__(self, url, username, password, timeout=15):
        self.url = url.rstrip('/') + '/'
        token = base64.b64encode(('%s:%s' % (username, password)).encode()).decode()
        self.headers = {'Authorization': 'Basic ' + token, 'Content-Type': 'application/json'}
        self.timeout = timeout

    def _call(self, method, path, payload=None):
        body = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.url + path, body, self.headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                text = resp.read().decode() or 'null'
        except urllib.error.HTTPError as e:
            raise AdGuardError('%s %s: HTTP %s %s' % (method, path, e.code,
                                                     e.read().decode(errors='replace')[:200]))
        except (urllib.error.URLError, OSError) as e:
            raise AdGuardError('%s %s: %s' % (method, path, e))
        try:
            return json.loads(text)
        except ValueError:
            return text

    def get(self, path):
        return self._call('GET', path)

    def post(self, path, payload):
        return self._call('POST', path, payload)


def resolve_services(unifi_ids, services):
    names = {}
    for service in services:
        for name in (service.get('name'), service.get('id')):
            if name:
                names.setdefault(str(name).strip().casefold(), set()).add(service['id'])
    resolved = set()
    for app_id in unifi_ids:
        name = APPLICATIONS.get(int(app_id))
        if name is None:
            raise ValueError('unknown UniFi application ID %s' % app_id)
        matches = names.get(name.strip().casefold(), set())
        if len(matches) != 1:
            raise ValueError('no AdGuard Home blocked service for %s' % name)
        resolved.update(matches)
    return sorted(resolved)


class AdGuardAppBlockSync:
    def __init__(self, adguard, controller, client_addresses=None):
        self.adguard = adguard
        self.controller = controller
        self.client_addresses = client_addresses

    def _global_services(self):
        try:   # v0.107.37+
            body = self.adguard.get('control/blocked_services/get')
            services = set(body.get('ids') or [])
            schedule = body.get('schedule') or {}
            if services and any(value for key, value in schedule.items() if key != 'time_zone'):
                raise ValueError('scheduled global AdGuard services require schedule inheritance')
            return services
        except AdGuardError:
            return set(self.adguard.get('control/blocked_services/list') or [])

    def _clients(self):
        return {c['name']: c for c in self.adguard.get('control/clients').get('clients') or []
                if str(c.get('name') or '').startswith(PREFIX)}

    def run(self):
        rules = self.controller.call('GET', 'v2/firewall-app-blocks')
        if not isinstance(rules, list):
            raise ValueError('controller app-block snapshot unavailable')
        owned = self._clients()
        if not rules and not owned:
            return {'requested': 0, 'clients': 0, 'changed': 0, 'backend': 'adguard'}
        desired, pending = {}, []
        if rules:
            services = self.adguard.get('control/blocked_services/all').get('blocked_services') or []
            networks = self.controller.call('GET', 'rest/networkconf') if any(
                r.get('type') == 'NETWORK' for r in rules if isinstance(r, dict)) else []
            plan = plan_blocks(rules, networks, services, resolve=resolve_services, allow_mixed=True)
            base = self._global_services()
            addresses = {}
            if any(scope['macs'] for scope in plan.values()):
                if self.client_addresses is None:
                    raise ValueError('device app blocks require current IP-to-MAC ownership')
                addresses = self.client_addresses()
                if not isinstance(addresses, dict):
                    raise ValueError('current device address snapshot unavailable')
            # AdGuard selects the most specific matching client. Materialize
            # the union of containing network policies on each device address,
            # so a device rule cannot override a broader network block.
            scopes = {}
            for scope in plan.values():
                for subnet in scope['networks']:
                    scopes.setdefault(str(ipaddress.ip_network(subnet)), set()).update(scope['apps'])
                for mac in scope['macs']:
                    ips = addresses.get(mac) or []
                    if not ips:
                        pending.append(mac)
                    for ip in ips:
                        addr = ipaddress.ip_address(ip)
                        if addr.is_unspecified or addr.is_multicast or addr.is_loopback or addr.is_link_local:
                            raise ValueError('invalid device address selector')
                        scopes.setdefault(str(addr), set()).update(scope['apps'])
            networks = [(ipaddress.ip_network(net), apps) for net, apps in scopes.items() if '/' in net]
            for selector, apps in scopes.items():
                selected = ipaddress.ip_network(selector, strict=False)
                effective = set(apps)
                for net, inherited in networks:
                    if selected.version == net.version and selected.subnet_of(net):
                        effective.update(inherited)
                name = PREFIX + hashlib.sha256(selector.encode()).hexdigest()[:20]
                desired[name] = {
                    'name': name, 'ids': [selector],
                    'use_global_settings': True, 'use_global_blocked_services': False,
                    'blocked_services': sorted(base | effective),
                    'tags': [], 'upstreams': []}
            # A manual, more-specific AdGuard client would bypass our network
            # rule. Reject the complete plan before mutating either collection.
            clients = self.adguard.get('control/clients').get('clients') or []
            for client in clients:
                if str(client.get('name') or '').startswith(PREFIX):
                    continue
                for identifier in client.get('ids') or []:
                    try:
                        manual = ipaddress.ip_network(identifier, strict=False)
                    except ValueError:
                        continue
                    if any(manual.version == ipaddress.ip_network(row['ids'][0], strict=False).version
                           and manual.overlaps(ipaddress.ip_network(row['ids'][0], strict=False))
                           for row in desired.values()):
                        raise ValueError('an unmanaged AdGuard client overlaps an app-block selector')
        changes = 0
        # Retire obsolete IP ownership first. If a later add fails, an address
        # reassigned to another device must not retain the previous block.
        for name in owned:
            if name not in desired:
                self.adguard.post('control/clients/delete', {'name': name})
                changes += 1
        for name, body in desired.items():
            current = owned.get(name)
            if current is None:
                self.adguard.post('control/clients/add', body)
            elif (sorted(current.get('ids') or []) != sorted(body['ids'])
                  or sorted(current.get('blocked_services') or []) != body['blocked_services']
                  or current.get('use_global_blocked_services') is not False):
                self.adguard.post('control/clients/update', {'name': name, 'data': body})
            else:
                continue
            changes += 1
        if changes:
            check = self._clients()
            for name, body in desired.items():
                got = check.get(name) or {}
                if (sorted(got.get('ids') or []) != sorted(body['ids'])
                        or sorted(got.get('blocked_services') or []) != body['blocked_services']):
                    raise AdGuardError('AdGuard Home client %s did not read back' % name)
            if set(check) - set(desired):
                raise AdGuardError('stale AdGuard Home clients remain')
        return {'requested': len(rules), 'clients': len(desired), 'changed': changes,
                'pending_devices': len(set(pending)), 'backend': 'adguard'}
