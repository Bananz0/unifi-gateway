"""UniFi simple app blocks enforced by AdGuard Home's per-client blocked
services, a FOSS alternative to Zenarmor policies.

Each blocked scope (a client MAC or a LAN subnet, from ``plan_blocks``)
becomes an AdGuard Home persistent client named ``unifi-gw-app-<hash>``
whose blocked services are AdGuard's global ones plus the UniFi apps. A
client's own list replaces the global one, hence the union. UniFi apps are
matched to AdGuard services by exact name; a missing match fails closed.

This is DNS-level blocking: a device using its own DNS-over-HTTPS or
hard-coded addresses is not covered, and cached answers expire by TTL.
"""
import base64
import json
import urllib.error
import urllib.request

from .opnsense_appblocks import plan_blocks
from .unifi_dpi import APPLICATIONS

PREFIX = 'unifi-gw-app-'


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
    def __init__(self, adguard, controller):
        self.adguard = adguard
        self.controller = controller

    def _global_services(self):
        try:   # v0.107.37+
            return set(self.adguard.get('control/blocked_services/get').get('ids') or [])
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
        desired = {}
        if rules:
            services = self.adguard.get('control/blocked_services/all').get('blocked_services') or []
            networks = self.controller.call('GET', 'rest/networkconf') if any(
                r.get('type') == 'NETWORK' for r in rules if isinstance(r, dict)) else []
            plan = plan_blocks(rules, networks, services, resolve=resolve_services)
            base = self._global_services()
            for key, scope in plan.items():
                name = PREFIX + key.rsplit('-', 1)[-1]
                desired[name] = {
                    'name': name, 'ids': scope['macs'] + scope['networks'],
                    'use_global_settings': True, 'use_global_blocked_services': False,
                    'blocked_services': sorted(base | set(scope['apps'])),
                    'tags': [], 'upstreams': []}
        changes = 0
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
        for name in owned:
            if name not in desired:
                self.adguard.post('control/clients/delete', {'name': name})
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
                'backend': 'adguard'}
