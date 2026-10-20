"""Scoped UniFi simple-app-block reconciliation through Zenarmor policies.

Each policy is cloned from Default, configured while disabled and activated
only after its selectors and app controls read back correctly. License errors
remain errors; a client-only block never falls back to a global policy.
"""
import hashlib
import ipaddress
import json
import re
import time

from .opnsense_api import OPNsenseAPIError
from .opnsense_appcontrol import ZenarmorAppPolicy, resolve_app_ids


PREFIX = 'unifi-gw:app-'


def _security_baseline(detail):
    fields = ('advanced_security', 'essential_security', 'web_controls', 'web_controls_custom',
              'app_controls_custom', 'tls_controls', 'casb', 'url_blocks',
              'file_reputation', 'rtap', 'exclusions')
    result = {key: detail.get(key) for key in fields}
    configs = detail.get('configs') or {}
    result['configs'] = {key: configs.get(key) for key in (
        'decision_is_block', 'block_untrusted_devices', 'block_ech', 'sso',
        'safe_search', 'webcategory_type')}
    return result


def plan_blocks(rules, networks, applications):
    """Compile captured Network 10.6 simple-app-block fields into exact scopes."""
    if not isinstance(rules, list):
        raise ValueError('app-block response is not a rule list')
    grouped = {}
    network_map = {n['_id']: n for n in networks if n.get('_id')}
    for rule in rules:
        if not isinstance(rule, dict) or not rule.get('_id'):
            raise ValueError('app block lacks a stable rule ID')
        unknown = set(rule) - {'_id', 'name', 'type', 'target_type', 'network_ids',
                               'client_macs', 'app_ids', 'app_category_ids', 'schedule'}
        if unknown:
            raise ValueError('unsupported app-block fields: ' + ','.join(sorted(unknown)))
        schedule = rule.get('schedule') or {}
        if schedule != {'mode': 'ALWAYS'}:
            raise ValueError('app-block schedule requires a schedule translator')
        if rule.get('target_type') != 'APP_ID' or rule.get('app_category_ids'):
            raise ValueError('application category blocks require an explicit category map')
        apps = resolve_app_ids(rule.get('app_ids') or [], applications)
        if not apps:
            raise ValueError('app block has no applications')
        scopes = []
        if rule.get('type') == 'DEVICE':
            if rule.get('network_ids'):
                raise ValueError('device block unexpectedly contains network selectors')
            for mac in rule.get('client_macs') or []:
                mac = str(mac).lower().replace('-', ':')
                if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac) or int(mac[:2], 16) & 1 or mac == '00:00:00:00:00:00':
                    raise ValueError('invalid application-block client MAC')
                scopes.append(('mac', mac))
        elif rule.get('type') == 'NETWORK':
            if rule.get('client_macs'):
                raise ValueError('network block unexpectedly contains client selectors')
            for network_id in rule.get('network_ids') or []:
                network = network_map.get(network_id)
                if not network or network.get('purpose') not in ('corporate', 'guest'):
                    raise ValueError('app-block network is missing or is not a LAN')
                # Dynamic IPv6 prefixes cannot safely be approximated with the
                # IPv4 subnet. Keep this unsupported until interface scopes exist.
                if network.get('ipv6_interface_type') not in (None, '', 'none', 'disabled'):
                    raise ValueError('IPv6 network app blocks require an interface scope')
                subnet = ipaddress.ip_network(network.get('ip_subnet', ''), strict=False)
                if subnet.prefixlen == 0:
                    raise ValueError('app-block network selector is not a LAN subnet')
                scopes.append(('network', str(subnet)))
        else:
            raise ValueError('unknown application-block source type')
        if not scopes:
            raise ValueError('empty app-block scope must not become a global block')
        for scope in scopes:
            grouped.setdefault(scope, set()).update(apps)
    kinds = {scope[0] for scope in grouped}
    if len(kinds) > 1:
        raise ValueError('mixed client/network app blocks require policy-overlap resolution')
    subnets = [ipaddress.ip_network(s[1]) for s in grouped if s[0] == 'network']
    for index, subnet in enumerate(subnets):
        if any(subnet.overlaps(other) for other in subnets[index + 1:] if subnet.version == other.version):
            raise ValueError('overlapping network app blocks require policy-overlap resolution')
    return {PREFIX + hashlib.sha256(json.dumps(scope).encode()).hexdigest()[:20]: {
        'macs': [scope[1]] if scope[0] == 'mac' else [],
        'networks': [scope[1]] if scope[0] == 'network' else [],
        'apps': sorted(apps)} for scope, apps in grouped.items()}


class SimpleAppBlockSync:
    def __init__(self, api, controller):
        self.api = api
        self.controller = controller
        self.app_policy = ZenarmorAppPolicy(api)
        self._retry_snapshot = None
        self._retry_after = 0
        self._retry_error = ''

    @staticmethod
    def _saved(result, operation):
        if not isinstance(result, dict) or result.get('success') is not True:
            message = result.get('message', '') if isinstance(result, dict) else ''
            raise OPNsenseAPIError('%s rejected: %s' % (operation, str(message)[:200]))
        return result

    def _put(self, action, policy_id, payload):
        return self._saved(self.api.put('zenarmor/policy/' + action, payload,
                                        params={'id': policy_id}), action)

    def _remove(self, name, policy):
        policy_id = policy['id']
        detail = self.app_policy.detail(policy_id)
        if policy_id == 0 or detail.get('name') != name or not name.startswith(PREFIX):
            raise ValueError('managed application policy identity changed')
        self._saved(self.api.post('zenarmor/policy/delete',
                                  {'cloud_id': policy_id}), 'remove app policy')

    @staticmethod
    def _selectors(detail, field):
        return sorted(str(row.get('value')) for row in detail.get(field, [])
                      if isinstance(row, dict) and not row.get('is_disabled'))

    def _configure(self, policy_id, name, desired, baseline, default):
        detail = self.app_policy.detail(policy_id)
        if detail.get('name') != name or not name.startswith(PREFIX) or policy_id == 0:
            raise ValueError('refusing to edit an unmanaged Zenarmor policy')
        if _security_baseline(detail) != _security_baseline(default):
            if detail.get('isActive'):
                self._put('config', policy_id, {'operation': 'set-status', 'status': False})
            raise OPNsenseAPIError('Default security controls changed; scoped app policy disabled pending inheritance refresh')
        current_macs = self._selectors(detail, 'mac_addresses')
        current_nets = self._selectors(detail, 'networks')
        selectors_changed = current_macs != desired['macs'] or current_nets != desired['networks']
        expected_apps = baseline | set(desired['apps'])
        current_apps = set(map(int, detail['app_controls']))
        directions = (detail.get('configs') or {}).get('directions') or {}
        direction_changed = directions != {'inbound': True, 'outbound': True}
        if not selectors_changed and not direction_changed and current_apps == expected_apps and detail.get('isActive') is True:
            return False
        # Keep every intermediate configuration inactive, including a policy
        # left active by a previous successful cycle.
        if detail.get('isActive'):
            self._put('config', policy_id, {'operation': 'set-status', 'status': False})
        try:
            if direction_changed:
                configs = dict(detail.get('configs') or {})
                configs['directions'] = {'inbound': True, 'outbound': True}
                self._put('config', policy_id, {'operation': 'set-configs', 'configs': configs})
            if selectors_changed:
                self._put('macAddresses', policy_id, {'macAddresses': [
                    {'value': mac, 'desc': name, 'is_disabled': False} for mac in desired['macs']]})
                self._put('networks', policy_id, {'networks': [
                    {'value': net, 'desc': name, 'is_disabled': False} for net in desired['networks']]})
            self.app_policy.set_apps(policy_id, blocked=expected_apps,
                                      allowed=current_apps - expected_apps, expected_name=name)
            check = self.app_policy.detail(policy_id)
            if (self._selectors(check, 'mac_addresses') != desired['macs']
                    or self._selectors(check, 'networks') != desired['networks']
                    or (check.get('configs') or {}).get('directions') != {'inbound': True, 'outbound': True}):
                raise OPNsenseAPIError('Zenarmor application-policy selectors differ from request')
            # The installed plugin performs license and policy conflict checks
            # here. A rejection leaves this policy disabled and is surfaced.
            self._put('config', policy_id, {'operation': 'set-status', 'status': True})
            check = self.app_policy.detail(policy_id)
            if not check.get('isActive'):
                raise OPNsenseAPIError('Zenarmor application policy did not activate')
        except Exception:
            # Never leave an unverified scoped policy enabled after a failed
            # activation/readback. If disabling fails, propagate that failure.
            self._put('config', policy_id, {'operation': 'set-status', 'status': False})
            raise
        return True

    def run(self):
        rules = self.controller.call('GET', 'v2/firewall-app-blocks')
        if not isinstance(rules, list):
            raise ValueError('controller app-block snapshot unavailable')
        result = self.api.get('zenarmor/policy/index')
        policies = result.get('policies') if isinstance(result, dict) else None
        if not isinstance(policies, list):
            raise OPNsenseAPIError('Zenarmor policy inventory unavailable')
        owned = {p['name']: p for p in policies if str(p.get('name') or '').startswith(PREFIX)}
        if not rules and not owned:
            return {'requested': 0, 'policies': 0, 'changed': 0}
        if not rules:
            for name, policy in owned.items():
                self._remove(name, policy)
            return {'requested': 0, 'policies': 0, 'changed': len(owned)}
        if any(p.get('isActive') and p.get('id') != 0
               and not str(p.get('name') or '').startswith(PREFIX) for p in policies):
            raise ValueError('existing custom Zenarmor policies require policy-inheritance resolution')
        applications = self.app_policy.applications()
        networks = self.controller.call('GET', 'rest/networkconf') if any(
            r.get('type') == 'NETWORK' for r in rules if isinstance(r, dict)) else []
        desired = plan_blocks(rules, networks, applications)
        default = self.app_policy.detail(0)
        if not default.get('isActive') or default.get('isCentralized'):
            raise ValueError('local active Zenarmor Default policy is required')
        configs = default.get('configs') or {}
        if (any(default.get(k) for k in ('mac_addresses', 'networks', 'devices', 'device_categories', 'schedules'))
                or any(configs.get(k) for k in ('groups', 'interfaces', 'interface_tags', 'usernames', 'vlans'))):
            raise ValueError('scoped Zenarmor Default policy requires explicit inheritance handling')
        baseline = set(map(int, default['app_controls']))
        snapshot = json.dumps({'desired': desired, 'baseline': sorted(baseline),
                               'security': _security_baseline(default)}, sort_keys=True)
        if snapshot == self._retry_snapshot and time.monotonic() < self._retry_after:
            raise OPNsenseAPIError(self._retry_error)
        changes = 0
        try:
            for name, scope in desired.items():
                policy = owned.get(name)
                if policy is None:
                    created = self._saved(self.api.post('zenarmor/policy/clone?id=0',
                                                       {'name': name}), 'clone Default policy')
                    policy_id = (created.get('nodePolicy') or {}).get('id')
                    if not isinstance(policy_id, int) or policy_id <= 0:
                        raise OPNsenseAPIError('Zenarmor did not return a scoped policy identifier')
                else:
                    policy_id = policy['id']
                changes += int(self._configure(policy_id, name, scope, baseline, default))
        except OPNsenseAPIError as e:
            # Avoid repeated engine reloads/cloud syncs for a rejected license
            # or backend failure. A changed rule bypasses the backoff; deleting
            # all rules still cleans owned policies immediately.
            self._retry_snapshot, self._retry_after = snapshot, time.monotonic() + 300
            self._retry_error = str(e)
            raise
        self._retry_snapshot = None
        # Stale policies are deleted only after all replacements activate.
        for name, policy in owned.items():
            if name not in desired:
                self._remove(name, policy)
                changes += 1
        return {'requested': len(rules), 'policies': len(desired), 'changed': changes}
