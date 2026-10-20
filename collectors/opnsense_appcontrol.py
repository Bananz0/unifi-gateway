"""Zenarmor application-control primitives, distinct from DPI telemetry.

These are explicit policy operations, not a blanket mapping from UniFi rules.
The caller must first establish the requested policy/device/network scope and
ownership. An application id from UniFi must never be sent directly to Zenarmor.
"""
from .opnsense_api import OPNsenseAPIError
from .unifi_dpi import APPLICATIONS


def resolve_app_ids(unifi_ids, applications):
    """Resolve exact application names; ambiguity and missing matches fail closed.

There is intentionally no category fallback: a missing Instagram match cannot
silently become a block of every social network or of generic HTTPS.
"""
    names = {}
    for application in applications:
        name = str(application.get('name') or '').strip().casefold()
        if name:
            names.setdefault(name, set()).add(int(application['id']))
    resolved = set()
    for app_id in unifi_ids:
        name = APPLICATIONS.get(int(app_id))
        if name is None:
            raise ValueError('unknown UniFi application ID %s' % app_id)
        matches = names.get(name.strip().casefold(), set())
        if len(matches) != 1:
            raise ValueError('no unambiguous Zenarmor application for %s' % name)
        resolved.update(matches)
    return sorted(resolved)


class ZenarmorAppPolicy:
    def __init__(self, api):
        self.api = api

    def applications(self):
        result = self.api.get('zenarmor/policy/applicationDatabase')
        if not isinstance(result, dict) or result.get('success') is not True:
            raise OPNsenseAPIError('Zenarmor application database unavailable')
        applications = (result.get('applicationDatabase') or {}).get('applications')
        if not isinstance(applications, list):
            raise OPNsenseAPIError('invalid Zenarmor application database')
        return applications

    def detail(self, policy_id):
        result = self.api.get('zenarmor/policy/detail', params={'id': policy_id})
        if (not isinstance(result, dict) or result.get('id') != policy_id
                or not isinstance(result.get('app_controls'), list)):
            raise OPNsenseAPIError('Zenarmor policy readback unavailable')
        return result

    def set_apps(self, policy_id, blocked=(), allowed=(), expected_name=None):
        """Apply only explicit app deltas and verify readback; preserve other apps.

        This method never creates or broadens a policy, changes its scope, or
        bypasses license checks. Policy readback proves configuration, not that
        the engine has classified and dropped a particular client connection.
        """
        before = self.detail(policy_id)
        if expected_name is not None and before.get('name') != expected_name:
            raise ValueError('Zenarmor policy identity changed')
        blocked, allowed = set(map(int, blocked)), set(map(int, allowed))
        if blocked & allowed:
            raise ValueError('an application cannot be both blocked and allowed')
        current = set(map(int, before['app_controls']))
        changes = [{'id': app, 'value': True, 'isCustom': False}
                   for app in sorted(blocked - current)]
        changes += [{'id': app, 'value': False, 'isCustom': False}
                    for app in sorted(allowed & current)]
        if not changes:
            return False
        # Validate against the installed catalog before sending any mutation.
        available = {int(a['id']) for a in self.applications()}
        if any(row['id'] not in available for row in changes):
            raise ValueError('application is absent from the installed Zenarmor catalog')
        result = self.api.put('zenarmor/policy/appControls', {'apps': changes},
                              params={'id': policy_id})
        if not isinstance(result, dict) or result.get('success') is not True:
            raise OPNsenseAPIError('Zenarmor application policy update rejected')
        after = set(map(int, self.detail(policy_id)['app_controls']))
        if after != (current | blocked) - allowed:
            raise OPNsenseAPIError('Zenarmor application policy readback differs from request')
        return True
