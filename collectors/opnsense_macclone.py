"""UDAPI ``interfaces[].identification.macOverride`` (UniFi MAC address
clone) on OPNsense interface assignments (``spoofmac``).

Assignments carry no ownership tag, so a small state file records the value
an interface had before UniFi overrode it. When the override goes away it is
restored, unless someone changed the MAC in OPNsense since; then it is left
alone. Changing a WAN MAC renews its lease, so callers keep this opt-in.
"""
import json
import os
import re

from .opnsense_api import OPNsenseAPI, OPNsenseAPIError

ASSIGN = 'interfaces/assignment/'
MAC = re.compile(r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$')


def _mac(value):
    mac = str(value or '').strip().lower().replace('-', ':')
    if not MAC.match(mac) or int(mac[:2], 16) & 1 or mac == '00:00:00:00:00:00':
        raise ValueError('invalid MAC override %s' % value)
    return mac


def plan_overrides(interfaces, resolve):
    desired = {}
    for iface in interfaces or []:
        ident = (iface or {}).get('identification') or {}
        if 'macOverride' not in ident:
            continue
        if ident.get('type') != 'ethernet':
            raise ValueError('MAC override on %s interface %s' % (ident.get('type'), ident.get('id')))
        target = resolve(ident.get('id'))
        if not target:
            raise ValueError('MAC override interface %s is not assigned' % ident.get('id'))
        desired[target] = _mac(ident['macOverride'])
    return desired


class MACOverrideSync:
    def __init__(self, api, state_file):
        self.api = api
        self.state_file = state_file

    def _load(self):
        try:
            with open(self.state_file) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def _save(self, state):
        tmp = self.state_file + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(state, f)
        os.replace(tmp, self.state_file)

    def sync(self, desired):
        state = self._load()
        rows = {r.get('identifier'): r for r in self.api.search(ASSIGN + 'search_item')}
        writes = {}
        for ident, mac in desired.items():
            row = rows.get(ident)
            if row is None:
                raise ValueError('interface %s has no assignment' % ident)
            current = str(row.get('spoofmac') or '').lower()
            if current != mac:
                state.setdefault(ident, {'original': current})
                writes[ident] = mac
            state.setdefault(ident, {'original': current})['applied'] = mac
        for ident in [i for i in state if i not in desired]:
            row = rows.get(ident)
            current = str((row or {}).get('spoofmac') or '').lower()
            if row is not None and current == state[ident].get('applied'):
                writes[ident] = state[ident]['original']
            del state[ident]
        if not writes:
            self._save(state)
            return len(desired)
        if self.api.get(ASSIGN + 'pending').get('status') != 'ok':
            raise OPNsenseAPIError('finish pending OPNsense interface changes before changing MACs')
        self._save(state)   # before writing, so a crash can still restore
        for ident, mac in writes.items():
            result = self.api.post(ASSIGN + 'set_item/' + rows[ident]['uuid'],
                                   {'interface': {'spoofmac': mac}})
            OPNsenseAPI.check_saved(result, 'set MAC of %s' % ident)
        result = self.api.post(ASSIGN + 'reconfigure')
        if not isinstance(result, dict) or result.get('status') != 'ok':
            raise OPNsenseAPIError('interface reconfigure failed: %s' % result)
        for ident, mac in writes.items():
            raw = self.api.get(ASSIGN + 'get_item/' + rows[ident]['uuid']).get('interface') or {}
            if str(raw.get('spoofmac') or '').lower() != mac:
                raise OPNsenseAPIError('MAC of %s did not read back as %s' % (ident, mac or 'default'))
        return len(desired)
