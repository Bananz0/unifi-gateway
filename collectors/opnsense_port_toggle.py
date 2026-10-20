"""Enable/disable OPNsense interfaces when a UniFi Ethernet port is toggled.

UDAPI carries the port switch as ``interfaces[].status.enabled`` on
``ethernet`` interfaces. Only transitions act: the first push records every
port's state, then a port UniFi switches off disables its OPNsense
interface (assignment ``enable``) and switching it back on enables it. A
deploy therefore never disables a port that was already marked off, and the
operator's own changes in OPNsense stand until UniFi next toggles that port.

The interface the controller is reached through is never disabled: UniFi
could not switch it back on.
"""
import ipaddress
import json
import os

from .opnsense_api import OPNsenseAPI, OPNsenseAPIError

ASSIGN = 'interfaces/assignment/'


def port_states(interfaces):
    """{udapi port id: enabled} for Ethernet ports."""
    states = {}
    for iface in interfaces or []:
        ident = (iface or {}).get('identification') or {}
        status = (iface or {}).get('status') or {}
        if ident.get('type') == 'ethernet' and isinstance(status.get('enabled'), bool):
            states[ident['id']] = status['enabled']
    return states


class PortToggleSync:
    def __init__(self, api, port_map, state_file, protected_hosts=()):
        self.api = api
        self.port_map = port_map
        self.state_file = state_file
        self.protected_hosts = protected_hosts

    def _load(self):
        try:
            with open(self.state_file) as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    def _save(self, state):
        tmp = self.state_file + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(state, f)
        os.replace(tmp, self.state_file)

    def _protected(self, identifier):
        """True when a controller address lies in the interface's subnet."""
        overview = self.api.get('interfaces/overview/interfaces_info')
        rows = overview.get('rows', []) if isinstance(overview, dict) else overview or []
        for row in rows:
            if row.get('identifier') != identifier:
                continue
            for cidr in [row.get('addr4'), row.get('addr6')] + list(row.get('ipv4') or []):
                cidr = cidr.get('ipaddr') if isinstance(cidr, dict) else cidr
                try:
                    net = ipaddress.ip_interface(cidr).network
                except (TypeError, ValueError):
                    continue
                for host in self.protected_hosts:
                    try:
                        if ipaddress.ip_address(host) in net:
                            return True
                    except ValueError:
                        return True     # a hostname: can't tell, so protect
        return False

    def sync(self, interfaces, warn):
        """Returns {opnsense identifier: enabled} for interfaces changed."""
        current = port_states(interfaces)
        previous = self._load()
        if previous is None:
            self._save(current)     # first push: record, don't act
            return {}
        wanted = {}
        for port, enabled in current.items():
            if port in previous and previous[port] != enabled:
                identifier = self.port_map(port)
                if not identifier:
                    warn('port %s toggled in UniFi but has no OPNsense interface' % port)
                elif not enabled and self._protected(identifier):
                    warn('not disabling %s (%s): the controller is reached through it'
                         % (port, identifier))
                else:
                    wanted[identifier] = enabled
        changed = {}
        if wanted:
            rows = {r.get('identifier'): r for r in self.api.search(ASSIGN + 'search_item')}
            todo = {i: e for i, e in wanted.items()
                    if i in rows and (str(rows[i].get('enable')) == '1') != e}
            if todo:
                if self.api.get(ASSIGN + 'pending').get('status') != 'ok':
                    raise OPNsenseAPIError('finish pending OPNsense interface changes first')
                for identifier, enabled in todo.items():
                    result = self.api.post(ASSIGN + 'set_item/' + rows[identifier]['uuid'],
                                           {'interface': {'enable': '1' if enabled else '0'}})
                    OPNsenseAPI.check_saved(result, 'toggle interface %s' % identifier)
                result = self.api.post(ASSIGN + 'reconfigure')
                if not isinstance(result, dict) or result.get('status') != 'ok':
                    raise OPNsenseAPIError('interface reconfigure failed: %s' % result)
                for identifier, enabled in todo.items():
                    raw = self.api.get(ASSIGN + 'get_item/' + rows[identifier]['uuid']).get('interface') or {}
                    if (str(raw.get('enable')) == '1') != enabled:
                        raise OPNsenseAPIError('interface %s did not read back %s'
                                               % (identifier, 'enabled' if enabled else 'disabled'))
                changed = todo
        # recorded only after a successful apply, so a failure retries
        self._save(current)
        return changed
