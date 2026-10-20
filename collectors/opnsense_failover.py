"""UDAPI ``services.wanFailover`` on OPNsense gateway priorities.

Network 10.6 sends ``{enabled, wanInterfaces: [{interface: {id},
routingTable, metric, monitors: [{id, interval, timePeriod, target,
alert?: {lossThreshold}}]}]}``. OPNsense fails the default route over by
gateway priority when "Allow default gateway switching" is on (a legacy
System setting with no API; required, not changed here). Each WAN's IPv4
gateway gets the metric as its priority and the alerting monitor's interval,
window and loss threshold, with monitoring switched on. Monitor targets stay OPNsense's: UniFi sends a
hostname (ping.ui.com) and dpinger needs an address.

Gateways belong to the operator, so a state file records the values before
the first change and restores them when UniFi stops managing the WAN. A
dynamic gateway that exists only virtually is persisted to change it and
deleted again on restore. One WAN has nothing to fail over to; nothing is
written. Weighted load balancing needs policy routing and is rejected.
"""
import json
import os

from .opnsense_api import OPNsenseAPI, OPNsenseAPIError

GW = 'routing/settings/'
FIELDS = ('priority', 'interval', 'time_period', 'losshigh', 'monitor_disable')
WAN_FIELDS = {'interface', 'routingTable', 'metric', 'monitors'}


def plan_failover(section, resolve):
    """{opnsense interface: {field: value}}; empty unless 2+ WANs."""
    if not isinstance(section, dict) or not section.get('enabled'):
        return {}
    if set(section) - {'enabled', 'wanInterfaces'}:
        raise ValueError('unsupported WAN failover fields (load balancing?)')
    wans = section.get('wanInterfaces') or []
    if len(wans) < 2:
        return {}
    plan = {}
    for wan in wans:
        if not isinstance(wan, dict) or set(wan) - WAN_FIELDS:
            raise ValueError('unsupported WAN failover interface fields')
        interface = resolve((wan.get('interface') or {}).get('id'))
        if not interface:
            raise ValueError('WAN failover interface %s is not assigned'
                             % (wan.get('interface') or {}).get('id'))
        metric = wan.get('metric')
        if isinstance(metric, bool) or not isinstance(metric, int) or not 1 <= metric <= 255:
            raise ValueError('invalid WAN failover metric')
        values = {'priority': str(metric)}
        alerting = [m for m in wan.get('monitors') or [] if isinstance(m, dict) and m.get('alert')]
        if len(alerting) > 1:
            raise ValueError('several alerting WAN monitors')
        for monitor in alerting:
            interval, period = monitor.get('interval'), monitor.get('timePeriod')
            loss = (monitor.get('alert') or {}).get('lossThreshold')
            if not all(isinstance(v, int) and not isinstance(v, bool) and v > 0
                       for v in (interval, period, loss)) or loss > 100 or period < 2 * interval:
                raise ValueError('invalid WAN failover monitor')
            values.update(interval=str(interval * 1000), time_period=str(period * 1000),
                          losshigh=str(loss), monitor_disable='0')
        if interface in plan:
            raise ValueError('duplicate WAN failover interface %s' % interface)
        plan[interface] = values
    return plan


def _flat(detail):
    out = {}
    for key, value in detail.items():
        if isinstance(value, dict):
            value = ','.join(k for k, v in value.items() if isinstance(v, dict) and v.get('selected'))
        out[key] = '' if value is None else str(value)
    return out


class FailoverSync:
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

    def _gateways(self):
        return [r for r in self.api.get(GW + 'search_gateway').get('rows') or []
                if r.get('ipprotocol') == 'inet' and not r.get('disabled')]

    def sync(self, plan):
        state = self._load()
        rows = self._gateways()
        changed = False
        for interface, values in plan.items():
            matches = [r for r in rows if r.get('interface') == interface]
            if len(matches) != 1:
                raise ValueError('WAN failover needs exactly one IPv4 gateway on %s, found %d'
                                 % (interface, len(matches)))
            row = matches[0]
            if all(str(row.get(k) or '') == v for k, v in values.items()):
                state.setdefault(row['name'], {'original': {k: str(row.get(k) or '') for k in FIELDS}})
                continue
            entry = state.setdefault(row['name'], {
                'original': {k: str(row.get(k) or '') for k in FIELDS},
                'created': bool(row.get('virtual'))})
            self._save(state)
            if row.get('virtual'):
                payload = {'name': row['name'], 'interface': interface, 'ipprotocol': 'inet',
                           'gateway': 'dynamic', 'monitor_disable': str(row.get('monitor_disable') or '0')}
                payload.update(values)
                result = self.api.post(GW + 'add_gateway', {'gateway_item': payload})
            else:
                payload = _flat(self.api.get(GW + 'get_gateway/' + row['uuid']).get('gateway_item') or {})
                payload.update(values)
                result = self.api.post(GW + 'set_gateway/' + row['uuid'], {'gateway_item': payload})
            OPNsenseAPI.check_saved(result, 'set WAN failover on gateway %s' % row['name'])
            entry['applied'] = values
            changed = True
        managed = {r['name'] for r in rows if r.get('interface') in plan}
        for name in [n for n in state if n not in managed]:
            row = next((r for r in rows if r['name'] == name), None)
            entry = state.pop(name)
            applied = entry.get('applied')
            if row is None or not applied or any(str(row.get(k) or '') != v for k, v in applied.items()):
                continue    # gone, never changed, or edited in OPNsense since
            if entry.get('created'):
                self._delete(row['uuid'])
            else:
                payload = _flat(self.api.get(GW + 'get_gateway/' + row['uuid']).get('gateway_item') or {})
                payload.update(entry['original'])
                result = self.api.post(GW + 'set_gateway/' + row['uuid'], {'gateway_item': payload})
                OPNsenseAPI.check_saved(result, 'restore gateway %s' % name)
            changed = True
        self._save(state)
        if changed:
            result = self.api.post(GW + 'reconfigure')
            if not isinstance(result, dict) or str(result.get('status')).lower() != 'ok':
                raise OPNsenseAPIError('gateway reconfigure failed: %s' % result)
        return len(plan)

    def _delete(self, uuid):
        result = self.api.post(GW + 'del_gateway/' + uuid)
        if not isinstance(result, dict) or result.get('result') not in ('deleted', 'not found'):
            raise OPNsenseAPIError('delete gateway %s failed: %s' % (uuid, result))
