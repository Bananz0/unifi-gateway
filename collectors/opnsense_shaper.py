"""UDAPI ``qos/ip`` (UniFi Smart Queues) on OPNsense's traffic shaper.

Network 10.6 sends ``{global: {enabled, connectivity: {interfaceID,
downloadSpeed, uploadSpeed}, defaultQoSIPQueue}, queues: []}`` with speeds in
kbit/s. Smart Queues are FQ-CoDel on the WAN, so this creates one FQ-CoDel
pipe per direction and a rule each on that interface (``in`` = download).
Per-IP queues are not translated and reject the section. An unmanaged shaper
rule on the same interface also rejects it: two shapers would stack.
"""
from .opnsense_api import OPNsenseAPIError
from .opnsense_sync import ItemSpec, make_tag, parse_tag

PIPES = ItemSpec('shaper pipe', 'trafficshaper/settings/search_pipes',
                 'trafficshaper/settings/add_pipe', 'trafficshaper/settings/set_pipe/',
                 'trafficshaper/settings/del_pipe/', 'pipe', 'description')
RULES = ItemSpec('shaper rule', 'trafficshaper/settings/search_rules',
                 'trafficshaper/settings/add_rule', 'trafficshaper/settings/set_rule/',
                 'trafficshaper/settings/del_rule/', 'rule', 'description')
KEY_PREFIX = 'sq-'
GLOBAL_FIELDS = {'enabled', 'connectivity', 'defaultQoSIPQueue'}
CONNECTIVITY_FIELDS = {'interfaceID', 'downloadSpeed', 'uploadSpeed'}


def _speed(value, field):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= 100000000:
        raise ValueError('invalid Smart Queue %s' % field)
    return str(value)


def plan_shaper(section, resolve):
    """(interface, {direction: kbit/s}) or None when Smart Queues are off."""
    if not isinstance(section, dict) or set(section) - {'global', 'queues'}:
        raise ValueError('unsupported qos/ip fields')
    if section.get('queues'):
        raise ValueError('per-IP QoS queues are not translated')
    glob = section.get('global') or {}
    if not isinstance(glob, dict) or set(glob) - GLOBAL_FIELDS:
        raise ValueError('unsupported qos/ip global fields')
    if not glob.get('enabled'):
        return None
    conn = glob.get('connectivity') or {}
    if set(conn) - CONNECTIVITY_FIELDS:
        raise ValueError('unsupported qos/ip connectivity fields')
    interface = resolve(conn.get('interfaceID'))
    if not interface:
        raise ValueError('Smart Queue interface %s is not assigned' % conn.get('interfaceID'))
    return interface, {'in': _speed(conn.get('downloadSpeed'), 'download speed'),
                       'out': _speed(conn.get('uploadSpeed'), 'upload speed')}


def sync_shaper(sync, section):
    plan = plan_shaper(section, sync.resolve_interface)
    rules = {}
    pipes = {}
    if plan:
        interface, speeds = plan
        for row in sync.api.search(RULES.search):
            if not str(parse_tag(row.get('description')) or '').startswith(KEY_PREFIX) \
                    and row.get('interface') == interface and str(row.get('enabled')) == '1':
                raise ValueError('an unmanaged traffic shaper rule already shapes %s' % interface)
        for direction, kbits in speeds.items():
            key = '%s%s-%s' % (KEY_PREFIX, interface, direction)
            pipes[key] = {'enabled': '1', 'bandwidth': kbits, 'bandwidthMetric': 'Kbit',
                          'mask': 'none', 'scheduler': 'fq_codel',
                          'description': make_tag(key, 'UniFi Smart Queue %s'
                                                  % ('download' if direction == 'in' else 'upload'))}
    pipes_changed, uuids = sync.sync_items(PIPES, pipes, delete_stale=False)
    if any(not uuids.get(key) for key in pipes):
        raise OPNsenseAPIError('shaper pipe API did not return a UUID')
    if plan:
        interface, speeds = plan
        for direction in speeds:
            key = '%s%s-%s' % (KEY_PREFIX, interface, direction)
            rules[key] = {'enabled': '1', 'sequence': '1', 'interface': interface,
                          'proto': 'ip', 'source': 'any', 'destination': 'any',
                          'direction': direction, 'target': uuids[key],
                          'description': make_tag(key, 'UniFi Smart Queue')}
    owned = lambda key: not key.startswith(KEY_PREFIX)
    rules_changed, _ = sync.sync_items(RULES, rules, keep=owned)
    # pipes go after the rules that referenced them
    stale_changed, _ = sync.sync_items(PIPES, pipes, keep=owned)
    if pipes_changed or rules_changed or stale_changed:
        result = sync.api.post('trafficshaper/service/reconfigure')
        if not isinstance(result, dict) or str(result.get('status')).lower() != 'ok':
            raise OPNsenseAPIError('traffic shaper reconfigure failed: %s' % result)
    return 1 if plan else 0
