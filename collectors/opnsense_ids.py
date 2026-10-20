# -*- coding: utf-8 -*-
"""UniFi Threat Management (UDAPI ``services.idsIps``) on OPNsense Suricata.

Network 10.6 sends ``{enabled, mode, signatures, interfaces, blockTime,
suppress}``; ``signatures`` are ET Open category names, which match
OPNsense's ruleset files (``emerging-malware`` -> ``emerging-malware.rules``).

The translation is additive: it enables Suricata, the listed rulesets and
the listed interfaces, but never disables rulesets or interfaces the
operator chose in OPNsense, and never switches Suricata into inline IPS
(netmap) mode, which would compete with Zenarmor for the same interfaces.
A blocking mode is reported as a warning instead.
"""
import logging

from .opnsense_api import OPNsenseAPIError

logger = logging.getLogger('unifi-gateway')

# UniFi category -> OPNsense ruleset file where the names differ
RULESET_ALIASES = {'botcc-portgrouped': 'botcc.portgrouped.rules'}


def _selected(value):
    """OPNsense option lists come back as {key: {value, selected}}."""
    if isinstance(value, dict):
        return [k for k, v in value.items() if isinstance(v, dict) and v.get('selected')]
    return [v for v in str(value or '').split(',') if v]


def apply_ids(api, ids, resolve_interface, warn):
    """Returns the number of rulesets newly enabled."""
    if not isinstance(ids, dict) or not ids.get('enabled'):
        return 0
    try:
        general = api.get('ids/settings/get')['ids']['general']
        rulesets = api.get('ids/settings/list_rulesets').get('rows', [])
    except (OPNsenseAPIError, KeyError, TypeError) as e:
        warn('threat management not applied: Suricata (os-suricata) unavailable: %s' % e)
        return 0

    files = {r.get('filename'): r for r in rulesets}
    wanted = []
    for category in ids.get('signatures') or []:
        filename = RULESET_ALIASES.get(category, '%s.rules' % category)
        if filename in files:
            wanted.append(filename)
        else:
            warn('threat management: category %s has no OPNsense ruleset' % category)
    to_enable = [f for f in wanted if files[f].get('enabled') != '1']

    interfaces = set(_selected(general.get('interfaces')))
    added_ifs = set()
    for iface in ids.get('interfaces') or []:
        opn_if = resolve_interface(iface.get('id') if isinstance(iface, dict) else iface)
        if opn_if and opn_if not in interfaces:
            added_ifs.add(opn_if)
    if 'blocking' in str(ids.get('mode', '')) and general.get('ips') != '1':
        warn('threat management: UniFi asks for blocking (IPS); Suricata is left in '
             'detection mode because inline IPS would compete with Zenarmor for netmap. '
             'Enable IPS mode in OPNsense if that is wanted.')

    changed = False
    if general.get('enabled') != '1' or added_ifs:
        payload = {'ids': {'general': {
            'enabled': '1',
            'interfaces': ','.join(sorted(interfaces | added_ifs)),
        }}}
        api.post('ids/settings/set', payload)
        changed = True
    if to_enable:
        api.post('ids/settings/toggle_ruleset/%s/1' % ','.join(to_enable))
        changed = True
    if changed:
        api.post('ids/service/reconfigure')
        if to_enable:
            api.post('ids/service/update_rules')
        logger.info('Threat management applied to Suricata: rulesets %s, interfaces %s',
                    to_enable or 'unchanged', sorted(added_ifs) or 'unchanged')
    return len(to_enable)
