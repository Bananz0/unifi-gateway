# -*- coding: utf-8 -*-
"""UniFi Threat Management -> OPNsense Suricata (additive)."""
from collectors.opnsense_ids import apply_ids

IDS = {'enabled': True, 'mode': 'pcap-l3-blocking-high', 'blockTime': 300,
       'signatures': ['emerging-malware', 'emerging-scan', 'botcc', 'dark-web-blocker-list'],
       'interfaces': [{'id': 'br0'}], 'suppress': []}


class FakeAPI:
    def __init__(self, enabled='1', interfaces=('wan',), ips='0'):
        self.posts = []
        self.general = {'enabled': enabled, 'ips': ips, 'interfaces': {
            name: {'value': name, 'selected': 1} for name in interfaces}}
        self.rulesets = [{'filename': 'emerging-malware.rules', 'enabled': '0'},
                         {'filename': 'emerging-scan.rules', 'enabled': '0'},
                         {'filename': 'botcc.rules', 'enabled': '1'},
                         {'filename': 'drop.rules', 'enabled': '1'}]

    def get(self, path, params=None, timeout=None):
        return {'ids/settings/get': {'ids': {'general': self.general}},
                'ids/settings/list_rulesets': {'rows': self.rulesets}}[path]

    def post(self, path, payload=None, timeout=None):
        self.posts.append((path, payload))
        return {'status': 'ok'}


def run(api):
    warnings = []
    n = apply_ids(api, IDS, {'br0': 'lan'}.get, warnings.append)
    return n, warnings, [p for p, _ in api.posts], dict(api.posts)


def test_enables_matching_rulesets_and_interfaces_additively():
    api = FakeAPI()
    n, warnings, paths, posts = run(api)
    assert n == 2
    assert 'ids/settings/toggle_ruleset/emerging-malware.rules,emerging-scan.rules/1' in paths
    # the operator's WAN stays, the UniFi LAN is added; nothing is disabled
    assert posts['ids/settings/set']['ids']['general']['interfaces'] == 'lan,wan'
    assert not any(p.endswith('/0') for p in paths)
    assert 'ids/service/reconfigure' in paths
    assert any('dark-web-blocker-list' in w for w in warnings)
    assert any('detection mode' in w for w in warnings)   # never switches to inline IPS


def test_nothing_to_do_and_disabled():
    api = FakeAPI(interfaces=('wan', 'lan'))
    for r in api.rulesets:
        r['enabled'] = '1'
    n, _, paths, _ = run(api)
    assert n == 0 and paths == []
    assert apply_ids(FakeAPI(), {'enabled': False}, {}.get, print) == 0


def test_inline_suricata_gets_no_new_interfaces():
    """Production: Suricata in IPS (netmap) mode; adding the LAN put it
    inline next to Zenarmor. Only rulesets may change then."""
    api = FakeAPI(ips='1')
    n, warnings, paths, _ = run(api)
    assert n == 2 and 'ids/settings/set' not in paths
    assert any('runs inline' in w for w in warnings)
