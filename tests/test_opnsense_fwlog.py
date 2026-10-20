# -*- coding: utf-8 -*-
"""OPNsense firewall-log blocks reported as UXG flow triggers."""
from collectors.opnsense_api import OPNsenseAPIError
from collectors.opnsense_fwlog import DEFAULT_POLICY_ID, FirewallLogTriggers


def entry(digest, action='block', label='Default deny / state violation rule', **kw):
    row = {'__digest__': digest, 'action': action, 'label': label, 'interface': 're0',
           'dir': 'in', 'protonum': '6', 'src': '79.124.62.230', 'dst': '102.140.218.150',
           'srcport': '55634', 'dstport': '20638', 'length': '44',
           '__timestamp__': '2026-10-20T03:41:35'}
    row.update(kw)
    return row


class FakeAPI:
    def __init__(self):
        self.rows = []

    def get(self, path, params=None, timeout=None):
        assert path == 'diagnostics/firewall/log'
        if self.rows is None:
            raise OPNsenseAPIError('down')
        return list(reversed(self.rows))       # newest first, like the API


def make(policies=None):
    api = FakeAPI()
    return api, FirewallLogTriggers(api, {'re0': 'wan', 'em0': 'lan'},
                                    lambda: policies or {})


def test_history_is_skipped_then_blocks_become_triggers():
    api, log = make({'Block IoT': 'aaaaaaaaaaaaaaaaaaaaaaaa'})
    api.rows = [entry('old')]
    assert log.poll() == 0 and log.take() == []
    api.rows += [entry('d1'), entry('p1', action='pass'),
                 entry('d2', label='Block IoT', interface='em0', dir='out', protonum='17',
                       src='10.0.5.60', dst='8.8.8.8', srcport='5000', dstport='53'),
                 entry('m1', dst='224.0.0.5', protonum='89', srcport='', dstport='')]
    assert log.poll() == 2
    default, iot = log.take()
    assert default['id'] == DEFAULT_POLICY_ID and default['type'] == 'FIREWALL_RULE'
    assert default['in'] == 'wan' and 'out' not in default
    assert default['ip'] == {'saddr': '79.124.62.230', 'daddr': '102.140.218.150',
                             'protocol': 6, 'version': 'v4', 'sport': 55634, 'dport': 20638}
    assert default['stats'] == {'bytes': 44, 'packets': 1}
    assert default['timestamp'].endswith('Z')
    assert iot['id'] == 'aaaaaaaaaaaaaaaaaaaaaaaa' and iot['out'] == 'lan'
    assert iot['ip']['protocol'] == 17
    # already-seen entries are not reported twice
    assert log.poll() == 0


def test_api_failure_is_quiet():
    api, log = make()
    api.rows = None
    assert log.poll() == 0
