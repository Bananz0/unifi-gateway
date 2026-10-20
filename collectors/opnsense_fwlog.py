# -*- coding: utf-8 -*-
"""Blocked connections from OPNsense's firewall log, as UXG flow triggers.

A real UXG reports the packets its firewall drops as ``triggers`` in the
inform; Network 10.6 stores each as a blocked Traffic Flow attributed to the
UniFi policy whose id it carries (an unresolvable policy is still recorded
as blocked). This module tails ``diagnostics/firewall/log`` and turns block
entries into those triggers, naming the mirrored ``[OPNsense]`` UniFi rule
when the log label matches one.
"""
import collections
import ipaddress
import logging
import time

from .opnsense_api import OPNsenseAPIError

logger = logging.getLogger('unifi-gateway')

MAX_PENDING = 2000
LOG_LIMIT = 1000
# stands in for OPNsense's own rules (default deny, bogons...) that have no
# UniFi object; a fixed ObjectId so the controller groups them together
DEFAULT_POLICY_ID = '000000000000000000000001'


class FirewallLogTriggers:

    def __init__(self, api, interface_names, policy_ids=None):
        """``interface_names`` maps an OPNsense device (re0) to the token the
        inform builder translates (wan, lan); ``policy_ids`` returns
        {OPNsense rule description: UniFi rule _id}."""
        self.api = api
        self.interface_names = interface_names
        self.policy_ids = policy_ids or (lambda: {})
        self._seen = collections.OrderedDict()
        self._pending = collections.deque(maxlen=MAX_PENDING)
        self._started = None

    def poll(self):
        try:
            rows = self.api.get('diagnostics/firewall/log', params={'limit': LOG_LIMIT})
        except OPNsenseAPIError as e:
            logger.debug('Firewall log unavailable: %s', e)
            return 0
        if not isinstance(rows, list):
            return 0
        first = self._started is None
        if first:
            self._started = time.time()
        policies = None
        added = 0
        for row in reversed(rows):              # the API returns newest first
            digest = row.get('__digest__')
            if not digest or digest in self._seen:
                continue
            self._seen[digest] = True
            if first or row.get('action') != 'block':
                continue                         # no replay of old history
            if policies is None:
                try:
                    policies = self.policy_ids()
                except Exception as e:  # the mirror may be unreachable
                    logger.debug('UniFi policy lookup failed: %s', e)
                    policies = {}
            trigger = self._trigger(row, policies)
            if trigger:
                self._pending.append(trigger)
                added += 1
        while len(self._seen) > LOG_LIMIT * 4:
            self._seen.popitem(last=False)
        return added

    def take(self, limit=200):
        return [self._pending.popleft() for _ in range(min(limit, len(self._pending)))]

    def _trigger(self, row, policies):
        try:
            src = ipaddress.ip_address(row.get('src'))
            dst = ipaddress.ip_address(row.get('dst'))
            proto = int(row.get('protonum'))
        except (TypeError, ValueError):
            return None
        if dst.is_multicast or src.is_multicast:
            return None                          # routing chatter, not a flow
        try:
            stamp = time.mktime(time.strptime(row['__timestamp__'][:19], '%Y-%m-%dT%H:%M:%S'))
        except (KeyError, ValueError):
            stamp = time.time()
        iface = self.interface_names.get(row.get('interface'), row.get('interface'))
        ip = {'saddr': str(src), 'daddr': str(dst), 'protocol': proto,
              'version': 'v%d' % src.version}
        if row.get('srcport') and row.get('dstport'):
            ip.update(sport=int(row['srcport']), dport=int(row['dstport']))
        trigger = {
            'id': policies.get(row.get('label') or '', DEFAULT_POLICY_ID),
            'type': 'FIREWALL_RULE',
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(stamp)),
            'ip': ip,
            'ethernet': {'protocol': proto, 'family': 2 if src.version == 4 else 10},
            'stats': {'bytes': int(row.get('length') or 0), 'packets': 1},
            ('in' if row.get('dir') == 'in' else 'out'): iface,
        }
        return trigger
