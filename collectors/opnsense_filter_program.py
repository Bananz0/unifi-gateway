"""Compile UDAPI chain calls/returns into a scoped PF packet-tag program.

This compiler runs before source NAT, so source address/port predicates retain
their controller meaning. Egress-dependent branches are accepted only when
their callee is provably a no-op; meaningful egress constraints remain explicit
errors until a NAT-aware egress representation is implemented. No generated
rules are installed by importing or compiling this module.
"""
import collections
import hashlib
import heapq
import json
import re

from .opnsense_sync import make_tag
from .opnsense_udapi import RULE_KEYS


class FilterProgram:
    def __init__(self, sync, section, sets, ingress, root='FORWARD', sequence_start=700000,
                 node_limit=2048):
        if root not in ('INPUT', 'FORWARD'):
            raise ValueError('unsupported packet-processing root')
        if not isinstance(ingress, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,31}', ingress) or ingress == 'any':
            raise ValueError('a single explicit ingress interface is required')
        if not isinstance(section, list):
            raise ValueError('filter program requires a complete chain list')
        self.sync, self.sets, self.ingress, self.root = sync, sets, ingress, root
        self.sequence_start, self.node_limit = sequence_start, node_limit
        self.chains, self.configs = {}, {}
        for chain in section:
            if not isinstance(chain, dict):
                raise ValueError('invalid firewall chain record')
            config = chain.get('config') or {}
            name = config.get('name')
            if not name or name in self.chains:
                raise ValueError('missing or duplicate firewall chain name')
            if set(chain) - {'config', 'rules'} or set(config) - {'name', 'policy', 'logDefault'}:
                raise ValueError('unsupported firewall chain settings')
            if name not in ('INPUT', 'FORWARD', 'OUTPUT') and config.get('policy'):
                raise ValueError('non-root chain policies are unsupported')
            rules = chain.get('rules') or []
            if not isinstance(rules, list):
                raise ValueError('invalid chain rule list')
            if any(not isinstance(rule, dict) for rule in rules):
                raise ValueError('invalid firewall rule record')
            ids = [r.get('id') for r in rules]
            if any(isinstance(n, bool) or not isinstance(n, int) or not 0 <= n < 2**32 for n in ids) or len(set(ids)) != len(ids):
                raise ValueError('invalid or duplicate rule IDs')
            self.chains[name] = sorted(rules, key=lambda r: r['id'])
            self.configs[name] = config
        if root not in self.chains or self.configs[root].get('policy') not in ('ACCEPT', 'DROP', 'REJECT'):
            raise ValueError('explicit root firewall policy is required')
        self.nodes, self._ids, self._queue = [], {}, collections.deque()
        self.aliases, self.sources = {}, {}
        self._noop_cache = {}
        self._digest = hashlib.sha256(json.dumps([ingress, root, section], sort_keys=True).encode()).hexdigest()[:12]

    @staticmethod
    def _enabled(rule):
        if any(key in rule and not isinstance(rule[key], bool) for key in ('enabled', 'disabled')):
            raise ValueError('firewall enabled/disabled flags must be boolean')
        return rule.get('enabled', True) is not False and not rule.get('disabled')

    def _noop(self, chain, path=()):
        if chain in path:
            return False
        if chain in self._noop_cache:
            return self._noop_cache[chain]
        if self.configs[chain].get('logDefault'):
            return False
        for rule in self.chains[chain]:
            if not self._enabled(rule):
                continue
            target = rule.get('target')
            if rule.get('log') or rule.get('triggerTag') or set(rule) - RULE_KEYS:
                return False
            if target != 'RETURN' and not (target in self.chains and self._noop(target, path + (chain,))):
                return False
        self._noop_cache[chain] = True
        return True

    def _interface(self, ref):
        if isinstance(ref, dict):
            if set(ref) != {'id'}:
                raise ValueError('unsupported interface selector')
            ref = ref['id']
        identifier = self.sync.resolve_interface(ref)
        if not identifier:
            raise ValueError('firewall interface selector is not mapped')
        return identifier

    def _skip(self, rule):
        if not self._enabled(rule):
            return True
        if rule.get('inInterface') and self._interface(rule['inInterface']) != self.ingress:
            return True
        if set(rule) - RULE_KEYS:
            raise ValueError('unsupported firewall rule fields')
        target = rule.get('target')
        if rule.get('outInterface'):
            if target in self.chains and self._noop(target) and not rule.get('log') and not rule.get('triggerTag'):
                return True
            raise ValueError('meaningful egress-interface condition requires NAT-aware egress compilation')
        states = rule.get('states', rule.get('connectionStates', rule.get('connectionState')))
        if states is not None:
            if not isinstance(states, list):
                states = [states]
            states = {str(state).lower() for state in states}
            if 'new' not in states:
                if states and states <= {'established', 'related'} and target in ('ACCEPT', 'RETURN'):
                    if rule.get('log') or rule.get('triggerTag'):
                        raise ValueError('state-specific logging requires state-table integration')
                    return True  # PF handles established/related states before rules
                raise ValueError('state-specific filtering cannot be represented by this new-flow program')
            if states - {'new', 'established', 'related'}:
                raise ValueError('unsupported connection states')
        return False

    def _root_terminal(self):
        config = self.configs[self.root]
        return ('terminal', config['policy'], bool(config.get('logDefault')), self.root, 'policy')

    def _normalize(self, state):
        while state[0] == 'pc':
            _, chain, index, stack = state
            if index == len(self.chains[chain]):
                if not stack:
                    return self._root_terminal()
                caller, following = stack[-1]
                state = ('pc', caller, following, stack[:-1])
            elif self._skip(self.chains[chain][index]):
                state = ('pc', chain, index + 1, stack)
            else:
                break
        return state

    def _intern(self, state):
        state = self._normalize(state)
        if state in self._ids:
            return self._ids[state]
        if len(self.nodes) >= self.node_limit:
            raise ValueError('firewall control-flow program exceeds the node limit')
        index = len(self.nodes)
        self._ids[state] = index
        self.nodes.append({'state': state})
        self._queue.append(index)
        return index

    def compile(self):
        # Treat a compiler instance as single-use so accidental reuse cannot
        # retain old aliases/control-flow state across controller snapshots.
        if self.nodes:
            raise ValueError('filter compiler instances are single-use')
        entry = self._intern(('pc', self.root, 0, ()))
        while self._queue:
            index = self._queue.popleft()
            node = self.nodes[index]
            state = node['state']
            if state[0] == 'terminal':
                continue
            _, chain, offset, stack = state
            rule = self.chains[chain][offset]
            target = rule.get('target')
            following = ('pc', chain, offset + 1, stack)
            if target in self.chains:
                if target in {chain} | {frame[0] for frame in stack}:
                    raise ValueError('cyclic firewall chain call')
                if target in ('INPUT', 'FORWARD', 'OUTPUT'):
                    raise ValueError('jump into a firewall root chain is unsupported')
                outcome = ('pc', target, 0, stack + ((chain, offset + 1),))
            elif target == 'RETURN':
                outcome = ('pc', stack[-1][0], stack[-1][1], stack[:-1]) if stack else self._root_terminal()
            elif target in ('ACCEPT', 'DROP', 'REJECT'):
                outcome = ('terminal', target, bool(rule.get('log')), chain, rule['id'])
            else:
                raise ValueError('unsupported firewall target')
            predicate = dict(rule, target='ACCEPT', id=1)
            predicate.pop('inInterface', None)
            predicate.pop('outInterface', None)
            payload = self.sync._udapi_rule_payload(predicate, 'ufp-%s-%s' % (self._digest, index),
                self.ingress, 'in', False, self.sets, self.aliases)
            node.update(predicate=payload, rule=rule,
                        yes=self._intern(outcome), no=self._intern(following))
        # Every transition must point forward in the resulting PF rule list.
        # Topological ordering is essential when callers share continuations.
        degree = [0] * len(self.nodes)
        for node in self.nodes:
            for child in {node.get('yes'), node.get('no')} - {None}:
                degree[child] += 1
        ready = [i for i, count in enumerate(degree) if not count]
        heapq.heapify(ready)
        order = []
        while ready:
            index = heapq.heappop(ready)
            order.append(index)
            for child in {self.nodes[index].get('yes'), self.nodes[index].get('no')} - {None}:
                degree[child] -= 1
                if not degree[child]:
                    heapq.heappush(ready, child)
        if len(order) != len(self.nodes):
            raise ValueError('cyclic firewall control-flow graph')
        rules = {}
        sequence = self.sequence_start

        def tag(index):
            return 'ufg_%s_%d' % (self._digest, index)

        def emit(suffix, **fields):
            nonlocal sequence
            if not 1 <= sequence <= 999999:
                raise ValueError('firewall program exceeds the available sequence range')
            key = 'ufp-%s-%s' % (self._digest, suffix)
            payload = {'enabled': '1', 'action': 'pass', 'quick': '0', 'statetype': 'none',
                'interface': self.ingress, 'direction': 'in', 'ipprotocol': 'inet46',
                'protocol': 'any', 'source_net': 'any', 'source_not': '0', 'source_port': '',
                'destination_net': 'any', 'destination_not': '0', 'destination_port': '',
                'log': '0', 'tag': '', 'tagged': '', 'sequence': str(sequence),
                'description': make_tag(key, self.root + ' packet program')}
            payload.update(fields)
            rules[key] = payload
            sequence += 1
            return key

        destination_not = '0' if self.root == 'INPUT' else '1'
        emit('entry', destination_net='(self)', destination_not=destination_not, tag=tag(entry))
        for index in order:
            node = self.nodes[index]
            if node['state'][0] == 'terminal':
                _, action, log, chain, rule_id = node['state']
                key = emit('%d-end' % index, action={'ACCEPT': 'pass', 'DROP': 'block', 'REJECT': 'reject'}[action],
                    quick='1', statetype='keep' if action == 'ACCEPT' else 'none',
                    **{'state-policy': 'floating'}, tagged=tag(index), log='1' if log else '0')
                self.sources[key] = (chain, rule_id)
                continue
            predicate = {k: v for k, v in node['predicate'].items()
                         if k not in {'description', 'sequence', 'log'}}
            predicate.update(action='pass', quick='0', statetype='none',
                             tag=tag(node['yes']), tagged=tag(index))
            if node['rule'].get('log') and node['rule'].get('target') not in ('ACCEPT', 'DROP', 'REJECT'):
                predicate['log'] = '1'
            emit('%d-yes' % index, **predicate)
            emit('%d-no' % index, tagged=tag(index), tag=tag(node['no']))
        emit('guard', action='block', quick='1', log='1',
             destination_net='(self)', destination_not=destination_not)
        return rules, self.aliases
