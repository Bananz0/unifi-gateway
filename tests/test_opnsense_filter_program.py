"""Compare emitted PF control flow with an independent chain interpreter."""
import copy
import ipaddress
import itertools

import pytest

from collectors.opnsense_filter_program import FilterProgram
from collectors.opnsense_udapi import UDAPIConfigSync
from tests.test_opnsense_sync import FakeAPI


def chain(name, rules=(), policy=None):
    config = {'name': name, 'logDefault': False}
    if policy:
        config['policy'] = policy
    return {'config': config, 'rules': list(rules)}


TREE = [chain('FORWARD', [
    {'id': 10, 'target': 'A', 'protocol': 'tcp', 'source': {'address': '10.0.0.0/8'},
     'destination': {'port': '80'}},
    {'id': 20, 'target': 'ACCEPT', 'destination': {'address': '192.0.2.0/24'}},
], 'DROP'), chain('A', [
    {'id': 1, 'target': 'RETURN', 'destination': {'address': '192.0.2.7/32'}},
    {'id': 2, 'target': 'B', 'source': {'address': '10.1.0.0/16'}},
    {'id': 3, 'target': 'DROP', 'log': True},
]), chain('B', [{'id': 1, 'target': 'RETURN', 'protocol': 'tcp', 'destination': {'port': '80'}}])]


def network_matches(value, address, local=False):
    if value == 'any':
        return True
    if value == '(self)':
        return local
    return ipaddress.ip_address(address) in ipaddress.ip_network(value, strict=False)


def port_matches(value, port):
    if not value:
        return True
    for item in str(value).split(','):
        if '-' in item:
            low, high = map(int, item.split('-'))
            if low <= port <= high:
                return True
        elif port == int(item):
            return True
    return False


def packet(src='10.1.2.3', dst='192.0.2.8', proto='tcp', port=80, local=False, ingress='opt1'):
    return {'src': src, 'dst': dst, 'proto': proto, 'sport': 30000, 'dport': port,
            'local': local, 'in': ingress, 'out': 'wan'}


def evaluate_pf(rules, pkt):
    """Model PF's ordered match, sticky tag and quick action semantics."""
    tag, action, logs = '', None, []
    for key, row in sorted(rules.items(), key=lambda item: int(item[1]['sequence'])):
        if row['interface'] != pkt['in']:
            continue
        if row.get('tagged') and row['tagged'] != tag:
            continue
        family = 'inet' if ipaddress.ip_address(pkt['src']).version == 4 else 'inet6'
        if row['ipprotocol'] not in ('inet46', family):
            continue
        if row['protocol'] not in ('any', pkt['proto'].upper(), 'TCP/UDP' if pkt['proto'] in ('tcp', 'udp') else ''):
            continue
        if network_matches(row['source_net'], pkt['src']) == (row['source_not'] == '1'):
            continue
        if network_matches(row['destination_net'], pkt['dst'], pkt['local']) == (row['destination_not'] == '1'):
            continue
        if not port_matches(row['source_port'], pkt['sport']) or not port_matches(row['destination_port'], pkt['dport']):
            continue
        if row.get('tag'):
            tag = row['tag']
        action = row['action']
        if row['log'] == '1':
            logs.append((action, key))
        if row['quick'] == '1':
            return action, logs
    return action, logs


def evaluate_controller(section, pkt, root='FORWARD'):
    """Direct call-stack interpretation, independent of the emitted graph."""
    chains = {c['config']['name']: c for c in section}

    def walk(name):
        for rule in sorted(chains[name].get('rules') or [], key=lambda r: r['id']):
            if rule.get('enabled') is False or rule.get('disabled'):
                continue
            if rule.get('inInterface') and rule['inInterface']['id'] != pkt['in']:
                continue
            if rule.get('outInterface') and rule['outInterface']['id'] != pkt['out']:
                continue
            if rule.get('ipVersion', 'both') not in ('both', 'v4only' if ':' not in pkt['src'] else 'v6only'):
                continue
            if rule.get('protocol', 'all') not in ('all', pkt['proto']):
                continue
            matched = True
            for side, addr, port in [('source', 'src', 'sport'), ('destination', 'dst', 'dport')]:
                endpoint = rule.get(side) or {}
                if not network_matches(endpoint.get('address', 'any'), pkt[addr], pkt['local']):
                    matched = False
                if not port_matches(endpoint.get('port'), pkt[port]):
                    matched = False
            if not matched:
                continue
            target = rule['target']
            if target == 'RETURN':
                return None
            if target in chains:
                result = walk(target)
                if result is not None:
                    return result
            else:
                return target
        return None

    return walk(root) or chains[root]['config']['policy']


def compile_program(section, root='FORWARD', **kwargs):
    api = FakeAPI()
    sync = UDAPIConfigSync(api, {'opt1': 'opt1', 'wan': 'wan'}.get, lambda: ['opt1'])
    program = FilterProgram(sync, section, {}, 'opt1', root=root, **kwargs)
    rules, aliases = program.compile()
    assert api.posts == []
    return program, rules, aliases


def test_nested_returns_and_conditional_jumps_match_reference_across_packet_matrix():
    _, rules, aliases = compile_program(TREE)
    assert aliases == {}
    for src, dst, proto, port in itertools.product(
            ['10.1.2.3', '10.2.3.4', '172.16.0.1'],
            ['192.0.2.7', '192.0.2.8', '198.51.100.1'], ['tcp', 'udp'], [53, 80, 443]):
        pkt = packet(src, dst, proto, port)
        expected = {'ACCEPT': 'pass', 'DROP': 'block', 'REJECT': 'reject'}[evaluate_controller(TREE, pkt)]
        assert evaluate_pf(rules, pkt)[0] == expected, pkt


def test_return_from_child_is_not_terminal_accept():
    _, rules, _ = compile_program(TREE)
    assert evaluate_pf(rules, packet())[0] == 'block'  # B returns, then A drops
    assert evaluate_pf(rules, packet(dst='192.0.2.7'))[0] == 'pass'  # A returns to root


def test_block_logging_is_attached_to_final_block_not_intermediate_pass():
    program, rules, _ = compile_program(TREE)
    action, logs = evaluate_pf(rules, packet())
    assert action == 'block' and logs
    assert all(action == 'block' for action, _ in logs)
    assert program.sources[logs[-1][1]] == ('A', 3)


def test_provably_empty_egress_chain_is_removed_without_broadening_policy():
    tree = [chain('FORWARD', [{'id': 1, 'target': 'OUT', 'outInterface': {'id': 'wan'}}], 'DROP'),
            chain('OUT', [{'id': 1, 'target': 'RETURN', 'destination': {'address': '10.0.0.0/8'}}])]
    _, rules, _ = compile_program(tree)
    assert evaluate_pf(rules, packet())[0] == 'block'
    tree[1]['rules'].append({'id': 2, 'target': 'DROP'})
    with pytest.raises(ValueError, match='meaningful egress'):
        compile_program(tree)


def test_unknown_side_effect_is_not_pruned_as_noop_egress():
    tree = [chain('FORWARD', [{'id': 1, 'target': 'OUT', 'outInterface': {'id': 'wan'}}], 'ACCEPT'),
            chain('OUT', [{'id': 1, 'target': 'RETURN', 'setMark': 1}])]
    with pytest.raises(ValueError, match='egress'):
        compile_program(tree)


def test_program_is_scoped_to_one_ingress_and_kernel_path():
    _, forwarding, _ = compile_program([chain('FORWARD', policy='ACCEPT')])
    _, local, _ = compile_program([chain('INPUT', policy='DROP')], root='INPUT')
    assert evaluate_pf(forwarding, packet(ingress='lan'))[0] is None
    assert evaluate_pf(forwarding, packet(local=True))[0] is None
    assert evaluate_pf(local, packet(local=False))[0] is None
    assert evaluate_pf(local, packet(local=True))[0] == 'block'


def test_ipv4_ipv6_rules_keep_their_address_family():
    tree = [chain('FORWARD', [{'id': 1, 'target': 'DROP', 'ipVersion': 'v6only'}], 'ACCEPT')]
    _, rules, _ = compile_program(tree)
    assert evaluate_pf(rules, packet())[0] == 'pass'
    assert evaluate_pf(rules, packet(src='fd00::2', dst='2001:db8::1'))[0] == 'block'


def test_each_tag_transition_points_to_a_later_rule_block():
    _, rules, _ = compile_program(TREE)
    ordered = list(rules.values())
    locations = {r['tagged']: i for i, r in enumerate(ordered) if r.get('tagged')}
    for i, row in enumerate(ordered):
        if row.get('tag'):
            assert locations[row['tag']] > i
    assert all(row['statetype'] == 'none' for row in ordered if row['quick'] == '0')


@pytest.mark.parametrize('mode', ['cycle', 'duplicate_id', 'unknown_field', 'child_policy', 'established_drop'])
def test_unsupported_or_invalid_control_flow_fails_before_installation(mode):
    tree = copy.deepcopy(TREE)
    if mode == 'cycle':
        tree[1]['rules'][0]['target'] = 'A'
    elif mode == 'duplicate_id':
        tree[0]['rules'][1]['id'] = 10
    elif mode == 'unknown_field':
        tree[0]['rules'][0]['schedule'] = {'mode': 'CUSTOM'}
    elif mode == 'child_policy':
        tree[1]['config']['policy'] = 'DROP'
    else:
        tree[1]['rules'][2]['connectionState'] = ['established']
    with pytest.raises(ValueError):
        compile_program(tree)


def test_large_program_and_sequence_overflow_are_explicit_errors():
    with pytest.raises(ValueError, match='node limit'):
        compile_program(TREE, node_limit=2)
    with pytest.raises(ValueError, match='sequence'):
        compile_program(TREE, sequence_start=999999)


def test_captured_default_tree_compiles_with_predefined_rule_ids_intact():
    import json
    from pathlib import Path
    tree = json.loads((Path(__file__).parent / 'fixtures/uxg_setparam_10.6.106.json').read_text())['system_cfg']['udapi']
    api = FakeAPI()
    sync = UDAPIConfigSync(api, {'br0': 'opt1'}.get, lambda: ['opt1'])
    for root in ('INPUT', 'FORWARD'):
        program = FilterProgram(sync, tree['firewall/filter'], sync._collect_sets(tree['firewall/sets']), 'opt1', root=root)
        rules, _ = program.compile()
        assert evaluate_pf(rules, packet(local=root == 'INPUT'))[0] == 'pass'
    assert api.posts == []


@pytest.mark.parametrize('ingress', ['', 'any', 'opt1,wan', None])
def test_empty_or_broad_interface_scope_is_rejected(ingress):
    with pytest.raises(ValueError, match='explicit ingress'):
        FilterProgram(None, [chain('FORWARD', policy='ACCEPT')], {}, ingress)


def test_string_false_does_not_activate_a_return_and_bypass_a_drop():
    tree = [chain('FORWARD', [{'id': 1, 'target': 'RETURN', 'enabled': 'false'},
                              {'id': 2, 'target': 'DROP'}], 'ACCEPT')]
    with pytest.raises(ValueError, match='boolean'):
        compile_program(tree)


def test_established_logging_is_not_silently_ignored():
    tree = [chain('FORWARD', [{'id': 1, 'target': 'RETURN', 'connectionState': ['established'],
                              'log': True}], 'ACCEPT')]
    with pytest.raises(ValueError, match='state-specific logging'):
        compile_program(tree)


def test_unmapped_interface_selector_fails_explicitly_without_preinitialized_context():
    tree = [chain('FORWARD', [{'id': 1, 'target': 'DROP', 'inInterface': {'id': 'unknown'}}], 'ACCEPT')]
    with pytest.raises(ValueError, match='not mapped'):
        compile_program(tree)
