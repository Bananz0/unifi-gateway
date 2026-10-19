from tools import get_network_table


def test_clients_follow_observed_lan_without_leaking_internal_interface():
    ports = [
        {'ifname': 'eth0', 'realif': 're0', 'type': 'wan'},
        {'ifname': 'eth1', 'realif': 'em0', 'type': 'lan'},
        {'ifname': 'eth2', 'realif': 'vlan20', 'type': 'lan2'},
    ]
    data = {
        'ip': {p['ifname']: {'address': '10.0.0.1', 'netmask': '255.255.255.0'}
               for p in ports},
        'macs': {p['ifname']: '00:11:22:33:44:55' for p in ports},
        'host_table': [
            {'mac': 'a', 'realif': 'em0'},
            {'mac': 'b', 'realif': 'vlan20'},
            {'mac': 'legacy'},
            {'mac': 'unknown', 'realif': 'other'},
        ],
    }
    networks = {n['name']: n for n in get_network_table(data, ports)}
    assert networks['eth1']['host_table'] == [{'mac': 'a'}, {'mac': 'legacy'}]
    assert networks['eth2']['host_table'] == [{'mac': 'b'}]
    assert 'host_table' not in networks['eth0']
