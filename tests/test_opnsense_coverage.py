from collectors.opnsense_coverage import untranslated_paths


def test_reports_vpn_dhcp_ipv6_and_qos_gaps_without_values():
    report = untranslated_paths({
        'interfaces': [{'identification': {'id': 'eth4'}, 'addresses': [],
                        'vlan': {'id': 20}, 'ethernet': {'mac': 'private-mac'}}],
        'services': {
            'wireguard': {'privateKey': 'PRIVATE-KEY-DO-NOT-LOG'},
            'dhcpServers': [{'name': 'PRIVATE-NAME', 'rangeStart': '10.1.1.2',
                             'ipVersion': 'v6', 'staticLeases': []}],
            'dnsForwarder': {'hostRecords': [], 'listenInterfaces': ['br0']},
        }, 'qos': {'rate': 1},
    })
    assert 'services/wireguard' in report
    assert 'services/dhcpServers/*/rangeStart' in report
    assert 'services/dhcpServers/*/ipVersion' in report
    assert 'interfaces/*/vlan' in report
    assert 'qos' in report
    assert not any('PRIVATE' in p or '10.1.1.2' in p for p in report)


def test_translated_sections_and_controller_transport_are_not_false_gaps():
    assert untranslated_paths({'firewall/filter': [], 'routes/static': [],
        'unifi': {'secret': 'x'}, 'version': '1',
        'services': {'unifiNetwork': {}, 'idsIps': {},
                     'dnsForwarder': {'hostRecords': []}}}) == []
