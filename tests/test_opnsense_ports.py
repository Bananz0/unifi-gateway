from collectors.opnsense_ports import discover_ports


EXISTING = [{'ifname': 'eth4', 'realif': 're0', 'type': 'wan'},
            {'ifname': 'eth0', 'realif': 'em0', 'type': 'lan'}]


def nic(device, **extra):
    return {'device': device, 'identifier': 'opt3', 'description': 'WAN2',
            'is_physical': True, 'media': 'Ethernet autoselect', **extra}


def test_adds_disabled_wan_without_moving_identity_and_is_idempotent():
    rows = [nic('re1', enabled=False, status='no carrier')]
    ports, warnings = discover_ports(EXISTING, rows)
    assert ports[:2] == EXISTING
    assert ports[2] == {'ifname': 'eth3', 'realif': 're1', 'name': 'WAN2',
                        'type': 'wan2', 'port_idx': 4, 'opnif': 'opt3'}
    assert not warnings
    assert discover_ports(ports, rows) == (ports, [])
    assert len(EXISTING) == 2


def test_virtual_devices_and_wireless_are_not_physical_ports():
    rows = [nic('tailscale0', groups=['tun']),
            nic('bridge0', groups=['bridge']), nic('vlan20', vlan_tag=20),
            nic('zen0', media='', supported_media=[]),
            nic('wlan0', media='IEEE 802.11 Wireless Ethernet', groups=['wlan'])]
    assert discover_ports(EXISTING, rows) == (EXISTING, [])


def test_capacity_overflow_is_explicit_and_deterministic():
    rows = [nic('igb%d' % n, description='OPT%d' % n) for n in range(5)]
    ports, warnings = discover_ports(EXISTING, rows)
    assert len(ports) == 5
    assert len({p['ifname'] for p in ports}) == 5
    assert len(warnings) == 2
    assert discover_ports(EXISTING, list(reversed(rows))) == (ports, warnings)


def test_custom_port_index_is_reserved():
    existing = EXISTING + [{'ifname': 'spare', 'realif': 'igb0',
                            'port_idx': 4, 'type': 'lan2'}]
    ports, _ = discover_ports(existing, [nic('re1')])
    assert ports[-1]['port_idx'] not in {1, 4, 5}


def test_unknown_model_never_assumes_unlimited_ports():
    ports, warnings = discover_ports(EXISTING, [nic('re1')], 'UXGPRO')
    assert ports == EXISTING
    assert warnings
