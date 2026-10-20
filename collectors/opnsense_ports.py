"""Stable, observational mapping of OPNsense Ethernet NICs to UXG ports.

Never change interface assignments or move an existing controller port.
Virtual networks and radios are not extra front-panel Ethernet sockets.
"""
import re


def discover_ports(existing, overview, model='UXGB'):
    ports = [dict(p) for p in existing]
    warnings = []
    # A UXG-Max has five front-panel sockets. Do not fabricate extra ports
    # the controller's model cannot represent. Other models require an
    # explicit capacity mapping before automatic discovery is enabled.
    capacity = {'UXGB': 5}.get(model.upper())
    if capacity is None:
        return ports, ['automatic port discovery is not defined for model %s' % model]
    used_devices = {p['realif'] for p in ports}
    used_names = {p['ifname'] for p in ports}
    used_indexes = {int(p['port_idx']) for p in ports if p.get('port_idx')}
    for row in sorted(overview, key=lambda r: r.get('device', '')):
        device = row.get('device', '')
        if not device or device in used_devices:
            continue
        groups = row.get('groups') or []
        if isinstance(groups, str):
            groups = groups.split()
        media = ' '.join(str(v) for v in row.get('supported_media') or [])
        media += ' ' + str(row.get('media') or '')
        if (row.get('is_physical') is not True or
                set(groups) & {'tun', 'tap', 'bridge', 'vlan', 'wlan', 'epair'} or
                row.get('vlan_tag') not in (None, '', 0, '0') or
                not re.search(r'ethernet|\d+(?:g)?base', media, re.I)):
            continue
        wan = bool(re.match(r'^WAN(?:\d+)?$', str(row.get('description', '')), re.I))
        # Reserve the model's second WAN socket where available. Existing
        # mappings always win, even if they use a different port layout.
        order = ([3, 4, 0, 1, 2] if wan else [0, 1, 2, 3, 4])
        slot = next((i for i in order if 'eth%d' % i not in used_names
                     and i + 1 not in used_indexes), None)
        if slot is None:
            warnings.append('%s cannot be mapped: %s has only %d physical ports' %
                            (device, model, capacity))
            continue
        existing_roles = {p['type'].lower() for p in ports}
        prefix = 'wan' if wan else 'lan'
        role = next(prefix + str(i) for i in range(2, capacity + 2)
                    if prefix + str(i) not in existing_roles)
        port = {'ifname': 'eth%d' % slot, 'realif': device,
                'name': row.get('description') or device, 'type': role,
                'port_idx': slot + 1}
        if row.get('identifier'):
            port['opnif'] = row['identifier']
        ports.append(port)
        used_names.add(port['ifname'])
        used_devices.add(device)
        used_indexes.add(slot + 1)
    return ports, warnings
