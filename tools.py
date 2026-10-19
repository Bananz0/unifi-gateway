# -*- coding: utf-8 -*-
import re
import socket
import subprocess
import time

try:
    import psutil
except ImportError:  # optional: OPNsense does not ship it
    psutil = None


def mac_string_2_array(mac):
    return [int(i, 16) for i in mac.split(':')]


def ip_string_2_array(ip):
    return [int(i) for i in ip.split('.')]


def netmask_to_cidr(netmask):
    return sum(bin(int(x)).count('1') for x in netmask.split('.'))


def boot_time():
    """System boot time as a Unix timestamp, or None if unknown."""
    if psutil is not None:
        try:
            return psutil.boot_time()
        except Exception:
            pass
    try:
        out = subprocess.check_output(
            ['sysctl', '-n', 'kern.boottime'], stderr=subprocess.DEVNULL, timeout=5
        ).decode('utf-8')
        match = re.search(r'sec = (\d+)', out)
        if match:
            return int(match.group(1))
    except (subprocess.SubprocessError, OSError):
        pass
    return None


def uptime():
    boot = boot_time()
    if boot:
        return int(time.time() - boot)
    try:
        with open('/proc/uptime', 'r') as f:
            return int(float(f.readline().split()[0]))
    except (IOError, OSError):
        return 0


def get_hostname():
    return socket.gethostname()


def get_if_table(data, ports):
    if_list = [d['ifname'] for d in ports]
    wan_if = [d['ifname'] for d in ports if d['type'].lower() == 'wan'][0]
    if_table = []
    if_data = data.get('ifstat', {})

    for iface, info in if_data.items():
        if iface not in if_list or iface not in data.get('ip', {}):
            continue
        if_entry = {
            'drops': int(info['rx_dropped']) + int(info['tx_dropped']),
            'enable': True,
            'full_duplex': True,
            'ip': data['ip'][iface]['address'],
            'mac': data['macs'][iface],
            'name': iface,
            'netmask': data['ip'][iface]['netmask'],
            'num_port': 1,
            'rx_bytes': info['rx_bytes'],
            'rx_bps': info['rx_bps'],
            'rx_dropped': info['rx_dropped'],
            'rx_errors': info['rx_errors'],
            'rx_multicast': info['rx_multicast'],
            'rx_packets': info['rx_packets'],
            'speed': info.get('speed', 1000),
            'tx_bytes': info['tx_bytes'],
            'tx_bps': info['tx_bps'],
            'tx_dropped': info['tx_dropped'],
            'tx_errors': info['tx_errors'],
            'tx_packets': info['tx_packets'],
            'up': True,
            'uptime': uptime(),
        }
        if iface == wan_if:
            if 'gateway' in data['ip'].get(iface, {}):
                if_entry['gateways'] = [data['ip'][iface]['gateway']]
            if_entry['nameservers'] = data.get('nameservers', [])
            if_entry['latency'] = data.get('latency', 0)
            if_entry['speedtest_lastrun'] = data.get('speedtest', {}).get('lastrun', 0)
            if_entry['speedtest_ping'] = data.get('speedtest', {}).get('ping', 0)
            if_entry['speedtest_status'] = 'Idle'
            if_entry['xput_down'] = data.get('speedtest', {}).get('download', 0)
            if_entry['xput_up'] = data.get('speedtest', {}).get('upload', 0)
        if_table.append(if_entry)
    return if_table


def get_network_table(data, ports):
    if_list = [d['ifname'] for d in ports]
    lan_if = [d['ifname'] for d in ports if d['type'].lower() == 'lan'][0]
    wan_if = [d['ifname'] for d in ports if d['type'].lower() == 'wan'][0]
    network_table = []
    lan_ports = {p['ifname']: p.get('realif') for p in ports
                 if p['type'].lower().startswith('lan')}

    for iface in if_list:
        if iface not in data.get('ip', {}):
            continue
        net_entry = {
            'address': '%s/%s' % (data['ip'][iface]['address'], netmask_to_cidr(data['ip'][iface]['netmask'])),
            'addresses': [
                '%s/%s' % (data['ip'][iface]['address'], netmask_to_cidr(data['ip'][iface]['netmask']))
            ],
            'autoneg': 'true',
            'duplex': 'full',
            'l1up': 'true',
            'mac': data['macs'][iface],
            'mtu': '1500',
            'name': iface,
            'speed': '1000',
            'stats': get_net_stats(data, iface),
            'up': 'true',
        }
        if iface in lan_ports:
            net_entry['host_table'] = [
                {k: v for k, v in host.items() if k != 'realif'}
                for host in data.get('host_table', [])
                if (host.get('realif') == lan_ports[iface] if host.get('realif')
                    else iface == lan_if)]
        elif iface == wan_if:
            if 'gateway' in data['ip'].get(iface, {}):
                net_entry['gateways'] = [data['ip'][iface]['gateway']]
            net_entry['nameservers'] = data.get('nameservers', [])
        network_table.append(net_entry)
    return network_table


def get_net_stats(data, iface):
    if_stat = data.get('ifstat', {}).get(iface, {})
    return {
        'multicast': if_stat.get('rx_multicast', '0'),
        'rx_bps': if_stat.get('rx_bps', 0),
        'rx_bytes': if_stat.get('rx_bytes', '0'),
        'rx_dropped': if_stat.get('rx_dropped', '0'),
        'rx_errors': if_stat.get('rx_errors', '0'),
        'rx_multicast': if_stat.get('rx_multicast', '0'),
        'rx_packets': if_stat.get('rx_packets', '0'),
        'tx_bps': if_stat.get('tx_bps', 0),
        'tx_bytes': if_stat.get('tx_bytes', '0'),
        'tx_dropped': if_stat.get('tx_dropped', '0'),
        'tx_errors': if_stat.get('tx_errors', '0'),
        'tx_packets': if_stat.get('tx_packets', '0'),
    }
