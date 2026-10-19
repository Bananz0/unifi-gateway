import json, sys, time, os  # run with PROBE_URL set; see docs/uxg-emulation.md
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    import uxg_probe as probe
    s = probe.load()
    CLIENT, CIP = 'aa:bb:cc:00:00:01', '192.168.1.50'
    init = str(int(time.time()) - 600)
    t0 = int(time.time())
    for i in range(1, 10):
        rx, tx = 1000000 * i, 50000 * i
        now = int(time.time())
        extra = {
            'time': now,
            'udapi_version': {'major': 1, 'minor': 0},
            'ipv4_active_leases': [{'mac': CLIENT, 'ip': CIP, 'hostname': 'dpi-test-client', 'expiration': now + 3600, 'network': 'br0'}],
            'if_table': [
                {'name': 'eth0', 'mac': probe.MAC, 'ip': '10.0.5.250', 'netmask': '255.255.255.0', 'up': True, 'speed': 1000, 'full_duplex': True,
                 'rx_bytes': rx * 3, 'tx_bytes': tx * 3, 'rx_packets': 100 * i, 'tx_packets': 50 * i, 'gateways': ['10.0.5.1'], 'nameservers': ['10.0.5.1'],
                 'latency': 5, 'uptime': 3600},
            ],
            'network_table': [{'name': 'br0', 'address': '192.168.1.1/24', 'addresses': ['192.168.1.1/24'], 'mac': probe.MAC, 'up': True,
                               'stats': {'rx_bytes': rx * 2, 'tx_bytes': tx * 2, 'rx_packets': 100 * i, 'tx_packets': 50 * i}}],
            'port_table': [
                {'port_idx': 1, 'mac': probe.MAC, 'num_port': 1, 'name': 'eth1', 'ifname': 'eth1', 'up': True, 'enable': True, 'speed': 1000, 'full_duplex': True, 'media': 'GE',
                 'rx_bytes': rx, 'tx_bytes': tx, 'rx_packets': 100 * i, 'tx_packets': 50 * i,
                 'mac_table': [{'mac': CLIENT, 'ip': CIP, 'hostname': 'dpi-test-client', 'age': 1, 'static': False, 'uptime': 600 + i * 10, 'vlan': 1}]},
                {'port_idx': 5, 'mac': '74:ac:b9:5e:00:02', 'num_port': 1, 'name': 'eth0', 'ifname': 'eth0', 'up': True, 'enable': True, 'speed': 1000, 'full_duplex': True, 'media': 'GE',
                 'is_uplink': True, 'mac_table': []},
            ],
            'dpi_stats': [{'mac': CLIENT, 'initialized': init, 'stats': [
                {'cat': 4, 'app': 112, 'rx_bytes': rx, 'tx_bytes': tx, 'rx_packets': 90 * i, 'tx_packets': 40 * i},
                {'cat': 9, 'app': 61, 'rx_bytes': 2000 * i, 'tx_bytes': 1000 * i, 'rx_packets': 10 * i, 'tx_packets': 10 * i}]}],
        }
        extra['dpi_stats'] = probe.up._modern_dpi_stats(extra['dpi_stats'])
        r = probe.inform(s, extra); probe.handle(s, r)
        print(i, r.get('_type'), {k: v for k, v in r.items() if k not in ('_type', 'server_time_in_utc', 'system_cfg', 'mgmt_cfg', 'interval')})
        time.sleep(10)


if __name__ == "__main__":
    main()
