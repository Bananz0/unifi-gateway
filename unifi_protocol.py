# -*- coding: utf-8 -*-
import time
import json
import re
import ast
import os

import logging
import zlib
try:
    import snappy
    HAS_SNAPPY = True
except ImportError:
    HAS_SNAPPY = False

# AES backend: pycryptodome when installed, otherwise the `cryptography`
# package (which OPNsense ships as a core dependency, unlike pycryptodome).
try:
    from Crypto.Cipher import AES as _AES
except ImportError:
    _AES = None
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
except ImportError:
    if _AES is None:
        raise ImportError('Install pycryptodome or cryptography for AES support')

logger = logging.getLogger('unifi-gateway')

from struct import pack, unpack
from binascii import a2b_hex

from tlv import UnifiTLV
from tools import (
    mac_string_2_array, ip_string_2_array, netmask_to_cidr,
    uptime, get_hostname, get_if_table, get_network_table,
)

MASTER_KEY = "ba86f2bbe107c7c57eb5f2690775c712"

# UXG-class models (type uxg in Network 10.6). They share the inform protocol
# with the USG but are provisioned with UDAPI and report clients differently.
UXG_MODELS = {'UXG', 'UXGB', 'UXGPRO', 'UXGA6AA'}
# The controller warns "Skip updating capability ... due to empty
# udapi_version" without it; this value was accepted in the lab adoption.
UDAPI_VERSION = {'major': 1, 'minor': 0}
# The controller stores this verbatim as the device's gw_caps.caps; on
# Network 10.6 it only carries IPS engine data (Suricata versions), which
# this emulator doesn't provide, so it is empty. Sent when a noop asks for it.
GW_CAPS = {}
# usg_caps bits (Network 10.6 device model): only what the emulator
# implements. 1 = DPI (also implied by has_dpi), 0x20000000 = trigger logs:
# firewall triggers in the inform become blocked Traffic Flows. IPS (128),
# ad blocking (0x40000000) and schedules (32) stay off,
# so the controller doesn't offer settings the translator can't apply.
USG_CAPS = 0x1 | 0x20000000
# Region Blocking, offered only when OPNsense has a GeoIP database to apply it
GEOIP_CAP = 0x40
# Threat Management (IDS/IPS + signature categories), applied to OPNsense
# Suricata when the operator opts in with [opnsense] ips = true
IPS_CAPS = 0x80 | 0x2000
AES_BLOCK_SIZE = 16


def _cbc_encrypt(key, iv, data):
    if _AES:
        return _AES.new(key, _AES.MODE_CBC, iv).encrypt(data)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def _cbc_decrypt(key, iv, data):
    if _AES:
        return _AES.new(key, _AES.MODE_CBC, iv).decrypt(data)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def _gcm_encrypt(key, iv, aad, data):
    """Return the ciphertext with the 16-byte tag appended."""
    if _AES:
        aes = _AES.new(key, _AES.MODE_GCM, iv)
        aes.update(aad)
        ciphertext, tag = aes.encrypt_and_digest(data)
        return ciphertext + tag
    return AESGCM(key).encrypt(iv, data, aad)


def _gcm_decrypt(key, iv, aad, data):
    """Decrypt ciphertext+tag; raises ValueError if authentication fails."""
    if _AES:
        aes = _AES.new(key, _AES.MODE_GCM, iv)
        aes.update(aad)
        return aes.decrypt_and_verify(data[:-16], data[-16:])
    try:
        return AESGCM(key).decrypt(iv, data, aad)
    except InvalidTag:
        raise ValueError('MAC check failed')


def encode_inform(config, data, encryption='CBC'):
    iv = os.urandom(16)
    key = MASTER_KEY

    if config.getboolean('gateway', 'is_adopted'):
        key = config.get('gateway', 'key')
    # a controller that has seen this MAC use AES-GCM rejects later CBC
    # informs as a downgrade, even after the device was forgotten
    if config.has_option('gateway', 'use_aes_gcm'):
        encryption = 'GCM' if config.getboolean('gateway', 'use_aes_gcm') else 'CBC'

    mac = config.get('gateway', 'lan_mac')

    # Flags: bit 0 = encrypted, bit 1 = zlib, bit 2 = snappy, bit 3 = GCM
    flags = 0x01
    if encryption == 'GCM':
        flags |= 0x08

    if HAS_SNAPPY:
        payload = snappy.compress(data.encode('utf-8'))
        flags |= 0x04
    else:
        payload = zlib.compress(data.encode('utf-8'))
        flags |= 0x02

    encoded_data = b'TNBU'
    encoded_data += pack('>I', 1)
    encoded_data += pack('BBBBBB', *mac_string_2_array(mac))
    encoded_data += pack('>H', flags)
    encoded_data += iv
    encoded_data += pack('>I', 1)

    if encryption == 'GCM':
        encoded_data += pack('>I', len(payload) + 16)
        payload = _gcm_encrypt(a2b_hex(key), iv, encoded_data, payload)
    elif encryption == 'CBC':
        pad_len = AES_BLOCK_SIZE - (len(payload) % AES_BLOCK_SIZE)
        payload += bytes([pad_len]) * pad_len
        payload = _cbc_encrypt(a2b_hex(key), iv, payload)
        encoded_data += pack('>I', len(payload))

    encoded_data += payload
    return encoded_data


def decode_inform(config, encoded_data):
    magic = encoded_data[0:4]
    if magic != b'TNBU':
        raise Exception("Missing magic in response: '{}' instead of 'TNBU'".format(magic))

    header = encoded_data[:40]
    flags = unpack('>H', encoded_data[14:16])[0]
    iv = encoded_data[16:32]
    payload_len = unpack('>I', encoded_data[36:40])[0]
    payload = encoded_data[40:(40 + payload_len)]

    flag = {
        'encrypted': bool(flags & 0x01),
        'zlibCompressed': bool(flags & 0x02),
        'SnappyCompression': bool(flags & 0x04),
        'encryptedGCM': bool(flags & 0x08),
    }

    key = MASTER_KEY
    if config.getboolean('gateway', 'is_adopted'):
        key = config.get('gateway', 'key')

    if flag['encrypted']:
        if flag['encryptedGCM']:
            payload = _gcm_decrypt(a2b_hex(key), iv, header, payload)
        else:
            payload = _cbc_decrypt(a2b_hex(key), iv, payload)
            pad_size = payload[-1]
            if pad_size > AES_BLOCK_SIZE:
                raise Exception('Response not padded or padding is corrupt')
            payload = payload[:(len(payload) - pad_size)]

    if flag['SnappyCompression']:
        if HAS_SNAPPY:
            payload = snappy.decompress(payload)
        else:
            raise Exception(
                'Response is snappy-compressed but python-snappy is not installed'
            )
    elif flag['zlibCompressed']:
        payload = zlib.decompress(payload)

    return json.loads(payload)


def _resolve_lan_identity(config, dc, lan_if):
    """Get LAN MAC and IP, preferring live data but falling back to config.

    The MAC is the device identity: the inform header always carries the
    configured ``lan_mac`` and the controller rejects a payload whose MAC
    differs ("mac inconsistent in header and payload"), so a configured MAC
    wins over the live interface MAC."""
    mac = config.get('gateway', 'lan_mac', fallback='')
    if not mac or mac == '00:00:00:00:00:00':
        mac = dc.data.get('macs', {}).get(lan_if) or mac
    ip_info = dc.data.get('ip', {}).get(lan_if, {})
    ip_addr = ip_info.get('address')
    if not ip_addr:
        ip_addr = config.get('gateway', 'lan_ip')
    return mac, ip_addr, ip_info


def _create_partial_inform(config, dc):
    ports = ast.literal_eval(config.get('gateway', 'ports'))
    lan_if = [d['ifname'] for d in ports if d['type'].lower() == 'lan'][0]
    mac, ip_addr, _ = _resolve_lan_identity(config, dc, lan_if)

    return json.dumps({
        'hostname': 'UBNT',
        'state': 0,
        'default': True,
        'inform_url': config.get('gateway', 'url'),
        'mac': mac,
        'ip': ip_addr,
        'model': config.get('gateway', 'device'),
        'model_display': config.get('gateway', 'device_display'),
        'version': config.get('gateway', 'firmware'),
        'uptime': uptime(),
    })


def _create_complete_inform(config, dc):
    ports = ast.literal_eval(config.get('gateway', 'ports'))
    lan_if = [d['ifname'] for d in ports if d['type'].lower() == 'lan'][0]
    wan_if = [d['ifname'] for d in ports if d['type'].lower() == 'wan'][0]
    mac, ip_addr, ip_info = _resolve_lan_identity(config, dc, lan_if)
    netmask = ip_info.get('netmask', '255.255.255.0')

    hostname = get_hostname()
    if config.has_option('gateway', 'hostname'):
        hostname = config.get('gateway', 'hostname')

    system_stats = dc.data.get('system_stats', {'cpu': '0', 'mem': '0'})
    device_uptime = dc.data.get('uptime') or uptime()

    active_leases = []
    for lease in dc.data.get('dhcp_leases', []):
        entry = {'mac': lease['mac'], 'ip': lease['ip']}
        if 'hostname' in lease:
            entry['hostname'] = lease['hostname']
        active_leases.append(entry)

    payload = {
        'bootrom_version': 'unknown',
        'cfgversion': config.get('provisioned', 'cfgversion') if config.has_option('provisioned', 'cfgversion') else '',
        'config_network_wan': {'type': dc.data.get('wan_type', 'dhcp')},
        'config_port_table': ports,
        'connect_request_ip': ip_addr,
        'connect_request_port': '36424',
        'default': False,
        'state': 2,
        'discovery_response': False,
        'fw_caps': 3,
        'guest_token': '4C1D46707239C6EB5A2366F505A44A91',
        'has_default_route_distance': True,
        'has_dnsmasq_hostfile_update': True,
        'has_dpi': 'dpi_stats' in dc.data,
        'has_eth1': True,
        'has_porta': True,
        'has_ssh_disable': True,
        'has_vti': True,
        'hostname': hostname,
        'inform_url': config.get('gateway', 'url'),
        'ip': ip_addr,
        'ipv4_active_leases': active_leases,
        'isolated': False,
        'locating': config.getboolean('gateway', 'locating') if config.has_option('gateway', 'locating') else False,
        'mac': mac,
        'model': config.get('gateway', 'device'),
        'model_display': config.get('gateway', 'device_display'),
        'netmask': netmask,
        'radius_caps': 1,
        'required_version': '4.0.0',
        'selfrun_beacon': True,
        'serial': mac.replace(':', ''),
        'version': config.get('gateway', 'firmware'),
        'time': int(time.time()),
        'uplink': wan_if,
        'uptime': device_uptime,
        'pfor-stats': [],
        'speedtest-status': _speedtest_status(dc),
        'ddns-status': {'dyndns': dc.data.get('ddns', [])},
        'system-stats': {
            'cpu': system_stats.get('cpu', '0'),
            'mem': system_stats.get('mem', '0'),
            'uptime': str(device_uptime),
        },
        'routes': _build_routes(dc, wan_if, lan_if),
        'network_table': get_network_table(dc.data, ports),
        'if_table': get_if_table(dc.data, ports),
    }

    if 'dpi_stats' in dc.data:
        payload['dpi-stats'] = dc.data['dpi_stats']
        payload['dpi-clients'] = [c['mac'] for c in dc.data['dpi_stats']]
        payload['dpi_stats'] = _modern_dpi_stats(dc.data['dpi_stats'])

    return json.dumps(payload)


def _speedtest_status(dc):
    speedtest = dc.data.get('speedtest', {})
    has_speedtest = speedtest.get('download', 0) > 0
    return {
        'latency': int(speedtest.get('ping', 0)),
        'rundate': speedtest.get('lastrun', 0),
        'runtime': 0,
        'status_download': 2 if has_speedtest else 0,
        'status_ping': 2 if speedtest.get('ping', 0) > 0 else 0,
        'status_summary': 2 if has_speedtest else 0,
        'status_upload': 2 if has_speedtest else 0,
        'xput_download': speedtest.get('download', 0),
        'xput_upload': speedtest.get('upload', 0),
    }


def is_uxg(config):
    return config.get('gateway', 'device', fallback='').upper() in UXG_MODELS


def _uxg_network_name(port, primary_lan):
    """UDAPI interface a LAN port's network is provisioned on: the port's
    ``network`` key, else br0 (the controller's default LAN bridge)."""
    if port.get('network'):
        return port['network']
    return 'br0' if port['ifname'] == primary_lan else port['ifname']


def _hosts_by_port(dc, ports, primary_lan):
    """Assign host_table entries to LAN ports (same rule as network_table)."""
    by_realif = {p.get('realif'): p['ifname'] for p in ports
                 if p['type'].lower().startswith('lan') and p.get('realif')}
    result = {}
    for host in dc.data.get('host_table', []):
        ifname = by_realif.get(host.get('realif')) if host.get('realif') else primary_lan
        if ifname:
            result.setdefault(ifname, []).append(host)
    return result


def _uxg_port_table(config, dc, ports, primary_lan):
    """port_table with per-port mac_table: how a UXG reports its clients."""
    ifstat = dc.data.get('ifstat', {})
    macs = dc.data.get('macs', {})
    hosts = _hosts_by_port(dc, ports, primary_lan)
    table = []
    for seq, port in enumerate(ports, 1):
        ifname = port['ifname']
        # UXG front-panel ports are ethN = port N+1 (UXG-Max: eth0-eth3 are
        # LAN ports 1-4, eth4 is the WAN port 5). The controller seeds its
        # port table from the model and matches reported ports by index, so
        # config order must not decide the number.
        match = re.match(r'^eth(\d+)$', ifname)
        idx = int(port.get('port_idx') or (int(match.group(1)) + 1 if match else seq))
        info = ifstat.get(ifname, {})
        entry = {
            'port_idx': idx,
            'name': ifname,
            'ifname': ifname,
            'mac': macs.get(ifname) or config.get('gateway', 'lan_mac'),
            'num_port': 1,
            'enable': True,
            'up': ifname in ifstat,
            'speed': info.get('speed', 1000),
            'full_duplex': True,
            'media': 'GE',
            'rx_bytes': int(info.get('rx_bytes', 0)),
            'tx_bytes': int(info.get('tx_bytes', 0)),
            'rx_packets': int(info.get('rx_packets', 0)),
            'tx_packets': int(info.get('tx_packets', 0)),
            'rx_errors': int(info.get('rx_errors', 0)),
            'tx_errors': int(info.get('tx_errors', 0)),
            'rx_dropped': int(info.get('rx_dropped', 0)),
            'tx_dropped': int(info.get('tx_dropped', 0)),
            'mac_table': [],
        }
        if port['type'].lower() == 'wan':
            entry['is_uplink'] = True
        for host in hosts.get(ifname, []):
            row = {k: v for k, v in host.items() if k not in ('realif', 'oui')}
            row.setdefault('age', 0)
            row['static'] = False
            row['vlan'] = int(port.get('vlan', 1))
            entry['mac_table'].append(row)
        table.append(entry)
    return table


def _uxg_active_leases(dc, ports, primary_lan):
    networks = {p['ifname']: _uxg_network_name(p, primary_lan) for p in ports
                if p['type'].lower().startswith('lan')}
    port_of = {h['mac']: ifname
               for ifname, hosts in _hosts_by_port(dc, ports, primary_lan).items()
               for h in hosts}
    leases = []
    for lease in dc.data.get('dhcp_leases', []):
        entry = {'mac': lease['mac'], 'ip': lease['ip'],
                 'network': networks.get(port_of.get(lease['mac'], primary_lan),
                                         networks.get(primary_lan, 'br0'))}
        if lease.get('hostname'):
            entry['hostname'] = lease['hostname']
        expiry = str(lease.get('expiry', ''))
        if expiry.isdigit() and int(expiry) > 0:
            entry['expiration'] = int(expiry)
        leases.append(entry)
    return leases


def _create_uxg_inform(config, dc, include_blocks=()):
    """Complete inform for a UXG-class model (device = UXGB etc.).

    Follows what the Network 10.6 UXG processor reads: clients come from
    port_table[].mac_table and ipv4_active_leases, DPI from dpi_stats.
    """
    ports = ast.literal_eval(config.get('gateway', 'ports'))
    lan_if = [d['ifname'] for d in ports if d['type'].lower() == 'lan'][0]
    wan_if = [d['ifname'] for d in ports if d['type'].lower() == 'wan'][0]
    mac, ip_addr, ip_info = _resolve_lan_identity(config, dc, lan_if)

    hostname = get_hostname()
    if config.has_option('gateway', 'hostname'):
        hostname = config.get('gateway', 'hostname')
    system_stats = dc.data.get('system_stats', {'cpu': '0', 'mem': '0'})
    device_uptime = dc.data.get('uptime') or uptime()

    network_table = []
    by_name = {p['ifname']: p for p in ports}
    for net in get_network_table(dc.data, ports):
        net = {k: v for k, v in net.items() if k != 'host_table'}
        port = by_name.get(net['name'], {})
        if port.get('type', '').lower().startswith('lan'):
            net['name'] = _uxg_network_name(port, lan_if)
        network_table.append(net)

    payload = {
        'board_rev': 1,
        'cfgversion': config.get('provisioned', 'cfgversion') if config.has_option('provisioned', 'cfgversion') else '',
        'connect_request_ip': ip_addr,
        'connect_request_port': '36424',
        'default': False,
        'state': 2,
        'discovery_response': False,
        'hostname': hostname,
        'inform_url': config.get('gateway', 'url'),
        'ip': ip_addr,
        'isolated': False,
        'locating': config.getboolean('gateway', 'locating') if config.has_option('gateway', 'locating') else False,
        'mac': mac,
        'model': config.get('gateway', 'device'),
        'model_display': config.get('gateway', 'device_display'),
        'netmask': ip_info.get('netmask', '255.255.255.0'),
        'required_version': '4.0.0',
        'serial': mac.replace(':', ''),
        'version': config.get('gateway', 'firmware'),
        'time': int(time.time()),
        'uptime': device_uptime,
        'udapi_version': dict(UDAPI_VERSION),
        'uplink': wan_if,
        'port_table': _uxg_port_table(config, dc, ports, lan_if),
        'ipv4_active_leases': _uxg_active_leases(dc, ports, lan_if),
        'if_table': get_if_table(dc.data, ports),
        'network_table': network_table,
        'routes': _build_routes(dc, wan_if, lan_if),
        'pfor-stats': [],
        'speedtest-status': _speedtest_status(dc),
        'ddns-status': {'dyndns': dc.data.get('ddns', [])},
        'system-stats': {
            'cpu': system_stats.get('cpu', '0'),
            'mem': system_stats.get('mem', '0'),
            'uptime': str(device_uptime),
        },
        'has_dpi': 'dpi_stats' in dc.data,
        'usg_caps': (USG_CAPS | (GEOIP_CAP if dc.data.get('geoip_ready') else 0)
                     | (IPS_CAPS if dc.data.get('ids_available') else 0)),
    }
    if 'dpi_stats' in dc.data:
        payload['dpi_stats'] = _modern_dpi_stats(dc.data['dpi_stats'])
    # Traffic Flows: allowed connections (conntrack) and firewall blocks
    # (triggers), with UDAPI interface names
    names = {'lan': _uxg_network_name(by_name[lan_if], lan_if), 'wan': wan_if}
    for key in ('connections', 'triggers'):
        if dc.data.get(key):
            payload[key] = [{**c, **{side: names.get(c[side], c[side])
                                     for side in ('in', 'out') if side in c}}
                            for c in dc.data[key]]
    if 'gw_caps' in (include_blocks or ()):
        payload['gw_caps'] = dict(GW_CAPS)
    return json.dumps(payload)


def _modern_dpi_stats(clients):
    """Translate legacy counters to the UXG inform schema.

    Network 10.6's client DPI processor reads rxBytes/txBytes. Sending the
    legacy snake_case fields under dpi_stats silently produces zero deltas.
    Keep the collector's legacy data intact for dpi-stats and older servers.
    """
    names = {'rx_bytes': 'rxBytes', 'tx_bytes': 'txBytes',
             'rx_packets': 'rxPackets', 'tx_packets': 'txPackets'}

    def counters(row):
        result = {names.get(key, key): value for key, value in row.items()
                  if key != 'countries'}
        if 'countries' in row:
            result['countries'] = [counters(country) for country in row['countries']]
        return result

    return [{**client, 'stats': [counters(row) for row in client.get('stats', [])]}
            for client in clients]


def _build_routes(dc, wan_if, lan_if):
    routes = []
    wan_gw = dc.data.get('ip', {}).get(wan_if, {}).get('gateway')
    if wan_gw:
        routes.append({
            'nh': [{'intf': wan_if, 'metric': '1/0', 't': 'S>*', 'via': wan_gw}],
            'pfx': '0.0.0.0/0',
        })

    lan_ip = dc.data.get('ip', {}).get(lan_if, {})
    if lan_ip.get('address') and lan_ip.get('netmask'):
        routes.append({
            'nh': [{'intf': lan_if, 't': 'C>*'}],
            'pfx': '%s/%s' % (lan_ip['address'], netmask_to_cidr(lan_ip['netmask'])),
        })

    return routes


def create_inform(config, dc, include_blocks=()):
    """``include_blocks`` are the data blocks the controller asked for in its
    last noop (UXG only)."""
    if not config.getboolean('gateway', 'is_adopted'):
        return _create_partial_inform(config, dc)
    if is_uxg(config):
        return _create_uxg_inform(config, dc, include_blocks)
    return _create_complete_inform(config, dc)


def create_broadcast_message(config, index, version=2, command=6):
    lan_mac = config.get('gateway', 'lan_mac')
    lan_ip = config.get('gateway', 'lan_ip')
    firmware = config.get('gateway', 'firmware')
    device = config.get('gateway', 'device')

    platform_name = 'UNIFI-GW'
    if config.has_option('gateway', 'platform'):
        platform_name = config.get('gateway', 'platform')

    tlv = UnifiTLV()
    tlv.add(1, bytearray(mac_string_2_array(lan_mac)))
    tlv.add(2, bytearray(mac_string_2_array(lan_mac) + ip_string_2_array(lan_ip)))
    tlv.add(3, '{}.v{}'.format(device, firmware).encode('ascii'))
    tlv.add(10, pack('!I', uptime()))
    tlv.add(11, platform_name.encode('ascii'))
    tlv.add(12, device.encode('ascii'))
    tlv.add(19, bytearray(mac_string_2_array(lan_mac)))
    tlv.add(18, pack('!I', index))
    tlv.add(21, device.encode('ascii'))
    tlv.add(27, firmware.encode('ascii'))
    tlv.add(22, firmware.encode('ascii'))
    return tlv.get(version=version, command=command)
