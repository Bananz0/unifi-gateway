#!/usr/bin/env python3
"""Inspect exposed Android Debug Bridge listeners on the local network.

Run from any laptop on the network (Python 3.8+, no other dependencies):

    python tv_scan.py                 # scans the laptop's /24
    python tv_scan.py 192.168.1.0/24  # or a given network

The default only negotiates ADB. --shell-check additionally runs echo and
getprop after a connection is accepted without authentication. No keys are
supplied, apps installed, settings changed, or device files written. Exposure
is not proof of infection; an unexpected response is inconclusive.
"""
import argparse
import concurrent.futures
import ipaddress
import json
import secrets
import socket
import struct
import sys
import time

ADB_PORT = 5555
VERSION = 0x01000000
MAXDATA = 4096
MAX_PAYLOAD = 65536


def _msg(command, arg0, arg1, data=b''):
    cmd = struct.unpack('<I', command)[0]
    return struct.pack('<6I', cmd, arg0, arg1, len(data), sum(data) & 0xffffffff,
                       cmd ^ 0xffffffff) + data


def _recv(sock):
    def exact(size):
        data = bytearray()
        while len(data) < size:
            part = sock.recv(size - len(data))
            if not part:
                raise EOFError('peer closed the ADB connection')
            data.extend(part)
        return bytes(data)

    command, arg0, arg1, size, checksum, magic = struct.unpack('<6I', exact(24))
    if command ^ magic != 0xffffffff or size > MAX_PAYLOAD:
        raise ValueError('invalid ADB frame header')
    payload = exact(size)
    if sum(payload) & 0xffffffff != checksum:
        raise ValueError('invalid ADB frame checksum')
    return struct.pack('<I', command), arg0, arg1, payload


def probe(host, timeout=1, shell_check=False, shell_timeout=3):
    result = {'ip': str(host), 'status': 'CLOSED'}
    try:
        sock = socket.create_connection((str(host), ADB_PORT), timeout=timeout)
    except (OSError, TimeoutError):
        return result
    with sock:
        # A socket timeout alone is not a total deadline: a trickling peer
        # could otherwise keep recv() alive indefinitely.
        deadline = time.monotonic() + (shell_timeout if shell_check else timeout)

        class BoundedSocket:
            def recv(self, size):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('ADB probe deadline exceeded')
                sock.settimeout(remaining)
                return sock.recv(size)

        def send(command, arg0, arg1, payload=b''):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('ADB probe deadline exceeded')
            sock.settimeout(remaining)
            sock.sendall(_msg(command, arg0, arg1, payload))

        connected = False
        try:
            send(b'CNXN', VERSION, MAXDATA, b'host::\0')
            command, version, maximum, _ = _recv(BoundedSocket())
            if command == b'AUTH':
                result['status'] = 'AUTH_REQUIRED'
                return result
            if command != b'CNXN' or version < VERSION or not 0 < maximum <= MAX_PAYLOAD:
                raise ValueError('unexpected ADB negotiation response')
            connected = True
            result['status'] = 'ADB_OPEN'
            if not shell_check:
                return result
            marker = 'tvscan_' + secrets.token_hex(8)
            service = ('shell:echo %s; getprop ro.product.model\0' % marker).encode()
            send(b'OPEN', 1, 0, service)
            output = bytearray()
            remote_id = None
            for _ in range(64):
                command, remote, local, payload = _recv(BoundedSocket())
                if command == b'AUTH':
                    result['status'] = 'AUTH_REQUIRED'
                    return result
                if command not in (b'OKAY', b'WRTE', b'CLSE') or local != 1:
                    raise ValueError('unexpected ADB shell frame')
                if remote_id is None:
                    remote_id = remote
                elif remote != remote_id:
                    raise ValueError('unexpected ADB shell stream')
                if command == b'CLSE':
                    send(b'CLSE', 1, remote)
                    break
                if command == b'WRTE':
                    output.extend(payload)
                    if len(output) > MAX_PAYLOAD:
                        raise ValueError('ADB shell output exceeded limit')
                    send(b'OKAY', 1, remote)
            else:
                raise ValueError('ADB shell frame limit exceeded')
            lines = output.decode('utf-8', 'replace').replace('\r', '').splitlines()
            if marker in lines:
                result['status'] = 'SHELL_OPEN'
                following = lines[lines.index(marker) + 1:]
                if following:
                    result['model'] = ''.join(c for c in following[0] if c.isprintable())[:120]
            else:
                result['status'] = 'UNVERIFIED_SHELL'
                result['detail'] = 'shell did not return the expected marker; cause is unknown'
        except (OSError, EOFError, ValueError) as error:
            result['status'] = 'UNVERIFIED_SHELL' if connected else 'NOT_ADB'
            result['detail'] = str(error)
    return result


def local_target():
    # connect() on a UDP socket selects a route without sending a packet.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(('192.0.2.1', 9))
        address = ipaddress.ip_address(sock.getsockname()[0])
    if not any(address in ipaddress.ip_network(net) for net in (
            '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')):
        raise ValueError('cannot infer a private LAN; specify an IP address or CIDR')
    return str(ipaddress.ip_network(str(address) + '/24', strict=False))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('target', nargs='?', help='IPv4 host or CIDR (default: routed private /24)')
    parser.add_argument('--shell-check', action='store_true', help='also test an unauthenticated read-only shell')
    parser.add_argument('--timeout', type=float, default=1, help='connect/negotiation deadline in seconds')
    parser.add_argument('--shell-timeout', type=float, default=3, help='total negotiation/shell deadline in seconds')
    parser.add_argument('--workers', type=int, default=32)
    parser.add_argument('--json', action='store_true', help='emit all host results as JSON')
    args = parser.parse_args(argv)
    if not 0 < args.timeout <= 30 or not 0 < args.shell_timeout <= 30 or not 1 <= args.workers <= 128:
        parser.error('timeouts must be 0-30 seconds and workers 1-128')
    try:
        network = ipaddress.ip_network(args.target or local_target(), strict=False)
        if network.version != 4 or network.num_addresses > 1024:
            raise ValueError('use one IPv4 host or a network of at most 1024 addresses')
    except (OSError, ValueError) as error:
        parser.error(str(error))
    hosts = list(network.hosts())
    if not args.json:
        print('Inspecting %s on TCP %s%s' % (network, ADB_PORT,
              ' with read-only shell checks' if args.shell_check else ' (negotiation only)'))
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        rows = list(pool.map(lambda host: probe(host, args.timeout, args.shell_check, args.shell_timeout), hosts))
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for row in rows:
            if row['status'] != 'CLOSED':
                print('%-15s %-18s %s' % (row['ip'], row['status'], row.get('model', row.get('detail', ''))))
        print('%d hosts checked; %d accepted ADB without authentication. This is not an infection scan.' % (
            len(rows), sum(row['status'] in ('ADB_OPEN', 'SHELL_OPEN') for row in rows)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
