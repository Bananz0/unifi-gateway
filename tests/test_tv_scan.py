import struct
import importlib.util
import sys
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('tv_scan_tool', Path(__file__).parents[1] / 'tools/tv_scan.py')
tv_scan = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = tv_scan
spec.loader.exec_module(tv_scan)
_msg, _recv, main, probe = tv_scan._msg, tv_scan._recv, tv_scan.main, tv_scan.probe


class Peer:
    def __init__(self, mode='shell'):
        self.mode = mode
        self.buffer = bytearray(_msg(b'AUTH', 1, 0, b'challenge') if mode == 'auth'
                                else _msg(b'CNXN', 0x01000000, 4096, b'device::\0'))
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def settimeout(self, value):
        assert value > 0

    def recv(self, size):
        # Real TCP can split both headers and payloads at any byte.
        size = min(size, 3)
        data = bytes(self.buffer[:size])
        del self.buffer[:size]
        return data

    def sendall(self, packet):
        self.sent.append(packet)
        if packet[:4] == b'OPEN':
            command = packet[24:].decode()
            marker = command.split('echo ', 1)[1].split(';', 1)[0]
            if self.mode == 'echoed_command':
                output = command.encode()
            elif self.mode == 'empty':
                output = b''
            else:
                output = (marker + '\r\nExample TV\r\n').encode()
            self.buffer.extend(_msg(b'OKAY', 17, 1))
            self.buffer.extend(_msg(b'WRTE', 17, 1, output))
            self.buffer.extend(_msg(b'CLSE', 17, 1))


def connect(monkeypatch, peer):
    monkeypatch.setattr('tv_scan_tool.socket.create_connection', lambda *a, **k: peer)


def test_read_only_shell_is_confirmed_over_fragmented_tcp(monkeypatch):
    peer = Peer()
    connect(monkeypatch, peer)
    result = probe('192.0.2.1', shell_check=True)
    assert result == {'ip': '192.0.2.1', 'status': 'SHELL_OPEN', 'model': 'Example TV'}
    commands = [p[:4] for p in peer.sent]
    assert commands == [b'CNXN', b'OPEN', b'OKAY', b'CLSE']
    service = peer.sent[1][24:]
    assert service.startswith(b'shell:echo tvscan_') and service.endswith(b'; getprop ro.product.model\0')


def test_default_probe_never_opens_a_shell(monkeypatch):
    peer = Peer()
    connect(monkeypatch, peer)
    assert probe('192.0.2.1')['status'] == 'ADB_OPEN'
    assert [p[:4] for p in peer.sent] == [b'CNXN']


def test_authentication_challenge_is_not_answered_with_a_key(monkeypatch):
    peer = Peer('auth')
    connect(monkeypatch, peer)
    assert probe('192.0.2.1', shell_check=True)['status'] == 'AUTH_REQUIRED'
    assert [p[:4] for p in peer.sent] == [b'CNXN']


@pytest.mark.parametrize('mode', ['echoed_command', 'empty'])
def test_unexpected_shell_is_inconclusive_not_an_infection_diagnosis(monkeypatch, mode):
    peer = Peer(mode)
    connect(monkeypatch, peer)
    result = probe('192.0.2.1', shell_check=True)
    assert result['status'] == 'UNVERIFIED_SHELL'
    assert 'cause is unknown' in result['detail']


@pytest.mark.parametrize('kind', ['magic', 'size', 'checksum', 'eof'])
def test_malformed_or_truncated_frames_are_bounded(kind):
    peer = Peer()
    packet = bytearray(_msg(b'CNXN', 0x01000000, 4096, b'device::\0'))
    if kind == 'magic':
        packet[20] ^= 1
    elif kind == 'size':
        packet[12:16] = struct.pack('<I', 0xffffffff)
    elif kind == 'checksum':
        packet[-1] ^= 1
    else:
        packet = packet[:10]
    peer.buffer = packet
    with pytest.raises((ValueError, EOFError)):
        _recv(peer)


def test_trickling_connection_cannot_extend_the_total_probe_deadline(monkeypatch):
    peer = Peer()
    connect(monkeypatch, peer)
    ticks = iter(i / 5 for i in range(100))
    monkeypatch.setattr('tv_scan_tool.time.monotonic', lambda: next(ticks))
    result = probe('192.0.2.1', timeout=1)
    assert result['status'] == 'NOT_ADB'
    assert 'deadline' in result['detail']


@pytest.mark.parametrize('args', [['10.0.0.0/8'], ['::1'], ['192.0.2.1', '--timeout', 'nan'],
                                  ['192.0.2.1', '--workers', '0']])
def test_cli_rejects_unbounded_or_invalid_scans_before_connect(monkeypatch, args):
    def unexpected(*args, **kwargs):
        pytest.fail('invalid scan attempted a connection')
    monkeypatch.setattr('tv_scan_tool.socket.create_connection', unexpected)
    with pytest.raises(SystemExit) as exit_info:
        main(args)
    assert exit_info.value.code == 2
