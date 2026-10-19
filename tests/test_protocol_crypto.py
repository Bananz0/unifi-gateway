# -*- coding: utf-8 -*-
"""The inform protocol must work with either AES backend: pycryptodome, or
`cryptography` (the only one available on stock OPNsense)."""
import configparser
import json

import pytest

import unifi_protocol

KEY = '0123456789abcdef0123456789abcdef'


@pytest.fixture
def config():
    cfg = configparser.ConfigParser()
    cfg.read_dict({'gateway': {
        'is_adopted': 'True', 'key': KEY, 'use_aes_gcm': 'False',
        'lan_mac': 'aa:bb:cc:dd:ee:ff'}})
    return cfg


@pytest.fixture(params=['pycryptodome', 'cryptography'])
def backend(request, monkeypatch):
    if request.param == 'cryptography':
        pytest.importorskip('cryptography')
        monkeypatch.setattr(unifi_protocol, '_AES', None)
    elif unifi_protocol._AES is None:
        pytest.skip('pycryptodome not installed')
    return request.param


@pytest.mark.parametrize('gcm', [False, True])
def test_roundtrip(config, backend, gcm):
    config.set('gateway', 'use_aes_gcm', str(gcm))
    payload = json.dumps({'hello': 'world', 'n': list(range(50))})
    packet = unifi_protocol.encode_inform(config, payload)
    flags = int.from_bytes(packet[14:16], 'big')
    assert bool(flags & 0x08) == gcm
    assert unifi_protocol.decode_inform(config, packet) == json.loads(payload)


@pytest.mark.parametrize('gcm', [False, True])
def test_backends_interoperate(config, gcm, monkeypatch):
    """A packet sealed by one backend opens with the other."""
    pytest.importorskip('cryptography')
    if unifi_protocol._AES is None:
        pytest.skip('pycryptodome not installed')
    config.set('gateway', 'use_aes_gcm', str(gcm))
    packet = unifi_protocol.encode_inform(config, '{"a": 1}')
    monkeypatch.setattr(unifi_protocol, '_AES', None)
    assert unifi_protocol.decode_inform(config, packet) == {'a': 1}


def test_gcm_tamper_detected(config, backend):
    config.set('gateway', 'use_aes_gcm', 'True')
    packet = bytearray(unifi_protocol.encode_inform(config, '{"a": 1}'))
    packet[-1] ^= 0xFF
    with pytest.raises(ValueError):
        unifi_protocol.decode_inform(config, bytes(packet))
