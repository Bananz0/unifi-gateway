import base64
import copy

import pytest

from collectors.opnsense_wireguard import bind_peers, plan_servers


PRIVATE = base64.b64encode(bytes(range(32))).decode()
PUBLIC = base64.b64encode(bytes(range(1, 33))).decode()
SERVER = {'id': '7', 'enabled': True, 'name': 'Remote access', 'port': 51890,
          'privateKey': PRIVATE, 'interfaceIPs': ['10.253.0.1/24', 'fd00:253::1/64'],
          'tunnelMTU': 1420, 'remotePeers': [
              {'name': 'Client', 'publicKey': PUBLIC, 'allowedIPs': ['10.253.0.2/32', 'fd00:253::2/128'],
               'persistentKeepAlive': 25}]}


def test_controller_server_and_peer_fields_translate_to_opnsense_models():
    servers, peers = plan_servers([SERVER])
    server = next(iter(servers.values()))
    peer = peers[server['peers'][0]]
    assert server['payload']['tunneladdress'] == '10.253.0.1/24,fd00:253::1/64'
    assert server['payload']['privkey'] == PRIVATE
    assert server['payload']['disableroutes'] == '1'
    assert peer['pubkey'] == PUBLIC
    assert peer['tunneladdress'] == '10.253.0.2/32,fd00:253::2/128'
    assert peer['keepalive'] == '25'
    assert peer['serveraddress'] == peer['serverport'] == ''


def test_owned_names_are_stable_across_display_name_and_peer_order_changes():
    before = plan_servers([SERVER])
    edited = copy.deepcopy(SERVER)
    edited['name'] = 'Renamed server'
    edited['remotePeers'][0]['name'] = 'Renamed client'
    assert plan_servers([edited]) == before


@pytest.mark.parametrize('field,value', [
    ('privateKey', 'not-base64'), ('privateKey', base64.b64encode(bytes(32)).decode()),
    ('privateKey', base64.b64encode(bytes(31)).decode()), ('enabled', 'false'),
    ('port', True), ('port', 0), ('id', None), ('interfaceIPs', ['10.0.0.1']),
    ('interfaceIPs', ['::/64']), ('interfaceIPs', ['127.0.0.1/8']),
    ('tunnelMTU', 1200), ('tunnelMTU', 9400), ('address', '198.51.100.1'),
    ('dnsServers', ['1.1.1.1']), ('searchDomains', ['private.test']),
    ('tunnelMSSClamping', {'enabled': True}), ('disableWan', True),
    ('remotePeers', None), ('unknown', True),
])
def test_unrepresented_or_invalid_server_settings_reject_the_entire_plan(field, value):
    edited = dict(SERVER, **{field: value})
    with pytest.raises(ValueError):
        plan_servers([edited])


@pytest.mark.parametrize('change', [
    {'publicKey': 'bad'}, {'allowedIPs': []}, {'allowedIPs': ['10.0.0.2']},
    {'address': 'example.test'}, {'port': 51820},
    {'address': 'bad\nendpoint', 'port': 51820},
    {'persistentKeepAlive': True}, {'persistentKeepAlive': -1}, {'mystery': 1},
    {'preSharedKey': 0}, {'address': 0},
])
def test_invalid_or_unimplemented_peer_fields_are_explicit_errors(change):
    edited = copy.deepcopy(SERVER)
    edited['remotePeers'][0].update(change)
    with pytest.raises(ValueError):
        plan_servers([edited])


def test_peer_endpoint_ipv6_psk_and_zero_keepalive():
    edited = copy.deepcopy(SERVER)
    edited['remotePeers'][0].update(address='2001:db8::1', port=51820,
                                   preSharedKey=PRIVATE, persistentKeepAlive=0)
    _, peers = plan_servers([edited])
    peer = next(iter(peers.values()))
    assert (peer['serveraddress'], peer['serverport'], peer['keepalive'], peer['psk']) == (
        '2001:db8::1', '51820', '', PRIVATE)


def test_disabled_server_disables_its_peers_and_empty_section_is_authoritative():
    servers, peers = plan_servers([dict(SERVER, enabled=False)])
    assert next(iter(servers.values()))['payload']['enabled'] == '0'
    assert next(iter(peers.values()))['enabled'] == '0'
    assert plan_servers([]) == ({}, {})


@pytest.mark.parametrize('duplicate', ['server', 'port', 'public', 'prefix'])
def test_conflicting_identity_socket_and_peer_prefixes_are_rejected(duplicate):
    edited = copy.deepcopy(SERVER)
    if duplicate == 'server':
        section = [SERVER, edited]
    elif duplicate == 'port':
        edited['id'] = '8'
        section = [SERVER, edited]
    else:
        peer = dict(edited['remotePeers'][0])
        if duplicate == 'prefix':
            peer['publicKey'] = PRIVATE
        edited['remotePeers'].append(peer)
        section = [edited]
    with pytest.raises(ValueError):
        plan_servers(section)


def test_key_validation_does_not_echo_the_secret_in_errors():
    secret = 'this-is-private-invalid-material'
    with pytest.raises(ValueError) as error:
        plan_servers([dict(SERVER, privateKey=secret)])
    assert secret not in str(error.value)


def test_peer_updates_explicitly_preserve_opnsense_instance_membership():
    servers, peers = plan_servers([SERVER])
    name = next(iter(servers))
    instance = 'bdc1aa5d-cafc-4cd9-aef1-bddf4997d39c'
    bound = bind_peers(servers, peers, {name: instance})
    assert next(iter(bound.values()))['servers'] == instance
    assert 'servers' not in next(iter(peers.values()))


@pytest.mark.parametrize('mode', ['missing', 'bad_uuid', 'extra', 'unknown_peer', 'orphan_peer'])
def test_incomplete_instance_binding_is_rejected_before_peer_writes(mode):
    servers, peers = plan_servers([SERVER])
    name = next(iter(servers))
    ids = {name: 'bdc1aa5d-cafc-4cd9-aef1-bddf4997d39c'}
    if mode == 'missing':
        ids = {}
    elif mode == 'bad_uuid':
        ids[name] = 'not-a-uuid'
    elif mode == 'extra':
        ids['extra'] = ids[name]
    elif mode == 'unknown_peer':
        servers[name]['peers'].append('unknown')
    else:
        peers['orphan'] = dict(next(iter(peers.values())))
    with pytest.raises(ValueError):
        bind_peers(servers, peers, ids)
