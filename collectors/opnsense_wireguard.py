"""Pure UDAPI WireGuard server/peer planning for OPNsense's MVC model.

The field names follow the controller's WireGuard server/remote-peer serializers.
This is not yet called by provisioning: firewall, routes, scoped listen-address
binding and controller status must be implemented before enabling that path.
No private keys or preshared keys belong in diagnostics or plan summaries.
"""
import base64
import binascii
import hashlib
import ipaddress
import re
import uuid


SERVER_FIELDS = {'id', 'enabled', 'name', 'address', 'port', 'privateKey',
                 'interfaceIPs', 'remotePeers', 'tunnelMTU', 'tunnelMSSClamping',
                 'tunnelMSS6Clamping', 'dnsServers', 'searchDomains',
                 'disableClientEvents', 'disableWan'}
PEER_FIELDS = {'name', 'publicKey', 'allowedIPs', 'address', 'preSharedKey',
               'port', 'persistentKeepAlive'}


def _key(value, field):
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError, binascii.Error):
        raise ValueError('invalid WireGuard ' + field) from None
    if len(raw) != 32 or not any(raw) or base64.b64encode(raw).decode() != value:
        raise ValueError('invalid WireGuard ' + field)
    return value


def _integer(value, field, low, high):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError('invalid WireGuard ' + field)
    return str(value)


def _addresses(values, interfaces=False):
    if not isinstance(values, list) or not values:
        raise ValueError('WireGuard address list must not be empty')
    result = []
    for value in values:
        if not isinstance(value, str) or '/' not in value or '%' in value:
            raise ValueError('WireGuard addresses require explicit prefixes')
        try:
            addr = ipaddress.ip_interface(value) if interfaces else ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise ValueError('invalid WireGuard address') from None
        if interfaces and (addr.ip.is_unspecified or addr.ip.is_multicast or addr.ip.is_loopback):
            raise ValueError('WireGuard interface requires a unicast address')
        text = str(addr)
        if text in result:
            raise ValueError('duplicate WireGuard address')
        result.append(text)
    return ','.join(result)


def _endpoint(value):
    if not isinstance(value, str) or not value or '%' in value:
        raise ValueError('invalid WireGuard endpoint')
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        if len(value) > 253 or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',
                                                   label) for label in value.rstrip('.').split('.')):
            raise ValueError('invalid WireGuard endpoint') from None
        return value.rstrip('.').lower()
    if addr.is_unspecified or addr.is_multicast:
        raise ValueError('invalid WireGuard endpoint')
    return str(addr)


def plan_servers(section):
    """Return server payloads/peer references and peers; perform no API calls.

    OPNsense calls instances 'servers' and remote peers 'clients'. Route
    installation is deliberately disabled here; it belongs to the routing
    translator, rather than implicitly replacing existing host/default routes.
    Names encode ownership because these models have no description field.
    """
    if not isinstance(section, list):
        raise ValueError('WireGuard server section must be a list')
    servers, peers, used_ports = {}, {}, set()
    for body in section:
        if not isinstance(body, dict) or set(body) - SERVER_FIELDS:
            raise ValueError('unsupported WireGuard server fields')
        ident = body.get('id')
        if not isinstance(ident, str) or not ident or len(ident) > 128:
            raise ValueError('WireGuard server requires a stable string ID')
        name = 'ufg_wgs_' + hashlib.sha256(ident.encode()).hexdigest()[:24]
        if name in servers:
            raise ValueError('duplicate WireGuard server ID')
        enabled = body.get('enabled')
        if not isinstance(enabled, bool):
            raise ValueError('WireGuard enabled flag must be boolean')
        if body.get('address') not in (None, '', '0.0.0.0', '::'):
            raise ValueError('WireGuard scoped listen address requires firewall binding')
        for field in ('tunnelMSSClamping', 'tunnelMSS6Clamping', 'dnsServers', 'searchDomains'):
            if body.get(field):
                raise ValueError('WireGuard ' + field + ' requires a dedicated translator')
        for field in ('disableClientEvents', 'disableWan'):
            if field in body and not isinstance(body[field], bool):
                raise ValueError('WireGuard ' + field + ' must be boolean')
        if body.get('disableWan'):
            raise ValueError('WireGuard disableWan requires firewall policy translation')
        port = _integer(body.get('port'), 'listen port', 1, 65535)
        if enabled and port in used_ports:
            raise ValueError('duplicate enabled WireGuard listen port')
        if enabled:
            used_ports.add(port)
        payload = {'name': name, 'enabled': '1' if enabled else '0', 'port': port,
                   'privkey': _key(body.get('privateKey'), 'private key'),
                   'tunneladdress': _addresses(body.get('interfaceIPs'), interfaces=True),
                   'disableroutes': '1', 'gateway': '', 'dns': '', 'debug': '0',
                   'mtu': _integer(body['tunnelMTU'], 'MTU', 576, 9300) if 'tunnelMTU' in body else ''}
        if ':' in payload['tunneladdress'] and payload['mtu'] and int(payload['mtu']) < 1280:
            raise ValueError('WireGuard IPv6 MTU must be at least 1280')
        remote = body.get('remotePeers')
        if not isinstance(remote, list):
            raise ValueError('WireGuard remotePeers must be a list')
        references, used_networks = [], set()
        for peer in remote:
            if not isinstance(peer, dict) or set(peer) - PEER_FIELDS:
                raise ValueError('unsupported WireGuard peer fields')
            public = _key(peer.get('publicKey'), 'public key')
            peer_name = 'ufg_wgp_' + hashlib.sha256((ident + ':' + public).encode()).hexdigest()[:24]
            if peer_name in peers:
                raise ValueError('duplicate WireGuard peer key')
            allowed = _addresses(peer.get('allowedIPs'))
            networks = set(allowed.split(','))
            if networks & used_networks:
                raise ValueError('WireGuard peers cannot own the same allowed prefix')
            used_networks.update(networks)
            address = peer.get('address')
            port = peer.get('port')
            has_address = address not in (None, '')
            if has_address != (port is not None):
                raise ValueError('WireGuard endpoint address and port must be paired')
            peers[peer_name] = {
                'name': peer_name, 'enabled': '1' if enabled else '0', 'pubkey': public,
                'tunneladdress': allowed, 'psk': _key(peer['preSharedKey'], 'preshared key')
                if peer.get('preSharedKey') not in (None, '') else '',
                'serveraddress': _endpoint(address) if has_address else '',
                'serverport': _integer(port, 'endpoint port', 1, 65535) if has_address else '',
                'keepalive': '',
            }
            if 'persistentKeepAlive' in peer:
                keepalive = _integer(peer['persistentKeepAlive'], 'keepalive', 0, 65535)
                peers[peer_name]['keepalive'] = '' if keepalive == '0' else keepalive
            references.append(peer_name)
        servers[name] = {'payload': payload, 'peers': references}
    return servers, peers


def bind_peers(servers, peers, server_uuids):
    """Resolve instance UUIDs for peer writes without dropping their links.

    OPNsense's volatile client.servers relation is write-active: omitting it
    when updating a peer removes that peer from every instance. Callers must
    create/read back instance UUIDs first and send these complete payloads.
    This helper only handles the supplied owned plan, not unrelated peers.
    """
    if set(server_uuids) != set(servers):
        raise ValueError('WireGuard instance UUIDs do not match the complete plan')
    try:
        resolved = {name: str(uuid.UUID(value)) for name, value in server_uuids.items()}
    except (ValueError, TypeError, AttributeError):
        raise ValueError('invalid WireGuard instance UUID') from None
    if len(set(resolved.values())) != len(resolved):
        raise ValueError('duplicate WireGuard instance UUID')
    bindings = {name: [] for name in peers}
    for name, server in servers.items():
        for peer in server['peers']:
            if peer not in bindings:
                raise ValueError('WireGuard instance references an unknown peer')
            bindings[peer].append(resolved[name])
    if any(not values for values in bindings.values()):
        raise ValueError('WireGuard peer has no instance binding')
    return {name: dict(payload, servers=','.join(sorted(set(bindings[name]))))
            for name, payload in peers.items()}
