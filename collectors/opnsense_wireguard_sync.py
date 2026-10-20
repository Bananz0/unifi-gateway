"""Apply a UDAPI WireGuard server plan to OPNsense.

Two phases around the firewall rule sync: ``prepare`` writes instances and
peers (the ``wireguard`` interface group must exist before rules can name
it) and returns filter rules admitting the listen port and passing tunnel
traffic; ``finish`` retires stale instances, writes source NAT and restarts
the service. Only ``ufg_wg*``-named objects and ``wg-``-tagged rules are
touched. Key material is never logged.
"""
import ipaddress

from .opnsense_api import OPNsenseAPI, OPNsenseAPIError
from .opnsense_sync import ALIASES, ItemSpec, make_tag
from .opnsense_wireguard import bind_peers, plan_servers


def _owned(prefix):
    return lambda row: row.get('name') if str(row.get('name') or '').startswith(prefix) else None


SERVERS = ItemSpec('WireGuard instance', 'wireguard/server/search_server',
                   'wireguard/server/add_server', 'wireguard/server/set_server/',
                   'wireguard/server/del_server/', 'server', 'name', key_fn=_owned('ufg_wgs_'))
PEERS = ItemSpec('WireGuard peer', 'wireguard/client/search_client',
                 'wireguard/client/add_client', 'wireguard/client/set_client/',
                 'wireguard/client/del_client/', 'client', 'name', key_fn=_owned('ufg_wgp_'))
SOURCE_NAT = ItemSpec('source NAT rule', 'firewall/source_nat/search_rule',
                      'firewall/source_nat/add_rule', 'firewall/source_nat/set_rule/',
                      'firewall/source_nat/del_rule/', 'rule', 'description')
# Rule keys this translator owns in the filter and source NAT collections
RULE_PREFIX = 'wg-'
# Aliases holding each instance's tunnel networks (filter rules reject a
# mixed IPv4/IPv6 list as a source)
ALIAS_PREFIX = 'ufg_wg_'
GROUP = 'wireguard'


def _detail_value(value):
    """Comparable text of a get_* field (option lists come back as
    {key: {value, selected}}, multi-values as comma lists)."""
    if isinstance(value, dict):
        value = ','.join(k for k, v in value.items()
                         if k and isinstance(v, dict) and v.get('selected'))
    return ','.join(sorted(p.strip() for p in str(value if value is not None else '').split(',')
                           if p.strip()))


def _same(detail, payload):
    return all(_detail_value(detail.get(k)) == _detail_value(v) for k, v in payload.items())


def _rule(key, interface, ipproto, protocol, source, destination, port, text):
    return {'enabled': '1', 'action': 'pass', 'quick': '1', 'interface': interface,
            'direction': 'in', 'ipprotocol': ipproto, 'protocol': protocol,
            'source_net': source, 'source_not': '0', 'source_port': '',
            'destination_net': destination, 'destination_not': '0',
            'destination_port': port, 'log': '0', 'sequence': '90',
            'description': make_tag(key, text)}


class WireGuardSync:

    def __init__(self, sync):
        self.sync = sync
        self.api = sync.api
        self.pending = False  # written since the last service reconfigure
        self.servers, self.peers, self.aliases = {}, {}, {}

    def prepare(self, section):
        servers, peers = plan_servers(section)
        targets = {name: self._listen_target(server['listen'])
                   for name, server in servers.items()}
        self._preflight(servers)
        uuids = self._upsert(SERVERS, {n: s['payload'] for n, s in servers.items()})
        self._upsert(PEERS, bind_peers(servers, peers, uuids))
        self.servers, self.peers = servers, peers
        if servers:
            general = self.api.get('wireguard/general/get').get('general') or {}
            if str(general.get('enabled')) != '1':
                result = self.api.post('wireguard/general/set', {'general': {'enabled': '1'}})
                OPNsenseAPI.check_saved(result, 'enable WireGuard')
                self.pending = True
            if self.pending:
                # creates the wgN devices and the interface group rules name
                self._reconfigure()
        rules, self.aliases = {}, {}
        for name, server in servers.items():
            if server['payload']['enabled'] != '1':
                continue
            interface, destination, ipproto = targets[name]
            port = server['payload']['port']
            short = name[len('ufg_wgs_'):]
            alias = ALIAS_PREFIX + short
            self.aliases[alias] = self.sync._alias_payload(
                alias, 'network', server['networks'], 'UniFi WireGuard networks')
            key = '%s%s-in' % (RULE_PREFIX, short)
            rules[key] = _rule(key, interface, ipproto, 'UDP', 'any', destination, port,
                               'UniFi WireGuard listen port %s' % port)
            key = '%s%s-tun' % (RULE_PREFIX, short)
            rules[key] = _rule(key, GROUP, 'inet46', 'any', alias, 'any', '',
                               'UniFi WireGuard clients')
        if self.sync.sync_items(ALIASES, self.aliases, delete_stale=False)[0]:
            self.sync.reconfigure_aliases()
        return rules

    def finish(self):
        stale_peers = self._stale(PEERS, self.peers)
        stale_servers = self._stale(SERVERS, self.servers)
        if stale_peers or stale_servers:
            # Stop retired tunnels while their records still exist, so the
            # service tears their devices down, then delete the records.
            for spec, rows in ((PEERS, stale_peers), (SERVERS, stale_servers)):
                for row in rows:
                    if str(row.get('enabled')) != '0':
                        result = self.api.post(spec.set + row['uuid'],
                                               {spec.wrapper: {'enabled': '0'}})
                        OPNsenseAPI.check_saved(result, 'disable retiring %s' % spec.name)
            self._reconfigure()
            for spec, rows in ((PEERS, stale_peers), (SERVERS, stale_servers)):
                for row in rows:
                    self.sync._delete(spec, row['uuid'])
            self.pending = True
        if self._sync_nat():
            self.sync.apply_filter()
        # the rules naming retired aliases are gone by now
        if self.sync.sync_items(ALIASES, self.aliases,
                                keep=lambda key: not key.startswith(ALIAS_PREFIX))[0]:
            self.sync.reconfigure_aliases()
        if self.pending:
            self._reconfigure()
        self._verify()
        return len(self.servers)

    # ── helpers ──────────────────────────────────────────────────────────

    def _listen_target(self, listen):
        """(interface, destination, ipprotocol) of the rule admitting peers.
        OPNsense instances listen on every address; the controller's
        binding scopes this rule instead."""
        ipproto = {'v4': 'inet', 'v6': 'inet6'}.get(listen.get('ipVersion'), 'inet46')
        if listen['source'] in ('any', 'wan'):
            return 'wan', 'wanip', ipproto
        if listen['source'] == 'static':
            version = ipaddress.ip_address(listen['address']).version
            return 'wan', listen['address'], 'inet' if version == 4 else 'inet6'
        interface = self.sync.resolve_interface(listen['id'])
        if not interface:
            raise ValueError('WireGuard listen interface %s is not assigned' % listen['id'])
        return interface, interface + 'ip', ipproto

    def _preflight(self, servers):
        ports = {s['payload']['port'] for s in servers.values()
                 if s['payload']['enabled'] == '1'}
        for row in self.api.search(SERVERS.search):
            if SERVERS.key_fn(row) or str(row.get('enabled')) != '1':
                continue
            if str(row.get('port')) in ports:
                raise ValueError('WireGuard port %s is used by an unmanaged instance'
                                 % row.get('port'))

    def _upsert(self, spec, desired):
        """Like OPNsenseConfigSync.sync_items, but compares against get_*
        detail (search rows omit keys) and never deletes."""
        get = spec.set.replace('/set_', '/get_')
        existing = {}
        for row in self.api.search(spec.search):
            key = spec.key_fn(row)
            if key:
                existing.setdefault(key, []).append(row)
        added = False
        for key, payload in desired.items():
            rows = existing.get(key) or []
            for dupe in rows[1:]:
                self.sync._delete(spec, dupe['uuid'])
                self.pending = True
            if rows:
                detail = self.api.get(get + rows[0]['uuid']).get(spec.wrapper)
                if not isinstance(detail, dict):
                    raise OPNsenseAPIError('could not read %s %s' % (spec.name, key))
                if _same(detail, payload):
                    continue
                result = self.api.post(spec.set + rows[0]['uuid'], {spec.wrapper: payload})
                OPNsenseAPI.check_saved(result, 'update %s %s' % (spec.name, key))
            else:
                result = self.api.post(spec.add, {spec.wrapper: payload})
                OPNsenseAPI.check_saved(result, 'add %s %s' % (spec.name, key))
                added = True
            self.pending = True
        # UUIDs are read back by name rather than taken from add responses
        rows = self.api.search(spec.search) if added else [r[0] for r in existing.values()]
        uuids = {}
        for row in rows:
            key = spec.key_fn(row)
            if key in desired:
                uuids.setdefault(key, row['uuid'])
        missing = set(desired) - set(uuids)
        if missing:
            raise OPNsenseAPIError('%s missing after write: %s'
                                   % (spec.name, ', '.join(sorted(missing))))
        return uuids

    def _stale(self, spec, desired):
        return [row for row in self.api.search(spec.search)
                if spec.key_fn(row) and spec.key_fn(row) not in desired]

    def _sync_nat(self):
        """Source NAT for IPv4 tunnel networks. Automatic outbound NAT only
        covers assigned interfaces, so this needs hybrid or manual mode; the
        mode is the operator's and is never changed here."""
        desired = {}
        for name, server in self.servers.items():
            v4 = [n for n in server['networks'] if ':' not in n]
            if server['payload']['enabled'] == '1' and v4:
                key = '%s%s-nat' % (RULE_PREFIX, name[len('ufg_wgs_'):])
                desired[key] = {'enabled': '1', 'interface': 'wan', 'ipprotocol': 'inet',
                                'protocol': 'any', 'source_net': ','.join(v4),
                                'destination_net': 'any', 'target': '',
                                'description': make_tag(key, 'UniFi WireGuard clients')}
        if desired:
            general = (self.api.get('firewall/source_nat/get').get('filter') or {}).get('general') or {}
            mode = _detail_value(general.get('snat_mode'))
            if mode not in ('hybrid', 'advanced'):
                self.sync._warn('WireGuard clients get no Internet source NAT: outbound NAT '
                                'mode is %s; set it to hybrid in OPNsense', mode or 'unknown')
                desired = {}
        changed, _ = self.sync.sync_items(SOURCE_NAT, desired,
                                          keep=lambda key: not key.startswith(RULE_PREFIX))
        return changed

    def _verify(self):
        """Every enabled owned instance must be up with exactly its peers;
        the service status endpoint reports 'unknown' even when it runs."""
        rows = self.api.get('wireguard/service/show').get('rows') or []
        up = {r.get('ifname') for r in rows if r.get('type') == 'interface' and r.get('status') == 'up'}
        attached = {(r.get('ifname'), r.get('name')) for r in rows if r.get('type') == 'peer'}
        for name, server in self.servers.items():
            if server['payload']['enabled'] != '1':
                continue
            if name not in up:
                raise OPNsenseAPIError('WireGuard instance %s is not up' % name)
            missing = [p for p in server['peers'] if (name, p) not in attached]
            if missing:
                raise OPNsenseAPIError('WireGuard instance %s lacks peers %s' % (name, ', '.join(missing)))

    def _reconfigure(self):
        result = self.api.post('wireguard/service/reconfigure')
        if not isinstance(result, dict) or str(result.get('result', result.get('status'))).lower() != 'ok':
            raise OPNsenseAPIError('WireGuard reconfigure failed: %s' % result)
        self.pending = False
