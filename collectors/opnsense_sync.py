# -*- coding: utf-8 -*-
"""Write controller configuration back into OPNsense through its REST API.

The UniFi controller provisions a USG by pushing ``system_cfg``: an EdgeOS
(Vyatta) config tree as JSON. This module translates the parts that have an
OPNsense equivalent:

- firewall groups (address/network/port)  -> firewall aliases
- user firewall rules (LAN_IN, WAN_LOCAL..) -> MVC filter rules
- port-forward rules                      -> destination NAT rules
- DHCP static mappings                    -> Kea reservations / Dnsmasq hosts
- static host mappings                    -> Unbound host overrides
- static routes                           -> routes (+ gateways if needed)

plus client blocking (``block-sta`` / ``unblock-sta`` / ``blocked_sta``).

Everything created here is tagged ``unifi-gw:<key>`` in its description
(aliases are additionally prefixed ``ufg_``), and only tagged objects are ever
modified or deleted. Controller built-ins (rule numbers 3000-3999 and the
per-network 6000+ rules, default-actions, masquerade NAT) are skipped:
OPNsense already provides stateful defaults and outbound NAT, and copying
them would duplicate or fight its own rules.
"""
import hashlib
import ipaddress
import json
import logging
import re
import time

from .opnsense_api import OPNsenseAPI, OPNsenseAPIError

logger = logging.getLogger('unifi-gateway')

TAG = 'unifi-gw'
ALIAS_PREFIX = 'ufg_'
BLOCKED_MAC_ALIAS = ALIAS_PREFIX + 'blocked'
BLOCKED_IP_ALIAS = ALIAS_PREFIX + 'blocked_ip'
BLOCK_RULE_KEY = 'block-clients'

# Controller-generated rule numbers we leave alone: 3000-3999 are the
# predefined guest/WAN rules, 6000+ are the automatic per-network rules.
PREDEFINED_RULE_RANGES = ((3000, 3999), (6000, 999999))

# configd caches 'interface gateways list' (used to validate routes) for 20s.
GATEWAY_LIST_CACHE_TTL = 22

# TTL for host overrides we create. Unbound's default (3600s) lets caches in
# front of it (AdGuard, clients) keep serving a removed or changed record
# for an hour.
DNS_OVERRIDE_TTL = 60

# Hosts the controller always injects for the USG's own setup UI.
SKIP_HOST_MAPPINGS = {'setup.ubnt.com'}

# Objects mirrored from OPNsense into UniFi carry this name prefix. The
# controller pushes them back in system_cfg; they already exist here, so
# they are skipped instead of being duplicated.
MIRROR_PREFIX = '[OPNsense]'


def is_mirrored(description):
    return str(description or '').strip().startswith(MIRROR_PREFIX)

PROTOCOLS = {
    'all': 'any', 'tcp_udp': 'TCP/UDP', 'tcp': 'TCP', 'udp': 'UDP',
    'icmp': 'ICMP', 'ipv6-icmp': 'IPV6-ICMP', 'icmpv6': 'IPV6-ICMP',
}
ACTIONS = {'accept': 'pass', 'drop': 'block', 'reject': 'reject'}


def make_tag(key, text=''):
    return ('%s:%s %s' % (TAG, key, text or '')).strip()[:255]


def parse_tag(descr):
    descr = descr or ''
    if not descr.startswith(TAG + ':'):
        return None
    return descr[len(TAG) + 1:].split(' ', 1)[0]


def alias_name(name):
    """Turn a controller group name into a valid OPNsense alias name."""
    clean = re.sub(r'[^A-Za-z0-9_]', '_', name)
    full = ALIAS_PREFIX + clean
    if len(full) > 32:
        digest = hashlib.sha1(name.encode('utf-8')).hexdigest()[:6]
        full = full[:25] + '_' + digest
    return full


def normalize_mac(mac):
    return (mac or '').strip().lower().replace('-', ':')


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def _norm(value):
    if isinstance(value, bool):
        return '1' if value else '0'
    if isinstance(value, (list, tuple)):
        return ','.join(sorted(str(v) for v in value))
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return str(value if value is not None else '').strip()


def _flatten(payload, prefix=''):
    out = {}
    for k, v in payload.items():
        key = prefix + k
        if isinstance(v, dict):
            out.update(_flatten(v, key + '.'))
        else:
            out[key] = v
    return out


def _row_value(row, key):
    """Raw value of a field in a search row (search rows are flattened, and
    list-type fields may come back as comma-joined strings or dicts)."""
    value = row.get(key)
    if isinstance(value, dict):
        selected = [k for k, v in value.items()
                    if isinstance(v, dict) and v.get('selected')]
        return ','.join(sorted(selected))
    if isinstance(value, str) and ',' in value:
        return ','.join(sorted(p.strip() for p in value.split(',')))
    if isinstance(value, str) and '\n' in value:
        return ','.join(sorted(p.strip() for p in value.split('\n')))
    return _norm(value)


def differs(row, payload):
    for key, value in _flatten(payload).items():
        if isinstance(value, str) and '\n' in value:
            wanted = ','.join(sorted(value.split('\n')))
        else:
            wanted = _norm(value)
        if _row_value(row, key) != wanted:
            return True
    return False


class ItemSpec:
    """Describes one MVC collection: where to search/add/set/delete and how
    objects are keyed."""

    def __init__(self, name, search, add, set_, delete, wrapper, descr_field,
                 key_fn=None):
        self.name = name
        self.search = search
        self.add = add
        self.set = set_
        self.delete = delete
        self.wrapper = wrapper
        self.descr_field = descr_field
        self.key_fn = key_fn or (lambda row: parse_tag(row.get(descr_field)))


FILTER_RULES = ItemSpec(
    'filter rule', 'firewall/filter/search_rule', 'firewall/filter/add_rule',
    'firewall/filter/set_rule/', 'firewall/filter/del_rule/', 'rule',
    'description')
DNAT_RULES = ItemSpec(
    'port forward', 'firewall/d_nat/search_rule', 'firewall/d_nat/add_rule',
    'firewall/d_nat/set_rule/', 'firewall/d_nat/del_rule/', 'rule', 'descr')
ALIASES = ItemSpec(
    'alias', 'firewall/alias/search_item', 'firewall/alias/add_item',
    'firewall/alias/set_item/', 'firewall/alias/del_item/', 'alias',
    'description', key_fn=lambda row: (
        row.get('name') if (row.get('name') or '').startswith(ALIAS_PREFIX)
        else None))
UNBOUND_HOSTS = ItemSpec(
    'DNS host override', 'unbound/settings/search_host_override',
    'unbound/settings/add_host_override', 'unbound/settings/set_host_override/',
    'unbound/settings/del_host_override/', 'host', 'description')
DNSMASQ_HOSTS = ItemSpec(
    'dnsmasq host', 'dnsmasq/settings/search_host', 'dnsmasq/settings/add_host',
    'dnsmasq/settings/set_host/', 'dnsmasq/settings/del_host/', 'host', 'descr')
KEA_RESERVATIONS = ItemSpec(
    'Kea reservation', 'kea/dhcpv4/search_reservation',
    'kea/dhcpv4/add_reservation', 'kea/dhcpv4/set_reservation/',
    'kea/dhcpv4/del_reservation/', 'reservation', 'description')
ROUTES = ItemSpec(
    'static route', 'routes/routes/searchroute', 'routes/routes/addroute',
    'routes/routes/setroute/', 'routes/routes/delroute/', 'route', 'descr')
GATEWAYS = ItemSpec(
    'gateway', 'routing/settings/search_gateway', 'routing/settings/add_gateway',
    'routing/settings/set_gateway/', 'routing/settings/del_gateway/',
    'gateway_item', 'descr')


class OPNsenseConfigSync:
    """Applies controller-pushed config to OPNsense.

    ``port_map`` maps an emulated UniFi interface name (eth0, eth1, ...) to
    the OPNsense interface identifier (wan, lan, opt1, ...). It is a callable
    so the collector can resolve it lazily from live interface data.
    """

    def __init__(self, api, port_map, lan_identifiers, options=None):
        self.api = api
        self.port_map = port_map
        self.lan_identifiers = lan_identifiers
        self.options = options or {}
        self.warnings = []

    def _enabled(self, name):
        return self.options.get(name, True)

    def _warn(self, msg, *args):
        text = msg % args if args else msg
        logger.warning('OPNsense sync: %s', text)
        self.warnings.append(text)

    # ── Generic collection sync ──────────────────────────────────────────

    def sync_items(self, spec, desired, delete_stale=True, keep=None):
        """Make the tagged objects of ``spec`` match ``desired`` (key -> payload).

        Returns (changed, {key: uuid}).
        """
        rows = self.api.search(spec.search)
        existing = {}
        for row in rows:
            key = spec.key_fn(row)
            if key:
                existing.setdefault(key, []).append(row)

        changed = False
        uuids = {}
        for key, payload in desired.items():
            matches = existing.pop(key, [])
            if matches:
                row = matches[0]
                for dupe in matches[1:]:
                    self._delete(spec, dupe['uuid'])
                    changed = True
                uuids[key] = row['uuid']
                if differs(row, payload):
                    result = self.api.post(
                        spec.set + row['uuid'], {spec.wrapper: payload})
                    OPNsenseAPI.check_saved(result, 'update %s %s' % (spec.name, key))
                    logger.info('Updated %s %s', spec.name, key)
                    changed = True
            else:
                result = self.api.post(spec.add, {spec.wrapper: payload})
                OPNsenseAPI.check_saved(result, 'add %s %s' % (spec.name, key))
                uuids[key] = result.get('uuid')
                logger.info('Added %s %s', spec.name, key)
                changed = True

        if delete_stale:
            for key, matches in existing.items():
                if keep and keep(key):
                    continue
                for row in matches:
                    self._delete(spec, row['uuid'])
                    logger.info('Removed %s %s', spec.name, key)
                    changed = True
        return changed, uuids

    def _delete(self, spec, uuid):
        result = self.api.post(spec.delete + uuid)
        if not (isinstance(result, dict) and result.get('result') in ('deleted', 'not found')):
            raise OPNsenseAPIError('delete %s %s failed: %s' % (spec.name, uuid, result))

    def apply_filter(self):
        result = self.api.post('firewall/filter/apply')
        logger.info('Applied firewall changes: %s', result.get('status', result)
                    if isinstance(result, dict) else result)

    def reconfigure_aliases(self):
        self.api.post('firewall/alias/reconfigure')

    # ── Client blocking ──────────────────────────────────────────────────

    def sync_blocked(self, macs, ips):
        """Block ``macs`` (and their currently known ``ips``) on all LAN
        interfaces. Returns True if anything changed on the firewall."""
        macs = sorted({normalize_mac(m) for m in macs if m})
        ips = sorted(set(ips))
        aliases = {
            BLOCKED_MAC_ALIAS: {
                'enabled': '1', 'name': BLOCKED_MAC_ALIAS, 'type': 'mac',
                'content': '\n'.join(macs),
                'description': make_tag('blocked', 'clients blocked from UniFi'),
            },
            BLOCKED_IP_ALIAS: {
                'enabled': '1', 'name': BLOCKED_IP_ALIAS, 'type': 'host',
                'content': '\n'.join(ips),
                'description': make_tag('blocked-ip', 'addresses of blocked clients'),
            },
        }
        alias_changed, _ = self.sync_items(
            ALIASES, aliases, delete_stale=False)
        if alias_changed:
            self.reconfigure_aliases()

        rule = {
            BLOCK_RULE_KEY: {
                'enabled': '1' if macs else '0',
                'action': 'block',
                'quick': '1',
                'interface': ','.join(self.lan_identifiers()),
                'direction': 'in',
                'ipprotocol': 'inet46',
                'protocol': 'any',
                'source_net': '%s,%s' % (BLOCKED_MAC_ALIAS, BLOCKED_IP_ALIAS),
                'destination_net': 'any',
                'sequence': '1',
                'log': '1',
                'description': make_tag(BLOCK_RULE_KEY, 'UniFi blocked clients'),
            }
        }
        rule_changed, _ = self.sync_items(
            FILTER_RULES, rule, delete_stale=False)
        if rule_changed:
            self.apply_filter()
        return alias_changed or rule_changed

    def kill_states(self, ip):
        """Drop all pf states to/from ``ip`` so a block takes effect now."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return 0
        if addr.version != 4:
            # The endpoint's input sanitizer strips ':' (and '/'), so IPv6
            # addresses can't be expressed; a bare IPv4 address is matched
            # by the state query as an exact /32 network.
            return 0
        result = self.api.post('diagnostics/firewall/kill_states', {'filter': ip})
        dropped = result.get('dropped_states', 0) if isinstance(result, dict) else 0
        logger.info('Dropped %s firewall states for %s', dropped, ip)
        return dropped

    # ── system_cfg translation ───────────────────────────────────────────

    def apply_system_cfg(self, cfg):
        """Translate and apply a controller system_cfg dict. Returns a summary."""
        self.warnings = []
        summary = {}
        fw = cfg.get('firewall', {})

        groups = self._collect_groups(fw)
        rules, used_aliases = ({}, {})
        if self._enabled('apply_firewall'):
            rules, used_aliases = self._translate_rules(cfg, groups)
        forwards, fwd_aliases = ({}, {})
        if self._enabled('apply_port_forward'):
            forwards, fwd_aliases = self._translate_port_forwards(cfg, groups)
        used_aliases.update(fwd_aliases)

        # 1. aliases first, rules reference them
        alias_changed, _ = self.sync_items(
            ALIASES, used_aliases, delete_stale=False)
        if alias_changed:
            self.reconfigure_aliases()

        # 2. rules and forwards
        filter_changed = False
        if self._enabled('apply_firewall'):
            changed, _ = self.sync_items(
                FILTER_RULES, rules, keep=lambda k: k == BLOCK_RULE_KEY)
            filter_changed |= changed
            summary['firewall_rules'] = len(rules)
        if self._enabled('apply_port_forward'):
            changed, _ = self.sync_items(DNAT_RULES, forwards)
            filter_changed |= changed
            summary['port_forwards'] = len(forwards)
        if filter_changed:
            self.apply_filter()

        # 3. drop aliases nothing references any more
        keep = set(used_aliases) | {BLOCKED_MAC_ALIAS, BLOCKED_IP_ALIAS}
        stale_changed, _ = self.sync_items(
            ALIASES, {}, keep=lambda k: k in keep)
        if stale_changed:
            self.reconfigure_aliases()
        summary['aliases'] = len(used_aliases)

        # The remaining sections are independent: one failing must not stop
        # the others from converging.
        for option, name, fn in (
                ('apply_dhcp', 'dhcp_reservations', self._sync_dhcp),
                ('apply_dns', 'dns_hosts', self._sync_dns),
                ('apply_routes', 'static_routes', self._sync_routes)):
            if not self._enabled(option):
                continue
            try:
                summary[name] = fn(cfg)
            except OPNsenseAPIError as e:
                self._warn('%s not applied: %s', name, e)

        summary['warnings'] = list(self.warnings)
        return summary

    # ── Groups / aliases ─────────────────────────────────────────────────

    @staticmethod
    def _collect_groups(fw):
        groups = {}
        group_types = {
            'address-group': ('host', 'address'),
            'ipv6-address-group': ('host', 'ipv6-address'),
            'network-group': ('network', 'network'),
            'ipv6-network-group': ('network', 'ipv6-network'),
            'port-group': ('port', 'port'),
        }
        for gtype, (alias_type, member_key) in group_types.items():
            for name, body in fw.get('group', {}).get(gtype, {}).items():
                groups[(gtype, name)] = {
                    'type': alias_type,
                    'members': _as_list(body.get(member_key)),
                    'description': body.get('description', ''),
                }
        return groups

    @staticmethod
    def _alias_payload(name, alias_type, members, descr):
        return {
            'enabled': '1', 'name': name, 'type': alias_type,
            'content': '\n'.join(members),
            'description': make_tag(name, descr),
        }

    def _group_alias(self, groups, gtype, name, aliases):
        group = groups.get((gtype, name))
        if group is None:
            return None
        aname = alias_name(name)
        aliases[aname] = self._alias_payload(
            aname, group['type'], group['members'], group['description'])
        return aname

    def _port_value(self, port, key, aliases):
        """Controller ports are '80', '80,443' or '1000-2000'. pf rules take one
        port or range, so lists become a port alias."""
        port = str(port).strip().replace(':', '-')
        if ',' not in port:
            return port
        aname = alias_name('ports_' + key)
        aliases[aname] = self._alias_payload(
            aname, 'port', [p.strip() for p in port.split(',')], 'ports for ' + key)
        return aname

    def _endpoint(self, side, key, groups, aliases):
        """Translate an EdgeOS source/destination block into
        (network, negate, port) or raise ValueError if unsupported."""
        network, negate, port = 'any', False, ''
        address = side.get('address')
        if address:
            address = str(address)
            if address.startswith('!'):
                negate, address = True, address[1:]
            network = address
            if '-' in address:  # ranges need an alias
                aname = alias_name('range_' + key)
                aliases[aname] = self._alias_payload(aname, 'host', [address], 'range')
                network = aname
        mac = side.get('mac-address')
        if mac:
            aname = alias_name('mac_' + key)
            aliases[aname] = self._alias_payload(
                aname, 'mac', [normalize_mac(str(mac).lstrip('!'))], 'MAC match')
            negate = str(mac).startswith('!')
            network = aname
        group = side.get('group', {})
        for gtype in ('address-group', 'network-group',
                      'ipv6-address-group', 'ipv6-network-group'):
            if gtype in group:
                gname = str(group[gtype])
                if gname.startswith('!'):
                    negate, gname = True, gname[1:]
                aname = self._group_alias(groups, gtype, gname, aliases)
                if aname is None:
                    raise ValueError('unknown %s %s' % (gtype, gname))
                network = aname
        if 'port-group' in group:
            aname = self._group_alias(groups, 'port-group', str(group['port-group']), aliases)
            if aname is None:
                raise ValueError('unknown port-group %s' % group['port-group'])
            port = aname
        if side.get('port'):
            port = self._port_value(side['port'], key, aliases)
        return network, negate, port

    # ── Firewall rules ───────────────────────────────────────────────────

    def _ruleset_bindings(self, cfg):
        """Map ruleset name -> list of (opnsense if, direction, local)."""
        bindings = {}

        def bind(ifname, fw_bind):
            opn_if = self.port_map(ifname.split('.')[0])
            if not opn_if:
                return
            for direction in ('in', 'out', 'local'):
                spec = fw_bind.get(direction, {})
                for key in ('name', 'ipv6-name'):
                    if spec.get(key):
                        bindings.setdefault(spec[key], []).append(
                            (opn_if, 'out' if direction == 'out' else 'in',
                             direction == 'local'))

        for ifname, body in cfg.get('interfaces', {}).get('ethernet', {}).items():
            if not isinstance(body, dict):
                continue
            bind(ifname, body.get('firewall', {}))
            for vif, vbody in (body.get('vif') or {}).items():
                if isinstance(vbody, dict):
                    bind('%s.%s' % (ifname, vif), vbody.get('firewall', {}))
        return bindings

    def _translate_rules(self, cfg, groups):
        fw = cfg.get('firewall', {})
        bindings = self._ruleset_bindings(cfg)
        rules, aliases = {}, {}
        for family_key, ipproto in (('name', 'inet'), ('ipv6-name', 'inet6')):
            for rs_name, ruleset in fw.get(family_key, {}).items():
                targets = bindings.get(rs_name)
                user_rules = {
                    num: rule for num, rule in ruleset.get('rule', {}).items()
                    if not self._is_predefined(num)
                }
                if not user_rules:
                    continue
                if not targets:
                    self._warn('ruleset %s is not bound to a mapped interface, '
                               'skipping %d rules', rs_name, len(user_rules))
                    continue
                for num, rule in user_rules.items():
                    if is_mirrored(rule.get('description')):
                        continue
                    for opn_if, direction, local in targets:
                        key = 'fw-%s-%s-%s' % (rs_name, num, opn_if)
                        try:
                            payload = self._rule_payload(
                                rule, key, opn_if, direction, local, ipproto,
                                int(num), groups, aliases)
                        except ValueError as e:
                            self._warn('rule %s/%s skipped: %s', rs_name, num, e)
                            continue
                        if payload:
                            rules[key] = payload
        return rules, aliases

    @staticmethod
    def _is_predefined(num):
        try:
            n = int(num)
        except (TypeError, ValueError):
            return True
        return any(lo <= n <= hi for lo, hi in PREDEFINED_RULE_RANGES)

    def _rule_payload(self, rule, key, opn_if, direction, local, ipproto, num,
                      groups, aliases):
        action = ACTIONS.get(rule.get('action', 'accept'))
        if action is None:
            raise ValueError('unsupported action %s' % rule.get('action'))
        protocol = str(rule.get('protocol', 'all')).lower()
        if protocol.startswith('!'):
            raise ValueError('negated protocol %s' % protocol)
        protocol = PROTOCOLS.get(protocol, protocol.upper())

        state = rule.get('state') or {}
        if state and state.get('new') != 'enable':
            # pf only evaluates rules for new connections; rules matching only
            # established/related/invalid traffic have no pf equivalent.
            raise ValueError('matches only existing connections')
        if rule.get('time'):
            raise ValueError('time schedules are not translated')

        src_net, src_not, src_port = self._endpoint(
            rule.get('source', {}), key + '_src', groups, aliases)
        dst_net, dst_not, dst_port = self._endpoint(
            rule.get('destination', {}), key + '_dst', groups, aliases)
        if local and dst_net == 'any':
            dst_net = '(self)'

        descr = rule.get('description', '')
        return {
            'enabled': '0' if 'disable' in rule else '1',
            'action': action,
            'quick': '1',
            'interface': opn_if,
            'direction': direction,
            'ipprotocol': ipproto,
            'protocol': protocol,
            'source_net': src_net,
            'source_not': '1' if src_not else '0',
            'source_port': src_port if protocol in ('TCP', 'UDP', 'TCP/UDP') else '',
            'destination_net': dst_net,
            'destination_not': '1' if dst_not else '0',
            'destination_port': dst_port if protocol in ('TCP', 'UDP', 'TCP/UDP') else '',
            'log': '1' if rule.get('log') == 'enable' else '0',
            'sequence': str(1000 + num),
            'description': make_tag(key, descr),
        }

    # ── Port forwards ────────────────────────────────────────────────────

    def _translate_port_forwards(self, cfg, groups):
        pf = cfg.get('port-forward', {})
        wan_ifs = _as_list(pf.get('wan-interface', 'eth0'))
        forwards, aliases = {}, {}
        for num, rule in (pf.get('rule') or {}).items():
            fwd = rule.get('forward-to', {})
            if not fwd.get('address') or is_mirrored(rule.get('description')):
                continue
            for wan in wan_ifs:
                opn_if = self.port_map(wan)
                if not opn_if:
                    self._warn('port forward %s: WAN %s is not mapped', num, wan)
                    continue
                key = 'pf-%s-%s' % (num, opn_if)
                protocol = str(rule.get('protocol', 'tcp_udp')).lower()
                protocol = {'tcp_udp': 'tcp/udp', 'all': 'any'}.get(protocol, protocol)
                orig_port = self._port_value(rule.get('original-port', ''), key, aliases)
                local_port = str(fwd.get('port') or '').replace(':', '-')
                source = 'any'
                src_not = False
                src = rule.get('src')
                if src and src != 'any':
                    src = str(src)
                    src_not = src.startswith('!')
                    source = src.lstrip('!')
                forwards[key] = {
                    'disabled': '1' if 'disable' in rule else '0',
                    'interface': opn_if,
                    'ipprotocol': 'inet',
                    'protocol': protocol,
                    'source': {'network': source, 'not': '1' if src_not else '0'},
                    'destination': {'network': opn_if + 'ip', 'port': orig_port},
                    'target': fwd['address'],
                    'local-port': '' if ',' in local_port else local_port,
                    'log': '1' if rule.get('log') == 'enable' else '0',
                    'pass': 'pass',
                    'descr': make_tag(key, rule.get('description', '')),
                }
        return forwards, aliases

    # ── DHCP reservations ────────────────────────────────────────────────

    def _dhcp_backend(self):
        try:
            if self.api.get('kea/dhcpv4/get').get('dhcpv4', {}).get(
                    'general', {}).get('enabled') == '1':
                return 'kea'
        except OPNsenseAPIError:
            pass
        try:
            if self.api.get('dnsmasq/settings/get').get('dnsmasq', {}).get('enable') == '1':
                return 'dnsmasq'
        except OPNsenseAPIError:
            pass
        return 'isc'

    @staticmethod
    def _static_mappings(cfg):
        mappings = []
        shared = cfg.get('service', {}).get('dhcp-server', {}).get(
            'shared-network-name', {})
        for net in shared.values():
            for subnet, body in (net.get('subnet') or {}).items():
                for host, m in (body.get('static-mapping') or {}).items():
                    if m.get('mac-address') and m.get('ip-address'):
                        mappings.append({
                            'subnet': subnet, 'hostname': host,
                            'mac': normalize_mac(m['mac-address']),
                            'ip': m['ip-address'],
                        })
        return mappings

    def _sync_dhcp(self, cfg):
        mappings = self._static_mappings(cfg)
        backend = self._dhcp_backend()
        if backend == 'isc':
            if mappings:
                self._warn('%d DHCP reservations not applied: ISC DHCP has no '
                           'API for static mappings (use Kea or Dnsmasq)', len(mappings))
            return 0

        hostname = lambda h: re.sub(r'[^A-Za-z0-9-]', '-', h).strip('-')[:63]
        # MACs that already have a reservation of the user's own (including
        # ones mirrored into UniFi) must not get a second, tagged one.
        spec = KEA_RESERVATIONS if backend == 'kea' else DNSMASQ_HOSTS
        mac_field = 'hw_address' if backend == 'kea' else 'hwaddr'
        own = set()
        for row in self.api.search(spec.search):
            if not spec.key_fn(row):
                own.update(normalize_mac(m) for m in re.split(r'[,\s]+', str(row.get(mac_field) or '')) if m)
        mappings = [m for m in mappings if m['mac'] not in own]
        desired = {}
        if backend == 'kea':
            subnets = {}
            for row in self.api.search('kea/dhcpv4/search_subnet'):
                try:
                    subnets[row['uuid']] = ipaddress.ip_network(row['subnet'], strict=False)
                except (KeyError, ValueError):
                    continue
            for m in mappings:
                ip = ipaddress.ip_address(m['ip'])
                subnet_uuid = next((u for u, n in subnets.items() if ip in n), None)
                if not subnet_uuid:
                    self._warn('reservation %s: no Kea subnet contains %s', m['hostname'], m['ip'])
                    continue
                key = 'dhcp-' + m['mac'].replace(':', '')
                desired[key] = {
                    'subnet': subnet_uuid, 'ip_address': m['ip'],
                    'hw_address': m['mac'], 'hostname': hostname(m['hostname']),
                    'description': make_tag(key, m['hostname']),
                }
            changed, _ = self.sync_items(KEA_RESERVATIONS, desired)
            if changed:
                self.api.post('kea/service/reconfigure')
        else:
            for m in mappings:
                key = 'dhcp-' + m['mac'].replace(':', '')
                desired[key] = {
                    'host': hostname(m['hostname']), 'ip': m['ip'],
                    'hwaddr': m['mac'], 'descr': make_tag(key, m['hostname']),
                }
            changed, _ = self.sync_items(
                DNSMASQ_HOSTS, desired, keep=lambda k: not k.startswith('dhcp-'))
            if changed:
                self.api.post('dnsmasq/service/reconfigure')
        return len(desired)

    # ── DNS host records ─────────────────────────────────────────────────

    def _sync_dns(self, cfg):
        system = cfg.get('system', {})
        default_domain = system.get('domain-name', 'localdomain')
        records = []
        for fqdn, body in (system.get('static-host-mapping', {})
                           .get('host-name', {}) or {}).items():
            if fqdn in SKIP_HOST_MAPPINGS:
                continue
            for addr in _as_list(body.get('inet')):
                records.append((fqdn, addr))
                for alias in _as_list(body.get('alias')):
                    records.append((alias, addr))

        def split(name):
            if '.' in name:
                host, domain = name.split('.', 1)
                return host, domain
            return name, default_domain

        try:
            unbound = self.api.get('unbound/settings/get').get('unbound', {}).get(
                'general', {}).get('enabled') == '1'
        except OPNsenseAPIError:
            unbound = False

        # skip records identical to an override the user already has
        spec = UNBOUND_HOSTS if unbound else DNSMASQ_HOSTS
        own = set()
        for row in self.api.search(spec.search):
            if not spec.key_fn(row):
                own.add(((row.get('hostname') or row.get('host') or '').lower(),
                         (row.get('domain') or '').lower(),
                         row.get('server') or row.get('ip') or ''))
        desired = {}
        for name, addr in records:
            host, domain = split(name)
            if (host.lower(), domain.lower(), addr) in own:
                continue
            key = 'dns-%s-%s' % (name, addr)
            key = re.sub(r'[^A-Za-z0-9._:-]', '_', key)
            if unbound:
                desired[key] = {
                    'enabled': '1', 'hostname': host, 'domain': domain,
                    'rr': 'AAAA' if ':' in addr else 'A', 'server': addr,
                    'ttl': str(DNS_OVERRIDE_TTL),
                    'description': make_tag(key, name),
                }
            else:
                desired[key] = {
                    'host': host, 'domain': domain, 'ip': addr,
                    'descr': make_tag(key, name),
                }
        if unbound:
            changed, _ = self.sync_items(UNBOUND_HOSTS, desired)
            if changed:
                self.api.post('unbound/service/reconfigure')
        else:
            changed, _ = self.sync_items(
                DNSMASQ_HOSTS, desired, keep=lambda k: not k.startswith('dns-'))
            if changed:
                self.api.post('dnsmasq/service/reconfigure')
        return len(desired)

    # ── Static routes ────────────────────────────────────────────────────

    def _sync_routes(self, cfg):
        static = cfg.get('protocols', {}).get('static', {})
        wanted = []
        for network, body in (static.get('route') or {}).items():
            for nexthop, nh_body in (body.get('next-hop') or {}).items():
                descr = (nh_body or {}).get('description', '') if isinstance(nh_body, dict) else ''
                if not is_mirrored(descr):
                    wanted.append((network, nexthop, descr))
            if 'blackhole' in body:
                self._warn('blackhole route %s not translated', network)
        for network in (static.get('interface-route') or {}):
            self._warn('interface route %s not translated', network)
        if not wanted and not self._has_tagged(ROUTES):
            return 0

        gateways = self.api.search('routing/settings/search_gateway')
        # Reuse the user's own gateways; ours are (re)declared below so the
        # stale-gateway cleanup keeps the ones still in use.
        by_address = {g.get('gateway'): g['name'] for g in gateways
                      if g.get('gateway') and not GATEWAYS.key_fn(g)}
        interfaces = self._interface_networks()

        desired_gw, desired_routes = {}, {}
        for network, nexthop, descr in wanted:
            gw_name = by_address.get(nexthop)
            if not gw_name:
                hop = ipaddress.ip_address(nexthop)
                opn_if = next((i for i, nets in interfaces.items()
                               if any(hop in n for n in nets)), None)
                if not opn_if:
                    self._warn('route %s: no interface reaches %s', network, nexthop)
                    continue
                gw_name = 'UFG_' + re.sub(r'[^A-Za-z0-9]', '_', nexthop)
                gkey = 'gw-' + nexthop
                desired_gw[gkey] = {
                    'disabled': '0', 'name': gw_name, 'interface': opn_if,
                    'ipprotocol': 'inet6' if ':' in nexthop else 'inet',
                    'gateway': nexthop, 'monitor_disable': '1',
                    'priority': '255', 'weight': '1',
                    'descr': make_tag(gkey, 'next hop for UniFi static routes'),
                }
            key = 'route-%s-%s' % (network, nexthop)
            desired_routes[key] = {
                'network': network, 'gateway': gw_name, 'enabled': '1',
                'descr': make_tag(key, descr),
            }

        gw_changed, _ = self.sync_items(GATEWAYS, desired_gw, delete_stale=False)
        if gw_changed:
            self.api.post('routing/settings/reconfigure')
        try:
            route_changed, _ = self.sync_items(ROUTES, desired_routes)
        except OPNsenseAPIError:
            if not gw_changed:
                raise
            # Route validation reads the gateway list through configd, which
            # caches it for 20s; a gateway added just now is not in it yet.
            time.sleep(GATEWAY_LIST_CACHE_TTL)
            route_changed, _ = self.sync_items(ROUTES, desired_routes)
        if route_changed:
            self.api.post('routes/routes/reconfigure')
        stale_gw, _ = self.sync_items(GATEWAYS, {}, keep=lambda k: k in desired_gw)
        if stale_gw:
            self.api.post('routing/settings/reconfigure')
        return len(desired_routes)

    def _has_tagged(self, spec):
        return any(spec.key_fn(r) for r in self.api.search(spec.search))

    def _interface_networks(self):
        networks = {}
        for row in self.api.search('interfaces/overview/interfaces_info'):
            ident = row.get('identifier')
            if not ident:
                continue
            for entry in (row.get('ipv4') or []) + (row.get('ipv6') or []):
                try:
                    net = ipaddress.ip_network(entry['ipaddr'].split('%')[0], strict=False)
                except (KeyError, ValueError):
                    continue
                if not net.is_link_local and net.prefixlen < net.max_prefixlen:
                    networks.setdefault(ident, []).append(net)
        return networks
