# -*- coding: utf-8 -*-
"""Write a UXG (UniFi Gateway Max etc.) controller config into OPNsense.

A UXG is provisioned with ``system_cfg = {"udapi": {...}, "ubntconf": "..."}``
where ``udapi`` is the UniFi OS router API tree. This module translates the
parts with an OPNsense equivalent into the same desired-state objects the
EdgeOS translator in ``opnsense_sync`` produces, and reuses its machinery
(``sync_items``, tagging, DHCP/DNS/route backends, skip rules):

- ``firewall/sets``                      -> firewall aliases (when referenced)
- ``firewall/filter`` user rules         -> MVC filter rules
- ``firewall/nat`` DNAT rules            -> destination NAT (port forwards)
- ``routes/static``                      -> routes (+ gateways if needed)
- ``services.dhcpServers[].staticLeases`` -> Kea reservations / Dnsmasq hosts
- ``services.dnsForwarder.hostRecords``   -> Unbound host overrides

The lab capture (tests/fixtures/uxg_setparam_10.6.106.json) contains no user
rules, NAT or routes, so the shape of those entries is inferred from the
built-in rules it does contain. The translator therefore fails closed:

- a rule carrying a field it does not understand is skipped with a warning,
  never applied with that constraint silently dropped;
- a skipped rule keeps whatever tagged object an earlier push created for it;
- a section missing from the tree is left alone (only a present, possibly
  empty, section is authoritative).
"""
import ipaddress
import logging
import re

from .opnsense_api import OPNsenseAPIError
from .opnsense_ids import apply_ids
from .opnsense_sync import (
    ALIAS_PREFIX, ALIASES, BLOCK_RULE_KEY, BLOCKED_IP_ALIAS, BLOCKED_MAC_ALIAS, DNAT_RULES,
    FILTER_RULES, OPNsenseConfigSync, _as_list, alias_name, is_mirrored,
    make_tag, normalize_mac,
)

logger = logging.getLogger('unifi-gateway')

# Chains the kernel enters directly. INPUT traffic is addressed to the
# gateway itself (EdgeOS "local"), FORWARD traffic is routed through it.
ROOT_CHAINS = {'INPUT': True, 'FORWARD': False}

# Controller-generated rule ids, by analogy with EdgeOS (3000-3999 and 6000+)
# scaled by ten: the capture has jumps at 30001, per-network rules at 60001+
# and chain terminators at 2^31-2 / 2^31-1.
PREDEFINED_RULE_RANGES = ((30000, 39999), (60000, 2 ** 32))

# Highest sequence an OPNsense MVC filter rule accepts.
MAX_SEQUENCE = 999999

TARGETS = {'ACCEPT': 'pass', 'RETURN': 'pass', 'DROP': 'block', 'REJECT': 'reject'}
IP_VERSIONS = {'both': 'inet46', 'v4only': 'inet', 'v6only': 'inet6',
               'v4': 'inet', 'v6': 'inet6'}
PROTOCOLS = {
    'all': 'any', 'any': 'any', 'tcp_udp': 'TCP/UDP', 'tcp': 'TCP', 'udp': 'UDP',
    'icmp': 'ICMP', 'icmpv6': 'IPV6-ICMP', 'ipv6-icmp': 'IPV6-ICMP',
}
PORT_PROTOCOLS = ('TCP', 'UDP', 'TCP/UDP')
SET_ALIAS_TYPES = {'address': None, 'mac': 'mac', 'port': 'port'}

RULE_KEYS = {'id', 'description', 'enabled', 'disabled', 'target', 'ipVersion',
             'protocol', 'source', 'destination', 'log', 'inInterface',
             'outInterface', 'states', 'connectionStates', 'connectionState',
             'icmpType', 'icmpv6Type',
             # the UniFi policy ({id, type}) a UXG names when it reports a hit
             'triggerTag'}
NAT_KEYS = RULE_KEYS | {'translation', 'chain'}

# Network 10.6 matches "this interface's address/subnet" with virtual sets
# named after the UDAPI interface (ADDRv4_eth4, NETv4_br0) that are not
# declared in firewall/sets.
INTERFACE_SET = re.compile(r'^(ADDR|NET)v([46])_(.+)$')

# UDAPI ICMP type names -> OPNsense filter icmptype / icmp6type values
ICMP_TYPES = {
    'echo-request': 'echoreq', 'echo-reply': 'echorep',
    'destination-unreachable': 'unreach', 'time-exceeded': 'timex',
    'parameter-problem': 'paramprob', 'redirect': 'redir',
    'router-advertisement': 'routeradv', 'router-solicitation': 'routersol',
    'source-quench': 'squench', 'timestamp-request': 'timereq',
    'timestamp-reply': 'timerep',
}
ICMP6_TYPES = {
    'echo-request': 'echoreq', 'echo-reply': 'echorep',
    'destination-unreachable': 'unreach', 'packet-too-big': 'toobig',
    'time-exceeded': 'timex', 'parameter-problem': 'paramprob',
    'neighbor-solicitation': 'neighbrsol', 'neighbor-advertisement': 'neighbradv',
    'router-solicitation': 'routersol', 'router-advertisement': 'routeradv',
}
ENDPOINT_KEYS = {'address', 'addresses', 'sets', 'port', 'ports', 'mac',
                 'macAddress', 'negate', 'invert'}

# Controller sets used by its guest portal / captive portal redirection; NAT
# rules referencing them are built-ins, not user port forwards.
GUEST_SETS = {'guest_network', 'guest_networkv6', 'guest_allow_dns_servers',
              'captive_portal_subnets', 'guest_portal_address',
              'guest_portal_ports', 'guest_portal_redirector_p'}

# DNS records the controller injects for its own setup / WiFiman UIs.
SKIP_HOST_RECORDS = {'setup.ui.com', 'setup.ubnt.com'}


# The controller prefixes rule descriptions with their ruleset, e.g.
# "[LAN_IN]Allow Network 192.168.1.0/24 Traffic" in the lab capture.
RULESET_PREFIX = re.compile(r'^\[[A-Z]+(?:v6)?_(?:IN|OUT|LOCAL)\]\s*')


# Network 10.6 names port-forward NAT entries after the forward:
# "PortForward DNAT [<name>]" / "PortForward MASQUERADE [<name>]".
PORT_FORWARD_NAME = re.compile(r'^PortForward \w+ \[(.*)\]$')


def _mirrored(rule):
    description = RULESET_PREFIX.sub('', str(rule.get('description') or ''))
    forward = PORT_FORWARD_NAME.match(description)
    return is_mirrored(forward.group(1) if forward else description)


# per-country aggregated CIDR lists, used when OPNsense has no MaxMind
# GeoIP database configured
COUNTRY_LIST_URL = 'https://www.ipdeny.com/ipblocks/data/aggregated/%s-aggregated.zone'


def trigger_tags(cfg):
    """{(chain, rule id): {id, type}}: the UniFi policy behind each UDAPI
    rule, which OPNsense rule keys (ufw-<chain>-<id>-<if>) carry back."""
    udapi = cfg.get('udapi') if isinstance(cfg, dict) else None
    tags = {}
    if not isinstance(udapi, dict):
        return tags
    for chain in udapi.get('firewall/filter') or []:
        name = (chain.get('config') or {}).get('name') if isinstance(chain, dict) else None
        for rule in (chain.get('rules') or []) if name else []:
            tag = rule.get('triggerTag') if isinstance(rule, dict) else None
            if isinstance(tag, dict) and tag.get('id') and 'id' in rule:
                tags[(name, str(rule['id']))] = {'id': str(tag['id']),
                                                 'type': str(tag.get('type') or 'FIREWALL_RULE')}
    for rule in udapi.get('firewall/nat') or []:
        tag = rule.get('triggerTag') if isinstance(rule, dict) else None
        if isinstance(tag, dict) and tag.get('id') and 'id' in rule:
            tags[(str(rule.get('chain', '')), str(rule['id']))] = {
                'id': str(tag['id']), 'type': str(tag.get('type') or 'PORT_FORWARDING')}
    return tags


def is_udapi_config(cfg):
    return isinstance(cfg, dict) and isinstance(cfg.get('udapi'), dict)


def _ref_id(value):
    if isinstance(value, dict):
        return value.get('id')
    return value


def _is_predefined(rule_id):
    try:
        n = int(rule_id)
    except (TypeError, ValueError):
        return True
    return any(lo <= n <= hi for lo, hi in PREDEFINED_RULE_RANGES)


def _family(network):
    """IP version of an address/CIDR literal, None for aliases and 'any'."""
    try:
        return ipaddress.ip_network(network, strict=False).version
    except ValueError:
        return None


def _enabled(rule):
    return rule.get('enabled', True) is not False and not rule.get('disabled')


def _chains(section):
    """Normalize a filter/nat section into [(chain name, [rules])]. Entries are
    chains ({config, rules}); a bare rule list is treated as one chain."""
    chains, loose = [], []
    for entry in section or []:
        if not isinstance(entry, dict):
            continue
        if 'config' in entry or 'rules' in entry:
            name = (entry.get('config') or {}).get('name', '')
            chains.append((name, [r for r in entry.get('rules') or []
                                  if isinstance(r, dict)]))
        else:
            loose.append(entry)
    if loose:
        chains.append(('', loose))
    return chains


class UDAPIConfigSync(OPNsenseConfigSync):
    """Applies a UXG ``system_cfg`` (UDAPI tree) to OPNsense."""

    def apply_system_cfg(self, cfg):
        if not is_udapi_config(cfg):
            raise ValueError('not a UDAPI system_cfg')
        udapi = cfg['udapi']
        self.warnings = []
        self._udapi_ifs = {
            i.get('identification', {}).get('id'): i
            for i in udapi.get('interfaces') or [] if isinstance(i, dict)}
        self._if_networks = None
        summary = {}
        sets = self._collect_sets(udapi.get('firewall/sets'))

        do_filter = self._enabled('apply_firewall') and 'firewall/filter' in udapi
        do_nat = self._enabled('apply_port_forward') and 'firewall/nat' in udapi
        rules, used_aliases, rules_failed = {}, {}, set()
        if do_filter:
            rules, used_aliases, rules_failed = self._translate_filter(
                udapi['firewall/filter'], sets)
        forwards, fwd_failed = {}, set()
        if do_nat:
            forwards, fwd_aliases, fwd_failed = self._translate_nat(
                udapi['firewall/nat'], sets)
            used_aliases.update(fwd_aliases)

        if do_filter:
            self._translate_geoip((udapi.get('services') or {}).get('geoipFiltering'),
                                  rules, used_aliases)

        alias_changed, _ = self.sync_items(ALIASES, used_aliases, delete_stale=False)
        if alias_changed:
            self.reconfigure_aliases()

        def keeper(failed, extra=()):
            return lambda k: k in extra or any(k.startswith(p) for p in failed)

        filter_changed = False
        if do_filter:
            changed, _ = self.sync_items(
                FILTER_RULES, rules, keep=keeper(rules_failed, (BLOCK_RULE_KEY,)))
            filter_changed |= changed
            summary['firewall_rules'] = len(rules)
        if do_nat:
            changed, _ = self.sync_items(DNAT_RULES, forwards, keep=keeper(fwd_failed))
            filter_changed |= changed
            summary['port_forwards'] = len(forwards)
        if filter_changed:
            self.apply_filter()

        # Drop aliases nothing references any more. Rules kept from an earlier
        # push (skipped or in a section absent from this one) still count.
        keep = (set(used_aliases) | self._referenced_aliases()
                | {BLOCKED_MAC_ALIAS, BLOCKED_IP_ALIAS})
        stale_changed, _ = self.sync_items(ALIASES, {}, keep=lambda k: k in keep)
        if stale_changed:
            self.reconfigure_aliases()
        summary['aliases'] = len(used_aliases)

        services = udapi.get('services') or {}
        legacy = self._legacy_cfg(udapi)
        for option, name, present, fn in (
                ('apply_dhcp', 'dhcp_reservations', 'dhcpServers' in services,
                 self._sync_dhcp),
                ('apply_dns', 'dns_hosts', 'dnsForwarder' in services, self._sync_dns),
                ('apply_routes', 'static_routes', 'routes/static' in udapi,
                 self._sync_routes)):
            if not self._enabled(option) or not present:
                continue
            try:
                summary[name] = fn(legacy)
            except (OPNsenseAPIError, ValueError) as e:
                self._warn('%s not applied: %s', name, e)

        if self._enabled('apply_ids') and 'idsIps' in services:
            try:
                summary['ids_rulesets'] = apply_ids(
                    self.api, services['idsIps'], self.resolve_interface, self._warn)
            except OPNsenseAPIError as e:
                self._warn('threat management not applied: %s', e)

        summary['warnings'] = list(self.warnings)
        return summary

    def _referenced_aliases(self):
        names = set()
        for spec in (FILTER_RULES, DNAT_RULES):
            for row in self.api.search(spec.search):
                if not spec.key_fn(row):
                    continue
                for field, value in row.items():
                    if field.startswith(('source', 'destination')) and isinstance(value, str):
                        names.update(v.strip() for v in value.split(',')
                                     if v.strip().startswith(ALIAS_PREFIX))
        return names

    # ── Interfaces ───────────────────────────────────────────────────────

    def resolve_interface(self, if_id, _depth=0):
        """OPNsense identifier for a UDAPI interface id (eth4, br0, ...).

        Tries, in order: the configured port map, the subnet of the UDAPI
        interface against OPNsense's interface networks, and the members /
        parent the interface is built on (bridge, VLAN, PPPoE)."""
        if not if_id or _depth > 4:
            return None
        direct = self.port_map(if_id)
        if direct:
            return direct
        body = self._udapi_ifs.get(if_id) or {}
        for addr in body.get('addresses') or []:
            try:
                iface = ipaddress.ip_interface(addr.get('cidr', ''))
            except ValueError:
                continue
            if iface.network.prefixlen == iface.network.max_prefixlen:
                continue
            for ident, nets in self._interface_networks_cached().items():
                if any(iface.ip in n for n in nets):
                    return ident
        lower = [m.get('id') for m in (body.get('bridge') or {}).get('interfaces') or []]
        for key in ('vlan', 'pppoe'):
            parent = (body.get(key) or {}).get('interface')
            if parent:
                lower.append(_ref_id(parent))
        for member in lower:
            ident = self.resolve_interface(member, _depth + 1)
            if ident:
                return ident
        return None

    def _interface_networks_cached(self):
        if self._if_networks is None:
            try:
                self._if_networks = self._interface_networks()
            except OPNsenseAPIError as e:
                self._warn('could not read OPNsense interface networks: %s', e)
                self._if_networks = {}
        return self._if_networks

    # ── Sets / aliases ───────────────────────────────────────────────────

    @staticmethod
    def _collect_sets(section):
        sets = {}
        for entry in section or []:
            ident = (entry or {}).get('identification') or {}
            name, stype = ident.get('name'), ident.get('type', 'address')
            if not name or stype not in SET_ALIAS_TYPES:
                continue
            members = _as_list(entry.get('entries'))
            alias_type = SET_ALIAS_TYPES[stype]
            if alias_type is None:
                alias_type = 'network' if any('/' in m for m in members) else 'host'
            if alias_type == 'mac':
                members = [normalize_mac(m) for m in members]
            sets[name] = {'type': alias_type, 'members': members,
                          'description': entry.get('description', '')}
        return sets

    def _set_alias(self, sets, name, aliases):
        body = sets.get(name)
        if body is None:
            raise ValueError('unknown set %s' % name)
        aname = alias_name(name)
        aliases[aname] = self._alias_payload(
            aname, body['type'], body['members'], body['description'])
        return aname, body['type']

    @staticmethod
    def _port_text(value):
        if isinstance(value, dict):
            start = value.get('start', value.get('from'))
            stop = value.get('stop', value.get('end', value.get('to', start)))
            if start is None:
                raise ValueError('unsupported port %r' % value)
            return str(start) if str(start) == str(stop) else '%s-%s' % (start, stop)
        if isinstance(value, (list, tuple)):
            return ','.join(UDAPIConfigSync._port_text(v) for v in value)
        return str(value).strip()

    def _udapi_endpoint(self, side, key, sets, aliases):
        """Translate a UDAPI source/destination into (network, negate, port)."""
        side = side or {}
        unknown = set(side) - ENDPOINT_KEYS
        if unknown:
            raise ValueError('unsupported match %s' % ','.join(sorted(unknown)))
        negate = bool(side.get('negate') or side.get('invert'))
        networks, port = [], ''

        addresses = _as_list(side.get('address')) + _as_list(side.get('addresses'))
        if addresses:
            if any(a.startswith('!') for a in addresses):
                if len(addresses) > 1:
                    raise ValueError('negated address list')
                negate, addresses = True, [addresses[0][1:]]
            if len(addresses) == 1 and '-' not in addresses[0]:
                networks.append(addresses[0])
            else:
                aname = alias_name('addr_' + key)
                alias_type = ('network' if any('/' in a for a in addresses)
                              and not any('-' in a for a in addresses) else 'host')
                aliases[aname] = self._alias_payload(aname, alias_type, addresses, key)
                networks.append(aname)

        mac = side.get('mac') or side.get('macAddress')
        if mac:
            mac = str(mac)
            if mac.startswith('!'):
                negate, mac = True, mac[1:]
            aname = alias_name('mac_' + key)
            aliases[aname] = self._alias_payload(aname, 'mac', [normalize_mac(mac)], 'MAC match')
            networks.append(aname)

        for set_name in _as_list(side.get('sets')):
            if set_name.startswith('!'):
                negate, set_name = True, set_name[1:]
            iface = INTERFACE_SET.match(set_name)
            if iface:
                opn_if = self.resolve_interface(iface.group(3))
                if not opn_if:
                    raise ValueError('interface set %s is not mapped' % set_name)
                networks.append(opn_if + 'ip' if iface.group(1) == 'ADDR' else opn_if)
                continue
            aname, alias_type = self._set_alias(sets, set_name, aliases)
            if alias_type == 'port':
                if port:
                    raise ValueError('more than one port match')
                port = aname
            else:
                networks.append(aname)

        if len(networks) > 1:
            # iptables ANDs these; an OPNsense list would OR them.
            raise ValueError('combined address/set/MAC match')
        for pkey in ('port', 'ports'):
            if side.get(pkey) not in (None, '', []):
                if port:
                    raise ValueError('more than one port match')
                port = self._port_value(self._port_text(side[pkey]), key, aliases)
        return (networks[0] if networks else 'any'), negate, port

    @staticmethod
    def _protocol(rule):
        value = rule.get('protocol', 'all')
        if isinstance(value, dict):
            if value.get('negate') or value.get('invert'):
                raise ValueError('negated protocol')
            value = value.get('name', 'all')
        value = str(value).lower()
        if value.startswith('!'):
            raise ValueError('negated protocol %s' % value)
        return PROTOCOLS.get(value, value.upper())

    @staticmethod
    def _icmp_type(rule, protocol):
        """OPNsense icmptype/icmp6type fields for a rule's ICMP type match."""
        for field, table, target in (('icmpType', ICMP_TYPES, 'icmptype'),
                                     ('icmpv6Type', ICMP6_TYPES, 'icmp6type')):
            value = str(rule.get(field) or '').lower()
            if value in ('', 'any'):
                continue
            if value not in table:
                raise ValueError('unsupported %s %s' % (field, value))
            return {target: table[value]}
        return {}

    @staticmethod
    def _check_states(rule):
        states = rule.get('states', rule.get('connectionStates', rule.get('connectionState')))
        if states is None:
            return
        states = [str(s).lower() for s in _as_list(states)]
        if 'new' not in states:
            # pf only evaluates rules for new connections.
            raise ValueError('matches only existing connections')

    # ── Firewall rules ───────────────────────────────────────────────────

    def _chain_bindings(self, chains):
        """Map chain name -> [(UDAPI in-if, UDAPI out-if, local)] by following
        jump rules from the root chains."""
        by_name = {name: rules for name, rules in chains}
        bindings = {}

        def walk(name, in_if, out_if, local, path):
            for rule in by_name.get(name, []):
                target = str(rule.get('target', ''))
                if target not in by_name or target in path or not _enabled(rule):
                    continue
                r_in = _ref_id(rule.get('inInterface')) or in_if
                r_out = _ref_id(rule.get('outInterface')) or out_if
                binding = (r_in, r_out, local)
                if binding not in bindings.setdefault(target, []):
                    bindings[target].append(binding)
                walk(target, r_in, r_out, local, path | {target})

        for root, local in ROOT_CHAINS.items():
            walk(root, None, None, local, {root})
        return bindings

    def _translate_filter(self, section, sets):
        chains = _chains(section)
        chain_names = {name for name, _ in chains}
        bindings = self._chain_bindings(chains)
        rules, aliases, failed = {}, {}, set()
        for chain, chain_rules in chains:
            user = [r for r in chain_rules
                    if str(r.get('target', '')) not in chain_names
                    and not _is_predefined(r.get('id'))
                    and not _mirrored(r)]
            if not user:
                continue
            targets = []
            for in_if, out_if, local in bindings.get(chain, []):
                if in_if:
                    opn_if, direction = self.resolve_interface(in_if), 'in'
                elif out_if and not local:
                    opn_if, direction = self.resolve_interface(out_if), 'out'
                else:
                    continue
                if opn_if and (opn_if, direction, local) not in targets:
                    targets.append((opn_if, direction, local))
            if not targets:
                self._warn('chain %s is not bound to a mapped interface, '
                           'skipping %d rules', chain, len(user))
                for rule in user:
                    failed.add('ufw-%s-%s-' % (chain, rule.get('id')))
                continue
            for rule in user:
                prefix = 'ufw-%s-%s-' % (chain, rule.get('id'))
                for opn_if, direction, local in targets:
                    key = prefix + opn_if
                    try:
                        rules[key] = self._udapi_rule_payload(
                            rule, key, opn_if, direction, local, sets, aliases)
                    except ValueError as e:
                        self._warn('rule %s/%s skipped: %s', chain, rule.get('id'), e)
                        failed.add(prefix)
                        break
                else:
                    continue
                for k in [k for k in rules if k.startswith(prefix)]:
                    del rules[k]
        return rules, aliases, failed

    def _geoip_source(self):
        try:
            geo = (self.api.get('firewall/alias/get_geo_i_p').get('alias') or {}).get('geoip') or {}
        except (OPNsenseAPIError, AttributeError):
            return False
        return bool(geo.get('url'))

    def _translate_geoip(self, geo, rules, aliases):
        """Region blocking (services.geoipFiltering) -> a GeoIP alias and
        quick rules on each listed WAN, ahead of the user rules. "block"
        drops traffic to/from the countries; "allow" drops everything else."""
        if not isinstance(geo, dict) or not geo.get('enabled'):
            return
        countries = [c for c in geo.get('countryList') or []
                     if re.match(r'^[A-Z]{2}$', str(c))]
        action = str(geo.get('action', 'block')).lower()
        direction = str(geo.get('direction', 'both')).lower()
        if not countries or action not in ('block', 'allow') or                 direction not in ('both', 'ingress', 'egress'):
            self._warn('region blocking skipped: unsupported settings %r', geo)
            return
        name = 'ufg_geoip'
        if self._geoip_source():
            aliases[name] = self._alias_payload(
                name, 'geoip', countries, 'UniFi region blocking')
        else:
            # no MaxMind database: per-country lists OPNsense downloads and
            # refreshes itself (URL Table aliases), nested in one alias
            members = []
            for code in countries:
                member = 'ufg_geo_%s' % code.lower()
                aliases[member] = dict(self._alias_payload(
                    member, 'urltable', [COUNTRY_LIST_URL % code.lower()],
                    'UniFi region blocking %s' % code), updatefreq='1')
                members.append(member)
            aliases[name] = self._alias_payload(
                name, 'network', members, 'UniFi region blocking')
        negate = '1' if action == 'allow' else '0'
        for iface in geo.get('interfaces') or [{'id': 'eth4'}]:
            opn_if = self.resolve_interface(_ref_id(iface))
            if not opn_if:
                self._warn('region blocking: interface %s not mapped', _ref_id(iface))
                continue
            for flow, wanted, side in (('in', ('both', 'ingress'), 'source'),
                                       ('out', ('both', 'egress'), 'destination')):
                if direction not in wanted:
                    continue
                key = 'ugeo-%s-%s' % (flow, opn_if)
                rules[key] = {
                    'enabled': '1', 'action': 'block', 'quick': '1',
                    'interface': opn_if, 'direction': flow, 'ipprotocol': 'inet',
                    'protocol': 'any',
                    'source_net': name if side == 'source' else 'any',
                    'source_not': negate if side == 'source' else '0', 'source_port': '',
                    'destination_net': name if side == 'destination' else 'any',
                    'destination_not': negate if side == 'destination' else '0',
                    'destination_port': '', 'log': '1', 'sequence': '100',
                    'description': make_tag(key, 'UniFi region %s %s' % (
                        action, ','.join(countries))),
                }

    def _udapi_rule_payload(self, rule, key, opn_if, direction, local, sets, aliases):
        unknown = set(rule) - RULE_KEYS
        if unknown:
            raise ValueError('unsupported field %s' % ','.join(sorted(unknown)))
        target = str(rule.get('target', '')).upper()
        action = TARGETS.get(target)
        if action is None:
            raise ValueError('unsupported target %s' % rule.get('target'))
        for field, wanted in (('inInterface', 'in'), ('outInterface', 'out')):
            if rule.get(field):
                if direction != wanted or \
                        self.resolve_interface(_ref_id(rule[field])) != opn_if:
                    raise ValueError('%s %s does not match the chain binding'
                                     % (field, _ref_id(rule[field])))
        ipproto = IP_VERSIONS.get(str(rule.get('ipVersion', 'both')))
        if ipproto is None:
            raise ValueError('unsupported ipVersion %s' % rule.get('ipVersion'))
        protocol = self._protocol(rule)
        self._check_states(rule)
        icmp = self._icmp_type(rule, protocol)
        num = int(rule['id'])
        if not 0 < num <= MAX_SEQUENCE:
            raise ValueError('rule id %s out of sequence range' % num)

        src_net, src_not, src_port = self._udapi_endpoint(
            rule.get('source'), key + '_src', sets, aliases)
        dst_net, dst_not, dst_port = self._udapi_endpoint(
            rule.get('destination'), key + '_dst', sets, aliases)
        if (src_port or dst_port) and protocol not in PORT_PROTOCOLS:
            raise ValueError('port match without TCP/UDP protocol')
        families = {_family(src_net), _family(dst_net)} - {None}
        if len(families) > 1:
            raise ValueError('mixes IPv4 and IPv6 addresses')
        if families:
            family = 'inet' if families == {4} else 'inet6'
            if ipproto not in ('inet46', family):
                raise ValueError('%s address in an %s rule' % (family, ipproto))
            ipproto = family  # keep the family consistent with the literal
        if local and dst_net == 'any':
            dst_net = '(self)'
        return {
            'enabled': '1' if _enabled(rule) else '0',
            'action': action,
            'quick': '1',
            'interface': opn_if,
            'direction': direction,
            'ipprotocol': ipproto,
            'protocol': protocol,
            'source_net': src_net,
            'source_not': '1' if src_not else '0',
            'source_port': src_port,
            'destination_net': dst_net,
            'destination_not': '1' if dst_not else '0',
            'destination_port': dst_port,
            'log': '1' if rule.get('log') else '0',
            **icmp,
            'sequence': str(num),
            'description': make_tag(key, rule.get('description', '')),
        }

    # ── Port forwards ────────────────────────────────────────────────────

    def _translate_nat(self, section, sets):
        forwards, aliases, failed = {}, {}, set()
        for chain_name, chain_rules in _chains(section):
            for rule in chain_rules:
                chain = chain_name or rule.get('chain', '')
                if str(rule.get('target', '')).upper() != 'DNAT':
                    continue  # masquerade / SNAT: OPNsense outbound NAT
                if _mirrored(rule):
                    continue
                refs = set()
                for side in ('source', 'destination'):
                    refs.update(s.lstrip('!') for s in _as_list(
                        (rule.get(side) or {}).get('sets')))
                if refs & GUEST_SETS:
                    continue
                prefix = 'upf-%s-%s-' % (chain or 'nat', rule.get('id'))
                try:
                    payload = self._dnat_payload(rule, prefix, sets, aliases)
                except ValueError as e:
                    self._warn('port forward %s/%s skipped: %s', chain, rule.get('id'), e)
                    failed.add(prefix)
                    continue
                forwards[prefix + payload['interface']] = payload
        return forwards, aliases, failed

    def _dnat_payload(self, rule, prefix, sets, aliases):
        unknown = set(rule) - NAT_KEYS
        if unknown:
            raise ValueError('unsupported field %s' % ','.join(sorted(unknown)))
        if rule.get('outInterface'):
            raise ValueError('outInterface on DNAT')
        wan = _ref_id(rule.get('inInterface'))
        destination = dict(rule.get('destination') or {})
        dst_sets = _as_list(destination.get('sets'))
        wan_sets = [s for s in dst_sets if INTERFACE_SET.match(s)
                    and INTERFACE_SET.match(s).group(1) == 'ADDR']
        if wan_sets:
            # "destination = this interface's address" is how 10.6 names the WAN
            if not wan:
                wan = INTERFACE_SET.match(wan_sets[0]).group(3)
            destination['sets'] = [s for s in dst_sets if s not in wan_sets]
            if not destination['sets']:
                del destination['sets']
        opn_if = self.resolve_interface(wan)
        if not opn_if:
            raise ValueError('WAN %s is not mapped' % wan)
        key = prefix + opn_if
        translation = rule.get('translation') or {}
        if set(translation) - {'address', 'port'}:
            raise ValueError('unsupported translation %s' % sorted(translation))
        target = translation.get('address')
        if not target:
            raise ValueError('no translation address')
        ipproto = IP_VERSIONS.get(str(rule.get('ipVersion', 'v4only')))
        if ipproto not in ('inet', 'inet6'):
            raise ValueError('port forward for both IP versions')
        protocol = self._protocol(rule)
        self._check_states(rule)

        src_net, src_not, src_port = self._udapi_endpoint(
            rule.get('source'), key + '_src', sets, aliases)
        if src_port:
            raise ValueError('source port match')
        dst_net, dst_not, dst_port = self._udapi_endpoint(
            destination, key + '_dst', sets, aliases)
        if dst_not:
            raise ValueError('negated destination')
        local_port = self._port_text(translation.get('port', '')).replace(':', '-')
        if ',' in local_port:
            raise ValueError('translation to a port list')
        return {
            'disabled': '0' if _enabled(rule) else '1',
            'interface': opn_if,
            'ipprotocol': ipproto,
            'protocol': protocol.lower(),
            'source': {'network': src_net, 'not': '1' if src_not else '0'},
            'destination': {'network': opn_if + 'ip' if dst_net == 'any' else dst_net,
                            'port': dst_port},
            'target': str(target),
            'local-port': local_port,
            'log': '1' if rule.get('log') else '0',
            'pass': 'pass',
            'descr': make_tag(key, rule.get('description', '')),
        }

    # ── DHCP / DNS / routes via the EdgeOS backends ──────────────────────

    def _legacy_cfg(self, udapi):
        """Express the UDAPI services and routes in the EdgeOS shape the
        inherited _sync_dhcp/_sync_dns/_sync_routes consume."""
        services = udapi.get('services') or {}
        system = udapi.get('system') or {}
        own_host = str(system.get('hostname') or '').lower()

        # UDAPI static leases carry no name; a UXG names the client through
        # a DNS host record for the same address when the operator made one
        record_names = {}
        for rec in (services.get('dnsForwarder') or {}).get('hostRecords') or []:
            addr = rec.get('address')
            addr = addr.get('address') if isinstance(addr, dict) else addr
            label = str(rec.get('hostName') or '').strip().split('.')[0]
            if addr and re.match(r'^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$', label):
                record_names.setdefault(str(addr), label)

        shared = {}
        for server in services.get('dhcpServers') or []:
            if not server.get('enabled', True) or server.get('ipVersion', 'v4') != 'v4':
                continue
            try:
                subnet = str(ipaddress.ip_network('%s/%s' % (
                    server.get('gatewayAddress'), server.get('ipv4Netmask')), strict=False))
            except ValueError:
                subnet = server.get('name', '')
            mappings = {}
            for lease in server.get('staticLeases') or []:
                mac = normalize_mac(lease.get('mac') or lease.get('macAddress')
                                    or lease.get('id'))
                addrs = _as_list(lease.get('addresses') or lease.get('address'))
                if not re.match(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', mac) or \
                        mac == '00:00:00:00:00:00' or not addrs:
                    self._warn('DHCP static lease %r skipped: no usable MAC/address', lease)
                    continue
                name = str(lease.get('hostname') or lease.get('name')
                           or lease.get('description') or record_names.get(addrs[0]) or '')
                if not name or name in mappings:
                    name = 'host-' + mac.replace(':', '')
                mappings[name] = {'mac-address': mac, 'ip-address': addrs[0]}
            shared[server.get('name') or subnet] = {
                'subnet': {subnet: {'static-mapping': mappings}}}

        hosts = {}
        for rec in (services.get('dnsForwarder') or {}).get('hostRecords') or []:
            name = str(rec.get('hostName') or '').strip().rstrip('.')
            addr = rec.get('address')
            addr = addr.get('address') if isinstance(addr, dict) else addr
            if not name or not addr or '*' in name or name.lower() in SKIP_HOST_RECORDS:
                continue
            if own_host and name.lower().split('.')[0] == own_host:
                continue  # the gateway's own name; OPNsense serves its own
            if is_mirrored(rec.get('description')):
                continue
            hosts.setdefault(name, {'inet': []})['inet'].append(str(addr))

        routes, interface_routes = {}, {}
        for route in udapi.get('routes/static') or []:
            if not isinstance(route, dict) or not _enabled(route):
                continue
            dest = route.get('destination') or route.get('network') or route.get('prefix')
            dest = dest.get('address') if isinstance(dest, dict) else dest
            if not dest:
                continue
            descr = route.get('description', '')
            nexthop = route.get('nextHop') or route.get('gateway') or route.get('via')
            nexthop = nexthop.get('address') if isinstance(nexthop, dict) else nexthop
            rtype = str(route.get('type', 'nexthop' if nexthop else '')).lower()
            if rtype == 'blackhole':
                routes.setdefault(dest, {})['blackhole'] = {}
            elif nexthop:
                routes.setdefault(dest, {}).setdefault('next-hop', {})[str(nexthop)] = {
                    'description': descr}
            else:
                interface_routes[dest] = {}

        return {
            'service': {'dhcp-server': {'shared-network-name': shared}},
            'system': {'domain-name': system.get('domainName', 'localdomain'),
                       'static-host-mapping': {'host-name': hosts}},
            'protocols': {'static': {'route': routes, 'interface-route': interface_routes}},
        }
