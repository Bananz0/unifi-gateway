# -*- coding: utf-8 -*-
"""Mirror OPNsense configuration into the UniFi controller.

The controller only knows what it provisioned itself, so port forwards,
firewall rules, DHCP reservations, routes and DNS records made directly on
OPNsense are invisible in the UniFi UI. This module copies them into the
controller through its REST API so everything shows up in one place.

OPNsense stays the source of truth for these objects: every mirrored object
is named ``[OPNsense] ...`` (clients get it in their note), is refreshed from
OPNsense on each run and removed when its OPNsense original goes away. When
the controller pushes its config back to the gateway, opnsense_sync skips
anything carrying the prefix, so nothing is applied twice.
"""
import http.cookiejar
import ipaddress
import json
import logging
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

from .opnsense_api import OPNsenseAPIError
from .opnsense_sync import MIRROR_PREFIX, TAG, is_mirrored, normalize_mac

logger = logging.getLogger('unifi-gateway')

PORT_PROTOCOLS = {'tcp': 'tcp', 'udp': 'udp', 'tcp/udp': 'tcp_udp'}
RULE_PROTOCOLS = {'': 'all', 'any': 'all', 'tcp': 'tcp', 'udp': 'udp',
                  'tcp/udp': 'tcp_udp', 'icmp': 'icmp'}
RULE_ACTIONS = {'pass': 'accept', 'block': 'drop', 'reject': 'reject'}


class UniFiAPIError(Exception):
    pass


class UniFiController:
    """Minimal session client for the classic Network API (works on UniFi OS
    consoles via /proxy/network and on standalone controllers)."""

    def __init__(self, url, username, password, site='default', verify_ssl=False,
                 timeout=30):
        self.url = url.rstrip('/')
        self.username = username
        self.password = password
        self.site = site
        self.timeout = timeout
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self._jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(self._jar))
        self._csrf = None
        self._prefix = None

    def _raw(self, method, path, payload=None):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        if self._csrf:
            headers['X-CSRF-Token'] = self._csrf
        data = json.dumps(payload).encode('utf-8') if payload is not None else None
        req = urllib.request.Request(self.url + path, data=data, headers=headers,
                                     method=method)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                token = resp.headers.get('X-Updated-CSRF-Token') or resp.headers.get('X-CSRF-Token')
                if token:
                    self._csrf = token
                body = resp.read()
                return resp.status, json.loads(body) if body else {}
        except urllib.error.HTTPError as e:
            body = e.read()[:300].decode('utf-8', 'replace')
            return e.code, {'error': body}
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise UniFiAPIError('%s %s: %s' % (method, path, e))

    def login(self):
        payload = {'username': self.username, 'password': self.password, 'remember': False}
        status, _ = self._raw('POST', '/api/auth/login', payload)
        if status == 200:
            self._prefix = '/proxy/network'           # UniFi OS console
            return
        status, body = self._raw('POST', '/api/login', payload)
        if status == 200:
            self._prefix = ''                         # standalone controller
            return
        raise UniFiAPIError('login failed (HTTP %s)' % status)

    def call(self, method, path, payload=None):
        """Call /api/s/<site>/<path> (or /v2/api/site/<site>/<path> for v2/...)."""
        if self._prefix is None:
            self.login()
        if path.startswith('v2/'):
            full = '%s/v2/api/site/%s/%s' % (self._prefix, self.site, path[3:])
        else:
            full = '%s/api/s/%s/%s' % (self._prefix, self.site, path)
        status, body = self._raw(method, full, payload)
        if status == 401:
            self.login()
            status, body = self._raw(method, full, payload)
        if status not in (200, 201, 204):
            raise UniFiAPIError('%s %s: HTTP %s %s' % (method, path, status,
                                                      json.dumps(body)[:300]))
        if isinstance(body, dict) and 'data' in body:
            return body['data']
        return body


ADBLOCK_NAME = 'Ad Blocking (AdGuard Home)'
ADGUARD_CONFIG = '/usr/local/AdGuardHome/AdGuardHome.yaml'


def adguard_filtering_enabled(path):
    """AdGuard Home's protection and filtering switches from its YAML
    (both must be on for it to block); None when it isn't installed."""
    try:
        with open(path, encoding='utf-8') as f:
            text = f.read()
    except OSError:
        return None
    flags = dict(re.findall(r'(?m)^\s+(protection_enabled|filtering_enabled):\s*(\w+)', text))
    return flags.get('protection_enabled', 'true') == 'true' and         flags.get('filtering_enabled', 'true') == 'true'


# the label OPNsense's firewall log gives its default block rule
DEFAULT_DENY = 'Default deny / state violation rule'


def _name(text):
    return ('%s %s' % (MIRROR_PREFIX, (text or '').strip() or 'unnamed'))[:128]


def _is_ip(value):
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


class OPNsenseMirror:

    def __init__(self, api, controller, lan_identifiers, wan_identifiers):
        self.api = api
        self.ctl = controller
        self.adguard_config = ADGUARD_CONFIG
        self.lan_identifiers = lan_identifiers
        self.wan_identifiers = wan_identifiers
        self.warnings = []
        self._networks = None
        self._base = None
        self._group_ids = {}

    def _warn(self, msg, *args):
        text = msg % args if args else msg
        if text not in self.warnings:
            self.warnings.append(text)

    # ── Generic UniFi collection sync ────────────────────────────────────

    def _sync(self, path, desired, existing, compare_keys, label):
        """desired/existing: name -> object. Creates, updates and deletes so
        the mirrored set equals ``desired``. Returns name -> _id."""
        ids, changes = {}, 0
        for name, obj in desired.items():
            current = existing.pop(name, None)
            try:
                if current is None:
                    created = self.ctl.call('POST', 'rest/' + path, obj)
                    ids[name] = created[0]['_id'] if created else None
                    changes += 1
                    logger.info('UniFi mirror: added %s %r', label, name)
                else:
                    ids[name] = current['_id']
                    if any(_cmp(current.get(k)) != _cmp(obj.get(k)) for k in compare_keys):
                        self.ctl.call('PUT', 'rest/%s/%s' % (path, current['_id']), obj)
                        changes += 1
                        logger.info('UniFi mirror: updated %s %r', label, name)
            except UniFiAPIError as e:
                self._warn('%s %r rejected by the controller: %s' % (label, name, _short(e)))
        for name, obj in existing.items():
            try:
                self.ctl.call('DELETE', 'rest/%s/%s' % (path, obj['_id']))
                changes += 1
                logger.info('UniFi mirror: removed %s %r', label, name)
            except UniFiAPIError as e:
                self._warn('could not remove %s %r: %s' % (label, name, _short(e)))
        return ids, changes

    def _mirrored(self, path):
        return {o['name']: o for o in self.ctl.call('GET', 'rest/' + path)
                if is_mirrored(o.get('name'))}

    # ── OPNsense lookups ─────────────────────────────────────────────────

    def _aliases(self):
        return {a['name']: a for a in self.api.search('firewall/alias/search_item')
                if not a['name'].startswith('ufg_') and a.get('enabled', '1') == '1'}

    @staticmethod
    def _alias_members(alias):
        content = alias.get('content') or ''
        return [m.strip() for m in re.split(r'[,\n]', content) if m.strip()]

    def _resolve_host(self, value, aliases):
        if _is_ip(value):
            return value.split('/')[0]
        alias = aliases.get(value)
        if alias and alias.get('type') == 'host':
            members = [m for m in self._alias_members(alias) if _is_ip(m)]
            if members:
                return members[0]
        return None

    def _resolve_ports(self, value, aliases):
        value = str(value or '').strip()
        if not value:
            return ''
        if re.match(r'^[0-9,:-]+$', value):
            return value.replace(':', '-')
        alias = aliases.get(value)
        if alias and alias.get('type') == 'port':
            members = [m.replace(':', '-') for m in self._alias_members(alias)
                       if re.match(r'^[0-9:-]+$', m)]
            return ','.join(members[:15])
        return None

    # ── Mirrors ──────────────────────────────────────────────────────────

    def run(self):
        self.warnings = []
        self._networks = None
        self._base = None
        summary = {}
        aliases = self._aliases()
        for label, fn in (('groups', lambda: self.mirror_groups(aliases)),
                          ('port_forwards', lambda: self.mirror_port_forwards(aliases)),
                          ('firewall_rules', lambda: self.mirror_firewall_rules(aliases)),
                          ('fixed_ips', self.mirror_reservations),
                          ('routes', self.mirror_routes),
                          ('ad_blocking', self.mirror_ad_blocking)):
            try:
                summary[label] = fn()
            except (UniFiAPIError, OPNsenseAPIError) as e:
                self._warn('%s not mirrored: %s' % (label, e))
        summary['warnings'] = self.warnings
        return summary

    def mirror_ad_blocking(self):
        """AdGuard Home on OPNsense filters DNS for the whole network: shown in
        UniFi as a Content Filtering profile with the Advertisement category
        (how Network 10.6 represents a UXG's ad blocking). Read-only on the
        AdGuard side; the profile follows AdGuard's filtering switch."""
        enabled = adguard_filtering_enabled(self.adguard_config)
        if enabled is None:
            return 0                          # no AdGuard Home on this router
        name = _name(ADBLOCK_NAME)
        profiles = [p for p in self.ctl.call('GET', 'v2/content-filtering') or []
                    if p.get('name') == name]
        if not enabled:
            for profile in profiles:
                self.ctl.call('DELETE', 'v2/content-filtering/%s' % profile['_id'])
                logger.info('UniFi mirror: removed %r (AdGuard filtering is off)', name)
            return 0
        networks = sorted(n['_id'] for n in self.ctl.call('GET', 'rest/networkconf')
                          if n.get('purpose') in ('corporate', 'guest'))
        desired = {'name': name, 'enabled': True, 'categories': ['ADVERTISEMENT'],
                   'network_ids': networks, 'client_macs': [], 'allow_list': [],
                   'block_list': [], 'safe_search': [], 'schedule': {'mode': 'ALWAYS'}}
        if not profiles:
            self.ctl.call('POST', 'v2/content-filtering/create', desired)
            logger.info('UniFi mirror: added %r', name)
        elif sorted(profiles[0].get('network_ids') or []) != networks or                 not profiles[0].get('enabled'):
            self.ctl.call('PUT', 'v2/content-filtering/%s' % profiles[0]['_id'],
                          dict(desired, _id=profiles[0]['_id']))
            logger.info('UniFi mirror: updated %r', name)
        return 1

    def mirror_groups(self, aliases):
        desired = {}
        for name, alias in sorted(aliases.items()):
            members = self._alias_members(alias)
            if alias.get('type') == 'port':
                members = [m.replace(':', '-') for m in members if re.match(r'^[0-9:-]+$', m)]
                group_type = 'port-group'
            elif alias.get('type') in ('host', 'network'):
                members = [m for m in members if _is_ip(m) or re.match(r'^[0-9.]+-[0-9.]+$', m)]
                v6 = [m for m in members if ':' in m]
                group_type = 'ipv6-address-group' if members and len(v6) == len(members) else 'address-group'
                members = v6 if group_type.startswith('ipv6') else [m for m in members if ':' not in m]
            else:
                continue
            if not members:
                continue
            desired[_name(name)[:64]] = {
                'name': _name(name)[:64], 'group_type': group_type,
                'group_members': members,
            }
        self._group_ids, changes = self._sync(
            'firewallgroup', desired, self._mirrored('firewallgroup'),
            ('group_type', 'group_members'), 'group')
        return len(desired)

    def mirror_port_forwards(self, aliases):
        desired = {}
        wan_ifs = set(self.wan_identifiers())
        for rule in self.api.search('firewall/d_nat/search_rule'):
            if rule.get('is_automatic') or TAG + ':' in (rule.get('descr') or ''):
                continue
            ifaces = set((rule.get('interface') or '').split(','))
            if not ifaces & wan_ifs:
                continue          # LAN-side redirects have no UniFi equivalent
            descr = rule.get('descr') or ''
            proto = PORT_PROTOCOLS.get((rule.get('protocol') or '').lower())
            dst_port = self._resolve_ports(rule.get('destination.port'), aliases)
            fwd = self._resolve_host(rule.get('target') or '', aliases)
            if not proto or not dst_port or not fwd:
                self._warn('port forward %r not mirrored (protocol/port/target '
                           'cannot be expressed in UniFi)' % descr)
                continue
            fwd_port = self._resolve_ports(rule.get('local-port'), aliases) or dst_port
            if ',' in dst_port and fwd_port != dst_port:
                self._warn('port forward %r not mirrored: UniFi cannot forward '
                           'several ports (%s) to one (%s)' % (descr, dst_port, fwd_port))
                continue
            src = rule.get('source.network') or 'any'
            src = src if (src == 'any' or _is_ip(src)) else 'any'
            name = _name(descr)
            while name in desired:
                name = (name + '*')[:128]
            desired[name] = {
                'name': name,
                'enabled': rule.get('disabled') != '1',
                'src': src, 'dst_port': dst_port,
                'fwd': fwd, 'fwd_port': fwd_port,
                'proto': proto, 'log': rule.get('log') == '1',
                'pfwd_interface': 'wan', 'destination_ip': 'any',
            }
        self._sync('portforward', desired, self._mirrored('portforward'),
                   ('enabled', 'src', 'dst_port', 'fwd', 'fwd_port', 'proto', 'log'),
                   'port forward')
        return len(desired)

    def _lan_network_id(self, address=None):
        if self._networks is None:
            self._networks = [n for n in self.ctl.call('GET', 'rest/networkconf')
                              if n.get('purpose') in ('corporate', 'guest')]
        nets = self._networks
        if address:
            for n in nets:
                try:
                    if ipaddress.ip_address(address) in ipaddress.ip_network(
                            n.get('ip_subnet', ''), strict=False):
                        return n['_id']
                except ValueError:
                    continue
        corporate = [n for n in nets if n.get('purpose') == 'corporate']
        return corporate[0]['_id'] if corporate else None

    def _endpoint(self, net, port, aliases, prefix, rule_descr):
        """Translate an OPNsense rule endpoint into UniFi src_/dst_ fields."""
        fields = {prefix + '_firewallgroup_ids': []}
        group_ids = self._group_ids
        net = (net or 'any').strip()
        if net in ('any', ''):
            pass
        elif ',' in net:
            raise ValueError('multiple networks')
        elif _is_ip(net):
            fields[prefix + '_address'] = net
        elif net in self.lan_identifiers() or net.lower() == 'lan':
            fields[prefix + '_networkconf_id'] = self._lan_network_id()
            fields[prefix + '_networkconf_type'] = 'NETv4'
        elif net.endswith('ip') and net[:-2] in self.lan_identifiers():
            fields[prefix + '_networkconf_id'] = self._lan_network_id()
            fields[prefix + '_networkconf_type'] = 'ADDRv4'
        elif net in ('(self)',) or (net.endswith('ip') and net[:-2] in self.wan_identifiers()):
            pass      # the firewall itself: expressed by the LOCAL ruleset
        elif _name(net)[:64] in group_ids:
            fields[prefix + '_firewallgroup_ids'].append(group_ids[_name(net)[:64]])
        else:
            raise ValueError('network %s has no UniFi equivalent' % net)
        port = (port or '').strip()
        if port:
            if re.match(r'^[0-9,:-]+$', port):
                fields[prefix + '_port'] = port.replace(':', '-')
            elif _name(port)[:64] in group_ids:
                fields[prefix + '_firewallgroup_ids'].append(group_ids[_name(port)[:64]])
            else:
                raise ValueError('port %s has no UniFi equivalent' % port)
        return fields

    def _rule_base(self):
        """First user rule number for this site's gateway: the controller
        only accepts 2000+ for a USG and 20000+ for UniFi OS gateways (UXG,
        UDM), answering api.err.FirewallRuleIndexOutOfRange otherwise."""
        if self._base is None:
            types = {d.get('type') for d in self.ctl.call('GET', 'stat/device')}
            self._base = 20000 if types & {'uxg', 'udm'} else 2000
        return self._base

    def mirror_firewall_rules(self, aliases):
        lan = set(self.lan_identifiers()) | {'LAN'}
        wan = set(self.wan_identifiers())
        overview = {r.get('identifier'): r.get('description') for r in
                    self.api.search('interfaces/overview/interfaces_info')}
        wan_descr = {overview.get(i) for i in wan}
        lan_descr = {overview.get(i) for i in lan if overview.get(i)}
        desired, index = {}, {}
        # indexes held by the operator's own UniFi rules; ours go around them
        taken = {(r.get('ruleset'), r.get('rule_index'))
                 for r in self.ctl.call('GET', 'rest/firewallrule')
                 if not is_mirrored(r.get('name'))}
        rows = sorted(self.api.search('firewall/filter/search_rule'),
                      key=lambda r: str(r.get('sort_order') or ''))
        for rule in rows:
            descr = rule.get('description') or ''
            if rule.get('is_automatic') or descr.startswith(TAG + ':'):
                continue
            ifaces = set((rule.get('interface') or '').split(','))
            if ifaces & (lan | lan_descr):
                base = 'LAN'
            elif ifaces & (wan | wan_descr):
                base = 'WAN'
            else:
                continue          # floating rules and other interfaces
            if rule.get('ipprotocol') == 'inet6':
                continue
            action = RULE_ACTIONS.get(rule.get('action'))
            proto = RULE_PROTOCOLS.get((rule.get('protocol') or '').lower())
            if not action or not proto or rule.get('source_not') == '1' or rule.get('destination_not') == '1':
                self._warn('firewall rule %r not mirrored (unsupported action, '
                           'protocol or negation)' % descr)
                continue
            dst = (rule.get('destination_net') or 'any').strip()
            local = dst == '(self)' or (dst.endswith('ip') and dst[:-2] in wan | lan)
            ruleset = '%s_%s' % (base, 'LOCAL' if local else 'IN')
            try:
                obj = {}
                obj.update(self._endpoint(rule.get('source_net'), rule.get('source_port'),
                                          aliases, 'src', descr))
                obj.update(self._endpoint(dst, rule.get('destination_port'),
                                          aliases, 'dst', descr))
            except ValueError as e:
                self._warn('firewall rule %r not mirrored: %s' % (descr, e))
                continue
            index[ruleset] = index.get(ruleset, self._rule_base() - 1) + 1
            while (ruleset, index[ruleset]) in taken:
                index[ruleset] += 1
            name = _name(descr)
            while name in desired:
                name = (name + '*')[:128]
            obj.update({
                'name': name, 'ruleset': ruleset, 'rule_index': index[ruleset],
                'enabled': rule.get('enabled') == '1', 'action': action,
                'protocol': proto, 'protocol_match_excepted': False,
                'logging': rule.get('log') == '1',
                'state_established': False, 'state_invalid': False,
                'state_new': False, 'state_related': False, 'ipsec': '',
            })
            desired[name] = obj
        # OPNsense's built-in default deny has no UniFi object. Firewall-log
        # blocks are reported as triggers that must name a blocking UniFi
        # policy, so it is mirrored as the last WAN_IN rule (the translator
        # never pushes [OPNsense] rules back).
        ruleset = 'WAN_IN'
        index[ruleset] = index.get(ruleset, self._rule_base() - 1) + 1
        while (ruleset, index[ruleset]) in taken:
            index[ruleset] += 1
        name = _name(DEFAULT_DENY)
        desired[name] = {
            'name': name, 'ruleset': ruleset, 'rule_index': index[ruleset],
            'enabled': True, 'action': 'drop', 'protocol': 'all',
            'protocol_match_excepted': False, 'logging': True,
            'state_established': False, 'state_invalid': False,
            'state_new': False, 'state_related': False, 'ipsec': '',
            'src_firewallgroup_ids': [], 'dst_firewallgroup_ids': [],
            'src_address': '', 'dst_address': '', 'src_port': '', 'dst_port': '',
            'src_networkconf_type': 'NETv4', 'dst_networkconf_type': 'NETv4',
        }
        self._sync('firewallrule', desired, self._mirrored('firewallrule'),
                   ('ruleset', 'rule_index', 'enabled', 'action', 'protocol',
                    'src_address', 'dst_address', 'dst_port', 'src_port',
                    'src_firewallgroup_ids', 'dst_firewallgroup_ids',
                    'src_networkconf_id', 'dst_networkconf_id', 'logging'),
                   'firewall rule')
        return len(desired)

    def mirror_reservations(self):
        hosts = []
        for spec_path, mac_key, ip_key, name_key in (
                ('dnsmasq/settings/search_host', 'hwaddr', 'ip', 'host'),
                ('kea/dhcpv4/search_reservation', 'hw_address', 'ip_address', 'hostname')):
            try:
                rows = self.api.search(spec_path)
            except OPNsenseAPIError:
                continue
            for row in rows:
                descr = row.get('descr') or row.get('description') or ''
                if descr.startswith(TAG + ':') or row.get('ignore') == '1':
                    continue
                macs = [normalize_mac(m) for m in re.split(r'[,\s]+', row.get(mac_key) or '') if m]
                ip = (row.get(ip_key) or '').split(',')[0]
                if macs and ip and ':' not in ip:
                    hosts.append((macs[0], ip, row.get(name_key) or ''))
        users = {u['mac'].lower(): u for u in self.ctl.call('GET', 'rest/user')}
        # UniFi's own devices (switches, APs) are not clients and can't have a
        # client fixed IP; the controller manages their addressing itself.
        devices = {d.get('mac', '').lower() for d in self.ctl.call('GET', 'stat/device')}
        wanted = {}
        for mac, ip, host in hosts:
            if mac not in devices:
                wanted[mac] = (ip, host)
        changes = 0
        for mac, (ip, host) in wanted.items():
            user = users.get(mac)
            update = {'use_fixedip': True, 'fixed_ip': ip,
                      'network_id': self._lan_network_id(ip),
                      'note': '%s DHCP reservation' % MIRROR_PREFIX, 'noted': True}
            if user is None:
                update.update({'mac': mac, 'name': host})
                try:
                    self.ctl.call('POST', 'rest/user', update)
                    changes += 1
                except UniFiAPIError as e:
                    self._warn('fixed IP for %s (%s) rejected: %s' % (host or mac, ip, _short(e)))
                continue
            if user.get('note') and not is_mirrored(user.get('note')):
                update.pop('note')        # keep the user's own note
                update.pop('noted')
            if not user.get('name') and host:
                update['name'] = host
            if any(_cmp(user.get(k)) != _cmp(v) for k, v in update.items()):
                try:
                    self.ctl.call('PUT', 'rest/user/%s' % user['_id'], update)
                    changes += 1
                except UniFiAPIError as e:
                    self._warn('fixed IP for %s (%s) rejected: %s' % (host or mac, ip, _short(e)))
        for mac, user in users.items():
            if mac not in wanted and is_mirrored(user.get('note')) and user.get('use_fixedip'):
                self.ctl.call('PUT', 'rest/user/%s' % user['_id'],
                              {'use_fixedip': False, 'note': '', 'noted': False})
                changes += 1
        if changes:
            logger.info('UniFi mirror: %d client fixed-IP changes', changes)
        return len(wanted)

    def mirror_routes(self):
        gateways = {}
        for g in self.api.search('routing/settings/search_gateway'):
            if g.get('gateway'):
                gateways[g['name']] = g['gateway']
        try:
            for s in self.api.get('routes/gateway/status').get('items', []):
                if s.get('address') not in (None, '', '~'):
                    gateways.setdefault(s['name'], s['address'])
        except OPNsenseAPIError:
            pass
        desired = {}
        for route in self.api.search('routes/routes/searchroute'):
            descr = route.get('descr') or route.get('network')
            if descr.startswith(TAG + ':'):
                continue
            nexthop = gateways.get(route.get('gateway'))
            if not nexthop:
                self._warn('route %s not mirrored: gateway %s has no address'
                           % (route.get('network'), route.get('gateway')))
                continue
            name = _name(descr)
            desired[name] = {
                'name': name, 'enabled': route.get('enabled', '1') == '1' and route.get('disabled') != '1',
                'type': 'static-route', 'static-route_type': 'nexthop-route',
                'static-route_network': route.get('network'),
                'static-route_nexthop': nexthop, 'static-route_distance': '1',
            }
        self._sync('routing', desired, self._mirrored('routing'),
                   ('enabled', 'static-route_network', 'static-route_nexthop'), 'route')
        return len(desired)


def _short(error):
    match = re.search(r'api\.err\.[A-Za-z]+', str(error))
    return match.group(0) if match else str(error)[:120]


def _cmp(value):
    if isinstance(value, list):
        return sorted(str(v) for v in value)
    if isinstance(value, bool):
        return value
    if value in (None, ''):
        return ''
    if str(value).lower() in ('true', 'false'):
        return str(value).lower() == 'true'
    return str(value)
