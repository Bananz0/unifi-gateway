"""UDAPI ``services.ddns`` on OPNsense's os-ddclient accounts.

Network 10.6 sends ``{enabled, clients: [{hostname, username, password,
interface: {id}, service, server?, customName?, serverPath?}]}``. It rewrites
some providers before sending: Namecheap becomes ``custom`` with a
``namecheap.N`` customName, and any provider with a custom server becomes
``custom``. Only accounts tagged ``unifi-gw:ddns-`` are touched; a client
that can't be represented rejects the whole section (no partial writes).
"""
import hashlib

from .opnsense_api import OPNsenseAPI, OPNsenseAPIError
from .opnsense_sync import ItemSpec, make_tag, parse_tag

ACCOUNTS = ItemSpec('DDNS account', 'dyndns/accounts/search_item',
                    'dyndns/accounts/add_item', 'dyndns/accounts/set_item/',
                    'dyndns/accounts/del_item/', 'account', 'description')
CLIENT_FIELDS = {'hostname', 'username', 'password', 'interface', 'service',
                 'server', 'customName', 'serverPath'}
# UniFi service name -> ddclient service. Providers whose ddclient protocol
# needs settings UniFi doesn't collect (Cloudflare's zone) are absent and
# rejected rather than guessed.
SERVICES = {
    'dyndns': 'dyndns2', 'no-ip': 'noip', 'afraid': 'freedns',
    'changeip': 'changeip', 'dnspark': 'dnspark', 'dslreports': 'dslreports1',
    'easydns': 'easydns', 'sitelutions': 'sitelutions', 'zoneedit': 'zoneedit1',
    'duckdns': 'duckdns', 'dynu': 'dynu', 'google': 'googledomains',
}
KEY_PREFIX = 'ddns-'


def plan_ddns(section, resolve):
    """{key: account payload}; key is stable per hostname and service."""
    if not isinstance(section, dict) or section.get('enabled') is False:
        return {}
    accounts = {}
    for client in section.get('clients') or []:
        if not isinstance(client, dict) or set(client) - CLIENT_FIELDS:
            raise ValueError('unsupported DDNS client fields')
        hostname, service = client.get('hostname'), client.get('service')
        if not hostname or not isinstance(hostname, str):
            raise ValueError('DDNS client requires a hostname')
        interface = resolve((client.get('interface') or {}).get('id'))
        if not interface:
            raise ValueError('DDNS interface %s is not assigned'
                             % (client.get('interface') or {}).get('id'))
        payload = {'enabled': '1', 'username': client.get('username') or '',
                   'password': client.get('password') or '', 'hostnames': hostname,
                   'interface': interface, 'checkip': 'if', 'protocol': '', 'server': '',
                   'force_ssl': '1'}
        custom = str(client.get('customName') or '')
        if service == 'custom' and custom.startswith('namecheap.'):
            # serverPath carries domain and password; ddclient builds it itself
            payload['service'] = 'namecheap'
        elif service == 'custom':
            if client.get('serverPath'):
                raise ValueError('DDNS custom server paths are not supported by ddclient')
            if not client.get('server'):
                raise ValueError('DDNS custom service requires a server')
            payload.update(service='custom', protocol='dyndns2', server=client['server'])
        elif service in SERVICES:
            payload['service'] = SERVICES[service]
        else:
            raise ValueError('DDNS service %s has no ddclient equivalent' % service)
        key = KEY_PREFIX + hashlib.sha256(
            ('%s|%s' % (hostname, payload['service'])).encode()).hexdigest()[:16]
        if key in accounts:
            raise ValueError('duplicate DDNS client %s' % hostname)
        payload['description'] = make_tag(key, hostname)
        accounts[key] = payload
    return accounts


class _DetailAPI:
    """Search rows for owned accounts filled in from get_item detail:
    search reports ``protocol`` empty even when one is stored, and get_item
    masks the password that search returns."""

    def __init__(self, api):
        self.api = api

    def __getattr__(self, name):
        return getattr(self.api, name)

    def search(self, path, *args, **kwargs):
        rows = self.api.search(path, *args, **kwargs)
        if path != ACCOUNTS.search:
            return rows
        out = []
        for row in rows:
            if str(parse_tag(row.get('description')) or '').startswith(KEY_PREFIX):
                detail = self.api.get('dyndns/accounts/get_item/' + row['uuid']).get('account')
                if isinstance(detail, dict):
                    row = dict(detail, **{k: v for k, v in row.items() if v not in ('', None)})
            out.append(row)
        return out


def sync_ddns(sync, section):
    accounts = plan_ddns(section, sync.resolve_interface)
    api = sync.api
    sync.api = _DetailAPI(api)
    try:
        changed, _ = sync.sync_items(ACCOUNTS, accounts,
                                     keep=lambda key: not key.startswith(KEY_PREFIX))
    finally:
        sync.api = api
    if accounts:
        general = (sync.api.get('dyndns/settings/get').get('ddclient') or {}).get('general') or {}
        if str(general.get('enabled')) != '1':
            result = sync.api.post('dyndns/settings/set',
                                   {'ddclient': {'general': {'enabled': '1'}}})
            OPNsenseAPI.check_saved(result, 'enable ddclient')
            changed = True
    if changed:
        result = sync.api.post('dyndns/service/reconfigure')
        if not isinstance(result, dict) or str(result.get('status')).lower() != 'ok':
            raise OPNsenseAPIError('ddclient reconfigure failed: %s' % result)
    return len(accounts)
