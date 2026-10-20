"""Report untranslated provisioning paths without logging their values.

Successful application of one section must not imply full router parity.
This is coverage reporting, not a schema validator for supported translators.
"""


def untranslated_paths(udapi, translated=()):
    """``translated``: further root paths an opt-in translator applied."""
    paths = set()
    supported_roots = {'firewall/filter', 'firewall/nat', 'firewall/sets',
                       'routes/static', 'services'} | set(translated)
    metadata = {'unifi', 'version', 'versionDetail', 'versionFormat'}
    for key in udapi:
        if key not in supported_roots | metadata | {'interfaces', 'system'}:
            paths.add(key)
    for key in (udapi.get('system') or {}):
        if key not in {'hostname', 'domainName'}:
            paths.add('system/' + key)
    for iface in udapi.get('interfaces') or []:
        for key in iface:
            if key != 'identification':
                paths.add('interfaces/*/' + key)
        if 'macOverride' in (iface.get('identification') or {}):
            paths.add('interfaces/*/identification/macOverride')
    services = udapi.get('services') or {}
    for key, value in services.items():
        if key in {'geoipFiltering', 'idsIps'}:
            continue  # dedicated translators validate these sections
        if key == 'dhcpServers':
            for server in value or []:
                for field in server:
                    if field not in {'name', 'staticLeases'}:
                        paths.add('services/dhcpServers/*/' + field)
        elif key == 'dnsForwarder':
            for field in value or {}:
                if field != 'hostRecords':
                    paths.add('services/dnsForwarder/' + field)
        elif 'services/' + key in translated:
            continue
        elif key not in {'unifiNetwork', 'bleHTTPTransport', 'wifiman'}:
            # Controller transport/device integrations aren't OPNsense
            # services. All other service configuration needs a translator.
            paths.add('services/' + key)
    return sorted(paths - set(translated))
