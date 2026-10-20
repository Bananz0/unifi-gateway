#!/usr/bin/env python3
"""Manage supported ALWAYS app blocks through UniFi's current API.

Network 11 permanently rejects the deprecated trafficrules create endpoint.
This tool uses firewall-app-blocks/create and reads credentials from the
gateway configuration. Saving a rule is separate from proving enforcement.
"""
import argparse
import configparser
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from collectors.opnsense_appblocks import plan_blocks
from collectors.unifi_dpi import APPLICATIONS
from collectors.unifi_mirror import UniFiAPIError, UniFiController


ENDPOINT = 'v2/firewall-app-blocks'


def build_rule(name, applications, macs=(), networks=()):
    macs, networks = macs or (), networks or ()
    if not name or not name.strip() or len(name) > 128:
        raise ValueError('supply a rule name of 1-128 characters')
    if bool(macs) == bool(networks):
        raise ValueError('select devices or networks, exclusively')
    ids = set()
    for application in applications:
        if str(application).isdigit() and int(application) in APPLICATIONS:
            matches = [int(application)]
        else:
            matches = [key for key, value in APPLICATIONS.items()
                       if value.casefold() == str(application).strip().casefold()]
        if len(matches) != 1:
            raise ValueError('application name/ID is unknown or ambiguous: ' + str(application))
        ids.add(matches[0])
    if not ids:
        raise ValueError('at least one application is required')
    return {'name': name.strip(), 'type': 'DEVICE' if macs else 'NETWORK',
            'target_type': 'APP_ID', 'client_macs': sorted(set(m.lower().replace('-', ':') for m in macs)),
            'network_ids': sorted(set(networks)), 'app_ids': sorted(ids),
            'app_category_ids': [], 'schedule': {'mode': 'ALWAYS'}}


def save_rule(controller, body):
    networks = controller.call('GET', 'rest/networkconf') if body['network_ids'] else []
    plan_blocks([dict(body, _id='preflight')], networks, [], resolve=lambda ids, _: ids)
    current = controller.call('GET', ENDPOINT)
    if not isinstance(current, list):
        raise ValueError('app-block snapshot unavailable')
    matches = [row for row in current if row.get('name') == body['name']]
    if matches:
        if len(matches) == 1 and all(matches[0].get(key) == value or (
                key in ('network_ids', 'client_macs', 'app_category_ids')
                and not value and not matches[0].get(key)) for key, value in body.items()):
            return matches[0], False
        raise ValueError('a different rule already uses this name; choose another name')
    saved = controller.call('POST', ENDPOINT + '/create', body)
    if not isinstance(saved, dict) or not saved.get('_id'):
        raise ValueError('controller did not return a saved app-rule ID')
    # Return the identity even if eventual readback fails, so callers never
    # suggest retrying a create blindly and leaving duplicate active rules.
    rows = controller.call('GET', ENDPOINT)
    if not any(row.get('_id') == saved['_id'] for row in rows):
        raise ValueError('rule created as %s but readback failed; inspect that ID before retrying' % saved['_id'])
    return saved, True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default=os.environ.get('UNIFI_GW_CONFIG',
                        '/usr/local/etc/unifi-gateway/unifi-gateway.conf'))
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('list')
    create = commands.add_parser('create')
    create.add_argument('--name', required=True)
    create.add_argument('--app', action='append', required=True, help='exact application name or UniFi ID; repeatable')
    scope = create.add_mutually_exclusive_group(required=True)
    scope.add_argument('--mac', action='append')
    scope.add_argument('--network', action='append', help='UniFi LAN network ID; repeatable')
    delete = commands.add_parser('delete')
    delete.add_argument('id')
    args = parser.parse_args(argv)
    try:
        config = configparser.RawConfigParser()
        if not config.read(args.config):
            raise ValueError('configuration file could not be read')
        controller = UniFiController(config.get('unifi', 'url'), config.get('unifi', 'username'),
                                     config.get('unifi', 'password'),
                                     site=config.get('unifi', 'site', fallback='default'),
                                     verify_ssl=config.getboolean('unifi', 'verify_ssl', fallback=False))
        if args.command == 'list':
            print(json.dumps(controller.call('GET', ENDPOINT), indent=2))
        elif args.command == 'create':
            rule, changed = save_rule(controller, build_rule(args.name, args.app, args.mac, args.network))
            print(json.dumps({'id': rule['_id'], 'created': changed,
                              'enforcement': 'saved; device enforcement must be verified separately'}))
        else:
            if not any(row.get('_id') == args.id for row in controller.call('GET', ENDPOINT)):
                raise ValueError('app-rule ID does not exist in this site')
            controller.call('DELETE', ENDPOINT + '/' + args.id)
            print(json.dumps({'deleted': args.id}))
    except (ValueError, configparser.Error, UniFiAPIError) as error:
        parser.exit(1, str(error) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
