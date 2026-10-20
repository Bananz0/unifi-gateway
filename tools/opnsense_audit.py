"""Read-only inventory/coverage audit. Never instantiates the live collector.

python tools/opnsense_audit.py --config /path/to/unifi-gateway.conf
Only GET APIs are used; output omits credentials and provisioning values.
"""
import argparse
import configparser
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from collectors.opnsense_api import OPNsenseAPI
from collectors.opnsense_audit import audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    config = configparser.RawConfigParser()
    if not config.read(args.config):
        parser.error('configuration file not found')
    o = config['opnsense']
    api = OPNsenseAPI(os.environ.get('OPNSENSE_URL', o.get('url', 'https://127.0.0.1')),
        os.environ.get('OPNSENSE_API_KEY', o.get('api_key', '')),
        os.environ.get('OPNSENSE_API_SECRET', o.get('api_secret', '')),
        verify_ssl=o.getboolean('verify_ssl', fallback=False))
    print(json.dumps(audit(config, api), indent=2))


if __name__ == '__main__':
    main()
