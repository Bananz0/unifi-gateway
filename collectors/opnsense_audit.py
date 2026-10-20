"""Read-only inventory and untranslated provisioning coverage."""
import ast
import json
from .opnsense_ports import discover_ports
from .opnsense_coverage import untranslated_paths


def audit(config, api):
    existing = ast.literal_eval(config.get('gateway', 'ports'))
    overview = api.get('interfaces/overview/interfaces_info')
    if isinstance(overview, dict):
        overview = overview.get('rows', [])
    if not isinstance(overview, list):
        raise ValueError('interface overview is not a row list')
    ports, warnings = discover_ports(existing, overview,
        config.get('gateway', 'device', fallback='UGW3'))
    raw = config.get('provisioned', 'system_cfg', fallback='{}')
    try:
        cfg = json.loads(raw)
    except ValueError:
        cfg = {}
        warnings.append('stored provisioning is not JSON; coverage unavailable')
    udapi = cfg.get('udapi') if isinstance(cfg, dict) else None
    return {'model': config.get('gateway', 'device', fallback=''),
            'interfaces': [{k: r.get(k) for k in (
                'identifier', 'device', 'description', 'status', 'enabled', 'vlan_tag')}
                for r in overview],
            'existing_ports': existing, 'proposed_ports': ports,
            'untranslated_settings': untranslated_paths(udapi) if isinstance(udapi, dict) else None,
            'warnings': warnings}
