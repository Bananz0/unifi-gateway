import configparser

from collectors.opnsense_audit import audit


def test_audit_uses_get_only_and_does_not_change_config():
    config = configparser.RawConfigParser()
    config.read_dict({'gateway': {'device': 'UXGB', 'ports': '[{"ifname":"eth4",'
        '"type":"wan","realif":"re0"},{"ifname":"eth0","type":"lan","realif":"em0"}]'},
        'provisioned': {'system_cfg': '{"udapi":{"services":{"wireguard":'
            '{"privateKey":"SECRET-DO-NOT-PRINT"}}}}'}})
    original = config.get('gateway', 'ports')

    class GetOnly:
        def get(self, path):
            assert path == 'interfaces/overview/interfaces_info'
            return [{'device': 're1', 'description': 'WAN2', 'identifier': 'opt3',
                     'is_physical': True, 'media': 'Ethernet autoselect'}]

    report = audit(config, GetOnly())
    assert config.get('gateway', 'ports') == original
    assert len(report['proposed_ports']) == 3
    assert report['untranslated_settings'] == ['services/wireguard']
    assert 'SECRET-DO-NOT-PRINT' not in str(report)
