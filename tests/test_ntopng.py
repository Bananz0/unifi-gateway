import pytest

from collectors.ntopng import NtopngDPI, classify_ndpi
from collectors.unifi_dpi import APPLICATIONS
from collectors.zenarmor import OTHER_APP, UNKNOWN_CAT

PHONE, PHONE_IP = 'aa:bb:cc:00:00:01', '10.0.5.174'
NAS, NAS_IP = 'aa:bb:cc:00:00:02', '10.0.5.20'


def name(key):
    return APPLICATIONS.get((key[0] << 16) | key[1])


@pytest.mark.parametrize('l7,expected', [
    ('QUIC', 'QUIC'), ('TLS.YouTube', 'Youtube'), ('TLS', 'SSL/TLS'),
    ('QUIC.WhatsAppFiles', 'WhatsApp'), ('TLS.MS_OneDrive', 'OneDrive'),
    ('DNS.Microsoft365', 'Microsoft Office 365'), ('FbookReelStory', 'Facebook'),
    ('TLS.PlayStore', 'Google Play'), ('DoH_DoT', 'DNS over HTTPS (DoH)'),
])
def test_ndpi_names_map_to_unifi_applications(l7, expected):
    assert name(classify_ndpi(l7)) == expected


def test_unmapped_ndpi_names_fall_back_to_a_category():
    assert classify_ndpi('TLS.Tailscale') == (11, OTHER_APP)
    assert classify_ndpi('WireGuard') == (11, OTHER_APP)
    assert classify_ndpi('Unknown') == (UNKNOWN_CAT, OTHER_APP)


def flow(key, client_ip, server_ip, total, cli_pct, l7='TLS.YouTube', name='',
         l4='TCP', country='', last_seen=1792535137):
    return {'key': key, 'hash_id': key, 'first_seen': 1792535000, 'last_seen': last_seen,
            'bytes': total, 'breakdown': {'cli2srv': cli_pct, 'srv2cli': 100 - cli_pct},
            'protocol': {'l4': l4, 'l7': l7},
            'client': {'ip': client_ip, 'port': 50557, 'name': ''},
            'server': {'ip': server_ip, 'port': 443, 'name': name, 'country': country}}


class FakeNtopng(NtopngDPI):
    def __init__(self, **kw):
        self.rows = []
        super().__init__('http://ntopng.test', 'u', 'p',
                         {PHONE_IP: PHONE, NAS_IP: NAS}.get, **kw)

    def _get(self, path):
        if 'interfaces' in path:
            return [{'ifid': 0}]
        return {'data': list(self.rows), 'totalRows': len(self.rows)}


def stats(dpi):
    return {(c['mac'], name((s['cat'], s['app']))): (s['rx_bytes'], s['tx_bytes'])
            for c in dpi.payload() for s in c['stats']}


def test_first_poll_is_a_baseline_then_growth_is_counted_live():
    dpi = FakeNtopng()
    dpi.rows = [flow('1', PHONE_IP, '2.20.250.210', 1000, 10)]
    assert dpi.poll() == 0 and dpi.payload() == []
    dpi.rows = [flow('1', PHONE_IP, '2.20.250.210', 11000, 10)]
    dpi.poll()
    # device is the client: it sent cli2srv (10%), received the rest
    assert stats(dpi) == {(PHONE, 'Youtube'): (9000, 1000)}
    dpi.rows = [flow('1', PHONE_IP, '2.20.250.210', 11000, 10)]
    dpi.poll()
    assert stats(dpi) == {(PHONE, 'Youtube'): (9000, 1000)}


def test_inbound_flow_counts_for_the_lan_server():
    dpi = FakeNtopng()
    dpi.poll()
    dpi.rows = [flow('2', '198.51.100.7', NAS_IP, 1000, 80, l7='SSH')]
    dpi.poll()
    assert stats(dpi) == {(NAS, 'Secure Shell (SSH)'): (800, 200)}


def test_finished_flows_become_traffic_flows():
    dpi = FakeNtopng()
    dpi.flows = True
    dpi.poll()
    dpi.rows = [flow('3', PHONE_IP, '2.20.250.210', 5000, 20, name='vod.supersport.com',
                     l4='UDP', l7='QUIC', country='ZA')]
    dpi.poll()
    assert dpi.take_connections() == []
    dpi.rows = []
    dpi.poll()
    [conn] = dpi.take_connections()
    assert conn['ip'] == {'saddr': PHONE_IP, 'daddr': '2.20.250.210', 'protocol': 17,
                          'version': 'v4', 'sport': 50557, 'dport': 443}
    assert conn['stats']['txBytes'] == 1000 and conn['stats']['rxBytes'] == 4000
    assert (conn['in'], conn['out']) == ('lan', 'wan')
    assert conn['hostnames'] == ['vod.supersport.com'] and conn['region'] == {'dst': 'ZA'}


def test_router_and_unknown_hosts_are_not_clients():
    dpi = FakeNtopng()
    dpi.poll()
    dpi.exclude_macs([PHONE])
    dpi.rows = [flow('4', PHONE_IP, '1.1.1.1', 500, 50), flow('5', '10.0.5.99', '1.1.1.1', 500, 50)]
    dpi.poll()
    assert dpi.payload() == []


def test_state_survives_restart(tmp_path):
    state = str(tmp_path / 'ntopng-dpi.json')
    dpi = FakeNtopng(state_file=state)
    dpi.poll()
    dpi.rows = [flow('1', PHONE_IP, '2.20.250.210', 1000, 10)]
    dpi.poll()
    again = FakeNtopng(state_file=state)
    assert stats(again) == {(PHONE, 'Youtube'): (900, 100)}
    assert again.initialized == dpi.initialized
