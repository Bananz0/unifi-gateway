import pytest

from collectors.base import speedtest_ping
from tests.test_protocol_uxg import DC, inform


@pytest.mark.parametrize('value', [600000, 1200000, 1800000, float('inf'),
                                  float('nan'), -1, None, 'invalid'])
def test_failed_probe_is_not_successful_latency(value):
    assert speedtest_ping(value) == 0


def test_valid_latency_and_partial_speedtest_report():
    assert speedtest_ping('172.5') == 172.5
    dc = DC(speedtest={'download': 21.03, 'upload': 17.46,
                      'ping': speedtest_ping(1800000), 'lastrun': 1792488810})
    report = inform(dc=dc)['speedtest-status']
    assert report['status_ping'] == 0
    assert report['status_download'] == report['status_upload'] == 2
    assert report['xput_download'] == 21.03
