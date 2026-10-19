"""Regression for the wire format validated with a Network 10.6 UXG lab."""
from copy import deepcopy

from unifi_protocol import _modern_dpi_stats


def test_modern_dpi_counters_and_country_breakdown_leave_legacy_data_intact():
    legacy = [{'mac': 'aa:bb:cc:00:00:01', 'initialized': '1234', 'stats': [{
        'cat': 4, 'app': 112, 'rx_bytes': 4000000, 'tx_bytes': 200000,
        'rx_packets': 360, 'tx_packets': 160,
        'countries': [{'iso': 'KE', 'rx_bytes': 100, 'tx_bytes': 20}],
    }]}]
    original = deepcopy(legacy)
    modern = _modern_dpi_stats(legacy)
    assert modern == [{'mac': 'aa:bb:cc:00:00:01', 'initialized': '1234', 'stats': [{
        'cat': 4, 'app': 112, 'rxBytes': 4000000, 'txBytes': 200000,
        'rxPackets': 360, 'txPackets': 160,
        'countries': [{'iso': 'KE', 'rxBytes': 100, 'txBytes': 20}],
    }]}]
    assert legacy == original
    assert _modern_dpi_stats([]) == []
