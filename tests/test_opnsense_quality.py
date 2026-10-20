import pytest

from collectors.opnsense_quality import WanQuality


def status(loss='0.0 %', delay='172.1 ms', monitor='1.1.1.1'):
    return {'monitor': monitor, 'loss': loss, 'delay': delay}


def test_observed_latency_and_loss_become_controller_monitor_fields():
    q = WanQuality()
    report = q.sample('WAN', status('2.0 %'), now=10)
    expected = {'target': '1.1.1.1', 'type': 'icmp',
                'availability': 98, 'latency_average': 172}
    assert report == {'uptime': 0, 'monitors': [expected],
                      'alerting_monitors': [expected]}
    assert q.sample('WAN', status(), now=20)['uptime'] == 10


def test_outages_and_recovery_only_count_observed_continuous_intervals():
    q = WanQuality()
    q.sample('WAN', status(), now=0)
    first = q.sample('WAN', status('100 %', '~'), now=10)
    assert first['downtime'] == 0
    assert 'latency_average' not in first['monitors'][0]
    assert q.sample('WAN', status('100 %', '~'), now=40)['downtime'] == 30
    assert q.sample('WAN', status(), now=50)['uptime'] == 0
    assert q.sample('WAN', status(), now=60)['uptime'] == 10


@pytest.mark.parametrize('sample', [status('~'), status('nan'), status('-1 %'),
    status('101 %'), status(delay='inf'), status(delay='-1 ms'),
    status(monitor='~'), {}, status(monitor='not-an-ip')])
def test_missing_invalid_data_is_not_perfect_connectivity(sample):
    q = WanQuality()
    report = q.sample('WAN', sample, now=0)
    # A missing delay can coexist with a measured loss; infinity must not
    # become a JSON NaN or an invented numeric latency.
    if sample.get('delay') == 'inf':
        assert 'latency_average' not in report['monitors'][0]
    else:
        assert report is None


def test_observation_gap_target_change_and_removed_wan_reset_duration():
    q = WanQuality(max_gap=30)
    q.sample('WAN', status(), now=0)
    assert q.sample('WAN', status(), now=31)['uptime'] == 0
    assert q.sample('WAN', status(monitor='8.8.8.8'), now=40)['uptime'] == 0
    q.retain([])
    assert q.sample('WAN', status(), now=50)['uptime'] == 0


def test_wan2_does_not_inherit_primary_wan_duration():
    q = WanQuality()
    q.sample('WAN', status(), now=0)
    assert q.sample('WAN2', status(monitor='8.8.8.8'), now=30)['uptime'] == 0
