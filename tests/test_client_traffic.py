from collectors.client_traffic import ClientTraffic


def counts(download, upload=0):
    return {'rx_bytes': download, 'tx_bytes': upload,
            'rx_packets': download // 100, 'tx_packets': upload // 100}


def test_confirmed_batch_is_released_once_across_informs():
    p = ClientTraffic(interval=30)
    assert p.counters('a', counts(1000000), now=0)['rx_bytes'] == 0
    assert p.counters('a', counts(1030000, 3000), now=30)['rx_bytes'] == 0
    a = p.counters('a', counts(1030000, 3000), now=40)
    b = p.counters('a', counts(1030000, 3000), now=50)
    c = p.counters('a', counts(1030000, 3000), now=60)
    assert [a['rx_bytes'], b['rx_bytes'], c['rx_bytes']] == [10000, 20000, 30000]
    assert [a['tx_bytes'], b['tx_bytes'], c['tx_bytes']] == [1000, 2000, 3000]
    assert p.counters('a', counts(1030000, 3000), now=600) == c


def test_restarts_preserve_published_and_unreleased_confirmed_budget(tmp_path, monkeypatch):
    state = str(tmp_path / 'clients.json')
    p = ClientTraffic(state)
    p.counters('a', counts(0), now=0)
    p.counters('a', counts(30000), now=30)
    assert p.counters('a', counts(30000), now=40)['rx_bytes'] == 10000
    p.save()
    monkeypatch.setattr('collectors.client_traffic.time.time', lambda: 100)
    restored = ClientTraffic(state)
    assert restored.counters('a', counts(30000), now=100)['rx_bytes'] == 10000
    assert restored.counters('a', counts(30000), now=120)['rx_bytes'] == 30000


def test_rollback_and_replay_cannot_double_count():
    p = ClientTraffic()
    p.counters('a', counts(0), now=0)
    p.counters('a', counts(30000), now=30)
    p.counters('a', counts(10000), now=40)
    p.counters('a', counts(30000), now=50)
    assert p.counters('a', counts(30000), now=60)['rx_bytes'] == 30000


def test_source_epoch_replacement_rebaselines_without_replaying_history():
    p = ClientTraffic()
    p.counters('a', counts(1000000), now=0, epoch='old')
    p.counters('a', counts(1030000), now=30, epoch='old')
    assert p.counters('a', counts(1030000), now=60, epoch='old')['rx_bytes'] == 30000
    assert p.counters('a', counts(9000000), now=70, epoch='new')['rx_bytes'] == 30000


def test_idle_clients_and_mac_changes_do_not_inherit_other_traffic():
    p = ClientTraffic()
    p.counters('a', counts(0), now=0)
    p.counters('a', counts(30000), now=30)
    assert p.counters('b', counts(30000), now=40)['rx_bytes'] == 0
    assert p.counters('a', counts(30000), now=60)['rx_bytes'] == 30000
    assert p.counters('b', counts(30000), now=70)['rx_bytes'] == 0
