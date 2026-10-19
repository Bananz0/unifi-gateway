"""Exercise real SQLite buckets, source isolation and address reassignment."""
import sqlite3
import time

from collectors.netflow import NetflowTotals, INTERVAL


def database(path):
    db = sqlite3.connect(path)
    db.execute('create table timeserie (mtime text, last_seen int, "if" text, '
               'src_addr text, direction text, octets int, packets int, '
               'primary key (mtime,"if",src_addr,direction))')
    return db


def row(db, bucket, octets, packets=1, iface='em0', direction='out', last_seen=None):
    db.execute('insert or replace into timeserie values(?,?,?,?,?,?,?)', (
        time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(bucket)),
        last_seen or bucket + 50, iface, '192.0.2.10', direction, octets, packets))
    db.commit()


def binding(mac='aa:bb:cc:00:00:01'):
    return [{'realif': 'em0', 'ip': '192.0.2.10', 'mac': mac}]


def setup(tmp_path, monkeypatch):
    clock = [1700000100]  # exactly on a five-minute boundary
    monkeypatch.setattr('collectors.netflow.time.time', lambda: clock[0])
    path = tmp_path / 'flow.sqlite'
    db = database(path)
    tracker = NetflowTotals(str(path), str(tmp_path / 'state.json'))
    tracker.bind(binding())
    return clock, db, tracker


def test_baseline_interfaces_directions_and_repeated_polls(tmp_path, monkeypatch):
    clock, db, tracker = setup(tmp_path, monkeypatch)
    row(db, clock[0], 100, 1)
    tracker.poll(['em0'])
    assert tracker.snapshot() == {}
    row(db, clock[0], 150, 4)
    row(db, clock[0], 20, 2, direction='in')
    row(db, clock[0], 99999, iface='re0')  # same traffic observed at WAN
    tracker.poll(['em0'])
    totals = tracker.snapshot()['aa:bb:cc:00:00:01']
    assert totals['rx_bytes'] == 50
    assert totals['rx_packets'] == 3
    assert totals['tx_bytes'] == 20
    assert totals['tx_packets'] == 2
    assert tracker.poll(['em0']) == 0
    assert tracker.snapshot()['aa:bb:cc:00:00:01'] == totals


def test_checkpoint_resume_and_new_bucket(tmp_path, monkeypatch):
    clock, db, tracker = setup(tmp_path, monkeypatch)
    tracker.poll(['em0'])
    row(db, clock[0], 100, 3)
    tracker.poll(['em0'])
    restored = NetflowTotals(tracker.db_path, tracker.state_file)
    restored.bind(binding())
    assert restored.poll(['em0']) == 0
    assert restored.snapshot() == tracker.snapshot()
    clock[0] += INTERVAL
    restored.bind(binding())
    row(db, clock[0], 200, 4)
    restored.poll(['em0'])
    assert restored.snapshot()['aa:bb:cc:00:00:01']['rx_bytes'] == 300


def test_ip_reassignment_does_not_inherit_old_totals(tmp_path, monkeypatch):
    clock, db, tracker = setup(tmp_path, monkeypatch)
    tracker.poll(['em0'])
    row(db, clock[0], 100)
    tracker.poll(['em0'])
    tracker.bind([])  # absence does not erase the previous ownership history
    clock[0] += 1  # shared bucket; changing exactly at its start is unambiguous
    tracker.bind(binding('aa:bb:cc:00:00:02'))
    row(db, clock[0], 900)
    tracker.poll(['em0'])
    assert 'aa:bb:cc:00:00:02' not in tracker.snapshot()
    for _ in range(5):
        clock[0] += 60
        tracker.bind(binding('aa:bb:cc:00:00:02'))
    row(db, clock[0] - 1, 30)
    tracker.poll(['em0'])
    totals = tracker.snapshot()
    assert totals['aa:bb:cc:00:00:01']['rx_bytes'] == 100
    assert totals['aa:bb:cc:00:00:02']['rx_bytes'] == 30


def test_expired_buckets_reset_and_late_history(tmp_path, monkeypatch):
    clock, db, tracker = setup(tmp_path, monkeypatch)
    tracker.poll(['em0'])
    row(db, clock[0], 100)
    tracker.poll(['em0'])
    row(db, clock[0], 20)  # database rebuild / corrections must not add again
    tracker.poll(['em0'])
    assert tracker.snapshot()['aa:bb:cc:00:00:01']['rx_bytes'] == 100
    row(db, clock[0], 100)
    tracker.poll(['em0'])
    assert tracker.snapshot()['aa:bb:cc:00:00:01']['rx_bytes'] == 100
    row(db, clock[0] - INTERVAL, 100000)  # late history before startup
    tracker.poll(['em0'])
    assert tracker.snapshot()['aa:bb:cc:00:00:01']['rx_bytes'] == 100
    clock[0] += 7200
    tracker.bind(binding())
    db.execute('delete from timeserie')
    db.commit()
    row(db, clock[0], 50)
    tracker.poll(['em0'])
    assert tracker.snapshot()['aa:bb:cc:00:00:01']['rx_bytes'] == 150


def test_conflicting_bindings_are_unattributed(tmp_path, monkeypatch):
    clock, db, tracker = setup(tmp_path, monkeypatch)
    tracker.poll(['em0'])
    tracker.bind(binding() + binding('aa:bb:cc:00:00:02'))
    row(db, clock[0], 100)
    tracker.poll(['em0'])
    assert tracker.snapshot() == {}


def test_new_owner_cannot_inherit_delayed_existing_bucket(tmp_path, monkeypatch):
    clock, db, tracker = setup(tmp_path, monkeypatch)
    tracker.bind([])
    row(db, clock[0], 100)
    tracker.poll(['em0'])
    clock[0] += 100
    tracker.bind(binding('aa:bb:cc:00:00:02'))
    row(db, clock[0] - 100, 150, last_seen=clock[0] - 70)
    tracker.poll(['em0'])
    assert tracker.snapshot() == {}


def test_ownership_expires_without_discovery_refresh(tmp_path, monkeypatch):
    clock, db, tracker = setup(tmp_path, monkeypatch)
    tracker.poll(['em0'])
    clock[0] += 100
    row(db, clock[0] - 100, 100)
    tracker.poll(['em0'])
    assert tracker.snapshot() == {}


def test_boundary_reassignment_keeps_next_bucket(tmp_path, monkeypatch):
    clock, db, tracker = setup(tmp_path, monkeypatch)
    tracker.poll(['em0'])
    clock[0] += INTERVAL
    tracker.bind(binding('aa:bb:cc:00:00:02'))
    row(db, clock[0], 30)
    tracker.poll(['em0'])
    assert tracker.snapshot()['aa:bb:cc:00:00:02']['rx_bytes'] == 30


def test_same_mac_after_discovery_gap_gets_fresh_baseline(tmp_path, monkeypatch):
    clock, db, tracker = setup(tmp_path, monkeypatch)
    tracker.poll(['em0'])
    clock[0] += 400
    tracker.bind(binding())
    row(db, clock[0] - 100, 100, last_seen=clock[0] - 50)
    tracker.poll(['em0'])
    assert tracker.snapshot() == {}
