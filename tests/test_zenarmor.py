# -*- coding: utf-8 -*-
"""Tests for turning Zenarmor connection records into UniFi DPI stats."""
import sqlite3

import pytest

from collectors.zenarmor import ZenarmorDPI, classify, OTHER_APP, UNKNOWN_CAT
from collectors.countries import country_code


def make_db(path):
    conn = sqlite3.connect(str(path))
    conn.execute(
        'create table conn_all (id integer primary key, src_hwaddr text, '
        'app_name text, app_category text, src_nbytes int, dst_nbytes int, '
        'src_npackets int, dst_npackets int)')
    conn.commit()
    return conn


def add(conn, mac, app, cat, sent, received, pkts_out=1, pkts_in=2):
    conn.execute(
        'insert into conn_all (src_hwaddr, app_name, app_category, src_nbytes, '
        'dst_nbytes, src_npackets, dst_npackets) values (?,?,?,?,?,?,?)',
        (mac, app, cat, sent, received, pkts_out, pkts_in))
    conn.commit()


class TestClassify:

    @pytest.mark.parametrize('app,cat,expected', [
        ('YouTube', 'Media Streaming', (4, 112)),            # exact, case-insensitive
        ('Domain Name Resolution', 'Network Management', (9, 61)),  # alias -> DNS
        ('Secure Web Browsing', 'Secure Web Browsing', (20, 185)),  # alias -> SSL/TLS
        ('Steam Games', 'Gaming', None),                       # alias -> Valve Steam
        ('Steam', 'Gaming', None),                             # unique word match
        ('Some Brand New App', 'Gaming', (8, OTHER_APP)),      # category fallback
        ('Mystery', 'Never Heard Of It', (UNKNOWN_CAT, OTHER_APP)),
        ('Secure Shell', 'Remote Access', (10, 21)),
        ('Discord IM', 'Instant Messaging', (6, 33)),
        ('Quic UDP Connection', 'Media Streaming', (13, 190)),
        ('Samsung Cloud', 'Cloud Services', (13, OTHER_APP)),
        ('Steam Tracker', 'Ad Tracker', (13, OTHER_APP)),
        ('Claude', 'A.I. Tools', (17, OTHER_APP)),
    ])
    def test_mapping(self, app, cat, expected):
        result = classify(app, cat)
        if expected is None:
            from collectors.unifi_dpi import APPLICATIONS
            assert APPLICATIONS[(result[0] << 16) | result[1]] == 'Valve Steam'
        else:
            assert result == expected


class TestPolling:

    def test_first_poll_skips_history_then_accumulates(self, tmp_path):
        conn = make_db(tmp_path / 'conn_all.sqlite')
        add(conn, 'd494a9f4e124', 'YouTube', 'Media Streaming', 100, 5000)
        dpi = ZenarmorDPI(str(tmp_path / 'conn_all.sqlite'))
        assert dpi.poll() == 0
        assert dpi.payload() == []

        add(conn, 'd494a9f4e124', 'YouTube', 'Media Streaming', 10, 1000, 3, 7)
        add(conn, 'd494a9f4e124', 'YouTube', 'Media Streaming', 20, 2000, 1, 1)
        add(conn, 'd494a9f4e124', 'Domain Name Resolution', 'Network Management', 0, 68)
        add(conn, '', 'YouTube', 'Media Streaming', 1, 1)       # no MAC: ignored
        assert dpi.poll() == 4

        [client] = dpi.payload()
        assert client['mac'] == 'd4:94:a9:f4:e1:24'
        stats = {(s['cat'], s['app']): s for s in client['stats']}
        yt = stats[(4, 112)]
        assert (yt['rx_bytes'], yt['tx_bytes']) == (3000, 30)
        assert (yt['rx_packets'], yt['tx_packets']) == (8, 4)
        assert stats[(9, 61)]['rx_bytes'] == 68

    def test_database_recreated(self, tmp_path):
        path = tmp_path / 'conn_all.sqlite'
        conn = make_db(path)
        for _ in range(5):
            add(conn, 'aabbccddeeff', 'YouTube', 'Media Streaming', 1, 1)
        dpi = ZenarmorDPI(str(path))
        dpi.poll()
        conn.close()
        path.unlink()
        conn = make_db(path)
        add(conn, 'aabbccddeeff', 'YouTube', 'Media Streaming', 7, 9)
        assert dpi.poll() == 1
        assert dpi.payload()[0]['stats'][0]['rx_bytes'] == 9

    def test_unavailable(self, tmp_path):
        assert ZenarmorDPI(str(tmp_path / 'missing.sqlite')).available is False

    def test_countries_inbound_direction_and_invalid_macs(self, tmp_path):
        conn = make_db(tmp_path / 'conn.sqlite')
        for field in ('direction', 'dst_hwaddr', 'dst_country_name', 'src_country_name'):
            conn.execute('alter table conn_all add column %s text' % field)
        dpi = ZenarmorDPI(str(tmp_path / 'conn.sqlite'))
        dpi.poll()
        conn.execute('insert into conn_all (src_hwaddr,dst_hwaddr,direction,app_name,'
                     'app_category,src_nbytes,dst_nbytes,src_npackets,dst_npackets,'
                     'src_country_name) values (?,?,?,?,?,?,?,?,?,?)',
                     ('112233445566', 'aabbcc000001', 'in', 'YouTube',
                      'Media Streaming', 900, 20, 9, 2, 'United States'))
        conn.commit()
        for raw in ('000000000000', 'ffffffffffff', 'zzzzzzzzzzzz', '010000000001'):
            add(conn, raw, 'YouTube', 'Media Streaming', 100, 100)
        dpi.poll()
        [client] = dpi.payload()
        assert client['mac'] == 'aa:bb:cc:00:00:01'
        stat = client['stats'][0]
        assert (stat['rx_bytes'], stat['tx_bytes'], stat['rx_packets'], stat['tx_packets']) == (900, 20, 9, 2)
        assert stat['countries'] == [{'iso': 'US', 'rx_bytes': 900, 'tx_bytes': 20}]

    def test_resume_does_not_skip_new_rows_or_replay_counters(self, tmp_path):
        path = tmp_path / 'conn.sqlite'
        state = tmp_path / 'dpi.json'
        conn = make_db(path)
        dpi = ZenarmorDPI(str(path), str(state))
        dpi.poll()
        add(conn, 'aabbcc000001', 'YouTube', 'Media Streaming', 10, 100)
        dpi.poll()
        restored = ZenarmorDPI(str(path), str(state))
        assert restored.initialized == dpi.initialized
        assert restored.payload() == dpi.payload()
        assert restored.poll() == 0
        add(conn, 'aabbcc000001', 'YouTube', 'Media Streaming', 20, 200)
        restored.poll()
        assert restored.payload()[0]['stats'][0]['rx_bytes'] == 300

    def test_database_replaced_with_larger_ids_and_different_uuids(self, tmp_path):
        path = tmp_path / 'conn.sqlite'
        conn = make_db(path)
        conn.execute('alter table conn_all add column conn_uuid text')
        add(conn, 'aabbcc000001', 'YouTube', 'Media Streaming', 1, 2)
        conn.execute("update conn_all set conn_uuid='old'")
        conn.commit()
        dpi = ZenarmorDPI(str(path))
        dpi.poll()
        conn.execute('delete from conn_all')
        add(conn, 'aabbcc000001', 'YouTube', 'Media Streaming', 7, 9)
        conn.execute("update conn_all set conn_uuid='new'")
        conn.commit()
        add(conn, 'aabbcc000001', 'YouTube', 'Media Streaming', 3, 5)
        assert dpi.poll() == 2
        assert dpi.payload()[0]['stats'][0]['rx_bytes'] == 14

    def test_router_macs_are_excluded(self, tmp_path):
        conn = make_db(tmp_path / 'conn.sqlite')
        dpi = ZenarmorDPI(str(tmp_path / 'conn.sqlite'))
        dpi.poll()
        dpi.exclude_macs(['aa:bb:cc:00:00:01'])
        add(conn, 'aabbcc000001', 'YouTube', 'Media Streaming', 10, 100)
        dpi.poll()
        assert dpi.payload() == []


@pytest.mark.parametrize('name,iso', [('United States', 'US'), ('The Netherlands', 'NL'),
                                  ('South Korea', 'KR'), ('KE', 'KE'), ('', None), ('unknown', None)])
def test_country_code(name, iso):
    assert country_code(name) == iso
