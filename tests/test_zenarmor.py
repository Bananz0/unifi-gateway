# -*- coding: utf-8 -*-
"""Tests for turning Zenarmor connection records into UniFi DPI stats."""
import sqlite3

import pytest

from collectors.zenarmor import ZenarmorDPI, classify, OTHER_APP, UNKNOWN_CAT


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
