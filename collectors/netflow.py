"""Client accounting from OPNsense's five-minute Netflow observation buckets.

Read only the configured LAN observation interfaces. Fold increases in each
bucket once, retaining per-MAC totals across bucket expiry and restarts.
These are exporter observations, including its reporting delay; they are
not instantaneous wire counters or exact arbitrary-second accounting.
"""
import calendar
import json
import logging
import os
import sqlite3
import tempfile
import threading
import time

from .zenarmor import _mac

logger = logging.getLogger('unifi-gateway')
DEFAULT_DB = '/var/netflow/src_addr_000300.sqlite'
INTERVAL = 300


class NetflowTotals:
    def __init__(self, db_path=DEFAULT_DB, state_file=None):
        self.db_path, self.state_file = db_path, state_file
        self.initialized = int(time.time())
        self._seen = {}
        self._totals = {}
        self._bindings = {}
        self._primed = False
        self._lock = threading.RLock()
        if state_file:
            try:
                with open(state_file, encoding='utf-8') as f:
                    state = json.load(f)
                if state['db_path'] == os.path.abspath(db_path):
                    self.initialized = int(state['initialized'])
                    self._seen = {tuple(k): v for k, v in state['seen']}
                    self._totals = state['totals']
                    self._bindings = {tuple(k): v for k, v in state['bindings']}
                    self._primed = True
            except FileNotFoundError:
                pass
            except (OSError, ValueError, KeyError, TypeError) as e:
                logger.warning('Could not restore Netflow accounting state: %s', e)

    @property
    def available(self):
        return os.path.isfile(self.db_path)

    @property
    def restored(self):
        return self._primed

    def bind(self, neighbors):
        """Record current observed interface/IP/MAC ownership.

        Drop attribution for a changed address through the end of its shared
        bucket; the old and new owner's bytes cannot be separated there.
        """
        now = int(time.time())
        current = {}
        observed = set()
        with self._lock:
            current = {key: {**owner, 'active': False}
                       for key, owner in self._bindings.items()}
            for row in neighbors:
                mac = _mac(row.get('mac'))
                iface, ip = row.get('realif'), row.get('ip')
                if not mac or not iface or not ip:
                    continue
                key = (iface, ip)
                previous = self._bindings.get(key)
                # Conflicting observations must remain unattributed.
                if key in observed and current[key]['mac'] != mac:
                    current[key]['mac'] = None
                    continue
                observed.add(key)
                if (previous and previous['mac'] == mac and previous.get('active', True)
                        and now - previous.get('observed', 0) <= 90):
                    current[key] = {**previous, 'active': True, 'observed': now}
                else:
                    current[key] = {'mac': mac, 'since': now,
                                    'active': True, 'observed': now,
                                    'floor': (now + INTERVAL - 1) // INTERVAL * INTERVAL}
            self._bindings = current

    def snapshot(self):
        with self._lock:
            return {mac: dict(counters) for mac, counters in self._totals.items()}

    def poll(self, interfaces):
        """Read a short, fixed-resolution window; retain cumulative totals."""
        interfaces = sorted(set(interfaces))
        if not interfaces:
            return 0
        now = int(time.time())
        cutoff = (now - 3600) // INTERVAL * INTERVAL
        sql_time = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(cutoff))
        with sqlite3.connect('file:%s?mode=ro' % self.db_path,
                             uri=True, timeout=10) as conn:
            rows = conn.execute(
                'select mtime, last_seen, "if", src_addr, direction, octets, packets '
                'from timeserie where mtime >= ? and "if" in (%s)' %
                ','.join('?' for _ in interfaces), [sql_time] + interfaces).fetchall()
        count = 0
        with self._lock:
            for stamp, last_seen, iface, ip, direction, octets, packets in rows:
                try:
                    bucket = calendar.timegm(time.strptime(stamp, '%Y-%m-%d %H:%M:%S'))
                    values = [max(0, int(octets)), max(0, int(packets))]
                except (ValueError, TypeError):
                    continue
                key = (bucket, iface, ip, direction)
                previous = self._seen.get(key, [0, 0])
                # Keep high-water marks if the exporter corrects/replays a
                # bucket. A rollback followed by recovery is not new traffic.
                self._seen[key] = [max(n, old) for n, old in zip(values, previous)]
                if not self._primed:
                    continue  # establish a baseline; do not replay history
                owner = self._bindings.get((iface, ip))
                if not owner or not owner.get('active', True) or not owner['mac'] or bucket < owner['floor']:
                    continue
                if now - owner.get('observed', 0) > 90:
                    continue
                prefix = {'in': 'tx_', 'out': 'rx_'}.get(direction)
                if not prefix:
                    continue
                # Reset/rebuilt buckets establish a new baseline, not a
                # negative counter or a replay of already counted bytes.
                if any(n < old for n, old in zip(values, previous)):
                    continue
                delta = [n - old for n, old in zip(values, previous)]
                # New delayed records from before we observed this binding
                # cannot be attributed confidently to the present owner.
                if not previous[0] and float(last_seen or 0) < owner['since']:
                    continue
                c = self._totals.setdefault(owner['mac'], {})
                for suffix, n in zip(('bytes', 'packets'), delta):
                    c[prefix + suffix] = c.get(prefix + suffix, 0) + n
                c['last_seen'] = max(c.get('last_seen', 0), int(last_seen or 0))
                count += bool(any(delta))
            self._seen = {k: v for k, v in self._seen.items() if k[0] >= cutoff}
            self._primed = True
            self._save()
        return count

    def _save(self):
        if not self.state_file:
            return
        path = os.path.abspath(self.state_file)
        tmp = None
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                    dir=os.path.dirname(path), delete=False) as f:
                tmp = f.name
                os.chmod(tmp, 0o600)
                json.dump({'db_path': os.path.abspath(self.db_path),
                           'initialized': self.initialized,
                           'seen': list(self._seen.items()),
                           'totals': self._totals,
                           'bindings': list(self._bindings.items())}, f)
            os.replace(tmp, path)
        except OSError as e:
            logger.warning('Could not save Netflow accounting state: %s', e)
        finally:
            if tmp and os.path.exists(tmp):
                os.unlink(tmp)
