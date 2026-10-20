"""Pace confirmed export batches for controllers deriving client rates.

No rate samples are integrated into invented totals. A new publication epoch
starts at zero; only subsequent confirmed counter increases are released.
The resulting rates are delayed averages, not instantaneous wire measurements.
"""
import json
import os
import tempfile
import time

FIELDS = ('rx_bytes', 'tx_bytes', 'rx_packets', 'tx_packets')


class ClientTraffic:
    def __init__(self, state_file=None, interval=30):
        self.state_file = state_file
        self.interval = max(10, int(interval))
        self.clients = {}
        if state_file:
            try:
                with open(state_file, encoding='utf-8') as f:
                    self.clients = json.load(f)['clients']
                if not isinstance(self.clients, dict):
                    raise ValueError('invalid client traffic state')
                now = time.time()
                for state in self.clients.values():
                    state['last_emit'] = now
                    state['last_change'] = now
            except (OSError, ValueError, KeyError, TypeError):
                self.clients = {}

    def counters(self, mac, confirmed, now=None, epoch=None):
        now = time.time() if now is None else now
        source = [max(0, int(confirmed.get(k, 0))) for k in FIELDS]
        if mac not in self.clients:
            self.clients[mac] = {'source': source, 'target': [0] * 4,
                'published': [0.] * 4, 'rate': [0.] * 4,
                'last_change': now, 'last_emit': now, 'epoch': epoch}
        state = self.clients[mac]
        if state.get('epoch') != epoch:
            state['source'] = source
            state['epoch'] = epoch
        elapsed = max(0, now - state['last_emit'])
        # Release only the previously confirmed budget. Never exceed it,
        # including after clock changes, idle periods or delayed updates.
        state['published'] = [min(target, value + rate * elapsed)
            for value, rate, target in zip(state['published'], state['rate'], state['target'])]
        state['last_emit'] = now
        delta = [max(0, n - old) for n, old in zip(source, state['source'])]
        # Preserve high-water marks through corrections/replays. A confirmed
        # source epoch change establishes a fresh baseline explicitly above.
        state['source'] = [max(n, old) for n, old in zip(source, state['source'])]
        if any(delta):
            window = max(self.interval, min(120, max(0, now - state['last_change'])))
            state['target'] = [n + d for n, d in zip(state['target'], delta)]
            state['rate'] = [(target - value) / window
                for target, value in zip(state['target'], state['published'])]
            state['last_change'] = now
        return {k: int(v) for k, v in zip(FIELDS, state['published'])}

    def save(self):
        if not self.state_file:
            return
        path = os.path.abspath(self.state_file)
        temporary = None
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                    dir=os.path.dirname(path), delete=False) as f:
                temporary = f.name
                os.chmod(temporary, 0o600)
                json.dump({'clients': self.clients}, f)
            os.replace(temporary, path)
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)
