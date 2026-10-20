"""Translate actual dpinger observations into UniFi WAN quality statistics.

Availability is 100 minus measured loss over dpinger's sampling window.
Uptime/downtime describe continuous observations since this collector started,
not invented historical reachability. Missing/stale measurements stay missing.
"""
import ipaddress
import math
import time


def measurement(value):
    try:
        result = float(str(value).strip().split()[0])
        return result if math.isfinite(result) else None
    except (ValueError, TypeError, IndexError):
        return None


class WanQuality:
    def __init__(self, max_gap=90):
        self.max_gap = max_gap
        self._observed = {}

    def sample(self, group, status, now=None):
        now = time.monotonic() if now is None else now
        target = str(status.get('monitor') or '')
        try:
            ipaddress.ip_address(target)
        except ValueError:
            self._observed.pop(group, None)
            return None
        loss = measurement(status.get('loss'))
        latency = measurement(status.get('delay'))
        if loss is None or not 0 <= loss <= 100 or (latency is not None and latency < 0):
            self._observed.pop(group, None)
            return None
        reachable = loss < 100
        previous = self._observed.get(group)
        continuous = (previous and previous['target'] == target
                      and previous['up'] == reachable
                      and 0 <= now - previous['last'] <= self.max_gap)
        since = previous['since'] if continuous else now
        self._observed[group] = {'target': target, 'up': reachable,
                                 'since': since, 'last': now}
        monitor = {'target': target, 'type': 'icmp',
                   'availability': int(round(100 - loss))}
        if latency is not None and reachable:
            monitor['latency_average'] = int(round(latency))
        result = {'monitors': [dict(monitor)], 'alerting_monitors': [dict(monitor)]}
        result['uptime' if reachable else 'downtime'] = max(0, int(now - since))
        return result

    def retain(self, groups):
        self._observed = {g: s for g, s in self._observed.items() if g in groups}
