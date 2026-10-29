"""Bounded in-process collection timings and counter-rate samples."""

from collections import deque
import math
import os
import threading
import time


def bounded_seconds_env(name, default=1.0, minimum=0.05, maximum=5.0):
    try:
        value = float(os.environ.get(name, default))
        return min(maximum, max(minimum, value)) if math.isfinite(value) and value > 0 else default
    except (TypeError, ValueError):
        return default


class IngestMetrics:
    """Only a fixed set of timings and at most 61 counter samples are retained."""

    STAGES = ('parse', 'enrich', 'spool_stage', 'spool_read', 'db_insert', 'spool_ack')
    COUNTERS = ('received', 'staged', 'inserted', 'dropped', 'queue_dropped')

    def __init__(self):
        self._lock = threading.Lock()
        self._timings = {name: {'count': 0, 'total_ms': 0.0, 'last_ms': 0.0, 'max_ms': 0.0,
                               'last_at': None, 'max_at': None}
                         for name in self.STAGES}
        self._slow_operations = deque(maxlen=32)
        self._samples = deque([(time.monotonic(), dict.fromkeys(self.COUNTERS, 0))], maxlen=61)

    def observe(self, name, started):
        elapsed = max(0, (time.monotonic() - started) * 1000)
        observed_at = time.time()
        with self._lock:
            value = self._timings[name]
            value['count'] += 1
            value['total_ms'] += elapsed
            value['last_ms'] = elapsed
            value['last_at'] = observed_at
            if elapsed >= value['max_ms']:
                value['max_ms'], value['max_at'] = elapsed, observed_at
            if elapsed >= 1000:
                self._slow_operations.append({'stage': name, 'duration_ms': elapsed,
                                              'finished_at': observed_at})

    def slow_operations(self):
        with self._lock:
            return [dict(value) for value in self._slow_operations]

    def snapshot(self, stats):
        now = time.monotonic()
        current = {key: stats[key] for key in self.COUNTERS}
        with self._lock:
            # At most one stored sample each second, independent of API polling.
            # Include the latest counters in the calculation without retaining
            # each read. Discard samples outside the trailing minute.
            while self._samples and now - self._samples[0][0] > 60:
                self._samples.popleft()
            if not self._samples:
                self._samples.append((now, current))
            started, previous = self._samples[0]
            elapsed = now - started
            rates = {'window_seconds': max(0, elapsed)}
            for key in self.COUNTERS:
                delta = current[key] - previous[key]
                rates[f'{key}_per_second'] = delta / elapsed if elapsed >= 1 and delta >= 0 else None
            if now - self._samples[-1][0] >= 1:
                self._samples.append((now, current))
            timings = {name: dict(value, mean_ms=value['total_ms'] / value['count'] if value['count'] else 0)
                       for name, value in self._timings.items()}
        return rates, timings
