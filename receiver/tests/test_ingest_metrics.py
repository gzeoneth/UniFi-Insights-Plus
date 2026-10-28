"""Collection observability stays bounded, explicit and independent of DB IO."""
import threading

import pytest

from ingest_metrics import IngestMetrics, bounded_seconds_env


@pytest.mark.parametrize(('raw', 'expected'), [
    ('0', 1), ('-1', 1), ('nan', 1), ('inf', 1), ('invalid', 1),
    ('0.001', 0.05), ('60', 5), ('0.25', 0.25),
])
def test_flush_interval_is_finite_and_bounded(monkeypatch, raw, expected):
    monkeypatch.setenv('EXAMPLE_FLUSH_INTERVAL', raw)
    assert bounded_seconds_env('EXAMPLE_FLUSH_INTERVAL') == expected


def test_rates_are_unknown_on_cold_start_and_measure_deltas(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr('ingest_metrics.time.monotonic', lambda: clock[0])
    metrics = IngestMetrics()
    stats = dict.fromkeys(metrics.COUNTERS, 0)
    rates, _ = metrics.snapshot(stats)
    assert rates['window_seconds'] == 0
    assert rates['received_per_second'] is None
    clock[0] += 2
    stats.update(received=200, staged=150, inserted=100, dropped=10, queue_dropped=10)
    rates, _ = metrics.snapshot(stats)
    assert rates['window_seconds'] == 2
    assert rates['received_per_second'] == 100
    assert rates['inserted_per_second'] == 50
    assert rates['dropped_per_second'] == 5


def test_rate_window_samples_remain_bounded_and_expire(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr('ingest_metrics.time.monotonic', lambda: clock[0])
    metrics = IngestMetrics()
    stats = dict.fromkeys(metrics.COUNTERS, 0)
    for i in range(10000):
        clock[0] += 0.1
        stats['received'] += 1
        rates, _ = metrics.snapshot(stats)
        assert len(metrics._samples) <= 61
        assert rates['window_seconds'] <= 60
    assert rates['received_per_second'] == pytest.approx(10)
    clock[0] += 1000
    rates, _ = metrics.snapshot(stats)
    assert rates['received_per_second'] is None
    assert rates['window_seconds'] == 0


def test_stage_timings_count_failed_and_successful_attempts_thread_safely(monkeypatch):
    monkeypatch.setattr('ingest_metrics.time.monotonic', lambda: 101.0)
    metrics = IngestMetrics()
    threads = [threading.Thread(target=lambda: [metrics.observe('spool_stage', 100.5) for _ in range(100)])
               for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(1)
    _, timings = metrics.snapshot(dict.fromkeys(metrics.COUNTERS, 0))
    assert timings['spool_stage'] == {
        'count': 400, 'total_ms': 200000, 'last_ms': 500, 'max_ms': 500, 'mean_ms': 500,
    }
