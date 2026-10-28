"""Public performance metrics must remain useful and contain no event data."""
import importlib
import json
import sys
import time
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def read_snapshot(monkeypatch, tmp_path):
    deps = MagicMock()
    deps.get_conn.side_effect = AssertionError('Performance snapshot must not query PostgreSQL')
    monkeypatch.setitem(sys.modules, 'deps', deps)
    monkeypatch.delitem(sys.modules, 'routes.health', raising=False)
    module = importlib.import_module('routes.health')
    path = tmp_path / 'status.json'
    monkeypatch.setenv('INGEST_STATUS_PATH', str(path))

    def read(**updates):
        now = time.time()
        data = {'schema_version': 1, 'updated_at': now, 'running': True,
                'worker_alive': True, 'last_progress_at': now,
                'stats': {'dropped': 0}, 'queue': {'depth': 0}, 'spool': {'rows': 0}}
        data.update(updates)
        path.write_text(json.dumps(data))
        result = module.read_ingest_health()
        deps.get_conn.assert_not_called()
        return result
    return read


def test_legacy_metrics_remain_unknown(read_snapshot):
    result = read_snapshot()
    assert result['rates']['received_per_second'] is None
    assert result['stats']['staged'] is None
    assert result['workers']['delivery']['alive'] is None
    assert result['spool']['oldest_age_seconds'] is None
    assert result['state'] == 'ready'


def test_metrics_do_not_leak_unrecognized_payloads(read_snapshot):
    result = read_snapshot(
        rates={'window_seconds': 60, 'received_per_second': 123.5, 'inserted_per_second': 0,
               'private_message': 'Synthetic secret'},
        workers={'delivery': {'alive': True, 'failed': False, 'last_progress_at': time.time(),
                              'error': 'Synthetic secret', 'destination': '203.0.113.2'}},
        timings={'db_insert': {'count': 3, 'mean_ms': 7.5, 'sql': 'Synthetic secret'}},
        batch={'size': 200, 'pending': 0, 'flush_interval_seconds': 1, 'message': 'Synthetic secret'},
        collection={'incomplete': False, 'reasons': ['Synthetic secret']})
    assert result['rates']['received_per_second'] == 123.5
    assert result['rates']['inserted_per_second'] == 0
    assert result['timings']['db_insert']['mean_ms'] == 7.5
    assert 'Synthetic secret' not in json.dumps(result)
    assert '203.0.113.2' not in json.dumps(result)


@pytest.mark.parametrize('invalid', [float('nan'), float('inf'), 10 ** 400, -1, True, '12'])
def test_invalid_numbers_are_unknown(read_snapshot, invalid):
    result = read_snapshot(rates={'window_seconds': 60, 'received_per_second': invalid},
                           timings={'parse': {'mean_ms': invalid}},
                           batch={'size': invalid})
    assert result['rates']['received_per_second'] is None
    assert result['timings']['parse']['mean_ms'] is None
    assert result['batch']['size'] is None


def test_stale_rates_are_not_presented_as_current(read_snapshot):
    result = read_snapshot(updated_at=time.time() - 20,
                           rates={'window_seconds': 60, 'received_per_second': 50})
    assert result['rates']['received_per_second'] is None
    assert result['state'] == 'unknown'
    assert 'stale_snapshot' in result['collection']['reasons']


def test_cold_rate_window_is_unknown(read_snapshot):
    result = read_snapshot(rates={'window_seconds': 0, 'received_per_second': 0})
    assert result['rates']['received_per_second'] is None


def test_busy_producer_does_not_hide_stalled_database_delivery(read_snapshot):
    now = time.time()
    result = read_snapshot(spool={'rows': 200, 'oldest_age_seconds': 65}, workers={
        'producer': {'alive': True, 'failed': False, 'last_progress_at': now},
        'delivery': {'alive': True, 'failed': False, 'last_progress_at': now - 65}})
    assert result['state'] == 'stalled'
    assert result['collection']['incomplete'] is True
    assert result['collection']['attention_required'] is True
    assert 'worker_stalled' in result['collection']['attention_reasons']
    assert 'backlog_lag' in result['collection']['attention_reasons']


def test_failed_delivery_worker_is_visible(read_snapshot):
    result = read_snapshot(workers={'delivery': {'alive': False, 'failed': True}})
    assert result['state'] == 'error'
    assert 'worker_error' in result['collection']['reasons']


def test_idle_delivery_is_not_stalled_on_new_backlog(read_snapshot):
    now = time.time()
    result = read_snapshot(last_progress_at=now - 100,
                           spool={'rows': 1, 'oldest_age_seconds': 0.1}, workers={
        'delivery': {'alive': True, 'failed': False, 'last_progress_at': now - 100}})
    assert result['state'] == 'pending'


def test_recent_delivery_start_is_not_stalled_after_idle(read_snapshot):
    now = time.time()
    result = read_snapshot(last_progress_at=now - 100,
                           spool={'rows': 1, 'oldest_age_seconds': 100}, workers={
        'delivery': {'alive': True, 'failed': False, 'last_progress_at': now - 100,
                     'busy_since': now - 1}})
    assert result['state'] == 'pending'


def test_only_inflight_packet_stalling_is_visible(read_snapshot):
    now = time.time()
    result = read_snapshot(batch={'pending': 0, 'inflight': 1}, workers={
        'producer': {'alive': True, 'failed': False, 'last_progress_at': now - 50,
                     'busy_since': now - 45}})
    assert result['state'] == 'stalled'


def test_cumulative_loss_stays_visible_after_current_rate_recovers(read_snapshot):
    result = read_snapshot(stats={'dropped': 12},
                           rates={'window_seconds': 60, 'dropped_per_second': 0})
    assert result['state'] == 'ready'
    assert result['rates']['dropped_per_second'] == 0
    assert result['collection']['incomplete'] is True
    assert result['collection']['attention_reasons'] == ['historical_loss']
    assert result['collection']['state'] == 'loss'


@pytest.mark.parametrize('counter', ['failed', 'parse_exceptions'])
def test_parse_loss_is_incomplete_even_without_queue_drops(read_snapshot, counter):
    result = read_snapshot(stats={counter: 1})
    assert result['collection']['incomplete'] is True
    assert result['collection']['attention_reasons'] == ['historical_loss']


@pytest.mark.parametrize('field', ['pending', 'inflight'])
def test_unstaged_batch_is_pending(read_snapshot, field):
    result = read_snapshot(batch={field: 5})
    assert result['state'] == 'pending'
    assert result['collection']['reasons'] == ['processing']
    assert result['collection']['attention_required'] is False
    assert result['collection']['state'] == 'processing'


def test_recent_batches_are_incomplete_without_attention_warning(read_snapshot):
    result = read_snapshot(queue={'depth': 2, 'capacity': 4096, 'oldest_age_seconds': 0.005},
                           spool={'rows': 90, 'oldest_age_seconds': 0.06},
                           batch={'pending': 12, 'oldest_age_seconds': 0.2,
                                  'flush_interval_seconds': 1})
    assert result['state'] == 'pending'
    assert result['collection'] == {
        'incomplete': True, 'reasons': ['processing'], 'attention_required': False,
        'attention_reasons': [], 'state': 'processing', 'lag_threshold_seconds': 10.0}


def test_partial_batch_age_is_allowlisted_and_exposes_lag(read_snapshot):
    result = read_snapshot(batch={'pending': 4, 'oldest_age_seconds': 15})
    assert result['batch']['oldest_age_seconds'] == 15
    assert result['collection']['state'] == 'delayed'
    assert result['collection']['attention_reasons'] == ['backlog_lag']


def test_untrusted_collection_classification_is_recomputed(read_snapshot):
    result = read_snapshot(spool={'rows': 1, 'oldest_age_seconds': 15},
                           collection={'attention_required': False, 'attention_reasons': [],
                                       'state': 'ready', 'lag_threshold_seconds': 999999})
    assert result['collection']['attention_required'] is True
    assert result['collection']['attention_reasons'] == ['backlog_lag']
    assert result['collection']['lag_threshold_seconds'] == 10.0
