"""Normal buffering and meaningful ingestion trouble must have distinct signals."""

import copy

import pytest

from ingest_health import collection_state, receiver_state


NOW = 1000.0


def snapshot(**updates):
    data = {'status': 'fresh', 'running': True, 'worker_alive': True,
            'last_progress_at': NOW, 'stats': {},
            'queue': {'depth': 0, 'capacity': 100, 'oldest_age_seconds': 0},
            'spool': {'rows': 0, 'oldest_age_seconds': 0, 'failed': False},
            'batch': {'pending': 0, 'inflight': 0, 'flush_interval_seconds': 1},
            'workers': {name: {'alive': True, 'failed': False, 'last_progress_at': NOW,
                               'busy_since': None} for name in ('producer', 'delivery')}}
    data.update(updates)
    return data


@pytest.mark.parametrize('group,values', [
    ('queue', {'depth': 1, 'capacity': 100, 'oldest_age_seconds': 0.1}),
    ('spool', {'rows': 30, 'oldest_age_seconds': 0.3}),
    ('batch', {'pending': 7, 'oldest_age_seconds': 0.8}),
    ('batch', {'inflight': 1}),
])
def test_routine_pending_is_not_an_attention_condition(group, values):
    data = snapshot(**{group: values})
    result = collection_state(data, NOW)
    assert receiver_state(data, NOW) == 'pending'
    assert result['incomplete'] is True
    assert result['state'] == 'processing'
    assert result['reasons'] == ['processing']
    assert result['attention_reasons'] == []
    assert result['attention_required'] is False


@pytest.mark.parametrize('age,expected', [(9.9, False), (10, False), (10.1, True)])
@pytest.mark.parametrize('group,count', [('queue', 'depth'), ('spool', 'rows'), ('batch', 'pending')])
def test_pending_age_crosses_documented_grace(group, count, age, expected):
    result = collection_state(snapshot(**{group: {count: 1, 'oldest_age_seconds': age}}), NOW)
    assert result['attention_required'] is expected
    assert ('backlog_lag' in result['attention_reasons']) is expected
    assert result['state'] == ('delayed' if expected else 'processing')


def test_flush_interval_can_extend_grace_without_claiming_pending_complete():
    data = snapshot(batch={'pending': 2, 'flush_interval_seconds': 8, 'oldest_age_seconds': 15})
    result = collection_state(data, NOW)
    assert result['lag_threshold_seconds'] == 16
    assert result['incomplete'] is True and result['attention_required'] is False
    data['batch']['oldest_age_seconds'] = 17
    assert collection_state(data, NOW)['attention_required'] is True


def test_snapshot_age_counts_towards_current_lag():
    result = collection_state(snapshot(age_seconds=4,
        spool={'rows': 1, 'oldest_age_seconds': 7}), NOW)
    assert result['attention_reasons'] == ['backlog_lag']


@pytest.mark.parametrize('depth,expected', [(79, False), (80, True), (100, True)])
def test_near_capacity_queue_warns_before_age_grace(depth, expected):
    result = collection_state(snapshot(queue={'depth': depth, 'capacity': 100,
                                              'oldest_age_seconds': 0.01}), NOW)
    assert result['attention_required'] is expected
    assert ('queue_pressure' in result['attention_reasons']) is expected


@pytest.mark.parametrize('field', ['pending', 'inflight'])
def test_partial_batch_worker_stall_is_not_hidden_by_empty_queue(field):
    data = snapshot(batch={field: 1})
    data['workers']['producer'].update(last_progress_at=NOW - 45, busy_since=NOW - 40)
    result = collection_state(data, NOW)
    assert receiver_state(data, NOW) == 'stalled'
    assert result['state'] == 'error'
    assert result['attention_required'] is True
    assert 'worker_stalled' in result['attention_reasons']


def test_slow_inflight_work_warns_before_worker_stall_threshold():
    data = snapshot(batch={'inflight': 1})
    data['workers']['producer']['busy_since'] = NOW - 12
    assert receiver_state(data, NOW) == 'pending'
    assert collection_state(data, NOW)['attention_reasons'] == ['backlog_lag']


def test_old_idle_worker_with_new_rows_is_normal_processing():
    data = snapshot(spool={'rows': 1, 'oldest_age_seconds': 0.2})
    data['workers']['delivery']['last_progress_at'] = NOW - 120
    assert receiver_state(data, NOW) == 'pending'
    assert collection_state(data, NOW)['attention_required'] is False


def test_empty_batch_age_cannot_make_new_queue_work_appear_stalled():
    data = snapshot(queue={'depth': 1, 'oldest_age_seconds': 0.1},
                    batch={'pending': 0, 'inflight': 0, 'oldest_age_seconds': 100})
    data['workers']['producer']['last_progress_at'] = NOW - 120
    assert receiver_state(data, NOW) == 'pending'
    assert collection_state(data, NOW)['attention_required'] is False


@pytest.mark.parametrize('updates,reason,state', [
    ({'retry': {'consecutive_failures': 1}}, 'delivery_retry', 'delayed'),
    ({'spool': {'failed': True}}, 'storage_error', 'error'),
    ({'running': False}, 'worker_error', 'error'),
    ({'worker_alive': False}, 'worker_error', 'error'),
    ({'workers': {'delivery': {'alive': True, 'failed': True}}}, 'worker_error', 'error'),
    ({'workers': {'delivery': {'alive': False}}}, 'worker_error', 'error'),
])
def test_active_failures_always_need_attention(updates, reason, state):
    result = collection_state(snapshot(**updates), NOW)
    assert result['incomplete'] is True and result['attention_required'] is True
    assert result['state'] == state
    assert reason in result['attention_reasons']


@pytest.mark.parametrize('counter', ['dropped', 'failed', 'parse_exceptions'])
def test_historical_loss_stays_distinct_after_current_flow_recovers(counter):
    data = snapshot(stats={counter: 1}, rates={'dropped_per_second': 0})
    result = collection_state(data, NOW)
    assert receiver_state(data, NOW) == 'ready'
    assert result['state'] == 'loss'
    assert result['attention_reasons'] == ['historical_loss']
    assert result['attention_required'] is True


def test_old_successfully_recovered_retry_counter_is_not_current_failure():
    result = collection_state(snapshot(stats={'flush_errors': 3, 'retry_attempts': 2},
                                      retry={'consecutive_failures': 0}), NOW)
    assert result['attention_required'] is False
    assert result['state'] == 'ready'


@pytest.mark.parametrize('status,reason', [('stale', 'stale_snapshot'), ('unavailable', 'unavailable_snapshot')])
def test_unknown_snapshot_never_reports_current_processing_as_healthy(status, reason):
    data = snapshot(status=status, queue={'depth': 90, 'capacity': 100, 'oldest_age_seconds': 200})
    result = collection_state(data, NOW)
    assert result['attention_reasons'] == [reason]
    assert result['state'] == 'unknown'


def test_classification_does_not_mutate_or_trust_provided_text():
    data = snapshot(collection={'state': 'Synthetic private value', 'attention_required': True})
    original = copy.deepcopy(data)
    result = collection_state(data, NOW)
    assert result['state'] == 'ready'
    assert result['attention_required'] is False
    assert data == original


def test_overflowing_interval_cannot_escape_as_nonfinite_json_number():
    result = collection_state(snapshot(batch={'flush_interval_seconds': 1e308}), NOW)
    assert result['lag_threshold_seconds'] == 10
