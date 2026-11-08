"""Shared collection classification, independent of storage and HTTP services."""

import math
import time


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _number(value, default=0):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            if math.isfinite(value) and value >= 0:
                return value
        except OverflowError:
            pass
    return default


def worker_stalled(worker, pending, now, backlog_age=None):
    if not pending or worker.get('alive') is not True:
        return False
    busy_since = _number(worker.get('busy_since'), None)
    if busy_since:
        return now - busy_since > 30
    progress_at = _number(worker.get('last_progress_at'), None)
    progress_age = max(0, now - progress_at) if progress_at else None
    ages = [value for value in (progress_age, backlog_age) if value is not None]
    # Old idle progress alone cannot make a newly arrived backlog stalled.
    return bool(ages) and min(ages) > 30


def receiver_state(snapshot, now=None):
    """Preserve the operational state contract for both snapshot producers."""
    now = time.time() if now is None else now
    if snapshot.get('status', 'fresh') != 'fresh':
        return 'unknown'
    workers = _mapping(snapshot.get('workers'))
    producer = _mapping(workers.get('producer'))
    delivery = _mapping(workers.get('delivery'))
    queue = _mapping(snapshot.get('queue'))
    spool = _mapping(snapshot.get('spool'))
    batch = _mapping(snapshot.get('batch'))
    retry = _mapping(snapshot.get('retry'))
    queue_depth = _number(queue.get('depth'))
    spool_rows = _number(spool.get('rows'))
    batch_pending = _number(batch.get('pending')) or _number(batch.get('inflight'))
    producer_pending = queue_depth or batch_pending
    if (snapshot.get('running') is not True or snapshot.get('worker_alive') is not True
            or spool.get('failed') is True
            or any(worker.get('failed') is True or worker.get('alive') is False
                   for worker in (producer, delivery))):
        return 'error'
    queue_age = _number(queue.get('oldest_age_seconds'), None) if queue_depth else None
    batch_age = _number(batch.get('oldest_age_seconds'), None) if batch_pending else None
    producer_ages = [age for age in (queue_age, batch_age) if age is not None]
    if (worker_stalled(producer, producer_pending, now, max(producer_ages, default=None))
            or worker_stalled(delivery, spool_rows, now,
                              _number(spool.get('oldest_age_seconds'), None))):
        return 'stalled'
    progress = _number(snapshot.get('last_progress_at'), None)
    if (all(worker.get('alive') is None for worker in (producer, delivery))
            and (producer_pending or spool_rows) and (not progress or now - progress > 30)):
        return 'stalled'
    if _number(retry.get('consecutive_failures')) or producer_pending or spool_rows:
        return 'pending'
    return 'ready'


def collection_state(snapshot, now=None):
    """Separate literal pending/incomplete data from conditions needing attention.

    Recent queued, batched or durable events are normal processing. Delay is
    actionable after ten seconds (or twice the configured flush interval).
    Neither a ready state nor absent recorded loss proves UDP delivery complete.
    """
    now = time.time() if now is None else now
    stats = _mapping(snapshot.get('stats'))
    queue = _mapping(snapshot.get('queue'))
    spool = _mapping(snapshot.get('spool'))
    batch = _mapping(snapshot.get('batch'))
    retry = _mapping(snapshot.get('retry'))
    workers = _mapping(snapshot.get('workers'))
    status = snapshot.get('status', 'fresh')
    operational_state = receiver_state(snapshot, now)
    threshold = max(10.0, _number(2 * _number(batch.get('flush_interval_seconds')), 10.0))
    queue_depth = _number(queue.get('depth'))
    spool_rows = _number(spool.get('rows'))
    batch_pending = _number(batch.get('pending')) or _number(batch.get('inflight'))
    pending = bool(queue_depth or spool_rows or batch_pending)
    reasons, attention = [], []

    def flag(reason):
        reasons.append(reason)
        attention.append(reason)

    if any(_number(stats.get(key)) for key in ('dropped', 'failed', 'parse_exceptions')):
        flag('historical_loss')
    if pending:
        reasons.append('processing')
    if status != 'fresh':
        flag('stale_snapshot' if status == 'stale' else 'unavailable_snapshot')
    else:
        if (snapshot.get('running') is not True or snapshot.get('worker_alive') is not True
                or any(_mapping(value).get('failed') is True or _mapping(value).get('alive') is False
                       for value in workers.values())):
            flag('worker_error')
        if spool.get('failed') is True:
            flag('storage_error')
        if operational_state == 'stalled':
            flag('worker_stalled')
        if _number(retry.get('consecutive_failures')):
            flag('delivery_retry')
        # Snapshot ages are measured when published. Add its current age so a
        # queued row does not appear younger while the same snapshot is read.
        snapshot_age = _number(snapshot.get('age_seconds'))
        ages = []
        for count, group in ((queue_depth, queue), (spool_rows, spool), (batch_pending, batch)):
            age = _number(group.get('oldest_age_seconds'), None)
            if count and age is not None:
                ages.append(age + snapshot_age)
        if batch_pending:
            busy = _number(_mapping(workers.get('producer')).get('busy_since'), None)
            if busy:
                ages.append(max(0, now - busy))
        if ages and max(ages) > threshold:
            flag('backlog_lag')
        capacity = _number(queue.get('capacity'))
        if capacity and queue_depth >= 0.8 * capacity:
            flag('queue_pressure')

    if status != 'fresh':
        state = 'unknown'
    elif any(reason in attention for reason in ('worker_error', 'storage_error', 'worker_stalled')):
        state = 'error'
    elif any(reason in attention for reason in ('backlog_lag', 'queue_pressure', 'delivery_retry')):
        state = 'delayed'
    elif 'historical_loss' in attention:
        state = 'loss'
    else:
        state = 'processing' if pending else 'ready'
    return {'incomplete': bool(reasons), 'reasons': reasons,
            'attention_required': bool(attention), 'attention_reasons': attention,
            'state': state, 'lag_threshold_seconds': threshold}
