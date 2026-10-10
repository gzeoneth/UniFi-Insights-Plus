"""Tests for the AbuseIPDB budget gate in BackfillTask._process_queue() (#103).

The budget is checked before the queue is pulled, so an exhausted quota
never touches threat_backfill_queue. When the rate-limit state is still
unknown (startup), one bootstrap pull is allowed.
"""
from unittest.mock import MagicMock

from backfill import BackfillTask, QUEUE_BATCH_SIZE


def _task(budget, rate_limit_known, enabled=True):
    db = MagicMock()
    db.pull_due_queue_batch.return_value = []  # stop right after the pull
    enricher = MagicMock()
    enricher.abuseipdb.remaining_budget = budget
    enricher.abuseipdb.enabled = enabled
    enricher.abuseipdb.is_rate_limit_known.return_value = rate_limit_known
    return BackfillTask(db, enricher), db


def test_exhausted_budget_skips_queue_pull():
    task, db = _task(budget=0, rate_limit_known=True)
    task._process_queue()
    db.pull_due_queue_batch.assert_not_called()


def test_unknown_rate_limit_bootstraps_queue_pull():
    task, db = _task(budget=0, rate_limit_known=False)
    task._process_queue()
    db.pull_due_queue_batch.assert_called_once_with(limit=QUEUE_BATCH_SIZE)


def test_disabled_abuseipdb_skips_queue_pull():
    task, db = _task(budget=0, rate_limit_known=False, enabled=False)
    task._process_queue()
    db.pull_due_queue_batch.assert_not_called()


def test_positive_budget_pulls_queue():
    task, db = _task(budget=5, rate_limit_known=True)
    task._process_queue()
    db.pull_due_queue_batch.assert_called_once_with(limit=QUEUE_BATCH_SIZE)
