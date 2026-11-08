"""Completion semantics and nonblocking index retries for service migration."""
from unittest.mock import MagicMock

import pytest

from backfill import BackfillTask


@pytest.mark.parametrize('marker', [None, False, 'false', 'true', 1, {}])
def test_only_boolean_true_skips_service_backfill(marker):
    database, enricher = MagicMock(), MagicMock()
    database.get_config.side_effect = lambda key, default=None: (
        marker if key == 'service_name_backfill_done' else 0)
    database.service_name_backfill_batch.return_value = [(1, 53, 'udp')]
    database.patch_service_names.return_value = 1
    BackfillTask(database, enricher)._service_name_migration()
    database.service_name_backfill_batch.assert_called_once()
    database.request_service_name_index_maintenance.assert_called_once()
    database.set_config.assert_called_with('service_name_backfill_last_id', 1)


def test_completed_backfill_still_requests_failed_drop_retry():
    database = MagicMock()
    database.get_config.return_value = True
    BackfillTask(database, MagicMock())._service_name_migration()
    database.service_name_backfill_batch.assert_not_called()
    database.request_service_name_index_maintenance.assert_called_once()


def test_empty_batch_commits_done_before_requesting_retirement():
    database = MagicMock()
    database.get_config.return_value = 0
    database.service_name_backfill_batch.return_value = []
    BackfillTask(database, MagicMock())._service_name_migration()
    calls = database.mock_calls
    mark = next(i for i, call in enumerate(calls)
                if call == ('set_config', ('service_name_backfill_done', True), {}))
    requests = [i for i, call in enumerate(calls)
                if call == ('request_service_name_index_maintenance', (), {})]
    assert requests[0] < mark < requests[1]
