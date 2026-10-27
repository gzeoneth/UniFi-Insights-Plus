"""Policy load failures must terminate cleanup without unsafe legacy fallback."""

from unittest.mock import MagicMock

import pytest

from db import Database


@pytest.mark.parametrize('saved_policy', [
    {'enabled': True, 'security_days': -1},
    {'enabled': True, 'batch_size': 0},
    'invalid-json-value',
])
def test_corrupt_policy_returns_failed_result_without_deleting(saved_policy):
    db = Database(conn_params={'host': 'unused'})
    db.get_config = MagicMock(return_value=saved_policy)
    db.get_conn = MagicMock()
    result = db.run_retention_cleanup(60, 10)
    assert result['status'] == 'failed'
    assert result['error']
    assert result['dns_deleted'] == 0
    assert result['non_dns_deleted'] == 0
    assert result['deleted_so_far'] == 0
    assert result['batches_completed'] == 0
    db.get_conn.assert_not_called()


def test_unreadable_policy_returns_failed_result_without_legacy_cleanup():
    db = Database(conn_params={'host': 'unused'})
    db.get_config = MagicMock(side_effect=RuntimeError('config database unavailable'))
    db.get_conn = MagicMock()
    result = db.run_retention_cleanup(60, 10)
    assert result['status'] == 'failed'
    assert result['error'] == 'config database unavailable'
    assert result['deleted_so_far'] == 0
    db.get_conn.assert_not_called()


def test_invalid_cleanup_arguments_still_raise_before_policy_lookup():
    db = Database(conn_params={'host': 'unused'})
    db.get_config = MagicMock()
    with pytest.raises(ValueError, match='positive'):
        db.run_retention_cleanup(0, 10)
    db.get_config.assert_not_called()
