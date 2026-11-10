"""Coverage and exclusion routing must never turn incomplete facts into counts."""

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
from fastapi import HTTPException
from psycopg2 import errors

import dashboard_source as source
from dashboard_queries import overview_query, series_query
from dashboard_tables import dimension_tables_sql, address_tables_sql
from field_filters import compile_exclusions

CUTOFF = datetime(2026, 1, 2, tzinfo=timezone.utc)
GROUPS = [{'conditions': [{'field': 'dst_port', 'operator': 'include', 'value': '443'}]}]


@pytest.fixture
def eligible(monkeypatch):
    monkeypatch.setattr(source, 'enabled', lambda: True)
    state = dict(schema_version=1, status='backfilling', healthy=True,
                 complete=False, coverage_from=CUTOFF)
    monkeypatch.setattr(source, 'snapshot_state', lambda cur: state)
    return state


def test_disabled_store_does_not_probe_database(monkeypatch):
    monkeypatch.setattr(source, 'enabled', lambda: False)
    cur = Mock()
    relation, scope = source.choose_dashboard_source(cur, CUTOFF, GROUPS)
    assert relation == 'logs'
    assert 'raw_log' in scope[0]
    cur.execute.assert_not_called()


@pytest.mark.parametrize('field', ['search', 'rule_name', 'rule_desc_exact',
                                  'device', 'src_device', 'dst_device', 'ips_signature'])
def test_omitted_fields_keep_raw_path(eligible, field):
    cur = Mock()
    groups = [{'conditions': [{'field': field, 'operator': 'include', 'value': 'sample'}]}]
    assert source.choose_dashboard_source(cur, CUTOFF, groups)[0] == 'logs'
    cur.execute.assert_not_called()


def test_covered_source_uses_snapshot_and_relation_lock(eligible):
    cur = Mock()
    relation, scope = source.choose_dashboard_source(cur, CUTOFF, GROUPS)
    assert relation == 'dashboard_events'
    sqls = [call.args[0] for call in cur.execute.call_args_list]
    assert sqls[0] == 'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY'
    assert sqls[1] == 'LOCK TABLE logs IN ACCESS SHARE MODE'
    assert 'security_ips OR security_cef' in scope[0]
    assert 'raw_log' not in scope[0]


def test_partial_coverage_is_not_full_history(eligible):
    assert source.choose_dashboard_source(Mock(), CUTOFF-timedelta(hours=1), GROUPS)[0] == 'logs'
    assert source.choose_dashboard_source(Mock(), CUTOFF+timedelta(hours=1), GROUPS)[0] == 'dashboard_events'


def test_complete_store_serves_older_cutoff(eligible):
    eligible.update(complete=True, coverage_from=None)
    assert source.choose_dashboard_source(Mock(), CUTOFF-timedelta(days=30), None)[0] == 'dashboard_events'


@pytest.mark.parametrize('change', [{'healthy': False}, {'schema_version': 2},
                                  {'status': 'disabled'}, {'coverage_from': None}])
def test_unusable_state_fails_to_raw(eligible, change):
    eligible.update(change)
    assert source.choose_dashboard_source(Mock(), CUTOFF, None)[0] == 'logs'


@pytest.mark.parametrize('error', [errors.UndefinedTable, errors.UndefinedColumn,
                                  errors.UndefinedFunction, errors.InsufficientPrivilege])
def test_missing_or_unreadable_store_restores_transaction(eligible, monkeypatch, error):
    monkeypatch.setattr(source, 'snapshot_state', Mock(side_effect=error()))
    cur = Mock()
    assert source.choose_dashboard_source(cur, CUTOFF, None)[0] == 'logs'
    sqls = [call.args[0] for call in cur.execute.call_args_list]
    assert 'ROLLBACK TO SAVEPOINT dashboard_store_probe' in sqls
    assert sqls[-1] == 'RELEASE SAVEPOINT dashboard_store_probe'


def test_cancellation_is_not_replaced_with_raw_scan(eligible, monkeypatch):
    monkeypatch.setattr(source, 'snapshot_state', Mock(side_effect=errors.QueryCanceled()))
    cur = Mock()
    with pytest.raises(errors.QueryCanceled):
        source.choose_dashboard_source(cur, CUTOFF, None)
    assert 'RELEASE SAVEPOINT dashboard_store_probe' not in [c.args[0] for c in cur.execute.call_args_list]


def test_invalid_profile_is_still_rejected(eligible):
    with pytest.raises(HTTPException):
        source.choose_dashboard_source(Mock(), CUTOFF, [{'conditions': [
            {'field': 'unknown', 'operator': 'include', 'value': 'sample'}]}])


def test_projected_exclusions_retain_exact_security_parameters():
    groups = GROUPS + [{'conditions': [
        {'field': 'security_event', 'operator': 'exclude', 'value': 'unparsed_cef'}]}]
    raw, raw_params = compile_exclusions(groups)
    projected, projected_params = compile_exclusions(groups, security_predicates=source.PROJECTED_SECURITY)
    assert raw_params == projected_params
    assert 'raw_log' in raw[0] and 'raw_log' not in projected[0]
    assert 'security_cef' in projected[0] and 'security_ips' in projected[0]


@pytest.mark.parametrize('factory', [
    lambda s: overview_query(CUTOFF, source=s),
    lambda s: series_query('hour', ('timestamp >= %s', [CUTOFF]), source=s),
    lambda s: dimension_tables_sql('timestamp >= %s', source=s),
    lambda s: address_tables_sql('timestamp >= %s', source=s),
])
def test_relation_names_are_not_caller_sql(factory):
    with pytest.raises(ValueError):
        factory('logs; SELECT 1')


def test_analytics_requires_explicit_opt_in():
    from dashboard_store import enabled
    assert enabled({}) is False
    assert enabled({'DASHBOARD_ANALYTICS_ENABLED': 'true'}) is True
