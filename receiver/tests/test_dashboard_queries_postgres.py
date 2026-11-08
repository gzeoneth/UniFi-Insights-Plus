"""Exact dashboard aggregates on an explicitly disposable PostgreSQL fixture."""
from datetime import datetime, timedelta, timezone
import os

import pytest

from dashboard_queries import (overview_query, overview_result, series_query,
                               series_result, zone_query)
from field_filters import append_exclusions


@pytest.fixture
def pg_dashboard():
    dsn = os.environ.get('TEST_POSTGRES_DSN')
    if not dsn:
        pytest.skip('set TEST_POSTGRES_DSN for disposable PostgreSQL checks')
    import psycopg2
    from psycopg2.extras import RealDictCursor
    params = psycopg2.extensions.parse_dsn(dsn)
    assert params.get('host') in ('127.0.0.1', 'localhost', '::1')
    assert params.get('dbname', '').endswith('_tests')
    conn = psycopg2.connect(dsn, cursor_factory=RealDictCursor)
    with conn.cursor() as cur:
        cur.execute('''CREATE TEMP TABLE logs (
            timestamp timestamptz, log_type text, direction text,
            rule_action text, threat_score integer, src_ip inet, dst_ip inet,
            interface_in text, interface_out text, rule_name text,
            hostname text, event_source text, ips_signature_id text, raw_log text)''')
        base = datetime(2026, 1, 2, 12, tzinfo=timezone.utc)
        rows = [
            ('firewall', 'outbound', 'allow', 50, '192.0.2.129/24', '2001:db8::2/64', 'EXAMPLE-1'),
            ('firewall', 'outbound', 'block', 51, '192.0.2.129/32', '2001:db8::2/128', 'EXAMPLE-2'),
            ('firewall', 'outbound', 'redirect', None, '192.0.2.130', '2001:db8::2', 'EXAMPLE-2'),
            ('firewall', None, None, 99, None, '2001:db8::3', 'EXAMPLE-2'),
            ('dns', 'outbound', 'block', 51, '192.0.2.5', None, 'EXAMPLE-2'),
            ('system', 'inbound', 'allow', 90, None, None, 'EXAMPLE-2'),
            (None, '', 'unknown', 50, '2001:db8::4', '198.51.100.1', 'EXAMPLE-2'),
        ]
        for offset in (0, 3600, 7200):
            for kind, direction, action, score, src, dst, rule in rows:
                cur.execute('''INSERT INTO logs VALUES
                    (%s,%s,%s,%s,%s,%s,%s,'example-in','example-out',%s,
                     'example-gateway',NULL,NULL,NULL)''',
                    [base+timedelta(seconds=offset), kind, direction, action, score, src, dst, rule])
        # Preserve the zero-valued action period created by an unknown action.
        cur.execute("INSERT INTO logs(timestamp,log_type,rule_action) VALUES (%s,'firewall','unknown')",
                    [base+timedelta(hours=3)])
        # A NULL-only action period is absent from traffic_by_action.
        cur.execute("INSERT INTO logs(timestamp,log_type) VALUES (%s,'firewall')",
                    [base+timedelta(hours=4)])
        # Older data and NULL interfaces must not leak into the chosen scope.
        cur.execute("INSERT INTO logs SELECT timestamp-interval '3 days',log_type,direction,rule_action,threat_score,src_ip,dst_ip,interface_in,interface_out,rule_name,hostname,event_source,ips_signature_id,raw_log FROM logs")
        cur.execute("INSERT INTO logs(timestamp,log_type,src_ip,dst_ip) VALUES (%s,'firewall','192.0.2.1','198.51.100.1')", [base])
        # Exclusion matching must retain actual security events.
        cur.execute("INSERT INTO logs SELECT timestamp,log_type,direction,rule_action,threat_score,src_ip,dst_ip,interface_in,interface_out,rule_name,hostname,'unifi_ips',NULL,NULL FROM logs WHERE rule_name='EXAMPLE-1'")
    try:
        yield conn
    finally:
        conn.close()


CUTOFF = datetime(2026, 1, 2, tzinfo=timezone.utc)
GROUPS = [{'conditions': [{'field': 'rule_name_exact', 'operator': 'include', 'value': 'EXAMPLE-1'}]}]


def fetch(conn, sql, params):
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return [dict(row) for row in cur.fetchall()]


@pytest.mark.parametrize('excluded', [False, True])
def test_overview_matches_separate_exact_queries(pg_dashboard, excluded):
    conn = pg_dashboard
    scope = append_exclusions('timestamp >= %s', [CUTOFF], GROUPS if excluded else None)
    where, params = scope
    sql, args = overview_query(CUTOFF, scope if excluded else None)
    actual = overview_result(fetch(conn, sql, args))
    scalar = fetch(conn, f'''SELECT COUNT(*) AS total,
        COUNT(*) FILTER (WHERE log_type='firewall' AND rule_action='allow') AS allowed,
        COUNT(*) FILTER (WHERE rule_action='block') AS blocked,
        COUNT(*) FILTER (WHERE threat_score>50) AS threats FROM logs WHERE {where}''', params)[0]
    types = fetch(conn, f'SELECT log_type,COUNT(*) AS n FROM logs WHERE {where} GROUP BY log_type', params)
    dirs = fetch(conn, f'SELECT direction,COUNT(*) AS n FROM logs WHERE {where} AND direction IS NOT NULL GROUP BY direction', params)
    total = fetch(conn, 'SELECT COUNT(*) AS n FROM logs WHERE timestamp >= %s', [CUTOFF])[0]['n']
    assert actual == {**scalar, 'by_type': {r['log_type']: r['n'] for r in types},
                      'by_direction': {r['direction']: r['n'] for r in dirs},
                      'view_counts': {'total': total, 'visible': scalar['total'], 'hidden': total-scalar['total']}}


@pytest.mark.parametrize('bucket', ['hour', 'day', 'week', 'month'])
@pytest.mark.parametrize('excluded', [False, True])
def test_series_matches_both_queries_including_unknown_and_null_actions(pg_dashboard, bucket, excluded):
    conn = pg_dashboard
    scope = append_exclusions('timestamp >= %s', [CUTOFF], GROUPS if excluded else None)
    where, params = scope
    sql, args = series_query(bucket, scope)
    totals, actions = series_result(fetch(conn, sql, args))
    old_totals = fetch(conn, f"SELECT date_trunc('{bucket}',timestamp) AS period,COUNT(*) AS count FROM logs WHERE {where} GROUP BY period ORDER BY period", params)
    old_actions = fetch(conn, f"SELECT date_trunc('{bucket}',timestamp) AS period,rule_action,COUNT(*) AS count FROM logs WHERE {where} AND log_type='firewall' AND rule_action IS NOT NULL GROUP BY period,rule_action ORDER BY period", params)
    expected_actions = {}
    for r in old_actions:
        key = r['period'].isoformat()
        expected_actions.setdefault(key, {'period': key, 'allow': 0, 'block': 0, 'redirect': 0})
        if r['rule_action'] in ('allow', 'block', 'redirect'):
            expected_actions[key][r['rule_action']] = r['count']
    assert totals == [{'period': r['period'].isoformat(), 'count': r['count']} for r in old_totals]
    assert actions == list(expected_actions.values())


@pytest.mark.parametrize('excluded', [False, True])
def test_zone_preaggregation_preserves_masks_nulls_and_exclusions(pg_dashboard, excluded):
    conn = pg_dashboard
    where, params = append_exclusions("timestamp >= %s AND log_type='firewall'", [CUTOFF], GROUPS if excluded else None)
    actual = fetch(conn, zone_query(where), params)
    expected = fetch(conn, f'''SELECT interface_in,interface_out,COUNT(*) AS total,
        COUNT(*) FILTER (WHERE rule_action='allow') AS allow_count,
        COUNT(*) FILTER (WHERE rule_action='block') AS block_count,
        COUNT(DISTINCT(set_masklen(src_ip,-1),set_masklen(dst_ip,-1)))
            FILTER(WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL) AS unique_pairs
        FROM logs WHERE {where} AND interface_in IS NOT NULL AND interface_out IS NOT NULL
        GROUP BY interface_in,interface_out ORDER BY total DESC''', params)
    assert actual == expected


def test_empty_window_and_bucket_validation(pg_dashboard):
    cutoff = datetime(2030, 1, 1, tzinfo=timezone.utc)
    sql, args = overview_query(cutoff)
    assert overview_result(fetch(pg_dashboard, sql, args)) == {
        'total': 0, 'allowed': 0, 'blocked': 0, 'threats': 0,
        'by_type': {}, 'by_direction': {},
        'view_counts': {'total': 0, 'visible': 0, 'hidden': 0}}
    sql, args = series_query('hour', ('timestamp >= %s', [cutoff]))
    assert series_result(fetch(pg_dashboard, sql, args)) == ([], [])
    assert fetch(pg_dashboard, zone_query('timestamp >= %s'), [cutoff]) == []
    with pytest.raises(ValueError):
        series_query("hour'); SELECT 1; --", ('TRUE', []))
