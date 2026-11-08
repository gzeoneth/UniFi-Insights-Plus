"""Exact map semantics and opt-in high-volume PostgreSQL comparisons."""

import importlib.util
import json
import os
from pathlib import Path
import statistics
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock
from uuid import uuid4

import pytest


@pytest.fixture
def threats(monkeypatch):
    dependencies = SimpleNamespace(get_conn=Mock(), put_conn=Mock())
    monkeypatch.setitem(sys.modules, 'deps', dependencies)
    path = Path(__file__).parents[1] / 'routes' / 'threats.py'
    spec = importlib.util.spec_from_file_location('synthetic_map_routes', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def legacy_query(where):
    """The shipped map query, retained only as an equivalence reference."""
    return f"""SELECT geo_lat AS lat, geo_lon AS lon, geo_country AS country,
        geo_city AS city, COUNT(*) AS count, MAX(threat_score) AS max_score,
        AVG(threat_score)::int AS avg_score,
        COUNT(DISTINCT COALESCE(host(src_ip), host(dst_ip))) AS unique_ips,
        (array_agg(id ORDER BY timestamp DESC))[1:50] AS log_ids
        FROM logs WHERE {where}
        GROUP BY geo_lat, geo_lon, geo_country, geo_city
        ORDER BY count DESC LIMIT 500"""


def where_for(mode):
    mode_sql = "threat_score > 70" if mode == 'threats' else "direction = 'outbound' AND rule_action = 'block'"
    return ("timestamp >= %s::timestamptz AND timestamp <= %s::timestamptz AND "
            + mode_sql + ' AND geo_lat IS NOT NULL AND geo_lon IS NOT NULL')


WINDOW = ['2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z']


@pytest.fixture
def pg_map():
    dsn = os.environ.get('TEST_POSTGRES_DSN')
    if not dsn:
        pytest.skip('set TEST_POSTGRES_DSN to a disposable loopback PostgreSQL')
    import psycopg2
    params = psycopg2.extensions.parse_dsn(dsn)
    if params.get('host') not in ('127.0.0.1', 'localhost', '::1'):
        pytest.fail('Map integration tests require an explicit loopback database')
    connection = psycopg2.connect(dsn)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SET TIME ZONE 'UTC'")
            cursor.execute("SET work_mem = '8MB'")
            cursor.execute('SET max_parallel_workers_per_gather = 0')
            cursor.execute('SET jit = off')
            cursor.execute('''CREATE TEMP TABLE logs (
                id bigint PRIMARY KEY, timestamp timestamptz NOT NULL,
                geo_lat decimal(9,6), geo_lon decimal(9,6),
                geo_country text, geo_city text, threat_score integer,
                src_ip inet, dst_ip inet, direction text, rule_action text,
                raw_log text)''')
        connection.commit()
        yield connection
    finally:
        connection.close()


def rows(connection, sql, params):
    from psycopg2.extras import RealDictCursor
    with connection.cursor(cursor_factory=RealDictCursor) as cursor:
        cursor.execute(sql, params)
        return list(cursor.fetchall())


def by_group(values):
    def canonical(value):
        return 'NaN' if isinstance(value, float) and value != value else value
    return {tuple(canonical(row[key]) for key in ('lat', 'lon', 'country', 'city')):
            {key: canonical(value) for key, value in row.items()} for row in values}


def assert_equivalent(connection, module, mode):
    where = where_for(mode)
    connection.commit()
    before = rows(connection, legacy_query(where), WINDOW)
    connection.rollback()
    after = module._load_geo_rows(connection, where, WINDOW)
    connection.rollback()
    assert by_group(after) == by_group(before)
    assert [row['count'] for row in after] == sorted((row['count'] for row in after), reverse=True)
    assert all(len(row['log_ids']) == min(50, row['count']) for row in after)
    return before, after


def test_map_queries_never_accumulate_unbounded_arrays_or_project_payloads(threats):
    sql = threats._geo_query('timestamp >= %s AND threat_score > 70')
    assert 'ORDER BY count DESC LIMIT 500' in sql
    assert 'raw_log' not in sql
    assert 'LATERAL' not in sql
    assert 'array_agg' not in sql
    assert 'COLLATE "C"' in sql
    sample_sql, params = threats._map_id_query([dict(lat=1, lon=2, country=None, city='')], 'timestamp >= %s')
    assert 'array_agg' not in sample_sql and 'raw_log' not in sample_sql
    assert 'MATERIALIZED' not in sample_sql and 'LATERAL' not in sample_sql
    assert sample_sql.count('FROM logs') == 1
    assert 'ORDER BY l.timestamp DESC' in sample_sql
    assert params == [0, 1, 2, None, '']
    assert '(l.geo_country IS NULL) = (g.country IS NULL)' in sample_sql
    assert '(l.geo_city IS NULL) = (g.city IS NULL)' in sample_sql


def fake_connection(groups, batches):
    cursor = MagicMock()
    cursor.__enter__.return_value = cursor
    cursor.fetchall.return_value = groups
    stream = MagicMock()
    stream.__enter__.return_value = stream
    stream.fetchmany.side_effect = batches
    connection = Mock()
    connection.cursor.side_effect = lambda **kwargs: stream if 'name' in kwargs else cursor
    return connection, cursor, stream


def test_route_preserves_mode_time_parameters_and_null_display_values(threats):
    connection, cursor, stream = fake_connection([dict(lat=1.5, lon=2.5, country=None, city='',
        count=2, max_score=None, avg_score=None, unique_ips=0)], [[(0, 8), (0, 7)]])
    threats.get_conn.return_value = connection
    result = threats.get_threats_geo(time_range=None, time_from=WINDOW[0],
                                     time_to=WINDOW[1], mode='blocked_outbound')
    sql, params = cursor.execute.call_args.args
    id_sql, id_params = stream.execute.call_args.args
    assert sql.count("direction = 'outbound'") == id_sql.count("direction = 'outbound'") == 1
    assert sql.count("rule_action = 'block'") == id_sql.count("rule_action = 'block'") == 1
    assert len(params) == 2 and params == id_params[-2:]
    assert cursor.execute.call_args_list[0].args == ('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY',)
    stream.__exit__.assert_called_once()
    feature = result['features'][0]
    assert feature['geometry']['coordinates'] == [2.5, 1.5]
    assert feature['properties'] == dict(country=None, city='', count=2, max_score=0,
                                         avg_score=0, unique_ips=0, log_ids=[8, 7])
    assert result['summary']['total_events'] == 2
    with pytest.raises(threats.HTTPException):
        threats.get_threats_geo(mode='unknown')
    assert threats.get_conn.call_count == 1


def test_empty_groups_do_not_open_a_server_cursor(threats):
    connection, cursor, stream = fake_connection([], [])
    assert threats._load_geo_rows(connection, 'TRUE', []) == []
    assert connection.cursor.call_count == 1
    stream.execute.assert_not_called()


def test_sampling_is_bounded_and_closes_the_cursor_early(threats):
    groups = [dict(lat=1, lon=2, country='ZZ', city='Synthetic', count=100000)]
    connection, cursor, stream = fake_connection(groups, [[(0, identifier) for identifier in range(100, 0, -1)]])
    sampled = threats._load_geo_rows(connection, 'TRUE', [])
    assert sampled[0]['log_ids'] == list(range(100, 50, -1))
    stream.fetchmany.assert_called_once_with(4096)
    stream.__exit__.assert_called_once()


def test_disconnect_between_fetches_closes_cursor_and_returns_connection(threats, monkeypatch):
    disconnected = threading.Event()
    monkeypatch.setattr(threats, 'current_work', lambda: SimpleNamespace(disconnected=disconnected))
    connection, cursor, stream = fake_connection([dict(lat=1, lon=2, country=None, city='', count=2)], [])
    def fetch(size):
        disconnected.set()
        return [(0, 2)]
    stream.fetchmany.side_effect = fetch
    threats.get_conn.return_value = connection
    with pytest.raises(threats.HTTPException) as error:
        threats.get_threats_geo(time_range=None, time_from=WINDOW[0], time_to=WINDOW[1], mode='threats')
    assert error.value.status_code == 499
    stream.__exit__.assert_called_once()
    stream.fetchmany.assert_called_once()
    connection.rollback.assert_called_once()
    threats.put_conn.assert_called_once_with(connection)


@pytest.mark.parametrize('mode', ['threats', 'blocked_outbound'])
def test_map_pg_equivalence_nulls_masks_scores_and_timestamp_order(pg_map, threats, mode):
    with pg_map.cursor() as cursor:
        cursor.execute('''INSERT INTO logs
            SELECT i, '2026-01-01'::timestamptz + i * interval '1 millisecond',
                   10.5, 20.5, 'ZZ', 'Synthetic repeated hosts',
                   CASE WHEN i % 7 = 0 THEN NULL ELSE i % 101 END,
                   CASE WHEN i % 3 = 0 THEN NULL
                        WHEN i % 2 = 0 THEN '198.51.100.1/24'::inet
                        ELSE '198.51.100.1/32'::inet END,
                   CASE WHEN i % 5 = 0 THEN NULL ELSE '2001:db8::1/64'::inet END,
                   CASE WHEN i % 4 = 0 THEN 'inbound' ELSE 'outbound' END,
                   CASE WHEN i % 6 = 0 THEN 'allow' ELSE 'block' END,
                   'Synthetic event'
            FROM generate_series(1, 125) i''')
        cursor.execute('''INSERT INTO logs
            SELECT 1000 + g * 100 + i, '2026-01-01'::timestamptz + i * interval '1 second',
                   1, 2, CASE WHEN g % 2 = 0 THEN NULL ELSE '' END,
                   CASE WHEN g < 2 THEN NULL ELSE '' END,
                   CASE WHEN g = 0 THEN NULL ELSE 90 END,
                   NULL, NULL, 'outbound', 'block', 'Synthetic null/empty group'
            FROM generate_series(0,3) g CROSS JOIN LATERAL generate_series(1,7+g) i''')
        cursor.execute('''INSERT INTO logs
            SELECT 2000+i, '2026-01-01'::timestamptz+i*interval '1 second',
                   3, 4, 'ZZ', 'Half rounding', i-1,
                   '192.0.2.1'::inet, NULL, 'outbound', 'block', ''
            FROM generate_series(1,2) i''')
        cursor.execute('''INSERT INTO logs VALUES
            (3001,'2026-01-01',5,6,'ZZ','Negative rounding',-1,'2001:db8::2',NULL,'outbound','block',''),
            (3002,'2026-01-01 00:00:01',5,6,'ZZ','Negative rounding',0,'2001:db8::2/64',NULL,'outbound','block',''),
            (3003,'2026-01-01',NULL,6,'ZZ','Missing latitude',90,NULL,NULL,'outbound','block',''),
            (3004,'2026-01-01',5,NULL,'ZZ','Missing longitude',90,NULL,NULL,'outbound','block',''),
            (3005,'2025-12-31',5,6,'ZZ','Before window',90,NULL,NULL,'outbound','block',''),
            (3006,'2026-01-03',5,6,'ZZ','After window',90,NULL,NULL,'outbound','block','')''')
        cursor.execute('ANALYZE logs')
    assert_equivalent(pg_map, threats, mode)


def test_map_pg_preserves_exact_top_500_groups(pg_map, threats):
    with pg_map.cursor() as cursor:
        cursor.execute('''INSERT INTO logs
            SELECT g*1000+i, '2026-01-01'::timestamptz+i*interval '1 second',
                   g%80, g%160, 'ZZ', 'Synthetic '||g, 90,
                   '192.0.2.1'::inet, NULL, 'outbound', 'block', ''
            FROM generate_series(1,520) g CROSS JOIN LATERAL generate_series(1,g) i''')
        cursor.execute('ANALYZE logs')
    before, after = assert_equivalent(pg_map, threats, 'threats')
    assert len(after) == 500
    assert after[0]['count'] == 520 and after[-1]['count'] == 21


def test_map_pg_timestamp_ties_keep_legacy_unspecified_tie_order(pg_map, threats):
    with pg_map.cursor() as cursor:
        cursor.execute('''INSERT INTO logs
            SELECT i, '2026-01-01'::timestamptz, 1, 2, NULL, '', 90,
                   '192.0.2.1'::inet, NULL, 'outbound', 'block', ''
            FROM generate_series(1,80) i''')
    where = where_for('threats')
    pg_map.commit()
    before = rows(pg_map, legacy_query(where), WINDOW)[0]
    pg_map.rollback()
    after = threats._load_geo_rows(pg_map, where, WINDOW)[0]
    pg_map.rollback()
    assert {key: value for key, value in before.items() if key != 'log_ids'} == {
        key: value for key, value in after.items() if key != 'log_ids'}
    # Both queries order only by timestamp. Neither specifies which equal-time
    # events occupy the 50-ID boundary or their order within that tie.
    assert len(after['log_ids']) == len(set(after['log_ids'])) == 50
    assert set(after['log_ids']) <= set(range(1, 81))


def test_map_pg_zero_signed_zero_nan_and_ip_family_identity(pg_map, threats):
    with pg_map.cursor() as cursor:
        # Keep a legacy/custom floating-point schema covered as well as the
        # decimal(9,6) columns used by the normal integration fixtures.
        cursor.execute('ALTER TABLE logs ALTER COLUMN geo_lat TYPE double precision')
        cursor.execute('ALTER TABLE logs ALTER COLUMN geo_lon TYPE double precision')
        cursor.execute('''INSERT INTO logs VALUES
            (1,'2026-01-01',0.0,'-0.0',NULL,'Zero',90,'192.0.2.1/24',NULL,'outbound','block',''),
            (2,'2026-01-01 00:00:01','-0.0',0.0,NULL,'Zero',90,'192.0.2.1/32',NULL,'outbound','block',''),
            (3,'2026-01-01 00:00:02',0.0,0.0,NULL,'Zero',90,'::ffff:192.0.2.1',NULL,'outbound','block',''),
            (4,'2026-01-01','NaN',1,NULL,'NaN',90,NULL,'2001:db8::1/64','outbound','block',''),
            (5,'2026-01-01 00:00:01','NaN',1,NULL,'NaN',90,NULL,'2001:db8::1/128','outbound','block','')''')
    before, after = assert_equivalent(pg_map, threats, 'threats')
    assert sorted(row['unique_ips'] for row in after) == [1, 2]
    assert sorted(row['count'] for row in after) == [2, 3]


def test_map_pg_numeric_coordinate_precision_and_boundaries(pg_map, threats):
    with pg_map.cursor() as cursor:
        cursor.execute('''INSERT INTO logs VALUES
            (1,'2026-01-01',0.000001,179.999999,'ZZ','Numeric',90,NULL,NULL,'outbound','block',''),
            (2,'2026-01-01 00:00:01',0.000001,179.999999,'ZZ','Numeric',90,NULL,NULL,'outbound','block',''),
            (3,'2026-01-01',0.000002,179.999999,'ZZ','Numeric',90,NULL,NULL,'outbound','block',''),
            (4,'2026-01-01',-90.000000,-180.000000,'ZZ','Numeric',90,NULL,NULL,'outbound','block','')''')
    before, after = assert_equivalent(pg_map, threats, 'threats')
    assert len(after) == 3 and sorted(row['count'] for row in after) == [1, 1, 2]


def test_map_pg_snapshot_race_and_pool_transaction_defaults(pg_map, threats, monkeypatch):
    import psycopg2
    from psycopg2 import sql
    schema = 'map_snapshot_' + uuid4().hex
    writer = psycopg2.connect(os.environ['TEST_POSTGRES_DSN'])
    with pg_map.cursor() as cursor:
        cursor.execute('SHOW transaction_isolation')
        original_isolation = cursor.fetchone()[0]
        cursor.execute('SHOW transaction_read_only')
        original_readonly = cursor.fetchone()[0]
        cursor.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
        cursor.execute(sql.SQL('CREATE TABLE {}.logs (LIKE logs)').format(sql.Identifier(schema)))
        cursor.execute(sql.SQL('SET search_path TO {}, pg_temp').format(sql.Identifier(schema)))
        cursor.execute('''INSERT INTO logs VALUES
            (1,'2026-01-01',1,2,NULL,'Snapshot',90,NULL,NULL,'outbound','block',''),
            (2,'2026-01-01 00:00:01',1,2,NULL,'Snapshot',90,NULL,NULL,'outbound','block','')''')
    pg_map.commit()
    original = threats._map_id_query
    def insert_after_counts(groups, where):
        with writer.cursor() as cursor:
            cursor.execute(sql.SQL('INSERT INTO {}.logs VALUES '
                "(3,'2026-01-01 00:00:02',1,2,NULL,'Snapshot',90,NULL,NULL,'outbound','block','')")
                .format(sql.Identifier(schema)))
        writer.commit()
        return original(groups, where)
    monkeypatch.setattr(threats, '_map_id_query', insert_after_counts)
    try:
        for finish in ('commit', 'rollback'):
            if finish == 'rollback':
                with writer.cursor() as cursor:
                    cursor.execute(sql.SQL('DELETE FROM {}.logs WHERE id=3').format(sql.Identifier(schema)))
                writer.commit()
            with pg_map.cursor() as cursor:
                # Exactly the setup performed by deps.get_conn before a map.
                cursor.execute("SET statement_timeout='30s'")
            sampled = threats._load_geo_rows(pg_map, where_for('threats'), WINDOW)
            assert sampled[0]['count'] == 2
            assert sampled[0]['log_ids'] == [2, 1]
            with pg_map.cursor() as cursor:
                cursor.execute("SELECT count(*) FROM pg_cursors WHERE name LIKE 'map_ids_%'")
                assert cursor.fetchone()[0] == 0
            getattr(pg_map, finish)()
            with pg_map.cursor() as cursor:
                cursor.execute('SHOW transaction_isolation')
                assert cursor.fetchone()[0] == original_isolation
                cursor.execute('SHOW transaction_read_only')
                assert cursor.fetchone()[0] == original_readonly
            pg_map.rollback()
    finally:
        writer.close()
        pg_map.rollback()
        with pg_map.cursor() as cursor:
            cursor.execute('SET search_path TO pg_temp, public')
            cursor.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(schema)))
        pg_map.commit()


def test_map_pg_nondeterministic_city_collation_matches_on_server(pg_map, threats):
    from psycopg2 import sql
    import psycopg2
    schema = 'map_collation_' + uuid4().hex
    with pg_map.cursor() as cursor:
        cursor.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
    pg_map.commit()
    try:
        try:
            with pg_map.cursor() as cursor:
                cursor.execute(sql.SQL("CREATE COLLATION {}.casefold (provider=icu, locale='und-u-ks-level2', deterministic=false)")
                               .format(sql.Identifier(schema)))
            pg_map.commit()
        except psycopg2.errors.FeatureNotSupported:
            pg_map.rollback()
            pytest.skip('This disposable PostgreSQL does not provide ICU collations')
        with pg_map.cursor() as cursor:
            cursor.execute(sql.SQL('ALTER TABLE logs ALTER COLUMN geo_city TYPE text COLLATE {}.casefold')
                           .format(sql.Identifier(schema)))
            cursor.execute('''INSERT INTO logs VALUES
                (1,'2026-01-01',1,2,NULL,'City',90,NULL,NULL,'outbound','block',''),
                (2,'2026-01-01 00:00:01',1,2,NULL,'city',90,NULL,NULL,'outbound','block','')''')
        before, after = assert_equivalent(pg_map, threats, 'threats')
        assert len(after) == 1 and after[0]['count'] == 2 and after[0]['log_ids'] == [2, 1]
    finally:
        pg_map.rollback()
        with pg_map.cursor() as cursor:
            cursor.execute('ALTER TABLE logs ALTER COLUMN geo_city TYPE text COLLATE "default"')
            cursor.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(schema)))
        pg_map.commit()


def plan_nodes(node):
    yield node
    for child in node.get('Plans', []):
        yield from plan_nodes(child)


class MeasuredConnection:
    """Keep measurement outside production code; count named-cursor traffic."""

    def __init__(self, connection):
        self.connection = connection
        self.fetched_ids = 0
        self.fetch_sizes = []
        self.named_queries = 0

    def cursor(self, **kwargs):
        cursor = self.connection.cursor(**kwargs)
        if 'name' not in kwargs:
            return cursor
        self.named_queries += 1
        owner = self

        class MeasuredCursor:
            def __enter__(self):
                cursor.__enter__()
                return self

            def __exit__(self, *args):
                return cursor.__exit__(*args)

            def execute(self, *args):
                return cursor.execute(*args)

            def fetchmany(self, size):
                values = cursor.fetchmany(size)
                owner.fetched_ids += len(values)
                owner.fetch_sizes.append(len(values))
                return values

        return MeasuredCursor()


@pytest.mark.skipif(os.environ.get('RUN_MAP_BENCHMARK') != '1',
                    reason='opt-in million-event PostgreSQL map benchmarks')
@pytest.mark.parametrize('distribution', ['repeated', 'unique', 'rare'])
def test_map_pg_high_volume_benchmark_final_loader(pg_map, threats, distribution):
    """Measure the complete loader, not just its first SQL statement.

    Fixtures span a 24-hour filter with three IP/group distributions. Repeated
    and unique hosts exercise distinct-sort cost. Rare groups require every
    selected ID, preventing an early-stop-only performance claim. Local warm
    timings describe these fixtures; they do not predict production latency.
    """
    rare = distribution == 'rare'
    event_count = 1024500 if rare else 1359200
    group_count = 50500 if rare else 1600
    with pg_map.cursor() as cursor:
        if rare:
            cursor.execute('''INSERT INTO logs
                SELECT g*100+i,
                       '2026-01-01'::timestamptz+i*interval '20 minutes',
                       g%160-80, g%320-160, 'ZZ', 'Synthetic '||g,
                       90, '198.51.100.1'::inet, NULL,
                       'outbound','block','Synthetic event'
                FROM generate_series(0,50499)g
                CROSS JOIN LATERAL generate_series(1,CASE WHEN g<500 THEN 49 ELSE 20 END)i''')
        else:
            address = ("'2001:db8:1::1'::inet+(g*10000+i)" if distribution == 'unique'
                       else "'198.51.100.1'::inet+(i%32)")
            cursor.execute(f'''INSERT INTO logs
                SELECT g*10000+i,
                       '2026-01-01'::timestamptz+(i::double precision/(50+g))*interval '23 hours',
                       g%160-80, g%320-160,
                       CASE WHEN g%11=0 THEN NULL ELSE 'ZZ' END,
                       CASE WHEN g%13=0 THEN NULL ELSE 'Synthetic '||g END,
                       CASE WHEN i%19=0 THEN NULL ELSE 80+i%21 END,
                       {address}, NULL, 'outbound','block','Synthetic event'
                FROM generate_series(0,1599)g
                CROSS JOIN LATERAL generate_series(1,50+g)i''')
        cursor.execute('CREATE INDEX map_benchmark_timestamp ON logs(timestamp DESC)')
        cursor.execute('ANALYZE logs')
    pg_map.commit()
    where = where_for('blocked_outbound')
    reference, actual = assert_equivalent(pg_map, threats, 'blocked_outbound')
    elapsed = {'before': [], 'after': []}
    fetched = []
    # Alternate ordering to reduce the advantage of immediately warmed pages.
    for repetition in range(3):
        order = ('before', 'after') if repetition % 2 == 0 else ('after', 'before')
        for name in order:
            measured = MeasuredConnection(pg_map)
            started = time.perf_counter()
            if name == 'before':
                result = rows(pg_map, legacy_query(where), WINDOW)
            else:
                result = threats._load_geo_rows(measured, where, WINDOW)
            elapsed[name].append((time.perf_counter() - started) * 1000)
            pg_map.rollback()
            assert by_group(result) == by_group(reference)
            if name == 'after':
                assert measured.named_queries == 1
                assert max(measured.fetch_sizes) <= threats._MAP_FETCH_ROWS
                assert all(len(group['log_ids']) <= 50 for group in result)
                fetched.append(measured.fetched_ids)
    sample_sql, sample_params = threats._map_id_query(actual, where)
    with pg_map.cursor() as cursor:
        # Inspect the final selected-group query, including its actual bindings.
        # EXPLAIN alone avoids timing a different, fully drained ID workload.
        cursor.execute('EXPLAIN (VERBOSE, FORMAT JSON) ' + sample_sql, sample_params + WINDOW)
        id_plan = cursor.fetchone()[0][0]['Plan']
    pg_map.rollback()
    nodes = list(plan_nodes(id_plan))
    assert sum(node.get('Relation Name') == 'logs' for node in nodes) == 1
    assert any(node['Node Type'] == 'Hash Join' for node in nodes)
    # PostgreSQL's Seq Scan VERBOSE output lists the underlying row descriptor,
    # even when no payload is copied into the join/sort or client result.
    assert 'raw_log' not in str(id_plan.get('Output', []))
    assert all('raw_log' not in str(node.get('Output', []))
               for node in nodes if node['Node Type'] in ('Sort', 'Incremental Sort', 'Materialize'))
    report = {'distribution': distribution, 'events': event_count,
              'geo_groups': group_count, 'selected_groups': len(actual),
              'work_mem': '8MB', 'parallel_workers': 0,
              'execution_ms': elapsed,
              'median_ms': {key: statistics.median(values) for key, values in elapsed.items()},
              'fetched_id_rows': fetched,
              'retained_ids': sum(len(group['log_ids']) for group in actual),
              'id_plan_width': id_plan['Plan Width']}
    report['speedup'] = report['median_ms']['before'] / report['median_ms']['after']
    print('MAP_BENCHMARK ' + json.dumps(report, sort_keys=True))
    if rare:
        assert fetched == [24500, 24500, 24500]
    else:
        assert max(fetched) < event_count // 10
