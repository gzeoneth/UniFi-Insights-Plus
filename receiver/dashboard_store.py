"""Exact, narrow dashboard facts maintained in the event transaction.

The raw event table remains authoritative. Statement triggers keep this logged
projection current, including enrichment and retention performed by other
writers. Bounded background copying publishes only fully covered time bands;
readers must use the raw table until their requested cutoff is covered.
"""

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
import logging
import os

import psycopg2
from psycopg2 import errors, extensions

from security_predicates import PARSED_IPS_SQL, UNPARSED_CEF_THREAT_SQL


logger = logging.getLogger(__name__)
SCHEMA_VERSION = 1
BASE_COLUMNS = (
    'id', 'timestamp', 'log_type', 'direction', 'rule_action', 'threat_score',
    'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'interface_in',
    'interface_out', 'geo_country', 'geo_city', 'asn_name', 'service_name',
    'dns_query', 'remote_ip', 'rdns', 'threat_categories', 'event_source',
    'source', 'ips_risk', 'ips_signature_id', 'ips_severity', 'hostname',
    'rule_name',
)
SECURITY_COLUMNS = ('security_ips', 'security_cef')
EVENT_COLUMNS = BASE_COLUMNS + SECURITY_COLUMNS
TRIGGER_NAMES = (
    'dashboard_store_insert', 'dashboard_store_update',
    'dashboard_store_delete', 'dashboard_store_truncate',
)
MIGRATION_LOCK = (20261110, 11)
WORKER_LOCK = (20261110, 12)
DEFAULT_BATCH_SIZE = 1000
DEFAULT_PAUSE_SECONDS = 0.25


def enabled(environ=None):
    """Disable reads and background work for an explicit false setting."""
    values = os.environ if environ is None else environ
    return str(values.get('DASHBOARD_ANALYTICS_ENABLED', 'false')).strip().lower() in {
        '1', 'true', 'yes', 'on',
    }


def backfill_enabled(environ=None):
    """Pause historical copying without disabling capture or prepared reads."""
    values = os.environ if environ is None else environ
    return str(values.get('DASHBOARD_ANALYTICS_BACKFILL_ENABLED', 'true')).strip().lower() in {
        '1', 'true', 'yes', 'on',
    }


def _quote(name):
    return '"' + name.replace('"', '""') + '"'


def _table(schema, name):
    return _quote(schema) + '.' + _quote(name)


def _columns(alias=None, columns=EVENT_COLUMNS):
    prefix = alias + '.' if alias else ''
    return ', '.join(prefix + _quote(column) for column in columns)


def _security_sql(predicate, alias, *, ddl=False):
    # Only these three application-owned identifiers appear in the shared
    # security predicates. Values and the predicate itself are never supplied
    # by a request. Preserve doubled percents for parameterized copy statements.
    import re
    result = re.sub(r'\b(event_source|ips_signature_id|raw_log)\b',
                    lambda match: alias + '.' + _quote(match.group()), predicate)
    return result.replace('%%', '%') if ddl else result


def projection_select(alias='l', *, ddl=False):
    """Return the fixed column projection, including historical CEF protection."""
    return ', '.join((
        _columns(alias, BASE_COLUMNS),
        'COALESCE(' + _security_sql(PARSED_IPS_SQL, alias, ddl=ddl)
        + ', FALSE) AS security_ips',
        'COALESCE(' + _security_sql(UNPARSED_CEF_THREAT_SQL, alias, ddl=ddl)
        + ', FALSE) AS security_cef',
    ))


def _row_dict(cur, row):
    if row is None:
        return None
    if isinstance(row, Mapping):
        return dict(row)
    return dict(zip((column[0] for column in cur.description), row))


def _schema(cur):
    cur.execute("SELECT n.nspname FROM pg_class c JOIN pg_namespace n "
                "ON n.oid=c.relnamespace WHERE c.oid='logs'::regclass")
    row = cur.fetchone()
    return row['nspname'] if isinstance(row, Mapping) else row[0]


def _exists(cur, qualified_name):
    cur.execute('SELECT to_regclass(%s)', [qualified_name])
    row = cur.fetchone()
    return next(iter(row.values())) is not None if isinstance(row, Mapping) else row[0] is not None


def snapshot_state(cur):
    """Read coverage in the caller's transaction; no result or auth caching.

    Readers should establish their read-only repeatable snapshot before calling
    this helper. A missing store returns None; SQL errors remain visible so the
    caller can roll back its savepoint and use the raw event table.
    """
    if not _exists(cur, 'dashboard_store_state'):
        return None
    cur.execute("""SELECT s.*,
        (SELECT count(*) = 4 FROM pg_trigger t
         WHERE t.tgrelid='logs'::regclass AND NOT t.tgisinternal
           AND t.tgname=ANY(%s) AND t.tgenabled IN ('O','A')) AS triggers_enabled
        FROM dashboard_store_state s WHERE s.id=1""", [list(TRIGGER_NAMES)])
    state = _row_dict(cur, cur.fetchone())
    if state is None:
        return None
    cur.execute("""SELECT EXISTS(
        SELECT 1 FROM pg_class c WHERE c.oid=to_regclass('dashboard_events')
          AND c.relkind='r' AND c.relpersistence='p')""")
    row = cur.fetchone()
    logged = next(iter(row.values())) if isinstance(row, Mapping) else row[0]
    indexes = _index_status(cur, 'dashboard_events')
    state['healthy'] = bool(state['triggers_enabled'] and logged
                            and _columns_valid(cur, 'logs', 'dashboard_events')
                            and indexes.get('dashboard_events_pkey', {}).get('exact')
                            and indexes.get('idx_dashboard_events_time', {}).get('exact')
                            and state['schema_version'] == SCHEMA_VERSION)
    return state


def _reset_state(cur, state_table, status):
    cur.execute(f"""UPDATE {state_table} SET epoch=epoch+1,
        initial_max_id=NULL, oldest_timestamp=NULL, coverage_from=NULL,
        band_lower=NULL, band_upper=NULL, cursor_timestamp=NULL, cursor_id=NULL,
        complete=FALSE, rows_scanned=0, status=%s, last_error=NULL,
        updated_at=clock_timestamp() WHERE id=1""", [status])


def _trigger_functions(schema):
    facts = _table(schema, 'dashboard_events')
    state = _table(schema, 'dashboard_store_state')
    target_columns = _columns()
    values = projection_select('n', ddl=True)
    assignments = ', '.join(_quote(c) + '=EXCLUDED.' + _quote(c)
                            for c in EVENT_COLUMNS if c != 'id')
    different = ('ROW(' + _columns('d', EVENT_COLUMNS[1:]) + ') IS DISTINCT FROM ROW('
                 + _columns('EXCLUDED', EVENT_COLUMNS[1:]) + ')')
    upsert = (f'INSERT INTO {facts} AS d ({target_columns}) SELECT {values} '
              'FROM dashboard_new n {condition} ORDER BY n.id '
              f'ON CONFLICT (id) DO UPDATE SET {assignments} WHERE {different};')
    old_values = projection_select('o', ddl=True)
    # Comparing complete fixed projections also catches raw-log changes that
    # alter historical security classification, without copying raw messages.
    update_condition = (
        'LEFT JOIN dashboard_old o ON o.id=n.id '
        'WHERE o.id IS NULL OR ROW(' + values.replace(' AS security_ips', '').replace(' AS security_cef', '')
        + ') IS DISTINCT FROM ROW('
        + old_values.replace(' AS security_ips', '').replace(' AS security_cef', '') + ')'
    )
    bodies = {
        'insert': upsert.format(condition=''),
        'update': (f'DELETE FROM {facts} d USING dashboard_old o WHERE d.id=o.id '
                   'AND NOT EXISTS (SELECT 1 FROM dashboard_new n WHERE n.id=o.id); '
                   + upsert.format(condition=update_condition)),
        'delete': f'DELETE FROM {facts} d USING dashboard_old o WHERE d.id=o.id;',
        'truncate': (f'TRUNCATE {facts}; UPDATE {state} SET epoch=epoch+1, '
                     'initial_max_id=NULL, oldest_timestamp=NULL, coverage_from=NULL, '
                     'band_lower=NULL, band_upper=NULL, cursor_timestamp=NULL, cursor_id=NULL, '
                     "complete=FALSE, rows_scanned=0, status='pending', last_error=NULL, "
                     'updated_at=clock_timestamp() WHERE id=1;'),
    }
    for operation, body in bodies.items():
        yield (f'CREATE OR REPLACE FUNCTION {_table(schema, "dashboard_store_" + operation)}() '
               f'RETURNS trigger LANGUAGE plpgsql AS $dashboard_store$ BEGIN {body} '
               'RETURN NULL; END $dashboard_store$')


class _IndexRepairNeeded(Exception):
    def __init__(self, primary=False):
        self.primary = primary


def _index_status(cur, facts):
    cur.execute("""SELECT c.relname,i.indisvalid,i.indisready,i.indisprimary,
        i.indisunique,i.indnkeyatts,i.indnatts,i.indpred IS NULL AS unpartial,
        i.indexprs IS NULL AS unexpressed,m.amname,i.indoption::smallint[],
        ARRAY(SELECT a.attname FROM unnest(i.indkey::smallint[]) WITH ORDINALITY k(attnum,n)
              LEFT JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum
              ORDER BY k.n) AS keys
        FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
        JOIN pg_am m ON m.oid=c.relam
        WHERE i.indrelid=to_regclass(%s) AND c.relname=ANY(%s)""",
                [facts, ['dashboard_events_pkey', 'idx_dashboard_events_time']])
    result = {}
    for raw in cur.fetchall():
        row = tuple(raw.values()) if isinstance(raw, Mapping) else raw
        name, valid, ready, primary, unique, nkeys, natts, plain, expressions, method, options, keys = row
        expected = ('id',) if name == 'dashboard_events_pkey' else ('timestamp', 'id')
        shape = (tuple(keys) == expected and nkeys == len(expected)
                 and natts == len(expected) and plain and expressions and method == 'btree')
        if name == 'dashboard_events_pkey':
            shape = shape and primary and unique
        else:
            shape = shape and not primary and not unique and tuple(options) == (3, 3)
        result[name] = {'valid': valid and ready, 'primary': primary,
                        'exact': bool(valid and ready and shape)}
    return result


def _columns_valid(cur, logs, facts):
    cur.execute("""SELECT a.attrelid=to_regclass(%s) AS raw,a.attname,
        a.atttypid,a.atttypmod,a.attcollation,a.attnotnull
        FROM pg_attribute a WHERE a.attrelid IN (to_regclass(%s),to_regclass(%s))
          AND a.attnum>0 AND NOT a.attisdropped""", [logs, logs, facts])
    source, target = {}, {}
    for raw in cur.fetchall():
        row = tuple(raw.values()) if isinstance(raw, Mapping) else raw
        is_raw, name, type_oid, modifier, collation, not_null = row
        (source if is_raw else target)[name] = (type_oid, modifier, collation, not_null)
    if set(target) != set(EVENT_COLUMNS):
        return False
    if any(name not in source or target[name][:3] != source[name][:3] for name in BASE_COLUMNS):
        return False
    return (target['id'][3] and target['timestamp'][3]
            and all(target[name][0] == 16 and target[name][3] for name in SECURITY_COLUMNS))


def install_schema(connection):
    """Install small schema/trigger DDL in a caller-owned transaction.

    No historical data is scanned or copied here. The raw relation is locked
    before any state mutation, avoiding a lock-order inversion with TRUNCATE.
    Failure must roll back this entire transaction; callers may then use raw
    queries and retry installation later.
    """
    if connection.autocommit:
        raise ValueError('dashboard schema installation requires a transaction')
    with connection.cursor() as cur:
        cur.execute("SET LOCAL lock_timeout='500ms'")
        cur.execute("SET LOCAL statement_timeout='10s'")
        cur.execute('SELECT pg_try_advisory_xact_lock(%s,%s)', MIGRATION_LOCK)
        if not cur.fetchone()[0]:
            raise RuntimeError('dashboard schema maintenance already active')
        schema = _schema(cur)
        logs, facts, state = (_table(schema, name) for name in
                              ('logs', 'dashboard_events', 'dashboard_store_state'))
        cur.execute(f'LOCK TABLE {logs} IN SHARE ROW EXCLUSIVE MODE')
        state_existed = _exists(cur, state)
        facts_existed = _exists(cur, facts)
        if facts_existed and not state_existed:
            # Without our version marker this might be an unrelated external
            # database table. Never clear or claim somebody else's data.
            raise RuntimeError('dashboard projection name exists without its state marker')
        cur.execute(f'CREATE TABLE IF NOT EXISTS {facts} AS '
                    f'SELECT {projection_select("l", ddl=True)} FROM {logs} l WITH NO DATA')
        indexes = _index_status(cur, facts)
        if facts_existed:
            cur.execute(f'SELECT 1 FROM {facts} LIMIT 1')
            populated = cur.fetchone() is not None
        else:
            populated = False
            cur.execute(f'ALTER TABLE {facts} ALTER COLUMN id SET NOT NULL, '
                        'ALTER COLUMN timestamp SET NOT NULL, '
                        'ALTER COLUMN security_ips SET NOT NULL, ALTER COLUMN security_cef SET NOT NULL')
        if not _columns_valid(cur, logs, facts):
            raise _IndexRepairNeeded(primary=True)
        primary = indexes.get('dashboard_events_pkey')
        if not primary or not primary['exact']:
            if populated:
                raise _IndexRepairNeeded(primary=True)
            cur.execute('SELECT conname FROM pg_constraint WHERE conrelid=%s::regclass AND contype=%s',
                        [facts, 'p'])
            constraint = cur.fetchone()
            if constraint:
                cur.execute(f'ALTER TABLE {facts} DROP CONSTRAINT {_quote(constraint[0])}')
            elif primary:
                cur.execute(f'DROP INDEX {_table(schema, "dashboard_events_pkey")}')
            cur.execute(f'ALTER TABLE {facts} ADD CONSTRAINT dashboard_events_pkey PRIMARY KEY (id)')
        chronological = indexes.get('idx_dashboard_events_time')
        if not chronological or not chronological['exact']:
            if populated:
                raise _IndexRepairNeeded()
            if chronological:
                cur.execute(f'DROP INDEX {_table(schema, "idx_dashboard_events_time")}')
            cur.execute(f'CREATE INDEX idx_dashboard_events_time ON {facts} (timestamp DESC,id DESC)')
        cur.execute(f'ALTER TABLE {facts} SET (autovacuum_analyze_scale_factor=0.01, '
                    'autovacuum_analyze_threshold=1000)')
        cur.execute(f"""CREATE TABLE IF NOT EXISTS {state} (
            id SMALLINT PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL,
            epoch BIGINT NOT NULL DEFAULT 1, initial_max_id BIGINT,
            oldest_timestamp TIMESTAMPTZ, coverage_from TIMESTAMPTZ,
            band_lower TIMESTAMPTZ, band_upper TIMESTAMPTZ,
            cursor_timestamp TIMESTAMPTZ, cursor_id BIGINT,
            complete BOOLEAN NOT NULL DEFAULT FALSE,
            rows_scanned BIGINT NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending', last_error TEXT,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
        )""")
        cur.execute(f'INSERT INTO {state}(id,schema_version) VALUES(1,%s) ON CONFLICT(id) DO NOTHING', [SCHEMA_VERSION])
        cur.execute(f'SELECT schema_version FROM {state} WHERE id=1')
        if cur.fetchone()[0] != SCHEMA_VERSION:
            raise RuntimeError('unsupported dashboard store schema version')
        cur.execute("SELECT count(*) FROM pg_trigger WHERE tgrelid=%s::regclass "
                    "AND NOT tgisinternal AND tgname=ANY(%s) AND tgenabled IN ('O','A')",
                    [logs, list(TRIGGER_NAMES)])
        intact = cur.fetchone()[0] == len(TRIGGER_NAMES)
        if state_existed and (not intact or not facts_existed):
            # A disabled interval can contain missed updates/deletions. Never
            # reuse its previous coverage or stale ON-CONFLICT rows.
            cur.execute(f'TRUNCATE {facts}')
            _reset_state(cur, state, 'pending')
        for statement in _trigger_functions(schema):
            cur.execute(statement)
        transitions = {
            'insert': 'NEW TABLE AS dashboard_new',
            'update': 'OLD TABLE AS dashboard_old NEW TABLE AS dashboard_new',
            'delete': 'OLD TABLE AS dashboard_old',
            'truncate': '',
        }
        for operation, transition in transitions.items():
            name = 'dashboard_store_' + operation
            cur.execute(f'DROP TRIGGER IF EXISTS {_quote(name)} ON {logs}')
            reference = ' REFERENCING ' + transition if transition else ''
            cur.execute(f'CREATE TRIGGER {_quote(name)} AFTER {operation.upper()} ON {logs}'
                        f'{reference} FOR EACH STATEMENT EXECUTE FUNCTION {_table(schema, name)}()')


def disable_schema(connection):
    """Stop known projection write work while retaining its tables and data."""
    with connection.cursor() as cur:
        cur.execute("SET LOCAL lock_timeout='500ms'")
        cur.execute("SET LOCAL statement_timeout='5s'")
        schema = _schema(cur)
        logs, state = (_table(schema, name) for name in ('logs', 'dashboard_store_state'))
        cur.execute(f'LOCK TABLE {logs} IN SHARE ROW EXCLUSIVE MODE')
        cur.execute('SELECT tgname FROM pg_trigger WHERE tgrelid=%s::regclass '
                    "AND tgname=ANY(%s) AND tgenabled<>'D'", [logs, list(TRIGGER_NAMES)])
        names = [row[0] for row in cur.fetchall()]
        for name in names:
            cur.execute(f'ALTER TABLE {logs} DISABLE TRIGGER {_quote(name)}')
        if _exists(cur, state):
            cur.execute(f'SELECT status FROM {state} WHERE id=1')
            row = cur.fetchone()
            if names or (row and row[0] != 'disabled'):
                _reset_state(cur, state, 'disabled')


def _stopping(stop_event):
    return stop_event is not None and stop_event.is_set()


def _connect(conn_params):
    params = dict(conn_params)
    params.setdefault('connect_timeout', 5)
    return psycopg2.connect(**params)


def _close_registered(connection, callback):
    if connection is not None:
        connection.close()
    if callback is not None:
        callback(None)


def _repair_time_index(conn_params, *, connection_callback=None, stop_event=None):
    """Build only the owned chronological index outside the raw writer lock."""
    if _stopping(stop_event):
        return False
    connection = _connect(conn_params)
    if connection_callback is not None:
        connection_callback(connection)
    connection.autocommit = True
    try:
        if _stopping(stop_event):
            return False
        with connection.cursor() as cur:
            cur.execute('SELECT pg_try_advisory_lock(%s,%s)', (20261110, 13))
            if not cur.fetchone()[0]:
                return False
            cur.execute("SET lock_timeout='500ms'")
            cur.execute("SET statement_timeout='30min'")
            schema = _schema(cur)
            facts = _table(schema, 'dashboard_events')
            status = _index_status(cur, facts).get('idx_dashboard_events_time')
            index = _table(schema, 'idx_dashboard_events_time')
            if status and status['exact']:
                return True
            if _stopping(stop_event):
                return False
            if status:
                cur.execute(f'DROP INDEX CONCURRENTLY {index}')
            elif _exists(cur, index):
                raise RuntimeError('dashboard index name belongs to another relation')
            if _stopping(stop_event):
                return False
            cur.execute(f'CREATE INDEX CONCURRENTLY idx_dashboard_events_time '
                        f'ON {facts} (timestamp DESC,id DESC)')
            return True
    finally:
        _close_registered(connection, connection_callback)


def ensure_dashboard_store(conn_params, *, connection_callback=None, stop_event=None):
    """Return whether the requested install or disable completed successfully.

    This is maintenance success, not feature availability: a completed explicit
    disable returns True. Readers independently check enabled() and coverage.
    """
    for attempt in range(2):
        if _stopping(stop_event):
            return False
        connection = None
        try:
            connection = _connect(conn_params)
            if connection_callback is not None:
                connection_callback(connection)
            if _stopping(stop_event):
                return False
            with connection:
                if enabled():
                    install_schema(connection)
                else:
                    disable_schema(connection)
            return True
        except _IndexRepairNeeded as exc:
            connection.rollback()
            if exc.primary:
                # A missing PK on a populated versioned projection is manual
                # damage, not an interrupted initial install. Stop projection
                # writes before falling back rather than scanning under a raw
                # writer lock or risking ON-CONFLICT errors on ingestion.
                try:
                    with connection:
                        disable_schema(connection)
                except Exception:
                    connection.rollback()
                    logger.warning('Could not disable damaged dashboard projection triggers')
                logger.warning('Dashboard analytics schema or primary index requires repair; using raw queries')
                return False
            if attempt:
                return False
            _close_registered(connection, connection_callback)
            connection = None
            try:
                if not _repair_time_index(conn_params, connection_callback=connection_callback,
                                          stop_event=stop_event):
                    return False
            except Exception as repair_error:
                if not _stopping(stop_event):
                    logger.warning('Dashboard analytics index repair unavailable (%s); using raw queries',
                                   type(repair_error).__name__)
                return False
        except Exception as exc:
            if not _stopping(stop_event):
                logger.warning('Dashboard analytics setup unavailable (%s); raw queries remain available',
                               type(exc).__name__)
            return False
        finally:
            if connection is not None:
                _close_registered(connection, connection_callback)
    return False


class _StateChanged(Exception):
    pass


def _advance(cur, state, assignments, values):
    cur.execute(f"""UPDATE dashboard_store_state SET {assignments},
        updated_at=clock_timestamp() WHERE id=1 AND schema_version=%s AND epoch=%s
          AND initial_max_id IS NOT DISTINCT FROM %s
          AND band_lower IS NOT DISTINCT FROM %s AND band_upper IS NOT DISTINCT FROM %s
          AND cursor_timestamp IS NOT DISTINCT FROM %s AND cursor_id IS NOT DISTINCT FROM %s
          AND complete=FALSE""", [*values, SCHEMA_VERSION, state['epoch'],
          state['initial_max_id'], state['band_lower'], state['band_upper'],
          state['cursor_timestamp'], state['cursor_id']])
    if cur.rowcount != 1:
        raise _StateChanged()


def _nonfinite_history(cur, state):
    # psycopg maps PostgreSQL infinity to datetime.max/min, which cannot be
    # round-tripped as an exact keyset cursor. Keep this rare direct-SQL case
    # on raw queries instead of publishing incomplete coverage or looping.
    if state['status'] != 'unsupported' or state['last_error'] != 'nonfinite_timestamp':
        _advance(cur, state, "coverage_from=NULL, complete=FALSE, status='unsupported', "
                 "last_error='nonfinite_timestamp'", [])
    return {'status': 'unsupported', 'rows': 0, 'reason': 'nonfinite_timestamp'}


def backfill_step(connection, batch_size=DEFAULT_BATCH_SIZE, now=None):
    """Commit at most one bounded copy batch or coverage transition.

    SELECT FOR SHARE keeps every selected raw row locked through insertion,
    including against non-key updates. Deletes and enrichments that win the
    lock race are seen instead. The final epoch/cursor comparison prevents an
    earlier state read from publishing coverage across a concurrent TRUNCATE.
    No state row lock is held while waiting for raw rows.
    """
    if type(batch_size) is not int or not 1 <= batch_size <= 1000:
        raise ValueError('dashboard copy batch must be between 1 and 1000')
    if connection.info.transaction_status != extensions.TRANSACTION_STATUS_IDLE:
        raise ValueError('dashboard copying requires an idle dedicated connection')
    anchor = now or datetime.now(timezone.utc)
    if anchor.tzinfo is None:
        raise ValueError('dashboard copy anchor must include timezone')
    anchor = anchor.astimezone(timezone.utc)
    try:
        with connection:
            with connection.cursor() as cur:
                # ORDER BY followed by a READ COMMITTED row-lock wait may
                # return a concurrently moved timestamp out of order. A stable
                # snapshot instead raises40001, so no cursor can jump past an
                # untouched row. The whole small batch is then retried.
                cur.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
                cur.execute("SET LOCAL lock_timeout='500ms'")
                cur.execute("SET LOCAL statement_timeout='10s'")
                state = snapshot_state(cur)
                if not state or not state['healthy']:
                    return {'status': 'unavailable', 'rows': 0}
                if state['status'] == 'disabled':
                    return {'status': 'disabled', 'rows': 0}
                if state['complete']:
                    return {'status': 'ready', 'rows': 0, 'complete': True}
                if state['initial_max_id'] is None:
                    # Both lookups use existing raw indexes, never COUNT(*).
                    cur.execute('SELECT id FROM logs ORDER BY id DESC LIMIT 1')
                    row = cur.fetchone()
                    horizon = row[0] if row else 0
                    cur.execute('SELECT timestamp,isfinite(timestamp) FROM logs ORDER BY timestamp ASC LIMIT 1')
                    row = cur.fetchone()
                    oldest = row[0] if row else None
                    if row and not row[1]:
                        return _nonfinite_history(cur, state)
                    cur.execute('SELECT isfinite(timestamp) FROM logs ORDER BY timestamp DESC LIMIT 1')
                    row = cur.fetchone()
                    if row and not row[0]:
                        return _nonfinite_history(cur, state)
                    lower = anchor.replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
                    _advance(cur, state, 'initial_max_id=%s, oldest_timestamp=%s, '
                             "band_lower=%s, band_upper=NULL, status='backfill', last_error=NULL",
                             [horizon, oldest, lower])
                    return {'status': 'initialized', 'rows': 0, 'initial_max_id': horizon}
                where = ['l.id<=%s', 'l.timestamp>=%s']
                params = [state['initial_max_id'], state['band_lower']]
                if state['band_upper'] is not None:
                    where.append('l.timestamp<%s')
                    params.append(state['band_upper'])
                if state['cursor_timestamp'] is not None:
                    where.append('(l.timestamp,l.id)>(%s,%s)')
                    params.extend((state['cursor_timestamp'], state['cursor_id']))
                params.append(batch_size)
                raw_columns = _columns('l', BASE_COLUMNS + ('raw_log',))
                cur.execute(f"""WITH selected AS MATERIALIZED (
                    SELECT {raw_columns} FROM logs l WHERE {' AND '.join(where)}
                    ORDER BY l.timestamp,l.id LIMIT %s FOR SHARE OF l
                ), copied AS (
                    INSERT INTO dashboard_events ({_columns()})
                    SELECT {projection_select('n')} FROM selected n ORDER BY n.id
                    ON CONFLICT(id) DO NOTHING RETURNING id
                ), last_row AS (
                    SELECT timestamp,id FROM selected ORDER BY timestamp DESC,id DESC LIMIT 1
                ) SELECT (SELECT count(*) FROM selected) AS scanned,
                    (SELECT count(*) FROM copied) AS inserted,
                    r.timestamp,r.id,isfinite(r.timestamp)
                    FROM (SELECT 1) unused LEFT JOIN last_row r ON TRUE""", params)
                scanned, inserted, stamp, row_id, finite = cur.fetchone()
                if finite is False:
                    return _nonfinite_history(cur, state)
                if scanned == batch_size:
                    _advance(cur, state, "cursor_timestamp=%s, cursor_id=%s, rows_scanned=rows_scanned+%s, "
                             "status='backfill', last_error=NULL", [stamp, row_id, scanned])
                    return {'status': 'backfill', 'rows': inserted, 'scanned': scanned}
                complete = (state['oldest_timestamp'] is None
                            or state['band_lower'] <= state['oldest_timestamp'])
                next_lower = None if complete else state['band_lower'] - timedelta(hours=1)
                next_upper = None if complete else state['band_lower']
                _advance(cur, state, 'coverage_from=%s, complete=%s, band_lower=%s, band_upper=%s, '
                         'cursor_timestamp=NULL, cursor_id=NULL, rows_scanned=rows_scanned+%s, '
                         'status=%s, last_error=NULL',
                         [state['band_lower'], complete, next_lower, next_upper, scanned,
                          'ready' if complete else 'backfill'])
                return {'status': 'ready' if complete else 'band_complete', 'rows': inserted,
                        'scanned': scanned, 'coverage_from': state['band_lower'], 'complete': complete}
    except (_StateChanged, errors.SerializationFailure):
        return {'status': 'retry', 'rows': 0}


def _pause_requested(callback):
    if callback is None:
        return False
    try:
        return bool(callback())
    except Exception:
        # An unavailable collection-health snapshot is not permission to add
        # historical I/O. A later callback can recover without a restart.
        return True


def run_dashboard_store_worker(conn_params, stop_event, connection_callback=None,
                               pause_callback=None):
    """Resume bounded time-band copying after intake is available."""
    connection = None
    pause_reason = None

    def close_connection():
        nonlocal connection
        if connection is not None:
            connection.close()
            connection = None
        if connection_callback is not None:
            connection_callback(None)

    try:
        while not stop_event.is_set():
            if not enabled():
                close_connection()
                if ensure_dashboard_store(conn_params, connection_callback=connection_callback,
                                           stop_event=stop_event):
                    return
                stop_event.wait(2)
                continue
            if _pause_requested(pause_callback):
                if pause_reason != 'collection':
                    logger.info('Dashboard analytics copy paused while collection or index maintenance is busy')
                pause_reason = 'collection'
                stop_event.wait(2)
                continue
            try:
                if connection is None:
                    if not ensure_dashboard_store(conn_params, connection_callback=connection_callback,
                                                  stop_event=stop_event):
                        stop_event.wait(30)
                        continue
                    if stop_event.is_set():
                        break
                    connection = _connect(conn_params)
                    if connection_callback is not None:
                        connection_callback(connection)
                    with connection:
                        with connection.cursor() as cur:
                            cur.execute('SELECT pg_try_advisory_lock(%s,%s)', WORKER_LOCK)
                            owner = cur.fetchone()[0]
                    if not owner:
                        close_connection()
                        stop_event.wait(5)
                        continue
                if not backfill_enabled():
                    # Keep capture installed and retain the idle advisory owner.
                    # Existing coverage and cursors remain valid while new
                    # writes continue through the transactional triggers.
                    if pause_reason != 'configuration':
                        logger.info('Dashboard analytics historical copy paused by configuration; capture remains active')
                    pause_reason = 'configuration'
                    stop_event.wait(2)
                    continue
                if pause_reason:
                    logger.info('Dashboard analytics copy resumed after %s pause', pause_reason)
                    pause_reason = None
                result = backfill_step(connection)
                if result['status'] in ('ready', 'unsupported'):
                    # Keep a cheap idle owner so a later TRUNCATE or explicit
                    # projection reset can resume without an application boot.
                    stop_event.wait(30)
                    continue
                if result['status'] in ('disabled', 'unavailable'):
                    close_connection()
                    stop_event.wait(5)
                    continue
                if result['status'] == 'band_complete':
                    logger.info('Dashboard analytics coverage now starts at %s', result['coverage_from'])
                stop_event.wait(DEFAULT_PAUSE_SECONDS)
            except Exception as exc:
                if connection is not None:
                    try:
                        connection.rollback()
                    except Exception:
                        close_connection()
                if stop_event.is_set():
                    break
                logger.warning('Dashboard analytics copy paused (%s); raw fallback remains available',
                               type(exc).__name__)
                if connection is not None:
                    try:
                        with connection:
                            with connection.cursor() as cur:
                                cur.execute("SET LOCAL lock_timeout='500ms'")
                                cur.execute("SET LOCAL statement_timeout='2s'")
                                cur.execute("UPDATE dashboard_store_state SET last_error=%s, "
                                            "updated_at=clock_timestamp() WHERE id=1 AND schema_version=%s",
                                            [type(exc).__name__, SCHEMA_VERSION])
                    except Exception:
                        try:
                            connection.rollback()
                        except Exception:
                            close_connection()
                stop_event.wait(2)
    finally:
        close_connection()
