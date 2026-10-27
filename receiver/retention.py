"""Optional event retention, transactional daily summaries, and private archives.

No archive or summary is produced without an explicitly enabled policy. The
upstream general/DNS periods remain the fallback for every event class.
"""

from datetime import date, datetime, timedelta, timezone
import gzip
import hashlib
import json
import logging
import os
from pathlib import Path
import shutil
import stat
import tempfile

from psycopg2.extras import execute_values

logger = logging.getLogger('retention')
POLICY_KEY = 'retention_policy_v1'
DEFAULT_POLICY = {
    'enabled': False,
    'type_days': {},
    'security_days': None,
    'firewall_allow_days': None,
    'summaries_enabled': False,
    'summary_group_by_rule': False,
    'summary_retention_days': 365,
    'archives_enabled': False,
    'archive_directory': '/data/archives',
    'archive_max_bytes': 20 * 1024 ** 3,
    'archive_max_files': 100_000,
    'archive_min_free_bytes': 1024 ** 3,
    'batch_size': 1000,
    'max_batches': 1000,
}
KNOWN_TYPES = frozenset({'dns', 'firewall', 'dhcp', 'wifi', 'system', 'unknown',
                         'ips', 'security', 'threat'})
# Keep security rows out of every other pass even if the event says ALLOW.
SECURITY_FILTER = "(event_source = 'unifi_ips' OR log_type IN ('ips', 'security', 'threat'))"
NOT_SECURITY_FILTER = f'NOT COALESCE({SECURITY_FILTER}, FALSE)'
ALLOW_FILTER = "(log_type = 'firewall' AND LOWER(COALESCE(rule_action, '')) IN ('allow', 'accept'))"

RETENTION_SCHEMA_SQL = [
    """CREATE TABLE IF NOT EXISTS retention_daily_summaries (
        day DATE NOT NULL,
        log_type TEXT NOT NULL,
        rule_action TEXT NOT NULL,
        source TEXT NOT NULL,
        event_source TEXT NOT NULL,
        grouped_by_rule BOOLEAN NOT NULL,
        rule_name TEXT NOT NULL,
        event_count BIGINT NOT NULL CHECK (event_count > 0),
        first_event_at TIMESTAMPTZ NOT NULL,
        last_event_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (day, log_type, rule_action, source, event_source, grouped_by_rule, rule_name)
    )""",
]


def _integer(value, name, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f'{name} must be an integer between {minimum} and {maximum}')
    return value


def validate_policy(raw, general_days=60, dns_days=10):
    """Return a normalized policy; invalid saved policies stop cleanup safely."""
    if not isinstance(raw, dict):
        raise ValueError('retention policy must be an object')
    extra = set(raw) - set(DEFAULT_POLICY)
    if extra:
        raise ValueError(f'Unknown retention policy fields: {", ".join(sorted(extra))}')
    policy = {**DEFAULT_POLICY, **raw}
    for name in ('enabled', 'summaries_enabled', 'summary_group_by_rule', 'archives_enabled'):
        if type(policy[name]) is not bool:
            raise ValueError(f'{name} must be a boolean')
    for name in ('security_days', 'firewall_allow_days'):
        if policy[name] is not None:
            _integer(policy[name], name, 1, 3650)
    if not isinstance(policy['type_days'], dict):
        raise ValueError('type_days must be an object')
    for log_type, days in policy['type_days'].items():
        if log_type not in KNOWN_TYPES:
            raise ValueError(f'Unsupported log type: {log_type}')
        if log_type in ('ips', 'security', 'threat'):
            raise ValueError('Use security_days for ips, security, and threat events')
        _integer(days, f'type_days.{log_type}', 1, 3650)
    policy['type_days'] = dict(policy['type_days'])
    _integer(policy['summary_retention_days'], 'summary_retention_days', 1, 3650)
    _integer(policy['batch_size'], 'batch_size', 1, 5000)
    _integer(policy['max_batches'], 'max_batches', 1, 10_000)
    _integer(policy['archive_max_bytes'], 'archive_max_bytes', 1024, 1024 ** 5)
    _integer(policy['archive_max_files'], 'archive_max_files', 1, 1_000_000)
    _integer(policy['archive_min_free_bytes'], 'archive_min_free_bytes', 0, 1024 ** 5)
    directory = policy['archive_directory']
    if not isinstance(directory, str) or not directory or '\x00' in directory:
        raise ValueError('archive_directory must be an absolute path')
    path = Path(directory)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('archive_directory must be an absolute path without ..')
    module_dir = Path(__file__).resolve().parent
    # Source checkouts keep this module in receiver/; Docker copies it flat
    # into /app. Do not mistake / for the application root in that layout.
    repo = module_dir.parent if module_dir.name == 'receiver' else module_dir
    if path == Path('/') or path.resolve().is_relative_to(repo):
        raise ValueError('archive_directory must be private storage outside the application repository')
    # An explicit shorter allow period must not accidentally include IPS data.
    if policy['enabled'] and policy['firewall_allow_days'] is not None:
        security_days = policy['security_days'] or general_days
        if security_days <= policy['firewall_allow_days']:
            raise ValueError('security_days (or inherited general retention) must exceed firewall_allow_days')
    return policy


def load_policy(db, general_days=60, dns_days=10):
    raw = db.get_config(POLICY_KEY)
    return validate_policy({} if raw is None else raw, general_days, dns_days)


def retention_passes(policy, general_days, dns_days):
    """Disjoint predicates keep a longer security period out of shorter passes."""
    if not policy['enabled']:
        return [('dns', "log_type = 'dns'", [], dns_days),
                ('non_dns', "log_type != 'dns'", [], general_days)]
    types = policy['type_days']
    passes = [('security', SECURITY_FILTER, [], policy['security_days'] or general_days)]
    if policy['firewall_allow_days'] is not None:
        passes.append(('firewall_allow', f'{NOT_SECURITY_FILTER} AND {ALLOW_FILTER}', [],
                       policy['firewall_allow_days']))
        rest = f'{NOT_SECURITY_FILTER} AND NOT {ALLOW_FILTER}'
    else:
        rest = NOT_SECURITY_FILTER
    # Security log types are handled together by security_days, so per-type
    # entries for those types must not silently promise a different period.
    for kind in sorted(types):
        if kind not in ('ips', 'security', 'threat'):
            passes.append((kind, f'{rest} AND log_type = %s', [kind], types[kind]))
    excluded = [kind for kind in types if kind not in ('ips', 'security', 'threat')]
    if excluded:
        rest = f'{rest} AND NOT (log_type = ANY(%s))'
        params = [excluded]
    else:
        params = []
    if 'dns' not in types:
        passes.append(('dns', f"{rest} AND log_type = 'dns'", params, dns_days))
    passes.append(('non_dns', f"{rest} AND log_type != 'dns'", params, general_days))
    return passes


def _as_datetime(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError('Archive/summary timestamps must include a timezone')
    return value.astimezone(timezone.utc)


def summarize_rows(rows, group_by_rule):
    groups = {}
    for row in rows:
        stamp = _as_datetime(row['timestamp'])
        key = (stamp.date(), row['log_type'], row.get('rule_action') or '',
               row.get('source') or 'syslog', row.get('event_source') or '',
               group_by_rule, (row.get('rule_name') or '') if group_by_rule else '')
        if key not in groups:
            groups[key] = [0, stamp, stamp]
        agg = groups[key]
        agg[0] += 1
        agg[1] = min(agg[1], stamp)
        agg[2] = max(agg[2], stamp)
    return [(*key, *value) for key, value in sorted(groups.items())]


def _write_summaries(cur, rows, group_by_rule):
    values = summarize_rows(rows, group_by_rule)
    if values:
        execute_values(cur, """
            INSERT INTO retention_daily_summaries
                (day, log_type, rule_action, source, event_source, grouped_by_rule,
                 rule_name, event_count, first_event_at, last_event_at)
            VALUES %s
            ON CONFLICT (day, log_type, rule_action, source, event_source, grouped_by_rule, rule_name)
            DO UPDATE SET event_count = retention_daily_summaries.event_count + EXCLUDED.event_count,
                first_event_at = LEAST(retention_daily_summaries.first_event_at, EXCLUDED.first_event_at),
                last_event_at = GREATEST(retention_daily_summaries.last_event_at, EXCLUDED.last_event_at),
                updated_at = NOW()
        """, values, page_size=500)
    return len(values)


def _archive_directory(policy):
    path = Path(policy['archive_directory'])
    if path.is_symlink() or path.resolve() != path.absolute():
        raise ValueError('Archive directory and its parents must not be symlinks')
    info = path.stat()  # Must be provisioned on persistent storage by the operator.
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError('Archive path must be an existing directory')
    if info.st_mode & 0o077:
        raise ValueError('Archive directory must have private permissions (0700)')
    return path


def _archive_usage(path, policy):
    size = count = 0
    with os.scandir(path) as entries:
        for entry in entries:
            if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                raise ValueError('Archive directory must contain only regular archive files')
            size += entry.stat(follow_symlinks=False).st_size
            count += 1
            if size > policy['archive_max_bytes'] or count > policy['archive_max_files']:
                raise ValueError('Archive storage limit reached; cleanup stopped without deleting this batch')
    return size, count


def _json_line(row):
    # to_jsonb(logs) returns only JSON-native values; datetime support also
    # makes the archive writer useful with callers that provide decoded rows.
    return (json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       default=lambda value: value.isoformat() if isinstance(value, (date, datetime))
                       else str(value)) + '\n').encode('utf-8')


def write_archive(rows, policy):
    """Durably publish a bounded gzip JSONL file before the caller deletes rows.

    A content hash identifies retries of identical batches. Files left by a
    rolled-back DB transaction remain valid archives and consume the same
    configured quota. This function never removes published archive files.
    """
    path = _archive_directory(policy)
    digest = hashlib.sha256()
    for row in rows:
        digest.update(_json_line(row))
    hex_digest = digest.hexdigest()
    target = path / f'events-{hex_digest}.jsonl.gz'
    used, count = _archive_usage(path, policy)
    if target.exists():
        digest = hashlib.sha256()
        with gzip.open(target, 'rb') as existing:
            while block := existing.read(1024 * 1024):
                digest.update(block)
        if digest.hexdigest() != hex_digest:
            raise ValueError('Existing archive failed checksum verification; no rows deleted')
        return str(target), False
    if count >= policy['archive_max_files']:
        raise ValueError('Archive file limit reached; cleanup stopped without deleting this batch')
    free = shutil.disk_usage(path).free
    remaining = min(policy['archive_max_bytes'] - used,
                    free - policy['archive_min_free_bytes'])
    if remaining <= 0:
        raise ValueError('Archive disk budget reached; cleanup stopped without deleting this batch')
    fd, temporary = tempfile.mkstemp(prefix='.retention-', suffix='.tmp', dir=path)
    try:
        with os.fdopen(fd, 'wb') as output:
            # mtime=0 and empty filename keep gzip output deterministic.
            with gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0) as compressed:
                for row in rows:
                    compressed.write(_json_line(row))
                    if output.tell() > remaining:
                        raise ValueError('Archive disk budget exceeded; no rows deleted')
            output.flush()
            if output.tell() > remaining:
                raise ValueError('Archive disk budget exceeded; no rows deleted')
            os.fsync(output.fileno())
        # Same-directory hard link is atomic and cannot overwrite an archive.
        os.link(temporary, target)
        os.unlink(temporary)
        dir_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return str(target), True


def _delete_batch(db, predicate, params, cutoff, batch_size, policy):
    """Archive, summarize and delete one batch; DB work commits as one unit."""
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SET LOCAL statement_timeout = '60s'")
            if policy['enabled']:
                # Serialize policy batches across API and receiver processes,
                # including file-budget checks, without holding a session lock.
                cur.execute('SELECT pg_try_advisory_xact_lock(16436, 1)')
                if not cur.fetchone()[0]:
                    return None
            needs_rows = policy['enabled'] and (policy['archives_enabled'] or policy['summaries_enabled'])
            selection = (f'SELECT {"to_jsonb(logs)" if needs_rows else "id"} FROM logs '
                         f'WHERE {predicate} AND timestamp < %s '
                         'ORDER BY timestamp ASC, id ASC LIMIT %s FOR UPDATE SKIP LOCKED')
            query_params = [*params, cutoff, batch_size]
            if not needs_rows:
                cur.execute(f'DELETE FROM logs WHERE id IN ({selection}) RETURNING log_type', query_params)
                deleted = cur.fetchall()
                return {'count': len(deleted), 'dns': sum(row[0] == 'dns' for row in deleted),
                        'archives': 0, 'summaries': 0}
            cur.execute(selection, query_params)
            rows = [row[0] for row in cur.fetchall()]
            if not rows:
                return {'count': 0, 'dns': 0, 'archives': 0, 'summaries': 0}
            created = False
            if policy['archives_enabled']:
                _, created = write_archive(rows, policy)
            summary_groups = 0
            if policy['summaries_enabled']:
                summary_groups = _write_summaries(cur, rows, policy['summary_group_by_rule'])
            ids = [row['id'] for row in rows]
            cur.execute('DELETE FROM logs WHERE id = ANY(%s)', [ids])
            if cur.rowcount != len(ids):
                raise RuntimeError('Retention delete count changed; summary transaction rolled back')
            return {'count': len(rows), 'dns': sum(row['log_type'] == 'dns' for row in rows),
                    'archives': int(created), 'summaries': summary_groups}


def _prune_summaries(db, policy, now):
    cutoff = (now - timedelta(days=policy['summary_retention_days'])).date()
    deleted = 0
    for _ in range(policy['max_batches']):
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SET LOCAL statement_timeout = '60s'")
                cur.execute('DELETE FROM retention_daily_summaries WHERE ctid IN ('
                            'SELECT ctid FROM retention_daily_summaries WHERE day < %s '
                            'ORDER BY day LIMIT %s FOR UPDATE SKIP LOCKED)',
                            [cutoff, policy['batch_size']])
                count = cur.rowcount
        deleted += count
        if count < policy['batch_size']:
            break
    return deleted


def run_retention_cleanup(db, general_days=60, dns_days=10, progress_cb=None):
    """Run bounded transactions, preserving the existing cleanup result fields."""
    for name, days in (('general_days', general_days), ('dns_days', dns_days)):
        if type(days) is not int or days <= 0:
            raise ValueError(f'{name} must be a positive integer')
    result = {'status': 'complete', 'dns_deleted': 0, 'non_dns_deleted': 0,
              'deleted_so_far': 0, 'batches_completed': 0, 'error': None,
              'archives_written': 0, 'summary_groups_updated': 0, 'summary_groups_pruned': 0}
    try:
        policy = load_policy(db, general_days, dns_days)
        now = datetime.now(timezone.utc)
        batch_size = policy['batch_size'] if policy['enabled'] else db.RETENTION_BATCH_SIZE
        for label, predicate, params, days in retention_passes(policy, general_days, dns_days):
            cutoff = now - timedelta(days=days)
            while True:
                if policy['enabled'] and result['batches_completed'] >= policy['max_batches']:
                    result.update(status='partial', error='Batch limit reached; cleanup will continue on the next run')
                    return result
                batch = _delete_batch(db, predicate, params, cutoff, batch_size, policy)
                if batch is None:
                    result['skipped_locked'] = True
                    return result
                if batch['count'] == 0:
                    break
                result['dns_deleted'] += batch['dns']
                result['non_dns_deleted'] += batch['count'] - batch['dns']
                result['deleted_so_far'] += batch['count']
                result['batches_completed'] += 1
                result['archives_written'] += batch['archives']
                result['summary_groups_updated'] += batch['summaries']
                if progress_cb:
                    progress_cb({**result, 'phase': label})
        if policy['enabled'] and policy['summaries_enabled']:
            result['summary_groups_pruned'] = _prune_summaries(db, policy, now)
    except Exception as exc:
        result['error'] = str(exc)
        result['status'] = 'partial' if result['deleted_so_far'] else 'failed'
        logger.exception('Retention cleanup stopped after %d committed deletes', result['deleted_so_far'])
    logger.info('Retention cleanup %s: %d deleted, %d archives written', result['status'],
                result['deleted_so_far'], result['archives_written'])
    return result
