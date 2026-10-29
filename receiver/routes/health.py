"""Health check endpoint."""

import logging
import json
import math
import time
import os
import shutil
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException

from db import Database, estimate_log_count, get_config, is_external_db
from enrichment import get_abuseipdb_stats
from ingest_health import collection_state, receiver_state
from ingest_runtime import status_path
from deps import get_conn, put_conn, enricher_db, APP_VERSION

logger = logging.getLogger('api.health')

router = APIRouter()


_COUNTERS = (
    'received', 'parsed', 'filtered', 'failed', 'staged', 'inserted', 'duplicates',
    'flush_errors', 'dropped', 'parse_exceptions', 'enrich_exceptions',
    'queue_dropped', 'spool_dropped', 'spool_errors', 'delivery_attempts', 'retry_attempts', 'shutdown_dropped',
)
_PROVIDER_NAMES = ('geoip', 'asn', 'rdns', 'abuseipdb', 'unifi')
_PROVIDER_STATES = {'not_configured', 'ready', 'missing', 'error', 'pending'}
_RATE_FIELDS = ('received_per_second', 'staged_per_second', 'inserted_per_second',
                'dropped_per_second', 'queue_dropped_per_second')
_TIMING_STAGES = ('parse', 'enrich', 'spool_stage', 'spool_read', 'db_insert', 'spool_ack')
_TIMING_FIELDS = ('count', 'total_ms', 'last_ms', 'max_ms', 'mean_ms', 'last_at', 'max_at')
_WORKER_PHASES = {'idle', 'spool_open', 'parse_enrich', 'spool_stage', 'spool_read', 'db_insert', 'spool_ack'}


def _number(value, default=None):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            if math.isfinite(value) and value >= 0:
                return value
        except OverflowError:
            pass
    return default


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _performance_snapshot(raw, snapshot, now):
    """Allowlist additive metrics; missing older metrics remain unknown."""
    fresh = snapshot['status'] == 'fresh'
    rates = _mapping(raw.get('rates'))
    window = _number(rates.get('window_seconds'))
    snapshot['rates'] = {'window_seconds': window}
    for field in _RATE_FIELDS:
        snapshot['rates'][field] = _number(rates.get(field)) if fresh and window else None
    snapshot['timings'] = {
        stage: {field: _number(_mapping(_mapping(raw.get('timings')).get(stage)).get(field))
                for field in _TIMING_FIELDS} for stage in _TIMING_STAGES
    }
    snapshot['batch'] = {field: _number(_mapping(raw.get('batch')).get(field))
                         for field in ('size', 'flush_interval_seconds', 'pending', 'inflight',
                                       'oldest_age_seconds')}
    snapshot['spool']['oldest_age_seconds'] = _number(
        _mapping(raw.get('spool')).get('oldest_age_seconds'))
    storage = _mapping(_mapping(raw.get('spool')).get('storage'))
    snapshot['spool']['storage'] = {
        field: _number(storage.get(field)) for field in (
            'cache_kib', 'head_cache_rows', 'head_cache_bytes', 'head_cache_max_bytes',
            'wal_bytes', 'wal_checkpoint_bytes', 'wal_max_bytes', 'checkpoint_busy', 'checkpoint_errors')}
    snapshot['spool']['storage']['journal_mode'] = (
        storage.get('journal_mode') if storage.get('journal_mode') in ('wal', 'memory', 'delete') else None)
    snapshot['spool']['storage']['synchronous'] = 'FULL' if storage.get('synchronous') == 'FULL' else None
    snapshot['spool']['operations'] = {}
    for name in ('stage', 'due', 'acknowledge'):
        operation = _mapping(_mapping(_mapping(raw.get('spool')).get('operations')).get(name))
        phase = operation.get('phase')
        clean = {'phase': phase if phase in ('idle', 'waiting_lock', 'sql', 'commit', 'checkpoint') else None}
        for field in ('phase_started_at', 'phase_elapsed_seconds', 'errors'):
            clean[field] = _number(operation.get(field))
        for timing in ('lock_wait', 'sql', 'commit', 'checkpoint'):
            clean[timing] = {field: _number(_mapping(operation.get(timing)).get(field))
                             for field in ('count', 'last_seconds', 'max_seconds', 'total_seconds')}
        snapshot['spool']['operations'][name] = clean
    # Old receivers did not count staged records; do not imply they staged zero.
    snapshot['stats']['staged'] = _number(_mapping(raw.get('stats')).get('staged'))
    snapshot['workers'] = {}
    for name in ('producer', 'delivery'):
        worker = _mapping(_mapping(raw.get('workers')).get(name))
        clean = {field: worker.get(field) if isinstance(worker.get(field), bool) else None
                 for field in ('alive', 'failed')}
        for field in ('last_progress_at', 'busy_since', 'phase_started_at'):
            value = _number(worker.get(field))
            clean[field] = value if value and value <= now + 5 else None
        clean['progress_age_seconds'] = (
            max(0, now - clean['last_progress_at']) if clean['last_progress_at'] else None)
        phase = worker.get('phase')
        clean['phase'] = phase if isinstance(phase, str) and phase in _WORKER_PHASES else None
        snapshot['workers'][name] = clean
    snapshot['slow_operations'] = []
    operations = raw.get('slow_operations')
    for operation in operations[-32:] if isinstance(operations, list) else []:
        operation = _mapping(operation)
        stage, finished = operation.get('stage'), _number(operation.get('finished_at'))
        duration = _number(operation.get('duration_ms'))
        if stage in _TIMING_STAGES and finished and finished <= now + 5 and duration is not None:
            snapshot['slow_operations'].append(dict(stage=stage, finished_at=finished, duration_ms=duration))


def read_ingest_health():
    """Read a bounded, allowlisted process snapshot; never query DB or providers.

    A fresh file proves only that the health publisher ran. Separate worker
    liveness/progress fields reveal a stalled ingestion worker behind it.
    """
    unavailable = {'status': 'unavailable', 'state': 'unknown', 'updated_at': None,
                   'age_seconds': None, 'providers': {}}
    unavailable['collection'] = collection_state(unavailable)
    path = status_path()
    try:
        with open(path, 'r', encoding='utf-8') as stream:
            payload = stream.read(65537)
        if len(payload) > 65536:
            return dict(unavailable, reason='invalid_snapshot')
        raw = json.loads(payload)
        if not isinstance(raw, dict) or raw.get('schema_version') != 1:
            return dict(unavailable, reason='invalid_snapshot')
        now = time.time()
        updated = _number(raw.get('updated_at'))
        if updated is None or updated > now + 5:
            return dict(unavailable, reason='invalid_snapshot')
        age = max(0, now - updated)
        snapshot = {
            'status': 'fresh' if age <= 10 else 'stale',
            'state': 'ready', 'updated_at': updated, 'age_seconds': age,
            'running': raw.get('running') is True,
            'worker_alive': raw.get('worker_alive') is True,
            'last_progress_at': _number(raw.get('last_progress_at')),
            'last_receive_at': _number(raw.get('last_receive_at')) or None,
        }
        for group, fields in {
            'stats': _COUNTERS,
            'queue': ('depth', 'capacity', 'oldest_age_seconds'),
            'spool': ('rows', 'bytes', 'max_rows', 'max_bytes'),
            'retry': ('consecutive_failures', 'next_retry_at'),
            'enrichment': ('depth', 'capacity', 'pending', 'dropped', 'completed'),
        }.items():
            data = raw.get(group)
            data = data if isinstance(data, dict) else {}
            snapshot[group] = {key: _number(data.get(key), 0) for key in fields}
        # Older receivers named every DB batch delivery a retry. Preserve the
        # useful total while marking actual retries unknown, never as zero.
        raw_stats = raw.get('stats')
        raw_stats = raw_stats if isinstance(raw_stats, dict) else {}
        if _number(raw_stats.get('delivery_attempts')) is None:
            snapshot['stats']['delivery_attempts'] = _number(raw_stats.get('retry_attempts'))
            snapshot['stats']['retry_attempts'] = None
        spool = raw.get('spool')
        snapshot['spool']['failed'] = isinstance(spool, dict) and spool.get('failed') is True
        _performance_snapshot(raw, snapshot, now)
        providers = raw.get('providers')
        providers = providers if isinstance(providers, dict) else {}
        snapshot['providers'] = {}
        for name in _PROVIDER_NAMES:
            value = providers.get(name)
            value = value if isinstance(value, dict) else {}
            state = value.get('status')
            # Stale configuration cannot establish current provider readiness.
            snapshot['providers'][name] = {
                'status': state if state in _PROVIDER_STATES and age <= 10 else 'pending',
                'last_success_at': _number(value.get('last_success_at')),
                'last_error_at': _number(value.get('last_error_at')),
            }
        progress = snapshot['last_progress_at']
        snapshot['progress_age_seconds'] = max(0, now - progress) if progress else None
        snapshot['receive_age_seconds'] = max(0, now - snapshot['last_receive_at']) if snapshot['last_receive_at'] else None
        snapshot['state'] = receiver_state(snapshot, now)
        # Recompute from allowlisted evidence; never trust producer reason text.
        snapshot['collection'] = collection_state(snapshot, now)
        return snapshot
    except FileNotFoundError:
        return dict(unavailable, reason='not_started')
    except (OSError, ValueError, TypeError):
        return dict(unavailable, reason='unreadable_snapshot')


@router.get("/api/health/ingest")
def ingest_health():
    """Ingestion remains observable even when PostgreSQL cannot answer."""
    return read_ingest_health()


@router.get("/api/health")
def health():
    """Return service health, log count estimate, retention config, and storage stats."""
    conn = None
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            # Catalog estimate, not COUNT(*): on 100M+ rows the exact count takes
            # 5-7s per call and causes /api/health 503s via statement_timeout.
            total = estimate_log_count(cur)

            # MIN/MAX on idx_logs_timestamp btree: two index edge lookups (~1ms)
            cur.execute("SELECT MIN(timestamp), MAX(timestamp) FROM logs")
            oldest, latest = cur.fetchone()
        conn.commit()

        # The shared retention resolver handles UI > env > default + validation.
        retention_days = Database.resolve_retention_days(enricher_db).general

        # AbuseIPDB rate limit stats (written by receiver process)
        abuseipdb = get_abuseipdb_stats(enricher_db)

        # MaxMind database info
        maxmind_last_update = None
        mmdb_path = '/app/maxmind/GeoLite2-City.mmdb'
        try:
            if os.path.exists(mmdb_path):
                mtime = os.path.getmtime(mmdb_path)
                maxmind_last_update = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
        except Exception:
            pass

        # Calculate next MaxMind update (Wed=2, Sat=5 at 07:00 local)
        maxmind_next_update = None
        try:
            now = datetime.now().astimezone()
            target_time = now.replace(hour=7, minute=0, second=0, microsecond=0)
            # Find next Wed(2) or Sat(5)
            for days_ahead in range(1, 8):
                candidate = target_time + timedelta(days=days_ahead)
                if candidate.weekday() in (2, 5):  # Wed=2, Sat=5
                    maxmind_next_update = candidate.isoformat()
                    break
            # Edge case: today is Wed/Sat and it's before 07:00
            if now.weekday() in (2, 5) and now < target_time:
                maxmind_next_update = target_time.isoformat()
        except Exception:
            pass

        # Storage: database size + volume disk usage
        storage = {}
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_database_size(current_database())")
                storage['db_size_bytes'] = cur.fetchone()[0]
            conn.commit()
        except Exception:
            conn.rollback()
        if not is_external_db():
            try:
                usage = shutil.disk_usage('/var/lib/postgresql/data')
                storage['volume_total_bytes'] = usage.total
                storage['volume_used_bytes'] = usage.used
                storage['volume_available_bytes'] = usage.free
            except Exception as e:
                logger.warning("Failed to read disk usage for /var/lib/postgresql/data: %s", e)

        ingestion = read_ingest_health()
        return {
            'ingestion': ingestion,
            'providers': ingestion['providers'],
            'total_logs_is_estimate': True,
            'status': 'ok',
            'version': APP_VERSION,
            'total_logs': total,
            'oldest_log_at': oldest.isoformat() if oldest else None,
            'latest_log': latest.isoformat() if latest else None,
            'retention_days': retention_days,
            'abuseipdb': abuseipdb,
            'maxmind_last_update': maxmind_last_update,
            'maxmind_next_update': maxmind_next_update,
            'storage': storage,
        }
    except Exception as e:
        if conn is not None:
            conn.rollback()
        logger.exception("Health check failed")
        raise HTTPException(status_code=503, detail="Service unavailable") from None
    finally:
        if conn is not None:
            put_conn(conn)
