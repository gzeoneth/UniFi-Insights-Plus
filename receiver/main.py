"""
UniFi Log Insight - Syslog Receiver

UDP syslog listener that receives logs from UDR, parses them,
and stores them in PostgreSQL.

Phase 1: Receive → Parse → Store
Phase 2 will add: IP enrichment (GeoIP, AbuseIPDB, rDNS)
"""

import os
import sys
import time
import socket
import signal
import logging
import threading
import json
import queue
import tempfile
import uuid
from collections import deque

import schedule

from parsers import parse_log
import parsers
from log_utils import flush_suppressed, rate_limited_warning
from db import (Database, get_config, set_config, build_conn_params, is_external_db,
                wait_for_postgres, parse_positive_int, has_logs)
from enrichment import Enricher
from ingest_queue import RetrySpool, positive_env
from ingest_metrics import IngestMetrics, bounded_seconds_env
from backfill import BackfillTask
from blacklist import BlacklistFetcher
from unifi_api import UniFiAPI
from pihole_api import PiHolePoller
from routes.auth import auth_cleanup

# Set by the SIGUSR2 handler when retention_time may have changed.
# Consumed by the scheduler loop (single-writer, single-reader — safe).
# All `schedule` registry mutation stays on the scheduler thread.
_retention_reload_requested = threading.Event()

# Set by the SIGUSR2 handler when log-based WAN/gateway identity should be
# re-detected now rather than at the next WAN_REFRESH_INTERVAL_MINUTES run:
# the effective UniFi enabled flag flipped, or the set of configured WAN
# interfaces without a learned IP changed since the previous reload
# (_last_missing_wan). Decided from reloaded in-memory state only; consumed by
# the scheduler loop, so detection never runs inside the signal handler.
_identity_refresh_requested = threading.Event()

# Configured WAN interfaces with no learned IP at the previous SIGUSR2 reload.
# Starts empty: interfaces already missing at boot were covered by the startup
# refresh, so they trigger one refresh at most, never one per settings save.
_last_missing_wan = frozenset()

# The (wan_ip_by_iface, wan_ips, wan_ip, gateway_ips) tuple the receiver last
# loaded after a log-based identity refresh; None until the first refresh.
# Only _refresh_network_identity_from_logs() reads or writes it, and only after
# a successful reload, so a failed read or reload is retried on the next run.
_IDENTITY_KEYS = ('wan_ip_by_iface', 'wan_ips', 'wan_ip', 'gateway_ips')
_loaded_identity = None

# ── Configuration ──────────────────────────────────────────────────────────────

SYSLOG_PORT = 514
SYSLOG_BUFFER_SIZE = 8192      # Max UDP packet size
BATCH_SIZE = 200                # Bounded batches amortize durable transaction cost
BATCH_TIMEOUT = 1.0             # Maximum partial-batch staging delay
STATS_INTERVAL_MINUTES = 15     # Log stats every N minutes (DEBUG only)

# ── Logging ────────────────────────────────────────────────────────────────────

_log_level_name = os.environ.get('LOG_LEVEL', 'INFO').upper()
if _log_level_name not in ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'):
    _log_level_name = 'INFO'

logging.basicConfig(
    level=getattr(logging, _log_level_name),
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    stream=sys.stdout,
)
logger = logging.getLogger('receiver')


def _wan_refresh_interval_from_env() -> int:
    """Minutes between log-based WAN/gateway detections (default 360).

    Parsed after logging is configured, so a bad value warns instead of
    crashing at import; 0 or a negative value would make schedule.every()
    loop forever. Blank or unset uses the default silently.
    """
    default = 360
    raw = os.environ.get('WAN_REFRESH_INTERVAL_MINUTES', '').strip()
    parsed = parse_positive_int(raw)
    if parsed is not None:
        return parsed
    if raw:
        logger.warning("Invalid WAN_REFRESH_INTERVAL_MINUTES '%s' (must be a whole number >= 1), "
                       "using default %d", raw, default)
    return default


WAN_REFRESH_INTERVAL_MINUTES = _wan_refresh_interval_from_env()


# ── Syslog Receiver ───────────────────────────────────────────────────────────

class SyslogReceiver:
    """Socket intake, local parsing and durable DB delivery use separate threads."""

    HEARTBEAT_INTERVAL = 60

    def __init__(self, db: Database, enricher: Enricher):
        self.db = db
        self.enricher = enricher
        self.sock = None
        self.running = False
        self._shutdown_requested = False
        self.batch: list[dict] = []
        self._processing_rows = 0
        self._staging_rows = 0
        self.batch_lock = threading.Lock()
        self.batch_size = positive_env('INGEST_BATCH_SIZE', BATCH_SIZE, 1000)
        self.batch_timeout = bounded_seconds_env('INGEST_FLUSH_INTERVAL_SECONDS', BATCH_TIMEOUT)
        self._metrics = IngestMetrics()
        self.last_flush = time.monotonic()
        self.last_heartbeat = time.time()
        self.last_receive_time = 0.0
        self.last_progress_at = time.time()
        self.consecutive_flush_errors = 0
        self._db_retry_at = 0.0
        self._stats_lock = threading.Lock()
        self.stats = dict.fromkeys((
            'received', 'parsed', 'filtered', 'failed', 'staged', 'inserted', 'duplicates',
            'flush_errors', 'dropped', 'parse_exceptions', 'enrich_exceptions',
            'queue_dropped', 'spool_dropped', 'spool_errors', 'delivery_attempts', 'retry_attempts',
            'shutdown_dropped',
        ), 0)
        self.queue = queue.Queue(maxsize=positive_env('INGEST_QUEUE_CAPACITY', 4096, 65536))
        self._worker = None
        self._delivery_worker = None
        self._workers = {name: {'failed': False, 'last_progress_at': time.time(), 'busy_since': None}
                         for name in ('producer', 'delivery')}
        self._health_worker = None
        self._stop_event = threading.Event()
        self._delivery_wake = threading.Event()
        self._health_stop = threading.Event()
        self._shutdown_deadline = None
        self.config_reload_callback = None
        self.config_reload_requested = False
        self.geoip_reload_requested = False
        self._spool = None
        self._spool_init_lock = threading.Lock()
        self._spool_failed = False
        self._spool_path = os.environ.get('INGEST_SPOOL_PATH',
                                         '/var/lib/unifi-log-insight/ingest/retry.sqlite3')
        self._spool_state = {
            'rows': 0, 'bytes': 0,
            'max_rows': positive_env('INGEST_SPOOL_MAX_ROWS', 100000, 1000000),
            'max_bytes': positive_env('INGEST_SPOOL_MAX_BYTES', 64 * 1024 * 1024, 512 * 1024 * 1024),
        }
        self._status_path = os.environ.get('INGEST_STATUS_PATH',
                                          '/run/unifi-log-insight/receiver-health.json')
        self._load_disabled_types()

    def _count(self, key, count=1):
        with self._stats_lock:
            self.stats[key] += count

    def _load_disabled_types(self):
        disabled = set()
        if not get_config(self.db, 'wifi_processing_enabled', True):
            disabled.add('wifi')
        if not get_config(self.db, 'system_processing_enabled', True):
            disabled.add('system')
        self._disabled_log_types = disabled
        if disabled:
            logger.info("Log type filtering active: discarding %s", disabled)

    def _accept_datagram(self, data, addr):
        """The entire socket hot path: bounded nonblocking memory enqueue."""
        self.last_receive_time = time.time()
        self._count('received')
        try:
            self.queue.put_nowait((data, addr, self.last_receive_time))
        except queue.Full:
            self._count('queue_dropped')
            self._count('dropped')

    def start(self):
        if self._shutdown_requested:
            return
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
        logger.info("UDP socket SO_RCVBUF: requested=1048576, actual=%d",
                    self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF))
        self.sock.bind(('::', SYSLOG_PORT))
        self.sock.settimeout(1.0)
        self.running = True
        self._start_workers()
        self._health_worker = threading.Thread(target=self._health_loop, name='ingest-health', daemon=True)
        self._health_worker.start()
        logger.info("Syslog receiver listening on UDP port %d (queue capacity=%d)",
                    SYSLOG_PORT, self.queue.maxsize)
        try:
            while self.running and not self._shutdown_requested:
                try:
                    data, addr = self.sock.recvfrom(SYSLOG_BUFFER_SIZE)
                    self._accept_datagram(data, addr)
                except socket.timeout:
                    pass
                except OSError as exc:
                    if self.running:
                        logger.error("Socket error (will retry): %s", exc)
                        time.sleep(0.1)
        finally:
            self.stop()

    def request_stop(self):
        """Signal-safe request: never acquire a queue lock inside a handler."""
        self._shutdown_requested = True
        self.running = False

    def _ensure_spool(self):
        with self._spool_init_lock:
            if self._spool is None:
                self._spool = RetrySpool(self._spool_path,
                                        self._spool_state['max_rows'], self._spool_state['max_bytes'])
                self._spool_state = self._spool.snapshot()

    def _start_workers(self):
        self._worker = threading.Thread(target=self._process_queue, name='ingest-stage', daemon=True)
        self._delivery_worker = threading.Thread(target=self._deliver_spool, name='ingest-delivery', daemon=True)
        self._worker.start()
        self._delivery_worker.start()

    def _process_queue(self):
        try:
            self._ensure_spool()
        except Exception:
            self._spool_failed = True
            self._count('spool_errors')
            logger.error("Cannot open durable ingest spool; incoming rows will be explicitly dropped", exc_info=True)
        try:
            while not self._stop_event.is_set() or not self.queue.empty():
                if self._shutdown_deadline is not None and time.monotonic() >= self._shutdown_deadline:
                    break
                try:
                    data, addr, _received_at = self.queue.get(timeout=0.1)
                except queue.Empty:
                    pass
                else:
                    try:
                        self._workers['producer']['busy_since'] = time.time()
                        self._processing_rows = 1
                        self._handle_message(data, addr, count_received=False)
                    finally:
                        self._processing_rows = 0
                        self._workers['producer']['busy_since'] = None
                        self.queue.task_done()
                self._maybe_flush_batch()
                if self.geoip_reload_requested:
                    self.geoip_reload_requested = False
                    try:
                        self.enricher.reload_geoip()
                    except Exception:
                        logger.exception("GeoIP reload failed")
                self.last_progress_at = time.time()
                self._workers['producer']['last_progress_at'] = self.last_progress_at
        except Exception:
            self._workers['producer']['failed'] = True
            logger.exception("Ingestion worker stopped unexpectedly")
        finally:
            # Shutdown or a worker error must still stage its parsed rows.
            self._flush_batch()

    def _deliver_spool(self):
        """PostgreSQL latency never holds the producer or SQLite transaction."""
        try:
            while not self._stop_event.is_set():
                self._delivery_wake.clear()
                # One bounded batch per pass; errors retain backoff in SQLite.
                delivered = self._retry_spool()
                # Configuration reads can wait for PostgreSQL. Keep them off
                # the staging worker just like ordinary database delivery.
                if self.config_reload_requested and self.config_reload_callback:
                    self.config_reload_requested = False
                    self.config_reload_callback()
                if not delivered:
                    self._delivery_wake.wait(0.1)
        except Exception:
            self._workers['delivery']['failed'] = True
            logger.exception("Delivery worker stopped unexpectedly; durable rows retained")

    def stop(self):
        """Bounded drain; committed spool rows survive forced/slow DB shutdown."""
        logger.info("Stopping syslog receiver...")
        self.running = False
        if self._shutdown_deadline is None:
            self._shutdown_deadline = time.monotonic() + 5.0
        self._stop_event.set()
        self._delivery_wake.set()
        if self.sock:
            self.sock.close()
        if self._worker and self._worker is not threading.current_thread():
            self._worker.join(timeout=max(0, self._shutdown_deadline - time.monotonic()))
        elif self._worker is None:
            self._flush_batch()
        if self._delivery_worker and self._delivery_worker is not threading.current_thread():
            self._delivery_worker.join(timeout=max(0, self._shutdown_deadline - time.monotonic()))
        # UDP memory backlog cannot survive process exit: count its loss explicitly.
        while True:
            try:
                self.queue.get_nowait()
                self.queue.task_done()
                self._count('shutdown_dropped')
                self._count('dropped')
            except queue.Empty:
                break
        if self._worker and self._worker.is_alive():
            logger.warning("Ingest worker still finishing; durable rows will replay on restart")
        if self._delivery_worker and self._delivery_worker.is_alive():
            logger.warning("Database delivery still finishing; unacknowledged rows will replay on restart")
        self._health_stop.set()
        if self._health_worker:
            self._health_worker.join(timeout=1.0)
        self._write_status()
        logger.info("Syslog receiver stopped. Stats: %s", self.stats)

    def _handle_message(self, data: bytes, addr: tuple, count_received=True):
        """Parse and apply local/cached enrichment on the ingestion worker."""
        if count_received:
            self._count('received')
        raw_log = data.decode('utf-8', errors='replace').strip()
        if not raw_log:
            return
        try:
            started = time.monotonic()
            try:
                parsed = parse_log(raw_log)
            finally:
                self._metrics.observe('parse', started)
            if parsed is None:
                self._count('failed')
                return
            self._count('parsed')
            if parsed.get('log_type') in self._disabled_log_types:
                self._count('filtered')
                return
            try:
                started = time.monotonic()
                parsed = self.enricher.enrich(dict(parsed), defer_network=True)
            except Exception:
                self._count('enrich_exceptions')
                self._warn_rate_limited('enrich_exceptions', addr, raw_log)
            finally:
                self._metrics.observe('enrich', started)
            parsed['ingest_id'] = str(uuid.uuid4())
            self.batch.append(parsed)
            if len(self.batch) >= self.batch_size:
                self._flush_batch()
        except Exception:
            self._count('parse_exceptions')
            self._warn_rate_limited('parse_exceptions', addr, raw_log)

    def _warn_rate_limited(self, counter: str, addr: tuple, raw_log: str):
        rate_limited_warning(logger, f'receiver.{counter}',
                             "%s (total %d) while handling packet from %s: %.200r",
                             counter, self.stats[counter], addr, raw_log, exc_info=True)

    def _maybe_flush_batch(self):
        if time.monotonic() - self.last_flush >= self.batch_timeout and self.batch:
            self._flush_batch()

    def _flush_batch(self):
        """Commit parsed events locally, then wake independent delivery."""
        if not self.batch:
            self.last_flush = time.monotonic()
            return
        rows, self.batch = self.batch, []
        self._staging_rows = len(rows)
        self.last_flush = time.monotonic()
        started = time.monotonic()
        try:
            self._ensure_spool()
            accepted, rejected = self._spool.stage(rows)
            self._count('staged', len(accepted))
            self._spool_state = self._spool.snapshot()
            self._spool_failed = False
            if rejected:
                self._count('spool_dropped', rejected)
                self._count('dropped', rejected)
                rate_limited_warning(logger, 'receiver.spool_capacity',
                                     "Ingest spool full or invalid payload: %d newest rows dropped", rejected)
        except Exception:
            self._spool_failed = True
            self._count('spool_errors')
            self._count('spool_dropped', len(rows))
            self._count('dropped', len(rows))
            rate_limited_warning(logger, 'receiver.spool_write',
                                 "Ingest spool write failed: %d rows dropped", len(rows), exc_info=True)
            return
        finally:
            self._staging_rows = 0
            self._metrics.observe('spool_stage', started)
        self._delivery_wake.set()

    def _retry_spool(self):
        if self._spool is None or not self._spool.rows or time.time() < self._db_retry_at:
            return
        try:
            rows, retrying = self._spool.due_batch(self.batch_size)
        except Exception:
            self._count('spool_errors')
            self._spool_failed = True
            self._db_retry_at = time.time() + 5
            rate_limited_warning(logger, 'receiver.spool_read',
                                 "Ingest spool read failed; queued data retained", exc_info=True)
            return
        if not rows:
            return
        self._count('delivery_attempts')
        if retrying:
            self._count('retry_attempts')
        started = time.monotonic()
        self._workers['delivery']['busy_since'] = time.time()
        self._workers['delivery']['last_progress_at'] = self._workers['delivery']['busy_since']
        rejected = 0
        try:
            result = self.db.insert_logs_batch(rows)
            # A missing/old DB contract must never turn failure into success.
            counts = (result.inserted, getattr(result, 'duplicates', 0), result.dropped)
            if (any(type(value) is not int or value < 0 for value in counts)
                    or not isinstance(result.retryable, list)
                    or sum(counts) + len(result.retryable) != len(rows)
                    or len({row['ingest_id'] for row in result.retryable}) != len(result.retryable)
                    or not {row['ingest_id'] for row in result.retryable}.issubset(
                        {row['ingest_id'] for row in rows})):
                raise TypeError('Database did not return an InsertResult')
            self._count('inserted', result.inserted)
            self._count('duplicates', getattr(result, 'duplicates', 0))
            rejected = result.dropped
            retryable = result.retryable
        except Exception:
            retryable = rows
            rate_limited_warning(logger, 'receiver.db_insert',
                                 "Database insert failed; %d rows remain in durable spool", len(rows), exc_info=True)
        finally:
            self._metrics.observe('db_insert', started)
            self._workers['delivery']['busy_since'] = None
        if retryable:
            rate_limited_warning(logger, 'receiver.db_retry',
                                 'Database deferred %d rows; retained in durable ingest spool', len(retryable))
            self._count('flush_errors')
            self.consecutive_flush_errors += 1
            self._db_retry_at = time.time() + min(60, 2 ** min(self.consecutive_flush_errors - 1, 6))
        else:
            self.consecutive_flush_errors = 0
            self._db_retry_at = 0.0
        started = time.monotonic()
        try:
            self._spool.acknowledge(rows, retryable)
            # A malformed row is not finally discarded until its spool removal
            # commits. Do not count the same rejection again after an ack retry.
            self._count('dropped', rejected)
            self._spool_state = self._spool.snapshot()
            self._spool_failed = False
        except Exception:
            # PostgreSQL may already have committed: unchanged ingest IDs make
            # replay safe even when the local acknowledgement could not commit.
            self._count('spool_errors')
            self._spool_failed = True
            self._db_retry_at = time.time() + 5
            rate_limited_warning(logger, 'receiver.spool_ack',
                                 "Ingest spool acknowledgement failed; replay is idempotent", exc_info=True)
        finally:
            self._metrics.observe('spool_ack', started)
        self.last_progress_at = time.time()
        self._workers['delivery']['last_progress_at'] = self.last_progress_at
        return True

    def health_snapshot(self):
        with self._stats_lock:
            stats = dict(self.stats)
        enrichment = self.enricher.network_stats()
        if not isinstance(enrichment, dict):
            enrichment = {}
        providers = self.enricher.provider_stats()
        if not isinstance(providers, dict):
            providers = {}
        with self.queue.mutex:
            queue_depth = len(self.queue.queue)
            oldest = self.queue.queue[0][2] if self.queue.queue else None
        rates, timings = self._metrics.snapshot(stats)
        workers = {name: dict(value, alive=bool(thread and thread.is_alive()))
                   for name, value, thread in (
                       ('producer', self._workers['producer'], self._worker),
                       ('delivery', self._workers['delivery'], self._delivery_worker))}
        spool = self._spool.snapshot() if self._spool is not None else dict(self._spool_state)
        reasons = []
        if stats['dropped'] or stats['failed'] or stats['parse_exceptions']:
            reasons.append('historical_loss')
        if queue_depth or self.batch or self._processing_rows or self._staging_rows or spool['rows']:
            reasons.append('backlog')
        if any(value['failed'] or (self.running and not value['alive']) for value in workers.values()):
            reasons.append('worker_error')
        if self._spool_failed:
            reasons.append('storage_error')
        return {
            'providers': providers,
            'enrichment': enrichment,
            'schema_version': 1, 'updated_at': time.time(), 'running': self.running,
            'worker_alive': bool(self._worker and self._worker.is_alive()),
            'last_progress_at': self.last_progress_at, 'last_receive_at': self.last_receive_time,
            'stats': stats, 'queue': {'depth': queue_depth, 'capacity': self.queue.maxsize,
                                    'oldest_age_seconds': max(0, time.time() - oldest) if oldest else 0},
            'spool': dict(spool, failed=self._spool_failed),
            'workers': workers, 'rates': rates, 'timings': timings,
            'batch': {'size': self.batch_size, 'flush_interval_seconds': self.batch_timeout,
                      'pending': len(self.batch), 'inflight': max(self._processing_rows, self._staging_rows)},
            'collection': {'incomplete': bool(reasons), 'reasons': reasons},
            'retry': {'consecutive_failures': self.consecutive_flush_errors,
                      'next_retry_at': self._db_retry_at},
        }

    def _write_status(self):
        if not self._status_path:
            return
        temp_path = None
        try:
            directory = os.path.dirname(os.path.abspath(self._status_path))
            os.makedirs(directory, exist_ok=True)
            fd, temp_path = tempfile.mkstemp(prefix='.receiver-health-', dir=directory)
            with os.fdopen(fd, 'w') as stream:
                json.dump(self.health_snapshot(), stream, separators=(',', ':'))
                stream.flush()
            os.chmod(temp_path, 0o644)
            os.replace(temp_path, self._status_path)
        except OSError:
            rate_limited_warning(logger, 'receiver.health_write',
                                 "Could not publish ingest health snapshot", exc_info=True)
        finally:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)

    def _health_loop(self):
        while not self._health_stop.is_set():
            self._write_status()
            self._maybe_log_heartbeat()
            self._health_stop.wait(2.0)

    def _maybe_log_heartbeat(self):
        """Periodic heartbeat log to confirm the receiver is alive."""
        now = time.time()
        if now - self.last_heartbeat < self.HEARTBEAT_INTERVAL:
            return
        self.last_heartbeat = now

        silence = now - self.last_receive_time if self.last_receive_time else 0
        logger.debug("Heartbeat — received=%d parsed=%d failed=%d filtered=%d inserted=%d dropped=%d "
                     "flush_errors=%d parse_exc=%d enrich_exc=%d silence=%.0fs",
                     self.stats['received'], self.stats['parsed'], self.stats['failed'],
                     self.stats['filtered'], self.stats['inserted'], self.stats['dropped'],
                     self.stats['flush_errors'], self.stats['parse_exceptions'],
                     self.stats['enrich_exceptions'], silence)

        # Surface suppressed counts of rate-limited warnings after a burst ends
        flush_suppressed()

        # Warn if no packets received for a long time (gateway may have stopped sending)
        if self.last_receive_time and silence > 30:
            logger.warning("No UDP packets received for %.0fs — gateway may have stopped sending or port is unreachable", silence)


# ── Network identity gate ────────────────────────────────────────────────────

def _use_log_identity_detection(unifi_api: UniFiAPI) -> bool:
    """Return True when log-based WAN/gateway detection should run.

    One source of truth: the integration's effective enabled flag (env
    overrides, host and credentials included). UniFi is authoritative for
    identity only when it can actually poll, not merely when the DB flag is on.
    """
    return not unifi_api.enabled


def _refresh_network_identity_from_logs(db: Database, unifi_api: UniFiAPI,
                                        enricher: Enricher = None):
    """Run log-based WAN/gateway detection only when UniFi is not authoritative.

    After the detectors, the persisted identity (wan_ip_by_iface, wan_ips,
    wan_ip, gateway_ips) is compared with the tuple the receiver last loaded
    (_loaded_identity); when it differs, parsers reload and the enricher too
    when one is passed (startup passes none; the Enricher is built later and
    preloads from the DB). _loaded_identity is updated only after a
    successful reload, so a failed read or reload retries on the next run.

    Never raises: it runs at startup, as a scheduled job (schedule.run_pending()
    does not catch job exceptions, so one would end the scheduler thread) and
    from the scheduler tick.
    """
    global _loaded_identity
    try:
        if not _use_log_identity_detection(unifi_api):
            return
    except Exception as e:
        logger.error("Network identity refresh skipped (UniFi gate check failed): %s", e)
        return
    try:
        db.detect_wan_ip()
    except Exception as e:
        logger.error("WAN IP detection failed: %s", e)
    try:
        db.detect_gateway_ips()
    except Exception as e:
        logger.error("Gateway IP detection failed: %s", e)
    try:
        persisted = tuple(db.get_config(key) for key in _IDENTITY_KEYS)
        if persisted != _loaded_identity:
            parsers.reload_config_from_db(db)
            if enricher is not None:
                enricher.reload_config()
            _loaded_identity = persisted
    except Exception as e:
        logger.error("Reloading detected network identity failed, will retry: %s", e)


# ── Scheduler ─────────────────────────────────────────────────────────────────

def _retention_cleanup(db: Database):
    """Run a full retention cleanup pass. Called by the schedule library."""
    try:
        cfg = Database.resolve_retention_days(db)
        logger.info("Retention cleanup starting (general_retention=%d days, dns_retention=%d days)",
                    cfg.general, cfg.dns)
        result = db.run_retention_cleanup(cfg.general, cfg.dns)
        if result['status'] == 'partial':
            logger.warning("Retention cleanup partial: %d deleted, error: %s",
                           result['deleted_so_far'], result['error'])
        elif result['status'] == 'failed':
            logger.error("Retention cleanup failed: %s", result['error'])
    except Exception as e:
        logger.error("Retention cleanup failed: %s", e)

    # rdns_cache sweep — independent pass so a failure here is not misreported
    # as log-retention failure.
    try:
        deleted = db.cleanup_rdns_cache()
        if deleted:
            logger.info("rdns_cache retention sweep deleted %d rows", deleted)
    except Exception as e:
        logger.warning("rdns_cache retention sweep failed: %s", e)


def _register_retention_job(db: Database):
    """(Re-)register the daily retention cleanup with the saved time.

    MUST only be called on the scheduler thread — mutates the `schedule`
    module's job registry, which is not thread-safe.

    Tagged 'retention' so we can clear and re-register without touching the
    other scheduled jobs (stats, blacklist, auth cleanup, wan refresh).
    """
    schedule.clear('retention')
    cfg = Database.resolve_retention_time(db)
    (schedule.every()
             .day
             .at(cfg.time)   # 'HH:MM' — schedule library's native format
             .do(_retention_cleanup, db=db)
             .tag('retention'))
    logger.info("Retention cleanup scheduled daily at %s (source=%s, container-local time)",
                cfg.time, cfg.source)


def _scheduler_tick(db: Database, unifi_api: UniFiAPI = None, enricher: Enricher = None):
    """One iteration of the scheduler loop — extracted so tests can run it
    deterministically. Observes the retention-reload Event (set by the signal
    handler on another thread) and rebuilds the job before dispatching pending
    runs. All `schedule` registry mutation therefore stays on this thread.
    Also runs a requested identity refresh (see _identity_refresh_requested).
    """
    if _retention_reload_requested.is_set():
        _retention_reload_requested.clear()
        try:
            _register_retention_job(db)
        except Exception as e:
            # An exception here would end the scheduler thread; retry next tick.
            logger.error("Retention job rebuild failed, retrying next tick: %s", e)
            _retention_reload_requested.set()
    if _identity_refresh_requested.is_set():
        _identity_refresh_requested.clear()
        _refresh_network_identity_from_logs(db, unifi_api, enricher)
    schedule.run_pending()


def _reload_config(db: Database, unifi_api, pihole, enricher, receiver):
    """Reload runtime config from the database (SIGUSR2 body, testable).

    Requests the scheduler-thread follow-ups: the retention job rebuild
    always, and an identity refresh when the UniFi enabled flag changed or
    the set of configured WAN interfaces without a learned IP differs from
    the previous reload's. The trigger reads only the reloaded in-memory
    state (no extra DB IO in the signal handler). A removed interface does
    not trigger: pruning waits for the scheduled run.
    """
    global _last_missing_wan
    old_unifi = bool(unifi_api.enabled)
    # Each step runs on its own: a transient DB error in one must not leave
    # the others (or the scheduler follow-ups below) stale.
    steps = (
        ('parsers', lambda: parsers.reload_config_from_db(db)),
        ('unifi_api', unifi_api.reload_config),
        ('pihole', pihole.reload_config),
        ('enricher', enricher.reload_config),
        ('disabled log types', receiver._load_disabled_types),
    )
    for name, step in steps:
        try:
            step()
        except Exception as e:
            logger.error("Config reload step '%s' failed: %s", name, e)
    # scheduler thread will rebuild the retention job on its next tick
    _retention_reload_requested.set()
    missing = frozenset(parsers.WAN_INTERFACES - set(parsers.WAN_IP_BY_IFACE))
    if bool(unifi_api.enabled) != old_unifi or missing != _last_missing_wan:
        _identity_refresh_requested.set()
    _last_missing_wan = missing


def _handle_config_reload_signal(db: Database, unifi_api, pihole, enricher, receiver):
    """Apply a requested reload on the ingestion worker. Never raises.

    The SIGUSR2 handler only sets a flag so database/config IO cannot block
    the socket thread or interrupt it while a queue lock is held.
    """
    try:
        logger.info("Received SIGUSR2, reloading config from database...")
        _reload_config(db, unifi_api, pihole, enricher, receiver)

        # Write timestamp to confirm reload completed
        try:
            from pathlib import Path
            Path('/tmp/config_reloaded').write_text(str(time.time()))
        except Exception as e:
            logger.debug("Failed to write reload timestamp: %s", e)

        logger.info("Config reloaded: WAN=%s", parsers.WAN_INTERFACES)
    except Exception:
        logger.exception("Config reload failed")


def run_scheduler(db: Database, enricher: Enricher, unifi_api: UniFiAPI,
                  blacklist_fetcher: BlacklistFetcher = None):
    """Background thread for scheduled tasks (retention cleanup, stats, blacklist)."""

    def log_stats():
        # Output is DEBUG-only; skip the DB work when nobody can see it (#103).
        if not logger.isEnabledFor(logging.DEBUG):
            return
        try:
            db_stats = db.get_stats()
            enrich_stats = enricher.get_stats()
            logger.debug("DB stats — total: %s, last hour: %s", db_stats['total'], db_stats['last_hour'])
            logger.debug("Enrichment stats — %s", enrich_stats)
        except Exception as e:
            logger.error("Failed to get stats: %s", e)

    def pull_blacklist():
        if blacklist_fetcher:
            try:
                blacklist_fetcher.fetch_and_store()
            except Exception as e:
                logger.error("Blacklist pull failed: %s", e)

    def refresh_wan_ip():
        _refresh_network_identity_from_logs(db, unifi_api, enricher)

    schedule.every(STATS_INTERVAL_MINUTES).minutes.do(log_stats)
    schedule.every(WAN_REFRESH_INTERVAL_MINUTES).minutes.do(refresh_wan_ip)
    _register_retention_job(db)
    schedule.every().day.at("04:00").do(pull_blacklist)
    # auth_cleanup has its own internal try/except — no wrapper needed here.
    schedule.every().day.at("03:30").do(auth_cleanup)

    logger.info("Scheduler started — stats every %dm (DEBUG only), WAN refresh every %dm, "
                "blacklist daily at 04:00, auth cleanup daily at 03:30",
                STATS_INTERVAL_MINUTES, WAN_REFRESH_INTERVAL_MINUTES)

    # Initial blacklist pull after 30s startup delay
    time.sleep(30)
    pull_blacklist()

    while True:
        _scheduler_tick(db, unifi_api, enricher)
        time.sleep(10)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    # Build connection params from environment
    conn_params = build_conn_params()
    logger.info("Database: %s mode (host=%s:%s, db=%s)",
                "external" if is_external_db() else "embedded",
                conn_params['host'], conn_params['port'], conn_params['dbname'])

    # Wait for PostgreSQL
    wait_for_postgres(conn_params)

    # Initialize database
    db = Database(conn_params)
    db.connect()

    # Create performance indexes that require CONCURRENTLY (existing installs)
    db.ensure_post_boot_indexes()

    # Load system configuration and apply to parsers module
    # Check for existing user migration
    setup_complete = get_config(db, "setup_complete", None)
    if setup_complete is None:
        # Any firewall log means an existing installation
        if has_logs(db, 'firewall'):
            # Auto-migrate existing installation with safe defaults
            logger.info("Migrating existing installation to dynamic config...")
            set_config(db, "wan_interfaces", ["ppp0"])
            set_config(db, "interface_labels", {})  # Empty = use raw names
            set_config(db, "setup_complete", True)
            set_config(db, "config_version", 1)
            logger.info(
                "Migration complete with safe defaults (WAN=ppp0, labels=raw names). "
                "Users can customize via Settings → Reconfigure."
            )

    # Load config into parsers module
    parsers.reload_config_from_db(db)
    logger.info("Loaded config: WAN interfaces = %s", parsers.WAN_INTERFACES)

    # Initialize UniFi API client (self-disables when not configured). Built
    # before the identity refresh, which gates on its effective enabled flag;
    # construction only resolves config, polling starts further down.
    unifi_api = UniFiAPI(db=db)

    # Detect and persist WAN IP + gateway IPs from existing log data
    # (skipped when UniFi API is authoritative — identity comes from poll)
    _refresh_network_identity_from_logs(db, unifi_api)

    # Check config version for future migrations
    current_version = get_config(db, 'config_version', 0)
    if current_version < 1:
        # Future: handle config schema migrations
        pass

    # Initialize Pi-hole poller
    pihole = PiHolePoller(db=db, enricher=None)  # enricher set after creation

    # Initialize enrichment (with UniFi device name resolution)
    enricher = Enricher(db=db, unifi=unifi_api)

    # Wire enricher into Pi-hole poller (created before enricher for signal handler)
    pihole.set_enricher(enricher)

    # Start receiver
    receiver = SyslogReceiver(db, enricher)

    # Handle graceful shutdown
    def shutdown(signum, frame):
        logger.info("Received signal %d, shutting down...", signum)
        receiver.request_stop()

    # Handle GeoIP database reload
    def reload_geoip(signum, frame):
        logger.info("Received SIGUSR1, reloading GeoIP databases...")
        receiver.geoip_reload_requested = True

    # Handle config reload
    def reload_config(signum, frame):
        """Reload config from database when signaled by API process."""
        receiver.config_reload_requested = True

    receiver.config_reload_callback = lambda: _handle_config_reload_signal(
        db, unifi_api, pihole, enricher, receiver)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGUSR1, reload_geoip)
    signal.signal(signal.SIGUSR2, reload_config)

    # Start scheduler in background thread
    blacklist_fetcher = BlacklistFetcher(db)
    scheduler_thread = threading.Thread(target=run_scheduler,
                                        args=(db, enricher, unifi_api, blacklist_fetcher), daemon=True)
    scheduler_thread.start()

    # Start backfill daemon (queue-driven threat enrichment every 5 min)
    backfill = BackfillTask(db, enricher)
    backfill.start()

    # Start UniFi client/device polling (only runs if enabled)
    unifi_api.start_polling()

    # Start Pi-hole polling (only runs if enabled)
    pihole.start_polling()

    # Start receiving (blocks)
    try:
        receiver.start()
    except KeyboardInterrupt:
        pass  # start() already drains in its finally block
    finally:
        unifi_api.stop_polling()
        pihole.stop_polling()
        enricher.close()
        db.close()


if __name__ == '__main__':
    main()
