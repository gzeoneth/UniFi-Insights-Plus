"""
UniFi Log Insight - IP Enrichment

Enriches public IPs with:
- GeoIP (country, city, lat/lon) via MaxMind GeoLite2-City
- ASN (number, name) via MaxMind GeoLite2-ASN
- Threat score via AbuseIPDB (blocked firewall events only, cached 24h)
- Reverse DNS via PTR lookup (cached 24h)
"""

import os
import json
import math
import socket
import ipaddress
import logging
import time
import threading
import queue
from collections import OrderedDict
from typing import Optional

import requests

logger = logging.getLogger(__name__)

DEFAULT_TTL_SECONDS = 86400

# ── Bool-setting helpers (env + DB shared parsing) ───────────────────────────

_TRUE_TOKENS = ('1', 'true', 'yes', 'on')
_FALSE_TOKENS = ('0', 'false', 'no', 'off')


def _parse_bool_setting(value, default=None):
    """Strictly parse a bool setting. Accepts bool, integer 0/1, or recognised
    string tokens; otherwise returns default. Used for both env and DB values
    to defend against stringly-typed values arriving via config import
    (system_config bypasses the PUT-time validation in routes/setup.py).

    `default=None` lets callers distinguish "unrecognised" from "valid False":
      - validation paths pass default=None and treat None as a parse error
      - resolution paths pass default=True (or False) for fall-back semantics
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        token = value.strip().lower()
        if token in _TRUE_TOKENS:
            return True
        if token in _FALSE_TOKENS:
            return False
    return default


def _resolve_rdns_enabled(db) -> bool:
    """Resolve effective rdns_enabled flag. env > system_config > default(True).

    Unrecognised env values warn-and-fall-through to DB rather than silently
    disabling rDNS (a typo like RDNS_ENABLED=fasle must NOT disable lookups).
    Tolerates db=None (test paths, pre-init). Never raises.
    """
    # Local import: existing enrichment.py imports `get_config` lazily inside
    # methods. Keeping it local here preserves that convention and avoids
    # changing module import-time behaviour or risking a circular import.
    from db import get_config

    env = os.environ.get('RDNS_ENABLED')
    if env is not None:
        token = env.strip().lower()
        if token in _TRUE_TOKENS:
            return True
        if token in _FALSE_TOKENS:
            return False
        if token:
            logger.warning(
                "RDNS_ENABLED=%r not recognised; falling through to DB/default. "
                "Use one of: %s, %s",
                env, ', '.join(_TRUE_TOKENS), ', '.join(_FALSE_TOKENS),
            )
        # token == '' or unrecognised → fall through
    if db is None:
        return True
    try:
        return _parse_bool_setting(get_config(db, 'rdns_enabled', True), default=True)
    except Exception:
        logger.debug("Failed to read rdns_enabled from system_config", exc_info=True)
        return True


# ── Private/reserved IP detection ─────────────────────────────────────────────

def is_public_ip(ip_str: str) -> bool:
    """Check if an IP is public (not RFC1918, ULA, loopback, link-local, multicast).

    Works for both IPv4 and IPv6 addresses using Python's built-in is_global.
    """
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global and not ip.is_multicast
    except ValueError:
        return False


# ── AbuseIPDB stats retrieval ────────────────────────────────────────────────

def get_abuseipdb_stats(db):
    """Load AbuseIPDB rate-limit state from tmp file with DB fallback.

    Read order:
      1. /tmp/abuseipdb_stats.json  (written by receiver process each API call)
      2. system_config.abuseipdb_rate_limit  (persisted by enricher on shutdown)

    Returns dict with keys: limit, remaining, reset_at, paused_until, quota_reset_pending
    or None if no stats are available.
    """
    from db import get_config

    stats = None
    try:
        with open('/tmp/abuseipdb_stats.json', 'r') as f:
            stats = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    if not stats or stats.get('limit') is None:
        try:
            db_stats = get_config(db, 'abuseipdb_rate_limit')
            if db_stats:
                paused = db_stats.get('paused_until')
                pause_active = False
                if paused:
                    try:
                        pause_active = time.time() < float(paused)
                    except (ValueError, TypeError):
                        pass
                if db_stats.get('limit') is not None or pause_active:
                    stats = db_stats
        except Exception as e:
            logger.debug("Failed to read AbuseIPDB stats from DB: %s", e)
    return stats


# ── Thread-safe cache ─────────────────────────────────────────────────────────

class TTLCache:
    """Thread-safe TTL cache with optional LRU + watermark eviction."""

    def __init__(
        self,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        max_entries: Optional[int] = None,
        prune_trigger_ratio: float = 1.10,
        prune_target_ratio: float = 0.90,
    ):
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._cache = OrderedDict()
        self._lock = threading.Lock()
        if self.max_entries is not None:
            if self.max_entries <= 0:
                raise ValueError("max_entries must be positive")
            if prune_trigger_ratio < 1.0:
                raise ValueError("prune_trigger_ratio must be >= 1.0")
            if prune_target_ratio <= 0 or prune_target_ratio > 1.0:
                raise ValueError("prune_target_ratio must be within (0, 1]")
            trigger_count = math.ceil(self.max_entries * prune_trigger_ratio)
            target_count = math.floor(self.max_entries * prune_target_ratio)
            self._prune_trigger_count = max(self.max_entries, trigger_count)
            self._prune_target_count = max(1, min(self.max_entries, target_count))
        else:
            self._prune_trigger_count = None
            self._prune_target_count = None

    def _is_expired(self, entry_time: float, now: float) -> bool:
        return now - entry_time >= self.ttl

    def _prune_expired_locked(self, now: float):
        expired_keys = [
            key for key, entry in self._cache.items()
            if self._is_expired(entry['time'], now)
        ]
        for key in expired_keys:
            self._cache.pop(key, None)

    def _evict_overflow_locked(self):
        while len(self._cache) > self._prune_target_count:
            self._cache.popitem(last=False)

    def get(self, key: str) -> Optional[dict]:
        with self._lock:
            entry = self._cache.get(key)
            if entry and not self._is_expired(entry['time'], time.time()):
                self._cache.move_to_end(key)
                return entry['value']
            elif entry:
                del self._cache[key]
            return None

    def set(self, key: str, value: dict):
        with self._lock:
            now = time.time()
            self._cache[key] = {'value': value, 'time': now}
            self._cache.move_to_end(key)
            if (self._prune_trigger_count is not None
                    and len(self._cache) >= self._prune_trigger_count):
                self._prune_expired_locked(now)
                if len(self._cache) > self.max_entries:
                    self._evict_overflow_locked()

    def size(self) -> int:
        with self._lock:
            return len(self._cache)

    def delete(self, key: str):
        with self._lock:
            self._cache.pop(key, None)


# ── GeoIP Enrichment ─────────────────────────────────────────────────────────

class GeoIPEnricher:
    """MaxMind lookups with a bounded cache of scalar result fields."""

    CACHE_MAX_ENTRIES = 8192
    CACHE_TTL_SECONDS = 3600

    def __init__(self, db_dir: str = '/app/maxmind'):
        self.city_reader = None
        self.asn_reader = None
        self.db_dir = db_dir
        self._reader_lock = threading.Lock()
        self._close_lock = threading.Lock()
        self._close_worker = None
        self._closed = False
        self._cache = self._new_cache()
        self._load_databases(db_dir)

    def _new_cache(self):
        return TTLCache(ttl_seconds=self.CACHE_TTL_SECONDS,
                        max_entries=self.CACHE_MAX_ENTRIES,
                        prune_trigger_ratio=1.0)

    @staticmethod
    def _close_readers(*readers):
        for reader in readers:
            if reader is not None:
                try:
                    reader.close()
                except Exception:
                    logger.debug("Failed to close MaxMind reader", exc_info=True)

    def _load_databases(self, db_dir: str):
        # File opening may wait on storage. Keep the working readers and cache
        # available while replacement files are opened in the reload worker.
        if self._closed:
            return False
        city_was_loaded = self.city_reader is not None
        asn_was_loaded = self.asn_reader is not None
        city_reader = asn_reader = None
        try:
            import geoip2.database
            city_path = os.path.join(db_dir, 'GeoLite2-City.mmdb')
            asn_path = os.path.join(db_dir, 'GeoLite2-ASN.mmdb')

            if os.path.exists(city_path):
                city_reader = geoip2.database.Reader(city_path)
                logger.info("Loaded GeoLite2-City database")
            else:
                logger.warning("GeoLite2-City.mmdb not found at %s", city_path)
                if city_was_loaded:
                    raise FileNotFoundError("Replacement GeoLite2-City database is missing")

            if os.path.exists(asn_path):
                asn_reader = geoip2.database.Reader(asn_path)
                logger.info("Loaded GeoLite2-ASN database")
            else:
                logger.warning("GeoLite2-ASN.mmdb not found at %s", asn_path)
                if asn_was_loaded:
                    raise FileNotFoundError("Replacement GeoLite2-ASN database is missing")
        except ImportError:
            self._close_readers(city_reader, asn_reader)
            logger.error("geoip2 package not installed")
            return False
        except Exception as e:
            self._close_readers(city_reader, asn_reader)
            logger.error("Failed to load MaxMind databases: %s", e)
            return False

        # Cold lookups hold this lock, so no lookup can still be using an old
        # mmap when it is closed. Cache hits never wait for a cold lookup.
        with self._reader_lock:
            if self._closed:
                old_city, old_asn = city_reader, asn_reader
                installed = False
            else:
                old_city, old_asn = self.city_reader, self.asn_reader
                self.city_reader, self.asn_reader = city_reader, asn_reader
                self._cache = self._new_cache()
                installed = True
        self._close_readers(old_city, old_asn)
        return installed

    def reload(self):
        """Replace readers and invalidate cached results after a successful load."""
        logger.info("Reloading MaxMind databases...")
        loaded = self._load_databases(self.db_dir)
        if loaded:
            logger.info("MaxMind databases reloaded")
        return loaded

    def lookup(self, ip_str: str) -> dict:
        """Return GeoIP/ASN fields without repeating MMDB work for hot IPs."""
        if self._closed:
            return {}
        cached = self._cache.get(ip_str)
        if cached is not None:
            return dict(cached)
        with self._reader_lock:
            if self._closed:
                return {}
            # A concurrent lookup or reload may have populated/replaced it.
            cache = self._cache
            cached = cache.get(ip_str)
            if cached is not None:
                return dict(cached)
            result, complete = self._lookup_readers(ip_str)
            if complete and not self._closed:
                cache.set(ip_str, dict(result))
            return result

    def _lookup_readers(self, ip_str):
        try:
            from geoip2.errors import AddressNotFoundError
        except ImportError:
            return {}, False

        result = {}
        complete = True
        if self.city_reader:
            try:
                resp = self.city_reader.city(ip_str)
                result['geo_country'] = resp.country.iso_code
                result['geo_city'] = resp.city.name
                if resp.location:
                    result['geo_lat'] = float(resp.location.latitude) if resp.location.latitude is not None else None
                    result['geo_lon'] = float(resp.location.longitude) if resp.location.longitude is not None else None
            except AddressNotFoundError:
                pass  # A real database miss can be cached until TTL/reload.
            except Exception:
                complete = False  # A transient failure must not poison the cache.

        if self.asn_reader:
            try:
                resp = self.asn_reader.asn(ip_str)
                result['asn_number'] = resp.autonomous_system_number
                result['asn_name'] = resp.autonomous_system_organization
            except AddressNotFoundError:
                pass
            except Exception:
                complete = False
        return result, complete

    def _finish_close(self):
        with self._reader_lock:
            old_city, old_asn = self.city_reader, self.asn_reader
            self.city_reader = self.asn_reader = None
        self._close_readers(old_city, old_asn)

    def close(self):
        # A cold mmap lookup can be stalled on host storage. Shutdown must not
        # wait for it or close its live reader. One daemon retires it afterward.
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
            self._cache = self._new_cache()
        if self._reader_lock.acquire(blocking=False):
            try:
                old_city, old_asn = self.city_reader, self.asn_reader
                self.city_reader = self.asn_reader = None
            finally:
                self._reader_lock.release()
            self._close_readers(old_city, old_asn)
        else:
            self._close_worker = threading.Thread(
                target=self._finish_close, name='geoip-close', daemon=True)
            self._close_worker.start()


# ── AbuseIPDB Enrichment ─────────────────────────────────────────────────────

class AbuseIPDBEnricher:
    """AbuseIPDB threat score lookups. Only for blocked firewall events."""

    API_URL = 'https://api.abuseipdb.com/api/v2/check'
    STATS_FILE = '/tmp/abuseipdb_stats.json'
    MEMORY_CACHE_MAX_ENTRIES = 5000

    def __init__(self, api_key: str = None, db=None):
        self.api_key = api_key if api_key is not None else os.environ.get('ABUSEIPDB_API_KEY', '')
        self.cache = TTLCache(
            ttl_seconds=DEFAULT_TTL_SECONDS,
            max_entries=self.MEMORY_CACHE_MAX_ENTRIES,
        )  # 24h in-memory hot cache
        # Repeated blocked packets must not read the same absent DB entry on
        # every event while the external provider has no budget. This stores
        # only a short retry delay, never a fabricated reputation result.
        self._quota_misses = TTLCache(ttl_seconds=15, max_entries=1024,
                                     prune_trigger_ratio=1.0)
        self.db = db  # Database instance for persistent threat cache
        self.enabled = bool(self.api_key)
        self._lock = threading.Lock()
        self.STALE_DAYS = 4  # Refresh from API after this many days
        self.SAFETY_BUFFER = 0  # No reserve — first come first serve

        # Rate limit state — None means unknown (not yet bootstrapped)
        # After first API call, these are set from response headers
        self._rate_limit_limit = None      # e.g. 1000
        self._rate_limit_remaining = None  # e.g. 743
        self._rate_limit_reset = None      # Unix timestamp (seconds)

        # Pause until this UTC timestamp on 429
        self._paused_until = 0.0

        # IPs to exclude from lookups (e.g. our own WAN IP)
        self._excluded_ips = set()

        if self.enabled:
            logger.info("AbuseIPDB enrichment enabled (safety buffer: %d)", self.SAFETY_BUFFER)
            self._load_persisted_stats()
            self._write_stats()
        else:
            logger.warning("AbuseIPDB API key not set — threat enrichment disabled")

    def _load_persisted_stats(self):
        """Restore rate limit state from database on startup.

        If reset_at has passed, treat quota as renewed.
        If paused_until has expired, clear it.
        Missing fields stay None to preserve bootstrap semantics.
        """
        if not self.db:
            return
        try:
            stats = self.db.get_config('abuseipdb_rate_limit')
            if not stats:
                return

            # Restore pause even if limit is None (429 before first success)
            paused = stats.get('paused_until')
            if paused and float(paused) > time.time():
                self._paused_until = float(paused)
            else:
                self._paused_until = 0.0

            # Only restore rate limit fields if we have real data
            if stats.get('limit') is None:
                if self._paused_until > 0:
                    logger.info(
                        "AbuseIPDB: restored pause (until %s), no rate limit data yet",
                        time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self._paused_until))
                    )
                return

            self._rate_limit_limit = stats.get('limit')
            self._rate_limit_remaining = stats.get('remaining')
            self._rate_limit_reset = stats.get('reset_at')

            # If reset_at has passed, quota is renewed
            if self._rate_limit_reset is not None:
                try:
                    if time.time() > float(self._rate_limit_reset):
                        logger.info(
                            "AbuseIPDB: persisted reset_at %s has passed, "
                            "restoring quota to %s",
                            self._rate_limit_reset, self._rate_limit_limit
                        )
                        self._rate_limit_remaining = self._rate_limit_limit
                        self._rate_limit_reset = None
                        self._paused_until = 0.0
                except (ValueError, TypeError):
                    pass

            logger.info(
                "AbuseIPDB: restored persisted stats "
                "(limit=%s, remaining=%s, reset_at=%s)",
                self._rate_limit_limit,
                self._rate_limit_remaining,
                self._rate_limit_reset,
            )
        except Exception as e:
            logger.warning("Failed to load persisted AbuseIPDB stats: %s", e)

    def exclude_ip(self, ip_str: str):
        """Add an IP to the exclusion list (e.g. our own WAN IP)."""
        if ip_str:
            self._excluded_ips.add(ip_str)
            logger.info("AbuseIPDB: excluding IP %s from lookups", ip_str)

    def _check_rate_limit(self) -> bool:
        """Check if we can make an API call.
        
        Uses AbuseIPDB's own headers as the single source of truth.
        On first call after startup, remaining is None → allow it to bootstrap.
        """
        with self._lock:
            # Hard pause from 429
            if time.time() < self._paused_until:
                return False

            # Check if quota has reset (reset_at has passed)
            if self._rate_limit_reset is not None:
                try:
                    reset_ts = float(self._rate_limit_reset)
                    if time.time() > reset_ts:
                        # Quota has renewed — restore to known limit
                        logger.info("AbuseIPDB quota reset (reset_at %s has passed)", self._rate_limit_reset)
                        self._rate_limit_remaining = self._rate_limit_limit  # e.g. 1000; None if unknown
                        self._rate_limit_reset = None
                        self._paused_until = 0.0
                        self._write_stats()  # Persist so API process sees the reset
                except (ValueError, TypeError):
                    pass

            # Unknown state (startup or after reset) → allow one call to bootstrap
            if self._rate_limit_remaining is None:
                return True

            # Gate on real remaining with safety buffer
            return self._rate_limit_remaining > self.SAFETY_BUFFER

    @property
    def remaining_budget(self) -> int:
        """How many API calls we can still make this period.

        Used by backfill to limit orphan lookups.
        Returns 0 if unknown or exhausted.
        """
        self._check_rate_limit()  # Detect daily reset before reading state
        with self._lock:
            if self._rate_limit_remaining is None:
                return 0  # Unknown — don't let backfill guess
            return max(0, self._rate_limit_remaining - self.SAFETY_BUFFER)

    def is_rate_limit_known(self) -> bool:
        """True once rate-limit state is bootstrapped from an API response.

        Lets callers tell an exhausted budget (known, 0) from an unknown one
        (remaining_budget also returns 0 before the first call).
        """
        with self._lock:
            return self._rate_limit_remaining is not None

    def _update_rate_limits(self, resp_headers):
        """Update rate limit state from AbuseIPDB response headers."""
        with self._lock:
            limit = resp_headers.get('X-RateLimit-Limit')
            remaining = resp_headers.get('X-RateLimit-Remaining')
            reset_ts = resp_headers.get('X-RateLimit-Reset')
            if limit is not None:
                self._rate_limit_limit = int(limit)
            if remaining is not None:
                self._rate_limit_remaining = int(remaining)
            if reset_ts is not None:
                self._rate_limit_reset = reset_ts

    def _write_stats(self):
        """Write rate limit stats to shared file for API/UI to read,
        and persist to database for survival across restarts."""
        stats = {
            'limit': self._rate_limit_limit,
            'remaining': self._rate_limit_remaining,
            'reset_at': self._rate_limit_reset,
            'paused_until': self._paused_until if self._paused_until > time.time() else None,
            'updated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        }
        # IPC: tmp file for API process
        try:
            with open(self.STATS_FILE, 'w') as f:
                json.dump(stats, f)
        except Exception:
            pass  # Non-critical, don't break enrichment
        # Persistence: DB for restart survival
        # Persist when we have real rate limit data OR an active pause (429
        # before first successful call still needs to survive restarts)
        should_persist = (self._rate_limit_limit is not None
                          or self._paused_until > time.time())
        if self.db and should_persist:
            try:
                self.db.set_config('abuseipdb_rate_limit', stats)
            except Exception:
                pass

    def quota_miss_active(self, ip_str: str) -> bool:
        """Memory-only retry check, safe on the ingestion worker.

        A renewed/unknown budget bypasses the delay immediately. Do not call
        _check_rate_limit here: quota reset persistence can perform file/DB I/O.
        """
        if self._quota_misses.get(ip_str) is None:
            return False
        now = time.time()
        # The provider can hold this lock while persisting a quota reset. Skip
        # this optional optimization rather than make intake wait for that I/O.
        if not self._lock.acquire(blocking=False):
            return False
        try:
            if now < self._paused_until:
                return True
            if self._rate_limit_reset is not None:
                try:
                    if now > float(self._rate_limit_reset):
                        return False
                except (TypeError, ValueError):
                    pass
            return (self._rate_limit_remaining is not None
                    and self._rate_limit_remaining <= self.SAFETY_BUFFER)
        finally:
            self._lock.release()

    def lookup(self, ip_str: str, *, bypass_cooldown: bool = False) -> dict:
        """Check an IP against AbuseIPDB. Returns threat_score and categories.
        
        Lookup order:
        1. In-memory cache (hot path, no I/O)
        2. DB ip_threats table (< 4 days old)
        3. AbuseIPDB API (writes back to DB + memory cache)
        """
        if not self.enabled:
            return {}

        # Skip excluded IPs (our WAN IP)
        if ip_str in self._excluded_ips:
            return {}

        # 1. Check in-memory cache
        cached = self.cache.get(ip_str)
        if cached is not None:
            return cached
        if not bypass_cooldown and self.quota_miss_active(ip_str):
            return {}

        # 2. Check persistent DB cache
        db_missed = self.db is None
        if self.db:
            try:
                db_result = self.db.get_threat_cache(ip_str, max_age_days=self.STALE_DAYS)
                if db_result:
                    self.cache.set(ip_str, db_result)  # Promote to memory cache
                    return db_result
                db_missed = True
            except Exception as e:
                logger.debug("DB threat cache lookup failed for %s: %s", ip_str, e)

        # 3. Check rate limit before API call
        if not self._check_rate_limit():
            if db_missed:
                self._quota_misses.set(ip_str, {})
            return {}

        try:
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json',
            }
            params = {
                'ipAddress': ip_str,
                'maxAgeInDays': 90,
                'verbose': 'true',
            }
            resp = requests.get(self.API_URL, headers=headers, params=params, timeout=5)

            # Handle 429 — pause until reset
            if resp.status_code == 429:
                with self._lock:
                    retry_after = resp.headers.get('Retry-After')
                    reset_ts = resp.headers.get('X-RateLimit-Reset')
                    if retry_after:
                        self._paused_until = time.time() + int(retry_after)
                    elif reset_ts:
                        try:
                            self._paused_until = float(reset_ts)
                        except (ValueError, TypeError):
                            self._paused_until = time.time() + 3600
                    else:
                        self._paused_until = time.time() + 3600  # fallback: 1h
                    self._rate_limit_remaining = 0
                logger.warning("AbuseIPDB 429 — paused until %s",
                             time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self._paused_until)))
                self._write_stats()
                if db_missed:
                    self._quota_misses.set(ip_str, {})
                return {}

            resp.raise_for_status()
            data = resp.json().get('data', {})

            # Aggregate categories from all reports (verbose mode)
            all_cats = set()
            for report in data.get('reports', []):
                for cat in report.get('categories', []):
                    all_cats.add(str(cat))

            result = {
                'threat_score': data.get('abuseConfidenceScore', 0),
                'threat_categories': sorted(all_cats),
            }

            # Extra AbuseIPDB detail fields
            usage_type = data.get('usageType')
            if usage_type:
                result['abuse_usage_type'] = usage_type

            hostnames = data.get('hostnames', [])
            if hostnames:
                result['abuse_hostnames'] = ', '.join(hostnames)

            total_reports = data.get('totalReports')
            if total_reports is not None:
                result['abuse_total_reports'] = total_reports

            last_reported = data.get('lastReportedAt')
            if last_reported:
                result['abuse_last_reported'] = last_reported

            is_whitelisted = data.get('isWhitelisted')
            if is_whitelisted:
                result['abuse_is_whitelisted'] = True

            is_tor = data.get('isTor')
            if is_tor:
                result['abuse_is_tor'] = True

            # Update rate limits from response headers (source of truth)
            self._update_rate_limits(resp.headers)

            # Persist to DB and memory cache
            if self.db:
                try:
                    self.db.upsert_threat(ip_str, result)
                except Exception as e:
                    logger.debug("DB threat cache write failed for %s: %s", ip_str, e)

            self._write_stats()
            self.cache.set(ip_str, result)
            return result

        except requests.Timeout:
            logger.warning("AbuseIPDB timeout for %s", ip_str)
        except requests.RequestException as e:
            logger.warning("AbuseIPDB error for %s: %s", ip_str, e)
        except Exception as e:
            logger.error("AbuseIPDB unexpected error: %s", e)

        return {}

    @property
    def daily_usage(self) -> int:
        """Derived from API headers: limit - remaining."""
        with self._lock:
            if self._rate_limit_limit is None or self._rate_limit_remaining is None:
                return 0
            return self._rate_limit_limit - self._rate_limit_remaining


# ── Reverse DNS ───────────────────────────────────────────────────────────────

class RDNSEnricher:
    """Reverse DNS (PTR) lookups with two-tier caching (in-memory + DB).

    See issue #98 — the DB cold tier survives container restarts and the per-
    status TTLs let durable failures be cached longer than transient flaps.
    """

    MEMORY_CACHE_MAX_ENTRIES = 20000

    POSITIVE_TTL_SECONDS = 86400            # 24h — successful resolution
    NEGATIVE_TTL_SECONDS = 7 * 86400        # 7d  — durable DNS-layer failure
    TRANSIENT_TTL_SECONDS = 3600            # 1h  — transient (flap, TRY_AGAIN, OSError)
    _TTL_BY_STATUS = {
        'success': POSITIVE_TTL_SECONDS,
        'failure': NEGATIVE_TTL_SECONDS,
        'transient': TRANSIENT_TTL_SECONDS,
    }
    _TRY_AGAIN_HERRNO = 2  # netdb.h: TRY_AGAIN — transient name-server failure

    def __init__(self, timeout: float = 2.0, db=None):
        self.timeout = timeout
        # Cache ceiling = longest TTL so per-status expires_at decides freshness
        # without being capped by a shorter cache-wide TTL.
        self.cache = TTLCache(
            ttl_seconds=self.NEGATIVE_TTL_SECONDS,
            max_entries=self.MEMORY_CACHE_MAX_ENTRIES,
        )
        self._db = db
        self._db_failed = False  # one-shot WARNING de-duplication

    def _db_get(self, ip_str: str) -> Optional[dict]:
        """Wrap DB read with fault-tolerance. Never raises."""
        if self._db is None:
            return None
        try:
            return self._db.get_rdns_cache(ip_str)
        except Exception:
            if not self._db_failed:
                logger.warning(
                    "rdns_cache DB read failed (degrading to memory-only)",
                    exc_info=True,
                )
                self._db_failed = True
            else:
                logger.debug("rdns_cache DB read failed", exc_info=True)
            return None

    def _db_set(self, ip_str: str, hostname: Optional[str], status: str):
        """Wrap DB write with fault-tolerance. Never raises."""
        if self._db is None:
            return
        try:
            self._db.set_rdns_cache(ip_str, hostname, status)
        except Exception:
            if not self._db_failed:
                logger.warning(
                    "rdns_cache DB write failed (degrading to memory-only)",
                    exc_info=True,
                )
                self._db_failed = True
            else:
                logger.debug("rdns_cache DB write failed", exc_info=True)

    def lookup(self, ip_str: str) -> dict:
        """Perform rDNS lookup. Returns {'rdns': hostname} or {'rdns': None}.

        Hot tier (in-memory) → cold tier (DB) → live PTR. Per-status TTL.
        Public return shape never leaks internal status/expires_at.
        """
        now = time.time()

        # Hot tier — honour per-entry expires_at, not cache-wide TTL
        entry = self.cache.get(ip_str)
        if entry is not None:
            if now < entry.get('expires_at', 0):
                return {'rdns': entry.get('rdns')}
            # Stale per status; free memory and fall through
            self.cache.delete(ip_str)

        # Cold tier — DB read-through. Do NOT rewrite looked_up_at on hit.
        row = self._db_get(ip_str)
        if row is not None:
            status = row.get('status')
            ttl = self._TTL_BY_STATUS.get(status)
            age = row.get('age_seconds') or 0
            if ttl is not None and age < ttl:
                # Use REMAINING DB lifetime so a near-expired DB row is not
                # extended in memory after a restart/read-through.
                expires_at = now + max(0, ttl - age)
                # Only success rows expose hostname; defend against a stale
                # hostname stored alongside a failure/transient status.
                hostname = row.get('hostname') if status == 'success' else None
                self.cache.set(ip_str, {
                    'rdns': hostname,
                    'status': status,
                    'expires_at': expires_at,
                })
                return {'rdns': hostname}

        # Live PTR — preserve existing 2s contract via setdefaulttimeout, but
        # save/restore the prior default so unrelated threads don't inherit
        # our PTR timeout on subsequent socket creation.
        prior_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.timeout)
        try:
            try:
                hostname, _, _ = socket.gethostbyaddr(ip_str)
                status = 'success'
                value_rdns = hostname
            except socket.gaierror as e:
                status = 'transient' if e.errno == socket.EAI_AGAIN else 'failure'
                value_rdns = None
            except socket.herror as e:
                status = 'transient' if (e.args and e.args[0] == self._TRY_AGAIN_HERRNO) else 'failure'
                value_rdns = None
            except (socket.timeout, OSError):
                status = 'transient'
                value_rdns = None
        finally:
            socket.setdefaulttimeout(prior_timeout)

        # Write to BOTH tiers
        self._db_set(ip_str, value_rdns, status)
        self.cache.set(ip_str, {
            'rdns': value_rdns,
            'status': status,
            'expires_at': time.time() + self._TTL_BY_STATUS[status],
        })
        return {'rdns': value_rdns}


# ── Main Enrichment Pipeline ──────────────────────────────────────────────────

class Enricher:
    """Orchestrates all enrichment for a parsed log entry."""

    # Coalescing TTL for touch/enqueue DB writes (seconds)
    _COALESCE_TTL = 60.0
    # Max entries before lazy-pruning the coalescing map
    _COALESCE_MAP_MAX_SIZE = 256

    def __init__(self, db=None, unifi=None):
        self.geoip = GeoIPEnricher()
        self.abuseipdb = AbuseIPDBEnricher(db=db)
        self.rdns = RDNSEnricher(db=db)
        self.unifi = unifi
        self._db = db
        self._known_wan_ip = None
        self._excluded_ips = set()  # WAN IPs, gateway IPs — not enrichable
        self._pihole_enrichment = 'both'  # none|geoip|threat|both
        self._recently_touched = {}
        self._touch_lock = threading.Lock()
        self._vpn_networks = []
        # One bounded daemon warms network caches. A stalled libc DNS lookup
        # consumes this worker only; it cannot stall UDP intake or DB delivery.
        from ingest_queue import positive_env
        self._network_queue = queue.Queue(maxsize=positive_env('ENRICHMENT_QUEUE_CAPACITY', 256, 4096))
        self._network_pending = set()
        self._network_lock = threading.Lock()
        self._network_stop = threading.Event()
        self._network_thread = None
        self._network_dropped = 0
        self._network_completed = 0
        self._provider_last_success = {}
        self._provider_last_error = {}

        # Pre-load WAN/gateway exclusions and pihole config from DB so
        # background threads (backfill) have exclusions before the first
        # enrich() call
        self._load_identity_exclusions()
        if db:
            try:
                from db import get_config
                value = get_config(db, 'pihole_enrichment', 'both')
                self._pihole_enrichment = value if value in ('none', 'geoip', 'threat', 'both') else 'both'
            except Exception:
                logger.debug("Failed to pre-load pihole_enrichment from DB", exc_info=True)

        # rDNS opt-out toggle: env > system_config > default(True)
        self._rdns_enabled = _resolve_rdns_enabled(db)
        self._load_vpn_networks()

    def _load_identity_exclusions(self):
        """Add persisted WAN and gateway IPs to the exclusion sets (additive).

        WAN IPs go to both this enricher's and the AbuseIPDB enricher's
        exclusions; gateway IPs only to this enricher's. Called at init, when
        enrich() sees a new WAN IP, and from reload_config(). No-op without a
        db; DB errors are logged at debug and leave the sets unchanged.
        """
        if not self._db:
            return
        try:
            from db import get_config, get_wan_ips_from_config
            for ip in get_wan_ips_from_config(self._db):
                self._excluded_ips.add(ip)
                if ip not in self.abuseipdb._excluded_ips:
                    self.abuseipdb.exclude_ip(ip)
            for ip in get_config(self._db, 'gateway_ips') or []:
                self._excluded_ips.add(ip)
        except Exception:
            logger.debug("Failed to load WAN/gateway exclusions from DB", exc_info=True)

    def _is_remote_ip(self, ip_str: str) -> bool:
        """Check if IP is remote (enrichable): public, not our WAN, not gateway."""
        if not ip_str:
            return False
        if not is_public_ip(ip_str):
            return False
        if ip_str in self._excluded_ips:
            return False
        return True

    def _load_vpn_networks(self):
        if self._db:
            try:
                from db import get_config, parse_vpn_config
                self._vpn_networks = parse_vpn_config(get_config(self._db, 'vpn_networks'))
            except Exception:
                logger.debug("Failed to reload VPN networks", exc_info=True)

    def _is_recently_touched(self, ip: str) -> bool:
        now = time.monotonic()
        with self._touch_lock:
            ts = self._recently_touched.get(ip)
            return ts is not None and now - ts < self._COALESCE_TTL

    def _mark_touched(self, ip):
        with self._touch_lock:
            if len(self._recently_touched) >= self._COALESCE_MAP_MAX_SIZE:
                self._recently_touched.pop(next(iter(self._recently_touched)))
            self._recently_touched[ip] = time.monotonic()

    def _touch_threat_coalesced(self, ip: str):
        if self._db and not self._is_recently_touched(ip):
            try:
                self._db.touch_threat_last_seen(ip)
            except Exception:
                logger.debug("touch_threat_last_seen failed for %s", ip, exc_info=True)
            self._mark_touched(ip)

    def _defer_network(self, ip, rdns, threat, policy=False):
        if not (rdns or threat or policy) or self._network_stop.is_set():
            return
        key = (ip, rdns, threat, policy)
        with self._network_lock:
            if key in self._network_pending:
                return
            try:
                self._network_queue.put_nowait(key)
            except queue.Full:
                self._network_dropped += 1
                return
            self._network_pending.add(key)
            if self._network_thread is None:
                self._network_thread = threading.Thread(
                    target=self._network_loop, name='network-enrichment', daemon=True)
                self._network_thread.start()

    def _network_loop(self):
        while not self._network_stop.is_set():
            try:
                key = self._network_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            ip, rdns, threat, policy = key
            try:
                if policy:
                    from firewall_policy_matcher import _get_snapshot
                    _get_snapshot(self.unifi, vpn_networks=self._vpn_networks)
                    continue
                if not self._is_remote_ip(ip):
                    continue
                if rdns and self._rdns_enabled:
                    self.rdns.lookup(ip)
                    entry = self.rdns.cache.get(ip)
                    if entry and entry.get('status') == 'transient':
                        self._provider_last_error['rdns'] = time.time()
                    else:
                        self._provider_last_success['rdns'] = time.time()
                if threat:
                    data = self.abuseipdb.lookup(ip)
                    if data:
                        self._provider_last_success['abuseipdb'] = time.time()
                        self._touch_threat_coalesced(ip)
                    elif self.abuseipdb.enabled and self.abuseipdb.remaining_budget > 0:
                        self._provider_last_error['abuseipdb'] = time.time()
                    # Existing backfill patches cold first events from the
                    # persistent threat cache, even when this lookup succeeded.
                    if self.abuseipdb.enabled and self._db and not self._is_recently_touched('queue:' + ip):
                        self._db.enqueue_threat_backfill(ip, source='live_miss')
                        self._mark_touched('queue:' + ip)
            except Exception:
                provider = 'unifi' if policy else ('rdns' if rdns else 'abuseipdb')
                self._provider_last_error[provider] = time.time()
                logger.debug("Deferred network enrichment failed", exc_info=True)
            finally:
                with self._network_lock:
                    self._network_pending.discard(key)
                    self._network_completed += 1
                self._network_queue.task_done()

    def network_stats(self):
        with self._network_lock:
            return {'depth': self._network_queue.qsize(), 'capacity': self._network_queue.maxsize,
                    'pending': len(self._network_pending), 'dropped': self._network_dropped,
                    'completed': self._network_completed,
                    'worker_alive': bool(self._network_thread and self._network_thread.is_alive())}

    def provider_stats(self):
        """Local process observations only; never probe a provider for health."""
        with self._network_lock:
            pending = {'rdns': any(key[1] for key in self._network_pending),
                       'abuseipdb': any(key[2] for key in self._network_pending)}
        def network(name, configured):
            success = self._provider_last_success.get(name)
            error = self._provider_last_error.get(name)
            if not configured:
                status = 'not_configured'
            elif error and (not success or error > success):
                status = 'error'
            elif pending.get(name):
                status = 'pending'
            else:
                status = 'ready'
            return {'status': status, 'last_success_at': success, 'last_error_at': error}
        result = {
            'geoip': {'status': 'ready' if self.geoip.city_reader is not None else 'missing'},
            'asn': {'status': 'ready' if self.geoip.asn_reader is not None else 'missing'},
            'rdns': network('rdns', self._rdns_enabled),
            'abuseipdb': network('abuseipdb', self.abuseipdb.enabled),
        }
        if self.abuseipdb.enabled and (self.abuseipdb._paused_until > time.time()
                                     or self.abuseipdb._rate_limit_remaining == 0):
            result['abuseipdb']['status'] = 'pending'
        if not self.unifi or not self.unifi.enabled:
            result['unifi'] = {'status': 'not_configured'}
        elif getattr(self.unifi, '_last_poll_error', None):
            result['unifi'] = {'status': 'error'}
        elif getattr(self.unifi, '_last_poll', None) is None:
            result['unifi'] = {'status': 'pending'}
        else:
            result['unifi'] = {'status': 'ready'}
        return result

    def enrich(self, parsed: dict, defer_network: bool = False) -> dict:
        """Enrich a parsed log entry with GeoIP, ASN, threat, and rDNS data.

        Strategy:
        - GeoIP + ASN: all remote public IPs (local lookups, fast)
        - AbuseIPDB: only blocked firewall events with remote public IPs
        - rDNS: all remote public IPs

        WAN and gateway IPs are excluded — they belong to us, not the remote party.
        """
        # Auto-exclude WAN IPs (v4 + v6) from enrichment as they're learned
        from parsers import get_wan_ip
        wan_ip = get_wan_ip()
        if wan_ip and wan_ip != self._known_wan_ip:
            self._known_wan_ip = wan_ip
            self._excluded_ips.add(wan_ip)
            self.abuseipdb.exclude_ip(wan_ip)
            # The ingestion worker only reads cached parser identity. Scheduled
            # refresh/reload keeps persisted gateway and WAN exclusions current.
            if not defer_network:
                self._load_identity_exclusions()
        if defer_network:
            from parsers import WAN_IPS
            self._excluded_ips.update(WAN_IPS)

        # Determine which IP to enrich — the remote party, not our infrastructure
        ip_to_enrich = None
        src_ip = parsed.get('src_ip')
        dst_ip = parsed.get('dst_ip')
        src_remote = self._is_remote_ip(src_ip)
        dst_remote = self._is_remote_ip(dst_ip)

        # Device name resolution (private IPs) — runs BEFORE public IP guard
        # so inter-VLAN and local-only traffic still gets device names
        if self.unifi and self.unifi.enabled:
            try:
                if src_ip and not src_remote:
                    parsed['src_device_name'] = (
                        self.unifi.resolve_name(ip=src_ip, mac=parsed.get('mac_address'))
                        or parsed.get('src_device_name')
                    )
                if dst_ip and not dst_remote:
                    parsed['dst_device_name'] = (
                        self.unifi.resolve_name(ip=dst_ip)
                        or parsed.get('dst_device_name')
                    )
            except Exception:
                logger.debug("Device name resolution failed for src=%s dst=%s", src_ip, dst_ip, exc_info=True)

        # Resolve rule_action from policy metadata for zone_index format rules.
        # At parse time, derive_action() may have set rule_action from desc_hint
        # (e.g. 'block' from "Block Unauthorized Traffic"). The policy metadata
        # is authoritative and should override the desc_hint when available.
        if (parsed.get('log_type') == 'firewall'
                and parsed.get('event_source') != 'unifi_ips'
                and self.unifi and self.unifi.enabled):
            try:
                from firewall_policy_matcher import parse_firewall_rule, resolve_rule_action
                parsed_rule = parse_firewall_rule(
                    parsed.get('rule_name'),
                    rule_desc=parsed.get('rule_desc'),
                )
                if parsed_rule and parsed_rule['format'] == 'zone_index':
                    action = resolve_rule_action(
                        parsed_rule, self.unifi,
                        interface_in=parsed.get('interface_in', ''),
                        interface_out=parsed.get('interface_out', ''),
                        vpn_networks=self._vpn_networks,
                        cached_only=defer_network,
                    )
                    if defer_network and not self._is_recently_touched('policy'):
                        self._defer_network(None, False, False, policy=True)
                        self._mark_touched('policy')
                    if action:
                        parsed['rule_action'] = action
            except Exception:
                logger.debug("Policy-based action resolution failed for %s",
                             parsed.get('rule_name'), exc_info=True)

        direction = parsed.get('direction')
        if direction == 'outbound' and dst_remote:
            ip_to_enrich = dst_ip
        elif direction == 'inbound' and src_remote:
            ip_to_enrich = src_ip
        elif src_remote and not dst_remote:
            ip_to_enrich = src_ip
        elif dst_remote and not src_remote:
            ip_to_enrich = dst_ip
        elif src_remote and dst_remote:
            ip_to_enrich = src_ip

        parsed['remote_ip'] = ip_to_enrich
        if not ip_to_enrich:
            return parsed

        # GeoIP + ASN (always, local lookup — unless pihole with geoip disabled)
        is_pihole = parsed.get('source') == 'pihole'
        if not is_pihole or self._pihole_enrichment in ('geoip', 'both'):
            geo_data = self.geoip.lookup(ip_to_enrich)
            parsed.update(geo_data)

        if defer_network:
            wants_rdns = not is_pihole and self._rdns_enabled
            wants_threat = ((is_pihole and self._pihole_enrichment in ('threat', 'both'))
                            or (parsed.get('log_type') == 'firewall' and parsed.get('rule_action') == 'block'))
            rdns_cached = self.rdns.cache.get(ip_to_enrich) if wants_rdns else None
            rdns_fresh = rdns_cached is not None and time.time() < rdns_cached.get('expires_at', 0)
            if rdns_fresh and rdns_cached.get('rdns'):
                parsed['rdns'] = rdns_cached['rdns']
            threat_cached = self.abuseipdb.cache.get(ip_to_enrich) if wants_threat else None
            if threat_cached:
                parsed.update(threat_cached)
            self._defer_network(ip_to_enrich, wants_rdns and not rdns_fresh,
                                wants_threat and self.abuseipdb.enabled and not threat_cached
                                and not self.abuseipdb.quota_miss_active(ip_to_enrich))
            return parsed

        # rDNS (skip for pihole — domain already in dns_query, or operator opt-out)
        if not is_pihole and self._rdns_enabled:
            rdns_data = self.rdns.lookup(ip_to_enrich)
            if rdns_data.get('rdns'):
                parsed['rdns'] = rdns_data['rdns']

        # AbuseIPDB (blocked firewall events, or pihole with threat enabled)
        if (is_pihole and self._pihole_enrichment in ('threat', 'both')):
            threat_data = self.abuseipdb.lookup(ip_to_enrich)
            if threat_data:
                parsed.update(threat_data)
                self._touch_threat_coalesced(ip_to_enrich)
        elif (parsed.get('log_type') == 'firewall'
                and parsed.get('rule_action') == 'block'):
            threat_data = self.abuseipdb.lookup(ip_to_enrich)
            if threat_data:
                parsed.update(threat_data)
                self._touch_threat_coalesced(ip_to_enrich)
            elif self.abuseipdb.enabled and self._db:
                # Enqueue for deferred lookup — coalesced, only when AbuseIPDB is configured
                if not self._is_recently_touched(ip_to_enrich):
                    try:
                        self._db.enqueue_threat_backfill(ip_to_enrich, source='live_miss')
                    except Exception:
                        logger.debug("enqueue_threat_backfill failed for %s", ip_to_enrich, exc_info=True)
                    self._mark_touched(ip_to_enrich)

        return parsed

    def get_stats(self) -> dict:
        """Return enrichment cache stats."""
        return {
            'geoip_loaded': self.geoip.city_reader is not None,
            'asn_loaded': self.geoip.asn_reader is not None,
            'abuseipdb_enabled': self.abuseipdb.enabled,
            'abuseipdb_daily_usage': self.abuseipdb.daily_usage,
            'abuseipdb_cache_size': self.abuseipdb.cache.size(),
            'rdns_cache_size': self.rdns.cache.size(),
        }

    def close(self):
        self._network_stop.set()
        if self._network_thread:
            self._network_thread.join(timeout=0.5)
        self.geoip.close()

    def reload_config(self):
        """Reload enrichment config from DB (called via SIGUSR2)."""
        if self._db:
            try:
                from db import get_config
                value = get_config(self._db, 'pihole_enrichment', 'both')
                self._pihole_enrichment = value if value in ('none', 'geoip', 'threat', 'both') else 'both'
            except Exception:
                logger.debug("Failed to reload pihole_enrichment config", exc_info=True)
        # rDNS toggle reload — env stays authoritative on reload as well.
        self._rdns_enabled = _resolve_rdns_enabled(self._db)
        self._load_vpn_networks()
        # Pick up WAN/gateway identity learned since start (detection or UniFi)
        self._load_identity_exclusions()

    def reload_geoip(self):
        """Reload GeoIP databases (called via SIGUSR1)."""
        return self.geoip.reload()
