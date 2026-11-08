"""
UniFi Log Insight - Pi-hole v6 API Poller

Polls a Pi-hole v6 instance for DNS query logs, maps them to the standard
log schema, enriches with GeoIP/threat data, and inserts via the shared
Database class.
"""

import ipaddress
import json
import logging
import os
import socket
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

import warnings

import requests
import urllib3

from db import encrypt_api_key, decrypt_api_key

# Suppress InsecureRequestWarning process-wide. This affects ALL urllib3
# callers, not just this module. Acceptable here because the only session
# with verify=False is the Pi-hole session (self-signed certs).
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# Pi-hole query status -> (rule_action, rule_desc)
_STATUS_MAP = {
    'FORWARDED':      ('allow', 'FORWARDED'),
    'CACHE':          ('allow', 'CACHE'),
    'RETRIED':        ('allow', 'RETRIED'),
    'RETRIED_DNSSEC': ('allow', 'RETRIED_DNSSEC'),
    'ALREADY_FORWARDED': ('allow', 'ALREADY_FORWARDED'),
    'GRAVITY':        ('block', 'GRAVITY'),
    'REGEX':          ('block', 'REGEX'),
    'DENYLIST':       ('block', 'DENYLIST'),
    'EXTERNAL_BLOCKED_IP':   ('block', 'EXTERNAL_BLOCKED_IP'),
    'EXTERNAL_BLOCKED_NULL': ('block', 'EXTERNAL_BLOCKED_NULL'),
    'EXTERNAL_BLOCKED_NXRA': ('block', 'EXTERNAL_BLOCKED_NXRA'),
    'SPECIAL_DOMAIN': ('block', 'SPECIAL_DOMAIN'),
    'DBBUSY':         ('block', 'DBBUSY'),
}

# DNS record types that can be resolved to IP addresses
_RESOLVABLE_TYPES = {'A', 'AAAA'}

# Reply types that indicate the query failed — skip self-resolution
_FAILED_REPLY_TYPES = {'NXDOMAIN', 'NODATA', 'SERVFAIL', 'REFUSED', 'NONE'}


def _is_private(ip_str):
    """Return True if the IP is private/reserved, or on any parse failure."""
    try:
        return ipaddress.ip_address(ip_str).is_private
    except (ValueError, TypeError):
        return True


class _DNSCache:
    """Simple TTL cache for DNS resolution results, keyed by (domain, qtype)."""

    def __init__(self, maxsize=2000, ttl=300):
        self._maxsize = maxsize
        self._ttl = ttl
        self._cache = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            if time.monotonic() - entry['time'] >= self._ttl:
                del self._cache[key]
                return None
            self._cache.move_to_end(key)
            return entry['value']

    def set(self, key, value):
        with self._lock:
            self._cache[key] = {'value': value, 'time': time.monotonic()}
            self._cache.move_to_end(key)
            while len(self._cache) > self._maxsize:
                self._cache.popitem(last=False)


class _EndpointResolver:
    """Bound endpoint DNS work separately from per-domain enrichment lookups."""

    def __init__(self):
        self._lock = threading.Lock()
        self._cache = OrderedDict()
        self._pending = None

    def resolve(self, hostname, timeout=2.0, cancelled=lambda: False):
        try:
            return str(ipaddress.ip_address(hostname))
        except ValueError:
            pass
        with self._lock:
            cached = self._cache.get(hostname)
            if cached and cached[0] > time.monotonic():
                self._cache.move_to_end(hostname)
                return cached[1]
            self._cache.pop(hostname, None)
            pending = self._pending
            if pending is not None and pending['host'] != hostname:
                return None
            if pending is None:
                pending = {'host': hostname, 'done': threading.Event(), 'address': None}
                self._pending = pending

                def lookup():
                    address = None
                    try:
                        answers = socket.getaddrinfo(hostname, 53, 0, socket.SOCK_DGRAM)
                        if answers:
                            address = str(ipaddress.ip_address(answers[0][4][0]))
                    except (OSError, ValueError):
                        pass
                    finally:
                        with self._lock:
                            pending['address'] = address
                            self._cache[hostname] = (time.monotonic() + (300 if address else 30), address)
                            while len(self._cache) > 8:
                                self._cache.popitem(last=False)
                            self._pending = None
                            pending['done'].set()

                threading.Thread(target=lookup, name='pihole-endpoint-dns', daemon=True).start()
        deadline = time.monotonic() + max(0, timeout)
        while not cancelled():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            if pending['done'].wait(min(remaining, 0.05)):
                return pending['address']
        return None


class PiHolePoller:
    """Pi-hole v6 API poller.

    Authenticates via session ID, polls /api/queries for DNS logs,
    maps to standard log schema, enriches, and batch-inserts.
    """

    TIMEOUT = 10  # seconds per HTTP request
    INSERT_BATCH_SIZE = 500
    DNS_QUERY_LIMIT = 128
    DNS_BUDGET_SECONDS = 5.0
    RELOAD_RETRY_SECONDS = 5.0

    def __init__(self, db, enricher=None):
        self._db = db
        self._enricher = enricher

        # Auth state
        self._session = None
        self._sid = None
        self._sid_obtained_at = 0.0  # monotonic time when SID was obtained
        self._sid_validity = 1800    # 30 minutes (Pi-hole default)

        # Polling state
        self._poll_thread = None
        self._poll_stop = threading.Event()
        self._lifecycle_lock = threading.RLock()
        self._poll_lock = threading.Lock()
        self._generation = 0
        self._want_polling = False
        self._reload_pending = False
        self._reload_retry = None
        self._reload_failures = 0
        self._lock = threading.Lock()
        self._last_poll = None
        self._last_poll_error = None

        # DNS resolution cache
        self._dns_cache = _DNSCache(maxsize=2000, ttl=300)
        self._endpoint_resolver = _EndpointResolver()

        # Version gate (checked once on first auth)
        self._version_checked = False
        self._rate_limit_until = 0.0
        self._first_poll_from = None

        # Config (loaded from DB + env)
        self.enabled = False
        self.host = ''
        self._password = ''
        self.poll_interval = 60
        self.enrichment_enabled = 'both'
        self._last_cursor = 0
        self._source_generation = 0
        self.dns_server = ''
        self._dns_server_invalid = False

        try:
            self._resolve_config()
        except Exception as e:
            logger.warning("PiHolePoller: config resolution failed (DB may not be ready): %s", e)

    # ── Config Resolution ────────────────────────────────────────────────────

    def _resolve_config(self):
        # A host transition resets its cursor under the DB's generation lock.
        # Retry a mixed read rather than importing against a different source.
        for _ in range(3):
            generation = int(self._db.get_config('pihole_source_generation', 0))
            self._resolve_config_values()
            if generation == int(self._db.get_config('pihole_source_generation', 0)):
                self._source_generation = generation
                return
        raise RuntimeError('Pi-hole source changed during configuration reload')

    def _resolve_config_values(self):
        """Load settings: env var > system_config DB > default."""
        self.host = (os.environ.get('PIHOLE_HOST') or
                     self._db.get_config('pihole_host', '')).strip().rstrip('/')

        # Password: env var overrides encrypted DB value
        env_password = os.environ.get('PIHOLE_PASSWORD', '')
        if env_password:
            self._password = env_password
        else:
            encrypted = self._db.get_config('pihole_password', '')
            if encrypted:
                self._password = decrypt_api_key(encrypted)
            else:
                self._password = ''

        env_interval = os.environ.get('PIHOLE_POLL_INTERVAL', '')
        try:
            parsed_interval = int(env_interval) if env_interval else 0
        except ValueError:
            logger.warning("Invalid PIHOLE_POLL_INTERVAL '%s', ignoring", env_interval)
            parsed_interval = 0
        if parsed_interval and not (15 <= parsed_interval <= 86400):
            logger.warning("PIHOLE_POLL_INTERVAL %d out of range (15-86400), ignoring", parsed_interval)
            parsed_interval = 0
        if not parsed_interval:
            try:
                parsed_interval = int(self._db.get_config('pihole_poll_interval', 60))
            except (ValueError, TypeError):
                logger.warning("Invalid pihole_poll_interval in DB, using default 60s")
                parsed_interval = 60
            if not (15 <= parsed_interval <= 86400):
                logger.warning("pihole_poll_interval %d out of range (15-86400), using default 60s", parsed_interval)
                parsed_interval = 60
        self.poll_interval = parsed_interval

        value = self._db.get_config('pihole_enrichment', 'both')
        self.enrichment_enabled = value if value in ('none', 'geoip', 'threat', 'both') else 'both'

        self._last_cursor = int(self._db.get_config('pihole_last_cursor', 0))
        dns_server = str(os.environ.get('PIHOLE_DNS_SERVER') or
                         self._db.get_config('pihole_dns_server', '') or '').strip()
        self._dns_server_invalid = False
        try:
            self.dns_server = str(ipaddress.ip_address(dns_server)) if dns_server else ''
        except ValueError:
            self.dns_server = ''
            self._dns_server_invalid = True
            logger.warning('Invalid numeric Pi-hole DNS server; active DNS enrichment is disabled')

        # Master toggle: env > DB > default
        enabled_env = os.environ.get('PIHOLE_ENABLED', '').lower()
        if enabled_env in ('true', '1', 'yes'):
            pihole_enabled = True
        elif enabled_env in ('false', '0', 'no'):
            pihole_enabled = False
        else:
            pihole_enabled = self._db.get_config('pihole_enabled', False)

        self.enabled = bool(pihole_enabled) and bool(self.host) and bool(self._password)

        # Auto-enable when both env vars are set
        if (not pihole_enabled and self.host and self._password
                and os.environ.get('PIHOLE_HOST') and os.environ.get('PIHOLE_PASSWORD')):
            try:
                self._db.set_config('pihole_enabled', True)
                self.enabled = True
                logger.info("Pi-hole API auto-enabled (PIHOLE_HOST + PIHOLE_PASSWORD env vars detected)")
            except Exception as e:
                logger.debug("Failed to auto-enable Pi-hole: %s", e)

    def set_enricher(self, enricher):
        """Set the enricher instance (deferred wiring — enricher created after poller)."""
        self._enricher = enricher

    def _apply_reload(self):
        """Called only after the previous poll releases its state/session."""
        old_host = self.host
        old_enabled = self.enabled
        old_dns_server = self.dns_server

        # Close existing session before invalidating
        if self._session:
            try:
                self._session.close()
            except Exception:
                logger.debug("Failed to close Pi-hole session on reload", exc_info=True)

        # Invalidate session and version gate on reload
        self._sid = None
        self._sid_obtained_at = 0.0
        self._session = None
        self._version_checked = False

        old_cursor = self._last_cursor
        config_fields = ('host', '_password', 'enabled', 'poll_interval', 'enrichment_enabled',
                         '_last_cursor', '_source_generation', 'dns_server', '_dns_server_invalid')
        previous = {field: getattr(self, field) for field in config_fields}
        try:
            self._resolve_config()
        except Exception:
            for field, value in previous.items():
                setattr(self, field, value)
            raise

        # Reset first-poll window when starting fresh
        if (old_host != self.host
                or (old_cursor != 0 and self._last_cursor == 0)
                or (not old_enabled and self.enabled)):
            self._first_poll_from = None

        # Invalidate DNS cache when host changes (answers from old Pi-hole are stale)
        if old_host != self.host or old_dns_server != self.dns_server:
            self._dns_cache = _DNSCache(maxsize=2000, ttl=300)

        logger.info("Pi-hole config reloaded (enabled=%s, host=%s)", self.enabled, self.host or '(none)')

    def _settle_lifecycle(self):
        """Apply a pending reload and start at most one worker once idle.

        The lifecycle lock is held by callers. Never wait on the poll lock:
        an in-flight request finishes on its original immutable stop event.
        """
        if self._poll_thread is not None and self._poll_thread.is_alive():
            return
        if not self._poll_lock.acquire(blocking=False):
            return
        ready = True
        try:
            if self._reload_pending:
                self._apply_reload()
                self._reload_pending = False
        except Exception:
            ready = False
            logger.exception('Pi-hole configuration reload failed; collector remains stopped')
        finally:
            self._poll_lock.release()
        if not ready and self._want_polling and self._reload_retry is None:
            self._reload_failures = min(self._reload_failures + 1, 4)

            def retry():
                with self._lifecycle_lock:
                    if self._reload_retry is not timer:
                        return
                    self._reload_retry = None
                    if self._want_polling and self._reload_pending:
                        self._settle_lifecycle()

            timer = threading.Timer(min(30, self.RELOAD_RETRY_SECONDS * 2 ** (self._reload_failures - 1)), retry)
            timer.daemon = True
            self._reload_retry = timer
            timer.start()
        if ready:
            self._reload_failures = 0
            if self._reload_retry is not None:
                self._reload_retry.cancel()
                self._reload_retry = None
        if ready and self._want_polling and self.enabled:
            self._start_worker()

    def reload_config(self, *, restart_polling=True):
        """Cancel the old generation; API callers refresh without collecting."""
        with self._lifecycle_lock:
            self._generation += 1
            self._want_polling = bool(restart_polling)
            if not self._want_polling and self._reload_retry is not None:
                self._reload_retry.cancel()
                self._reload_retry = None
            self._reload_pending = True
            self._poll_stop.set()
            self._settle_lifecycle()

    _ENV_MAP = {
        'host': 'PIHOLE_HOST',
        'password': 'PIHOLE_PASSWORD',
        'poll_interval': 'PIHOLE_POLL_INTERVAL',
        'enabled': 'PIHOLE_ENABLED',
        'dns_server': 'PIHOLE_DNS_SERVER',
    }

    def get_config_source(self, key: str) -> str:
        """Return 'env', 'db', or 'default' for a config key."""
        from deps import get_config_source
        return get_config_source(self._db, key, self._ENV_MAP, 'pihole')

    def get_settings_info(self) -> dict:
        """Return current config with source indicators for Settings UI."""
        return {
            'enabled': self.enabled,
            'host': self.host,
            'host_source': self.get_config_source('host'),
            'password_set': bool(self._password),
            'password_source': self.get_config_source('password'),
            'poll_interval': self.poll_interval,
            'poll_interval_source': self.get_config_source('poll_interval'),
            'enrichment': self.enrichment_enabled,
            'dns_server': self.dns_server,
            'dns_server_source': self.get_config_source('dns_server'),
            'last_cursor': self._last_cursor,
            'status': self._get_poll_status(),
        }

    def _get_poll_status(self) -> dict:
        """Return poll status, preferring in-memory state (receiver process)
        but falling back to DB-persisted state (API process).

        Matches the UniFi _get_poll_status() pattern exactly.
        """
        if self._last_poll is not None:
            with self._lock:
                return {
                    'connected': self._last_poll_error is None,
                    'last_poll': self._last_poll,
                    'last_error': self._last_poll_error,
                }
        # API process — read from DB (written by receiver)
        db_status = self._db.get_config('pihole_poll_status', None)
        if db_status and isinstance(db_status, dict):
            return dict(db_status)
        return {
            'connected': False,
            'last_poll': None,
            'last_error': None,
        }

    def _persist_poll_status(self, connected: bool, error: str = None):
        """Persist poll status to DB so the API process can read it.

        Matches the UniFi poll-status persistence pattern.
        """
        try:
            self._db.set_config('pihole_poll_status', {
                'connected': connected,
                'last_poll': self._last_poll,
                'last_error': error,
            })
        except Exception as e:
            logger.debug("Failed to persist Pi-hole poll status: %s", e)

    # ── HTTP Session & Auth ──────────────────────────────────────────────────

    def _get_session(self) -> requests.Session:
        """Lazily create a requests.Session."""
        if self._session is None:
            self._session = requests.Session()
            self._session.verify = False  # Pi-hole typically uses self-signed certs
        return self._session

    def _check_cancelled(self):
        cancelled = getattr(self, '_active_cancelled', None)
        if cancelled is not None and cancelled():
            raise RuntimeError('Pi-hole poll cancelled')

    def _authenticate(self):
        """POST /api/auth to obtain a session ID (SID).

        Raises on auth failure so callers can handle it.
        """
        url = f"{self.host}/api/auth"
        self._check_cancelled()
        session = self._get_session()
        try:
            resp = session.post(url, json={"password": self._password}, timeout=self.TIMEOUT)
        except requests.RequestException as e:
            raise ConnectionError(f"Pi-hole auth request failed: {e}") from e

        if resp.status_code == 401:
            raise PermissionError("Pi-hole authentication failed: invalid password")

        if resp.status_code == 429:
            try:
                retry_after = int(resp.headers.get('Retry-After', 60))
            except (ValueError, TypeError):
                retry_after = 60
            logger.warning("Pi-hole auth rate-limited (429), backing off %ds", retry_after)
            self._rate_limit_until = time.monotonic() + retry_after
            raise ConnectionError(f"Pi-hole rate-limited, retry after {retry_after}s")

        resp.raise_for_status()
        self._check_cancelled()

        data = resp.json()
        session_data = data.get('session', {})
        self._sid = session_data.get('sid')
        self._sid_validity = session_data.get('validity', 1800)
        self._sid_obtained_at = time.monotonic()

        if not self._sid:
            raise ValueError("Pi-hole auth response missing SID")

        logger.info("Pi-hole authenticated (SID validity=%ds)", self._sid_validity)

        # Version gate: only v6+ is supported. Check once on first auth.
        if not self._version_checked:
            try:
                self._check_cancelled()
                resp = session.get(
                    f"{self.host}/api/info/version",
                    headers={"sid": self._sid},
                    timeout=self.TIMEOUT,
                )
                if resp.ok:
                    version = (resp.json()
                               .get('version', {})
                               .get('ftl', {})
                               .get('local', {})
                               .get('version'))
                    if version and not version.startswith('v6'):
                        self._sid = None
                        raise RuntimeError(
                            f"Pi-hole {version} is not supported. Only Pi-hole v6 is supported."
                        )
                    logger.info("Pi-hole version: %s", version or 'unknown')
            except RuntimeError:
                raise
            except Exception:
                logger.debug("Could not verify Pi-hole version", exc_info=True)
            self._version_checked = True

    def _ensure_auth(self):
        """Ensure we have a valid SID. Re-authenticate if expired or missing."""
        # Respect rate limit backoff
        if self._rate_limit_until and time.monotonic() < self._rate_limit_until:
            remaining = self._rate_limit_until - time.monotonic()
            raise ConnectionError(f"Pi-hole auth rate-limited, {remaining:.0f}s remaining")

        if self._sid is None:
            self._authenticate()
            return

        # Renew if less than 5 minutes remaining
        elapsed = time.monotonic() - self._sid_obtained_at
        remaining = self._sid_validity - elapsed
        if remaining < 300:
            logger.debug("Pi-hole SID expiring in %.0fs, re-authenticating", remaining)
            self._sid = None
            self._authenticate()

    def _api_get(self, path: str, params: dict = None) -> dict:
        """Make an authenticated GET request to the Pi-hole API.

        Auto-retries once on 401 (expired/invalid SID).
        """
        self._ensure_auth()
        self._check_cancelled()
        session = self._get_session()
        url = f"{self.host}{path}"
        headers = {"sid": self._sid}

        try:
            resp = session.get(url, params=params, headers=headers, timeout=self.TIMEOUT)
        except requests.RequestException as e:
            raise ConnectionError(f"Pi-hole API request failed: {e}") from e

        # Retry once on 401 (SID may have been invalidated server-side)
        if resp.status_code == 401:
            self._check_cancelled()
            logger.debug("Pi-hole returned 401, re-authenticating")
            self._sid = None
            self._authenticate()
            headers = {"sid": self._sid}
            resp = session.get(url, params=params, headers=headers, timeout=self.TIMEOUT)

        resp.raise_for_status()
        return resp.json()

    # ── DNS Resolution ───────────────────────────────────────────────────────

    def _get_pihole_dns_server(self) -> tuple[str | None, int]:
        """Use the explicit native resolver when the HTTP endpoint is proxied."""
        if self._dns_server_invalid:
            return None, 53
        if self.dns_server:
            return self.dns_server, 53
        parsed = urlparse(self.host)
        hostname = parsed.hostname or self.host
        return hostname, 53

    def _resolve_domain(self, domain: str, qtype: str, *, cancelled=lambda: False,
                        deadline=None, budget=None) -> str | None:
        """Best-effort current lookup for enrichment, not historical evidence."""
        if self.enrichment_enabled == 'none' or cancelled():
            return None
        cache_key = (domain, qtype)
        cached = self._dns_cache.get(cache_key)
        if cached is not None:
            return cached  # May be '' for negative cache

        remaining = 2.0 if deadline is None else min(2.0, deadline - time.monotonic())
        if remaining <= 0 or (budget is not None and budget['remaining'] <= 0):
            return None
        if budget is not None:
            budget['remaining'] -= 1
        dns_host, dns_port = self._get_pihole_dns_server()
        if not dns_host:
            return None
        dns_host = self._endpoint_resolver.resolve(dns_host, remaining, cancelled)
        if not dns_host or cancelled():
            return None
        remaining = 2.0 if deadline is None else min(2.0, deadline - time.monotonic())
        if remaining <= 0:
            return None
        rdtype = 1 if qtype == 'A' else 28  # A=1, AAAA=28

        ip = self._udp_dns_query(dns_host, dns_port, domain, rdtype, timeout=remaining)
        if cancelled():
            return None

        if ip:
            self._dns_cache.set(cache_key, ip)
            return ip

        # Negative cache to avoid repeated failed lookups
        self._dns_cache.set(cache_key, '')
        return None

    @staticmethod
    def _udp_dns_query(server: str, port: int, domain: str, rdtype: int,
                       timeout: float = 2.0) -> str | None:
        """Send a raw UDP DNS query to a specific server and parse the first A/AAAA answer."""
        import struct, random

        # Build DNS query packet
        tx_id = random.randint(0, 0xFFFF)
        flags = 0x0100  # standard query, recursion desired
        header = struct.pack('!HHHHHH', tx_id, flags, 1, 0, 0, 0)

        # Encode domain name (IDNA-safe for internationalized domains)
        qname = b''
        for label in domain.rstrip('.').split('.'):
            try:
                encoded = label.encode('idna')
            except UnicodeError:
                return None
            if not 1 <= len(encoded) <= 63 or len(qname) + len(encoded) + 2 > 255:
                return None
            qname += bytes([len(encoded)]) + encoded
        qname += b'\x00'
        question = qname + struct.pack('!HH', rdtype, 1)  # class IN

        packet = header + question

        try:
            address = ipaddress.ip_address(server)
            family = socket.AF_INET if address.version == 4 else socket.AF_INET6
            sockaddr = (str(address), port) if address.version == 4 else (str(address), port, 0, 0)
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                # A connected UDP socket accepts replies only from this endpoint.
                sock.connect(sockaddr)
                sock.send(packet)
                data = sock.recv(4096)
        except (socket.timeout, OSError, ValueError):
            return None

        # Parse response: skip header (12 bytes), skip question section,
        # then read answer records
        if len(data) < 12:
            return None
        reply_id, resp_flags, qdcount, ancount = struct.unpack('!HHHH', data[:8])
        rcode = resp_flags & 0x0F
        if reply_id != tx_id or not (resp_flags & 0x8000) or resp_flags & 0x0200 or rcode != 0 or ancount == 0:
            return None

        # Skip question section
        offset = 12
        for _ in range(qdcount):
            while offset < len(data):
                length = data[offset]
                offset += 1
                if length == 0:
                    break
                if length >= 0xC0:  # pointer
                    offset += 1
                    break
                offset += length
            offset += 4  # QTYPE + QCLASS

        # Read first answer
        for _ in range(ancount):
            if offset >= len(data):
                break
            # Skip name (may be pointer)
            if data[offset] >= 0xC0:
                offset += 2
            else:
                while offset < len(data) and data[offset] != 0:
                    offset += data[offset] + 1
                offset += 1

            if offset + 10 > len(data):
                break
            atype, aclass, attl, rdlength = struct.unpack('!HHIH', data[offset:offset + 10])
            offset += 10

            if offset + rdlength > len(data):
                return None
            if atype == rdtype == 1 and rdlength == 4:  # A record
                ip = socket.inet_ntoa(data[offset:offset + 4])
                return ip
            elif atype == rdtype == 28 and rdlength == 16:  # AAAA record
                ip = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
                return ip
            offset += rdlength

        return None

    @staticmethod
    def _original_answer(record):
        """Accept only an explicit answer address, never the client/upstream IP.

        The standard v6 query response exposes reply type/time, not its address.
        Optional address fields are useful when an API version supplies them.
        """
        qtype = str(record.get('type') or '').upper()
        if qtype not in _RESOLVABLE_TYPES:
            return None
        reply = record.get('reply') if isinstance(record.get('reply'), dict) else {}
        candidates = [record.get('answer'), record.get('answers'), record.get('dns_answer'),
                      reply.get('ip'), reply.get('answer'), reply.get('answers')]
        for candidate in candidates:
            values = candidate if isinstance(candidate, list) else [candidate]
            for value in values:
                if isinstance(value, dict):
                    value = value.get('ip') or value.get('address')
                if not isinstance(value, str):
                    continue
                try:
                    address = ipaddress.ip_address(value)
                except ValueError:
                    continue
                if address.version == (4 if qtype == 'A' else 6):
                    return str(address)
        return None

    def _batch_resolve(self, queries: list[dict], *, cancelled=lambda: False,
                       deadline=None, budget=None) -> dict:
        """Resolve unique (domain, type) pairs from a batch of queries.

        Returns a dict of (domain, qtype) -> ip_str (or None).
        Only resolves non-blocked A/AAAA queries.
        """
        if self.enrichment_enabled == 'none':
            return {}
        to_resolve = set()
        for q in queries:
            status = (q.get('status') or '').upper()
            action, _ = _STATUS_MAP.get(status, ('allow', status))
            if action == 'block':
                continue
            # Skip queries whose reply indicates failure (no valid answer to resolve)
            reply = q.get('reply') if isinstance(q.get('reply'), dict) else {}
            reply_type = (reply.get('type') or '').upper()
            if reply_type in _FAILED_REPLY_TYPES:
                continue
            qtype = (q.get('type') or '').upper()
            if qtype not in _RESOLVABLE_TYPES:
                continue
            if self._original_answer(q):
                continue
            domain = q.get('domain', '')
            if domain:
                to_resolve.add((domain, qtype))

        results = {}
        failed = 0
        for domain, qtype in sorted(to_resolve):
            if cancelled():
                break
            ip = self._resolve_domain(domain, qtype, cancelled=cancelled,
                                      deadline=deadline, budget=budget)
            if ip:
                results[(domain, qtype)] = ip
            else:
                results[(domain, qtype)] = None
                failed += 1
        if failed:
            logger.debug("DNS batch resolve: %d/%d failed", failed, len(to_resolve))
        return results

    # ── Query Mapping ────────────────────────────────────────────────────────

    def _map_query(self, record: dict, resolved_ips: dict) -> dict:
        """Map a Pi-hole query record to the standard log dict (INSERT_COLUMNS shape)."""
        # Extract fields from Pi-hole API response
        client = record.get('client', {}) if isinstance(record.get('client'), dict) else {}
        src_ip = client.get('ip', '')
        client_name = client.get('name')
        domain = record.get('domain', '')
        qtype = (record.get('type') or '').upper()
        status = (record.get('status') or '').upper()
        ts_epoch = record.get('time', 0)

        # Convert epoch to datetime with timezone
        try:
            timestamp = datetime.fromtimestamp(ts_epoch, tz=timezone.utc)
        except (OSError, ValueError, OverflowError):
            timestamp = datetime.now(tz=timezone.utc)

        # Map status to action
        action, desc = _STATUS_MAP.get(status, ('allow', status))

        # Original answer and current enrichment lookup have different provenance.
        reply = record.get('reply') if isinstance(record.get('reply'), dict) else {}
        reply_type = (reply.get('type') or '').upper()
        dst_ip = None
        dns_answer = None
        if action != 'block' and qtype in _RESOLVABLE_TYPES and reply_type not in _FAILED_REPLY_TYPES:
            dns_answer = self._original_answer(record)
            resolved = dns_answer or resolved_ips.get((domain, qtype))
            if resolved:
                if not _is_private(resolved):
                    dst_ip = resolved

        protocol = record.get('protocol')
        protocol = protocol.upper() if isinstance(protocol, str) else None
        if protocol not in ('TCP', 'UDP'):
            protocol = None

        parsed = {
            'timestamp': timestamp,
            'log_type': 'dns',
            'direction': None,
            'src_ip': src_ip or None,
            'src_port': None,
            'dst_ip': dst_ip,
            'dst_port': 53,
            'protocol': protocol,
            'service_name': None,
            'rule_name': None,
            'rule_desc': desc,
            'rule_action': action,
            'interface_in': None,
            'interface_out': None,
            'mac_address': None,
            'hostname': None,
            'dns_query': domain or None,
            'dns_type': qtype or None,
            'dns_answer': dns_answer,
            'dhcp_event': None,
            'wifi_event': None,
            'geo_country': None,
            'geo_city': None,
            'geo_lat': None,
            'geo_lon': None,
            'asn_number': None,
            'asn_name': None,
            'threat_score': None,
            'threat_categories': None,
            'rdns': None,
            'abuse_usage_type': None,
            'abuse_hostnames': None,
            'abuse_total_reports': None,
            'abuse_last_reported': None,
            'abuse_is_whitelisted': None,
            'abuse_is_tor': None,
            'src_device_name': client_name if client_name else None,
            'dst_device_name': None,
            'remote_ip': dst_ip,  # public dst_ip for enrichment
            'source': 'pihole',
            'raw_log': json.dumps(record),
        }

        return parsed

    # ── Polling ──────────────────────────────────────────────────────────────

    FETCH_LIMIT = 10000

    def _cancelled(self, stop_event, generation):
        return stop_event.is_set() or generation != self._generation

    def poll(self, *, stop_event=None, generation=None):
        """Import one bounded snapshot with ordered, independently committed chunks."""
        if not self._poll_lock.acquire(blocking=False):
            return False
        stop_event = self._poll_stop if stop_event is None else stop_event
        generation = self._generation if generation is None else generation
        cancelled = lambda: self._cancelled(stop_event, generation)
        self._active_cancelled = cancelled
        try:
            if cancelled():
                return False
            host = self.host
            source_generation = self._source_generation
            params = {}

            if self._last_cursor == 0:
                # First run: only fetch last 5 minutes.
                # Lock in the timestamp so retries use the same window.
                if self._first_poll_from is None:
                    self._first_poll_from = int(
                        (datetime.now(tz=timezone.utc) - timedelta(minutes=5)).timestamp())
                params['from'] = self._first_poll_from
                logger.info("Pi-hole first poll: fetching queries from last 5 minutes")

            # Single large fetch — treats the response as a practical snapshot.
            # Avoids offset-pagination seam loss from queries arriving mid-scan.
            params['length'] = self.FETCH_LIMIT
            data = self._api_get('/api/queries', params=params)
            if cancelled():
                return False
            raw_queries = data.get('queries', [])

            # Filter to records above our cursor, deduped by ID
            seen_ids = set()
            queries = []
            for q in raw_queries:
                if not isinstance(q, dict):
                    continue
                qid = q.get('id', 0)
                if type(qid) is not int or qid < 1:
                    continue
                if qid <= self._last_cursor:
                    continue
                if qid in seen_ids:
                    continue
                seen_ids.add(qid)
                queries.append(q)

            if len(raw_queries) >= self.FETCH_LIMIT:
                logger.warning("Pi-hole returned %d queries (at fetch limit). "
                               "Some older queries between polls may be skipped. "
                               "Consider reducing poll interval.", len(raw_queries))

            if not queries:
                with self._lock:
                    self._last_poll = datetime.now(tz=timezone.utc).isoformat()
                    self._last_poll_error = None
                self._persist_poll_status(connected=True)
                return True

            # A chunk cursor covers only committed IDs, including after a failure
            # or cancellation. Never advance to a newest-first snapshot's maximum
            # before its older chunks have committed.
            queries.sort(key=lambda query: query['id'])
            deadline = time.monotonic() + self.DNS_BUDGET_SECONDS
            budget = {'remaining': self.DNS_QUERY_LIMIT}
            imported = 0
            for offset in range(0, len(queries), self.INSERT_BATCH_SIZE):
                if cancelled():
                    return False
                chunk = queries[offset:offset + self.INSERT_BATCH_SIZE]
                resolved_ips = self._batch_resolve(chunk, cancelled=cancelled,
                                                   deadline=deadline, budget=budget)
                logs = []
                for record in chunk:
                    if cancelled():
                        return False
                    parsed = self._map_query(record, resolved_ips)
                    if self.enrichment_enabled != 'none' and self._enricher:
                        try:
                            parsed = self._enricher.enrich(parsed)
                        except Exception as e:
                            logger.debug("Pi-hole enrichment failed for %s: %s",
                                         parsed.get('dns_query', '?'), e)
                    logs.append(parsed)
                if cancelled():
                    return False
                committed_cursor = self._db.insert_pihole_batch(
                    logs, chunk[-1]['id'], expected_host=host,
                    expected_generation=source_generation)
                if committed_cursor is None or cancelled():
                    return False
                if type(committed_cursor) is not int:
                    raise TypeError('Pi-hole insert did not return a committed cursor')
                self._last_cursor = max(self._last_cursor, committed_cursor)
                imported += len(logs)

            with self._lock:
                self._last_poll = datetime.now(tz=timezone.utc).isoformat()
                self._last_poll_error = None

            self._persist_poll_status(connected=True)
            logger.info("Pi-hole poll: processed %d queries (cursor=%d)", imported, self._last_cursor)
            return True

        except Exception as e:
            if cancelled():
                return False
            logger.error("Pi-hole poll failed: %s", e)
            with self._lock:
                self._last_poll = datetime.now(tz=timezone.utc).isoformat()
                self._last_poll_error = str(e)
            self._persist_poll_status(connected=False, error=str(e))
            return False
        finally:
            self._active_cancelled = None
            self._poll_lock.release()
            with self._lifecycle_lock:
                if self._poll_thread is None:
                    self._settle_lifecycle()

    def start_polling(self):
        """Request one receiver worker; an old generation must finish first."""
        with self._lifecycle_lock:
            self._want_polling = True
            self._generation += 1
            self._poll_stop.set()
            self._settle_lifecycle()

    def _start_worker(self):
        """Lifecycle lock held; the old worker has released all poll state."""
        stop_event = threading.Event()
        self._poll_stop = stop_event
        generation = self._generation
        poll_interval = self.poll_interval

        def _poll_loop():
            try:
                if self._enricher:
                    for _ in range(10):
                        if self._cancelled(stop_event, generation):
                            return
                        unifi = getattr(self._enricher, 'unifi', None)
                        if unifi and unifi.has_device_names():
                            break
                        if stop_event.wait(1):
                            return
                while not self._cancelled(stop_event, generation):
                    self.poll(stop_event=stop_event, generation=generation)
                    if stop_event.wait(poll_interval):
                        break
            finally:
                with self._lifecycle_lock:
                    if self._poll_thread is threading.current_thread():
                        self._poll_thread = None
                        self._settle_lifecycle()

        self._poll_thread = threading.Thread(target=_poll_loop, daemon=True,
                                              name='pihole-poller')
        self._poll_thread.start()
        logger.info("Pi-hole polling started (interval=%ds)", poll_interval)

    def stop_polling(self):
        """Cancel one generation without replacing its immutable stop event."""
        with self._lifecycle_lock:
            self._want_polling = False
            if self._reload_retry is not None:
                self._reload_retry.cancel()
                self._reload_retry = None
            self._generation += 1
            self._poll_stop.set()
            thread = self._poll_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5)
        with self._lifecycle_lock:
            if thread is not None and thread.is_alive():
                logger.info('Pi-hole stop requested; in-flight poll is finishing')
                return
            if self._poll_lock.acquire(blocking=False):
                try:
                    if self._session:
                        self._session.close()
                    self._session = None
                    self._sid = None
                finally:
                    self._poll_lock.release()
            logger.info('Pi-hole polling stopped')

    # ── Test Connection ──────────────────────────────────────────────────────

    def test_connection(self, host: str = None, password: str = None) -> dict:
        """Test Pi-hole connectivity and auth. Returns status dict.

        Can be called with explicit host/password (from Settings wizard)
        or uses stored config.
        """
        test_host = (host or self.host).rstrip('/')
        test_password = password or self._password

        if not test_host or not test_password:
            return {'success': False, 'error': 'Host and password are required'}

        session = requests.Session()
        session.verify = False

        try:
            resp = session.post(
                f"{test_host}/api/auth",
                json={"password": test_password},
                timeout=self.TIMEOUT,
            )
            if resp.status_code == 401:
                return {'success': False, 'error': 'Authentication failed: invalid password'}
            resp.raise_for_status()
            data = resp.json()
            sid = data.get('session', {}).get('sid')
            if not sid:
                return {'success': False, 'error': 'Auth succeeded but no SID returned'}

            # Quick query test
            resp2 = session.get(
                f"{test_host}/api/queries",
                params={'length': 1},
                headers={"sid": sid},
                timeout=self.TIMEOUT,
            )
            resp2.raise_for_status()
            query_data = resp2.json()
            total_queries = query_data.get('recordsTotal', 0)

            # Get version and validate v6+
            version = None
            try:
                resp3 = session.get(
                    f"{test_host}/api/info/version",
                    headers={"sid": sid},
                    timeout=self.TIMEOUT,
                )
                if resp3.ok:
                    vdata = resp3.json()
                    # Structure: version.ftl.local.version = "v6.5"
                    version = (vdata.get('version', {})
                               .get('ftl', {})
                               .get('local', {})
                               .get('version'))
            except Exception:
                logger.debug("Failed to fetch Pi-hole version during test", exc_info=True)

            # Reject non-v6 Pi-hole
            if version and not version.startswith('v6'):
                return {
                    'success': False,
                    'error': f'Pi-hole {version} is not supported. Only Pi-hole v6 is supported.',
                }

            # Check privacy level — anything other than 0 hides data we need
            privacy_level = None
            try:
                resp4 = session.get(
                    f"{test_host}/api/config",
                    headers={"sid": sid},
                    timeout=self.TIMEOUT,
                )
                if resp4.ok:
                    privacy_level = (resp4.json()
                                     .get('config', {})
                                     .get('misc', {})
                                     .get('privacylevel'))
            except Exception:
                logger.debug("Failed to fetch Pi-hole privacy level during test", exc_info=True)

            # Delete the session (logout)
            try:
                session.delete(
                    f"{test_host}/api/auth",
                    headers={"sid": sid},
                    timeout=5,
                )
            except Exception:
                logger.debug("Failed to logout Pi-hole test session", exc_info=True)

            if privacy_level is not None and privacy_level != 0:
                return {
                    'success': False,
                    'error': 'Pi-hole privacy level must be set to "Show everything and record everything". '
                             'Go to Pi-hole Settings > Privacy > Query Anonymization and select the first option. '
                             'Current level hides domains and/or client IPs, making query data unusable.',
                }

            return {
                'success': True,
                'version': version or 'v6',
                'total_queries': total_queries,
            }

        except requests.ConnectionError:
            return {'success': False, 'error': f'Cannot connect to {test_host}'}
        except requests.Timeout:
            return {'success': False, 'error': f'Connection to {test_host} timed out'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
