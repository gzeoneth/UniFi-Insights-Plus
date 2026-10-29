"""Small process-local caches for metadata, never log/search result sets."""

from collections import OrderedDict
from copy import deepcopy
import functools
import inspect
import sys
import threading
import time


def _size(value, seen=None):
    """Estimate retained Python memory, counting shared objects only once."""
    seen = set() if seen is None else seen
    if id(value) in seen:
        return 0
    seen.add(id(value))
    size = sys.getsizeof(value)
    if isinstance(value, dict):
        size += sum(_size(k, seen) + _size(v, seen) for k, v in value.items())
    elif isinstance(value, (tuple, list, set, frozenset)):
        size += sum(_size(item, seen) for item in value)
    return size


class ReadCache:
    """TTL/LRU cache with bounded retained memory and one loader per key.

    Slow loaders run outside the lock, so unrelated keys continue independently.
    Expired values and exceptions are never served as a fallback. Callers receive
    copies, protecting cached metadata from accidental response annotation.
    """

    def __init__(self, seconds=30, max_entries=32, max_bytes=4 * 1024 * 1024):
        if seconds <= 0 or max_entries <= 0 or max_bytes <= 0:
            raise ValueError('cache limits must be positive')
        self.seconds = seconds
        self.max_entries = max_entries
        self.max_bytes = max_bytes
        self._entries = OrderedDict()
        self._pending = set()
        self._condition = threading.Condition()
        self._generation = 0
        self._bytes = 0

    def clear(self):
        """Discard entries; an earlier in-flight read cannot repopulate them."""
        with self._condition:
            self._generation += 1
            self._entries.clear()
            self._bytes = 0
            self._condition.notify_all()

    def _remove(self, key):
        entry = self._entries.pop(key)
        self._bytes -= entry[2]

    def get_or_load(self, key, load):
        hit = False
        with self._condition:
            while True:
                now = time.monotonic()
                entry = self._entries.get(key)
                if entry is not None:
                    if now < entry[0]:
                        self._entries.move_to_end(key)
                        cached_result = entry[1]
                        hit = True
                        break
                    self._remove(key)
                # Include generation so invalidation does not make new readers
                # wait for an old database read that may still be running.
                pending_key = (key, self._generation)
                if pending_key not in self._pending:
                    self._pending.add(pending_key)
                    generation = self._generation
                    break
                self._condition.wait()

        if hit:
            # Cached objects are owned exclusively by this cache and immutable
            # after publication. Copy outside the lock so large metadata does
            # not hold up unrelated requests.
            return deepcopy(cached_result)
        try:
            result = load()
            size = _size((key, result))
            cached_result = deepcopy(result) if size <= self.max_bytes else None
            with self._condition:
                if generation == self._generation and size <= self.max_bytes:
                    now = time.monotonic()
                    for old_key, entry in list(self._entries.items()):
                        if now >= entry[0]:
                            self._remove(old_key)
                    while self._entries and (len(self._entries) >= self.max_entries
                                             or self._bytes + size > self.max_bytes):
                        self._remove(next(iter(self._entries)))
                    self._entries[key] = (now + self.seconds, cached_result, size)
                    self._bytes += size
            return result
        finally:
            with self._condition:
                self._pending.discard(pending_key)
                self._condition.notify_all()


def _freeze(value):
    """Keep every argument in the key, including types and nested filters."""
    if isinstance(value, dict):
        return ('dict', frozenset((_freeze(k), _freeze(v)) for k, v in value.items()))
    if isinstance(value, (list, tuple)):
        return (type(value), tuple(_freeze(v) for v in value))
    if isinstance(value, (set, frozenset)):
        return (type(value), frozenset(_freeze(v) for v in value))
    hash(value)  # Unsupported mutable inputs must bypass caching.
    return (type(value), value)


def ttl_cache(seconds=30, max_entries=32, max_bytes=4 * 1024 * 1024):
    """Cache metadata calls by their complete, default-normalized arguments.

    Do not apply to authenticated per-user responses unless the authenticated
    identity is a function argument, or to live event/search/security responses.
    """
    def decorator(fn):
        cache = ReadCache(seconds, max_entries, max_bytes)
        signature = inspect.signature(fn)

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            try:
                key = _freeze(bound.arguments)
            except TypeError:
                return fn(*args, **kwargs)
            return cache.get_or_load(key, lambda: fn(*args, **kwargs))

        wrapper.cache_clear = cache.clear
        return wrapper
    return decorator
