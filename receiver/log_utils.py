"""Logging helpers shared by the syslog receiver and the parsers.

UDP/514 accepts packets from any LAN host, so any warning triggered by packet
content must be bounded in time (not in packet count) or a flood of hostile
packets turns into a flood of log lines.
"""

import threading
import time

WARN_INTERVAL_SECONDS = 60.0

_lock = threading.Lock()
# key -> [monotonic time of the last emitted line, occurrences suppressed since, logger]
_state: dict[str, list] = {}


def rate_limited_warning(logger, key: str, msg: str, *args,
                         exc_info: bool = False,
                         interval: float = WARN_INTERVAL_SECONDS) -> bool:
    """Log ``msg % args`` as a WARNING at most once per ``key`` per ``interval``.

    Occurrences inside the interval are only counted; the next emitted line
    (or ``flush_suppressed``) reports how many were suppressed. ``exc_info``
    attaches a traceback to the emitted line only, so log volume per key is
    one line per interval whatever the packet rate. ``key`` must be a fixed
    string chosen by the caller, never packet content (the state is unbounded
    per distinct key). Returns True when a line was emitted.
    """
    now = time.monotonic()
    with _lock:
        state = _state.get(key)
        if state is not None and now - state[0] < interval:
            state[1] += 1
            return False
        suppressed = state[1] if state is not None else 0
        _state[key] = [now, 0, logger]
    logger.warning(msg + " (%d similar suppressed since the previous warning)",
                   *args, suppressed, exc_info=exc_info, stacklevel=2)
    return True


def flush_suppressed(interval: float = WARN_INTERVAL_SECONDS) -> int:
    """Report pending suppressed counts whose window has expired.

    Without this, a burst followed by silence would never report its count,
    because the count is otherwise only printed on the next emitted line.
    Logs one WARNING per such key through the logger that raised it, then
    starts a new window, so each key still emits at most one line per
    interval. Called from the receiver heartbeat. Returns the number of
    lines logged.
    """
    now = time.monotonic()
    pending = []
    with _lock:
        for key, state in _state.items():
            if state[1] and now - state[0] >= interval:
                pending.append((state[2], key, state[1]))
                _state[key] = [now, 0, state[2]]
    for logger, key, suppressed in pending:
        logger.warning("%s: %d similar suppressed since the previous warning", key, suppressed)
    return len(pending)


def reset_rate_limits():
    """Forget all rate-limit state (used by tests)."""
    with _lock:
        _state.clear()
