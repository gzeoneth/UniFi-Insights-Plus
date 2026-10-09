"""Logging helpers shared by the syslog receiver and the parsers.

UDP/514 accepts packets from any LAN host, so any warning triggered by packet
content must be bounded in time (not in packet count) or a flood of hostile
packets turns into a flood of log lines.
"""

import threading
import time

WARN_INTERVAL_SECONDS = 60.0

_lock = threading.Lock()
# key -> [monotonic time of the last emitted warning, occurrences suppressed since]
_state: dict[str, list] = {}


def rate_limited_warning(logger, key: str, msg: str, *args,
                         exc_info: bool = False,
                         interval: float = WARN_INTERVAL_SECONDS) -> bool:
    """Log ``msg % args`` as a WARNING at most once per ``key`` per ``interval``.

    Occurrences inside the interval are only counted; the next emitted line
    reports how many were suppressed since the previous one. ``exc_info``
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
        _state[key] = [now, 0]
    logger.warning(msg + " (%d similar suppressed since the previous warning)",
                   *args, suppressed, exc_info=exc_info, stacklevel=2)
    return True


def reset_rate_limits():
    """Forget all rate-limit state (used by tests)."""
    with _lock:
        _state.clear()
