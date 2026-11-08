"""Bounded, stateless pagination tokens for a frozen log browsing window.

Tokens are query positions, not authorization. Every request still passes
normal API authentication and filter validation. No server-side session grows
with the number of open browsers.
"""

import base64
import hashlib
import json
from datetime import datetime, timezone

from fastapi import HTTPException

from query_helpers import parse_time_range


def filter_fingerprint(filters):
    normalized = dict(filters)
    for key in ('filter_rules', 'exclude_groups'):
        if isinstance(normalized.get(key), str):
            try:
                normalized[key] = json.loads(normalized[key])
            except ValueError:
                pass  # the normal field parser reports invalid filters
    payload = json.dumps(normalized, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(payload.encode()).hexdigest()


def _timestamp(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError('invalid timestamp')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def new_window(fingerprint, time_range, time_from, time_to):
    now = datetime.now(timezone.utc).isoformat()
    return {
        'v': 1, 'filter': fingerprint,
        'from': _timestamp(time_from) if time_from else parse_time_range(time_range or '24h').isoformat(),
        'to': _timestamp(time_to) if time_to else now,
        'max_id': None, 'after': None,
    }


def encode_cursor(state):
    encoded = json.dumps(state, sort_keys=True, separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(encoded).decode().rstrip('=')


def decode_cursor(token, fingerprint):
    try:
        if not isinstance(token, str) or not 1 <= len(token) <= 2048:
            raise ValueError('invalid size')
        raw = base64.b64decode(token + '=' * (-len(token) % 4), altchars=b'-_', validate=True)
        state = json.loads(raw)
        if not isinstance(state, dict) or set(state) != {'v', 'filter', 'from', 'to', 'max_id', 'after'}:
            raise ValueError('invalid shape')
        if state['v'] != 1 or state['filter'] != fingerprint:
            raise ValueError('filters changed')
        state['from'], state['to'] = _timestamp(state['from']), _timestamp(state['to'])
        if type(state['max_id']) is not int or not 0 <= state['max_id'] <= 9223372036854775807:
            raise ValueError('invalid boundary')
        after = state['after']
        if after is not None:
            if not isinstance(after, list) or len(after) != 2:
                raise ValueError('invalid position')
            after[0] = _timestamp(after[0])
            if type(after[1]) is not int or not 0 < after[1] <= state['max_id']:
                raise ValueError('invalid row id')
        return state
    except (ValueError, TypeError, KeyError, UnicodeDecodeError, RecursionError, OverflowError) as error:
        raise HTTPException(400, detail='Invalid cursor or changed filters/sort; restart pagination') from error


def next_cursor(state, row):
    stamp = row['timestamp']
    if isinstance(stamp, datetime):
        stamp = stamp.isoformat()
    return encode_cursor({**state, 'after': [_timestamp(stamp), row['id']]})
