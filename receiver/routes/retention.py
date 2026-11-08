"""Settings for optional retention policies and bounded archived-event summaries."""

from datetime import date, datetime, timedelta, timezone
import logging

from fastapi import APIRouter, HTTPException, Query
from psycopg2.extras import RealDictCursor

from db import Database
from deps import enricher_db
from retention import POLICY_KEY, load_policy, validate_policy

logger = logging.getLogger('api.retention')
router = APIRouter()


def _settings_response(policy, days):
    return {
        'policy': policy,
        'inherited_general_days': days.general,
        'inherited_dns_days': days.dns,
        'summary_scope': 'expired events committed by retention cleanup only',
        'archive_deletion_enabled': False,
    }


@router.get('/api/config/retention/policy')
def get_retention_policy():
    days = Database.resolve_retention_days(enricher_db)
    try:
        policy = load_policy(enricher_db, days.general, days.dns)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=f'Saved retention policy is invalid: {exc}') from exc
    return _settings_response(policy, days)


@router.put('/api/config/retention/policy')
@router.post('/api/config/retention/policy')
def update_retention_policy(body: dict):
    """Replace the policy atomically; omitted fields use safe defaults."""
    days = Database.resolve_retention_days(enricher_db)
    try:
        policy = validate_policy(body, days.general, days.dns)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    # A single JSONB entry prevents half-written archive/retention settings.
    enricher_db.set_config(POLICY_KEY, policy)
    return {'success': True, **_settings_response(policy, days)}


@router.get('/api/retention/summaries')
def get_retention_summaries(
    start: date | None = None,
    end: date | None = None,
    log_type: str | None = Query(default=None, max_length=20),
    source: str | None = Query(default=None, max_length=100),
    event_source: str | None = Query(default=None, max_length=100),
    limit: int = Query(default=500, ge=1, le=5000),
):
    """Read UTC daily summaries, with an inclusive date window up to 366 days."""
    today = datetime.now(timezone.utc).date()
    end = end or today
    start = start or end - timedelta(days=29)
    if start > end or (end - start).days > 365:
        raise HTTPException(status_code=400, detail='Date window must be ordered and at most 366 days')
    where = ['day >= %s', 'day <= %s']
    params = [start, end]
    for name, value in (('log_type', log_type), ('source', source), ('event_source', event_source)):
        if value is not None:
            where.append(f'{name} = %s')
            params.append(value)
    params.append(limit + 1)
    try:
        with enricher_db.get_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SET LOCAL statement_timeout = '10s'")
                cur.execute('SELECT day, log_type, rule_action, source, event_source, grouped_by_rule, '
                            'rule_name, event_count, first_event_at, last_event_at '
                            'FROM retention_daily_summaries WHERE ' + ' AND '.join(where) +
                            ' ORDER BY day DESC, log_type, rule_action, source, event_source, '
                            'grouped_by_rule, rule_name LIMIT %s', params)
                rows = [dict(row) for row in cur.fetchall()]
    except Exception as exc:
        logger.exception('Failed to read retention summaries')
        raise HTTPException(status_code=500, detail='Could not read retention summaries') from exc
    return {'summaries': rows[:limit], 'truncated': len(rows) > limit,
            'start': start, 'end': end, 'timezone': 'UTC',
            'scope': 'expired events committed by retention cleanup only'}
