"""Security summaries keep gateway IPS events separate from IP reputation."""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from psycopg2.extras import RealDictCursor

from deps import get_conn, put_conn
from field_filters import PARSED_IPS_SQL, UNPARSED_CEF_THREAT_SQL
from query_helpers import build_time_conditions, validate_time_params

logger = logging.getLogger('api.security')
router = APIRouter()


@router.get('/api/security/summary')
def security_summary(
    time_range: Optional[str] = Query('24h'),
    time_from: Optional[str] = Query(None),
    time_to: Optional[str] = Query(None),
):
    time_range, time_from, time_to = validate_time_params(
        time_range, time_from, time_to)
    conditions, params = build_time_conditions(time_range, time_from, time_to)
    where = ' AND '.join(conditions)
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(f"""
                SELECT
                    COUNT(*) FILTER (WHERE {PARSED_IPS_SQL}
                        AND rule_action = 'block') AS ips_blocked,
                    COUNT(*) FILTER (WHERE {PARSED_IPS_SQL}
                        AND rule_action = 'allow') AS ips_allowed,
                    COUNT(*) FILTER (WHERE {PARSED_IPS_SQL}
                        AND (rule_action IS NULL OR rule_action NOT IN ('block', 'allow'))) AS ips_unknown,
                    COUNT(*) FILTER (WHERE log_type = 'firewall' AND rule_action = 'block'
                        AND NOT {PARSED_IPS_SQL}) AS firewall_blocks,
                    COUNT(*) FILTER (WHERE threat_score > 50) AS reputation_alerts,
                    COUNT(*) FILTER (WHERE {UNPARSED_CEF_THREAT_SQL}) AS unparsed_cef_threats
                FROM logs WHERE {where}
            """, params)
            result = dict(cur.fetchone())
            # Select risk/severity from the actual latest event, never MAX(text)
            # or an invented conversion to the AbuseIPDB percentage scale.
            cur.execute(f"""
                SELECT ips_signature_id, ips_signature, count, last_seen,
                       ips_risk, ips_severity, rule_action
                FROM (
                    SELECT ips_signature_id, ips_signature, ips_risk, ips_severity,
                           rule_action, timestamp AS last_seen,
                           COUNT(*) OVER (PARTITION BY ips_signature_id, ips_signature) AS count,
                           ROW_NUMBER() OVER (PARTITION BY ips_signature_id, ips_signature
                               ORDER BY timestamp DESC, id DESC) AS recency
                    FROM logs WHERE {where} AND {PARSED_IPS_SQL}
                ) signatures
                WHERE recency = 1
                ORDER BY count DESC, last_seen DESC, ips_signature_id, ips_signature
                LIMIT 10
            """, params)
            result['top_signatures'] = []
            for row in cur.fetchall():
                signature = dict(row)
                if signature.get('last_seen'):
                    signature['last_seen'] = signature['last_seen'].isoformat()
                result['top_signatures'].append(signature)
        result.update(time_range=time_range, time_from=time_from, time_to=time_to)
        return result
    except Exception:
        logger.exception('Failed to load security summary')
        raise HTTPException(status_code=500, detail='Failed to load security summary')
    finally:
        put_conn(conn)
