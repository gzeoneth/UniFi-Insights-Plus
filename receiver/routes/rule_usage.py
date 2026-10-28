"""Read-only observations of rule usage; these are log hits, not flow totals."""

import time
from typing import Literal
from fastapi import APIRouter, Query
from psycopg2.extras import RealDictCursor
from deps import get_conn, put_conn
from query_helpers import build_log_query, validate_time_params
from field_filters import append_exclusions, query_view_counts

router = APIRouter()


@router.get('/api/rules/usage')
def rule_usage(rule_name: str | None = None, time_range: str | None = '24h',
               time_from: str | None = None, time_to: str | None = None,
               filter_rules: str | None = None, limit: int = Query(200, ge=1, le=500),
               log_type: str | None = None, src_ip: str | None = None,
               dst_ip: str | None = None, ip: str | None = None,
               direction: str | None = None, rule_action: str | None = None,
               country: str | None = None, threat_min: int | None = None,
               search: str | None = None, service: str | None = None,
               interface: str | None = None, vpn_only: bool = False,
               asn: str | None = None, dst_port: str | None = None,
               src_port: str | None = None, protocol: str | None = None,
               exclude_groups: str | None = None,
               group_by: Literal['endpoint', 'rule'] = 'endpoint',
               count_mode: Literal['exact', 'none'] = 'exact'):
    time_range, time_from, time_to = validate_time_params(time_range, time_from, time_to)
    where, params = build_log_query(
        log_type=log_type, time_range=time_range, time_from=time_from, time_to=time_to,
        src_ip=src_ip, dst_ip=dst_ip, ip=ip, direction=direction, rule_action=rule_action,
        rule_name=rule_name, country=country, threat_min=threat_min, search=search,
        service=service, interface=interface, vpn_only=vpn_only, asn=asn,
        dst_port=dst_port, src_port=src_port, protocol=protocol, filter_rules=filter_rules,
    )
    # Preserve a saved view's constraints even if they select another type;
    # the rule-usage surface itself always remains firewall-only.
    where += " AND log_type = 'firewall'"
    base_where, base_params = where, params
    where, params = append_exclusions(where, params, exclude_groups)
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            started = time.perf_counter()
            view_counts = query_view_counts(cur, base_where, base_params, exclude_groups) if count_mode == 'exact' else None
            count_ms = round((time.perf_counter() - started) * 1000, 3) if count_mode == 'exact' else None
            # Rule totals avoid a group for every endpoint/port combination.
            # Keep emitter and action separate, including when rule names collide.
            endpoint_select = ', host(src_ip) AS src_ip, host(dst_ip) AS dst_ip, protocol, dst_port' if group_by == 'endpoint' else ''
            endpoint_group = ', src_ip, dst_ip, protocol, dst_port' if group_by == 'endpoint' else ''
            endpoint_order = ', src_ip, dst_ip, protocol, dst_port' if group_by == 'endpoint' else ''
            started = time.perf_counter()
            cur.execute(f"""
                SELECT hostname, rule_name, rule_desc, rule_action{endpoint_select},
                       COUNT(*) AS log_hits, MIN(timestamp) AS first_seen,
                       MAX(timestamp) AS last_seen
                FROM logs WHERE {where}
                GROUP BY hostname, rule_name, rule_desc, rule_action{endpoint_group}
                ORDER BY log_hits DESC, last_seen DESC, hostname, rule_name, rule_desc, rule_action{endpoint_order}
                LIMIT %s
            """, params + [limit + 1])
            rows = [dict(row) for row in cur.fetchall()]
            query_ms = round((time.perf_counter() - started) * 1000, 3)
        conn.commit()
        return {'view_counts': view_counts, 'data': rows[:limit], 'truncated': len(rows) > limit, 'limit': limit,
                'group_by': group_by, 'count_mode': count_mode,
                'timings': {'query_ms': query_ms, 'count_ms': count_ms},
                'measurement': 'observed_log_hits',
                'notice': 'Only logged events are visible. Rate limits and unlogged rules can hide traffic; absence is not proof a rule is unnecessary.'}
    except Exception:
        conn.rollback()
        raise
    finally:
        put_conn(conn)
