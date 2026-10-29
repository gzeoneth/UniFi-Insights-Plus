"""Dashboard statistics endpoint."""

import csv
import io
import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import StreamingResponse
from psycopg2.extras import RealDictCursor

from db import get_config, get_wan_ips_from_config
from deps import get_conn, put_conn, enricher_db
from ip_identity import load_identity_config, annotate_record, annotate_ip
from query_helpers import (parse_time_range, build_log_query, validate_time_params,
                          VALID_TIME_RANGES, device_name_client_lateral,
                          device_name_device_lateral, device_name_coalesce,
                          sanitize_csv_cell)

logger = logging.getLogger('api.stats')

router = APIRouter()


def _stats_scope(cutoff, exclude_groups):
    from field_filters import append_exclusions
    return append_exclusions('timestamp >= %s', [cutoff], exclude_groups)


def _stats_view_counts(cur, cutoff, exclude_groups, visible):
    if not exclude_groups:
        return {'total': visible, 'visible': visible, 'hidden': 0}
    from field_filters import query_view_counts
    return query_view_counts(cur, 'timestamp >= %s', [cutoff], exclude_groups)


def _apply_ip_filters(where, params, src_ip, dst_ip, interface_in, interface_out) -> tuple[str, list]:
    """Validate and append IP/interface exact-match filters to a WHERE clause."""
    if src_ip:
        try:
            ipaddress.ip_address(src_ip)
        except ValueError as err:
            raise HTTPException(status_code=400, detail="Invalid src_ip") from err
        where += " AND src_ip = %s::inet"
        params.append(src_ip)
    if dst_ip:
        try:
            ipaddress.ip_address(dst_ip)
        except ValueError as err:
            raise HTTPException(status_code=400, detail="Invalid dst_ip") from err
        where += " AND dst_ip = %s::inet"
        params.append(dst_ip)
    if interface_in:
        where += " AND interface_in = %s"
        params.append(interface_in)
    if interface_out:
        where += " AND interface_out = %s"
        params.append(interface_out)
    return where, params


def _build_exclude_ips():
    """Build the WAN IP exclusion list used by top-N queries."""
    wan_ips = get_wan_ips_from_config(enricher_db)
    exclude_ips = ['0.0.0.0']
    for ip in wan_ips:
        if ip not in exclude_ips:
            exclude_ips.append(ip)
    return exclude_ips


def _annotate_internal_ips(*ip_lists):
    """Annotate internal IP lists with gateway/WAN/VPN device names."""
    cfg = load_identity_config(enricher_db)
    for ip_list in ip_lists:
        for item in ip_list:
            name, vlan, _ = annotate_ip(cfg, item['ip'], item.get('device_name'))
            if name:
                item['device_name'] = name
            if vlan is not None:
                item['vlan'] = vlan


def _query_top_blocked_ips(cur, cutoff, exclude_ips, scope=None):
    """Top blocked external IPs (public src_ip, exclude WAN)."""
    where, query_params = scope or ('timestamp >= %s', [cutoff])
    cur.execute(
        "SELECT host(src_ip) as ip, COUNT(*) as count, "
        "MAX(geo_country) as country, MAX(asn_name) as asn, "
        "MAX(threat_score) as threat_score "
        "FROM logs "
        f"WHERE {where} AND rule_action = 'block' AND src_ip IS NOT NULL "
        "AND host(src_ip) != ALL(%s) "
        "AND is_public_inet(src_ip) "
        "GROUP BY src_ip ORDER BY count DESC LIMIT 10",
        [*query_params, exclude_ips]
    )
    return [dict(r) for r in cur.fetchall()]


def _query_top_blocked_internal_ips(cur, cutoff, scope=None):
    """Top blocked internal IPs with device name enrichment."""
    where, query_params = scope or ('timestamp >= %s', [cutoff])
    cur.execute(
        "WITH top_ips AS ("
        "  SELECT src_ip, host(src_ip) as ip, COUNT(*) as count "
        "  FROM logs "
        f"  WHERE {where} AND rule_action = 'block' AND src_ip IS NOT NULL "
        "  AND NOT is_public_inet(src_ip) "
        "  GROUP BY src_ip ORDER BY count DESC LIMIT 10"
        ") SELECT t.ip, t.count, "
        + device_name_coalesce('c', column_alias='device_name') + " "
        "FROM top_ips t "
        + device_name_client_lateral('t.src_ip', 'c', recency_expr='%s') + " "
        "ORDER BY t.count DESC",
        [*query_params, cutoff]
    )
    return [dict(r) for r in cur.fetchall()]


def _query_top_threat_ips(cur, cutoff, exclude_ips, scope=None):
    """Top scored remote IPs; outbound scores belong to the destination."""
    where, query_params = scope or ('timestamp >= %s', [cutoff])
    cur.execute(
        "SELECT host(l.remote_ip) as ip, COUNT(*) as count, "
        "MAX(l.geo_country) as country, MAX(l.asn_name) as asn, "
        "MAX(l.geo_city) as city, MAX(l.rdns) as rdns, "
        "MAX(l.threat_score) as threat_score, "
        "COALESCE(MAX(l.threat_categories), MAX(t.threat_categories)) as threat_categories, "
        "MAX(l.timestamp) as last_seen "
        f"FROM (SELECT * FROM logs WHERE {where}) l "
        "LEFT JOIN ip_threats t ON l.remote_ip = t.ip "
        "WHERE l.threat_score > 50 AND l.remote_ip IS NOT NULL "
        "AND host(l.remote_ip) != ALL(%s) "
        "GROUP BY l.remote_ip ORDER BY max(l.threat_score) DESC, count DESC LIMIT 10",
        [*query_params, exclude_ips]
    )
    results = []
    for r in cur.fetchall():
        row = dict(r)
        if row.get('last_seen'):
            row['last_seen'] = row['last_seen'].isoformat()
        results.append(row)
    return results


def _query_top_allowed_destinations(cur, cutoff, exclude_ips, scope=None):
    """Top allowed external destinations (public dst_ip, exclude WAN)."""
    where, query_params = scope or ('timestamp >= %s', [cutoff])
    cur.execute(
        "SELECT host(dst_ip) as ip, COUNT(*) as count, "
        "MAX(geo_country) as country, MAX(asn_name) as asn "
        "FROM logs "
        f"WHERE {where} AND rule_action = 'allow' AND dst_ip IS NOT NULL "
        "AND host(dst_ip) != ALL(%s) "
        "AND is_public_inet(dst_ip) "
        "GROUP BY dst_ip ORDER BY count DESC LIMIT 10",
        [*query_params, exclude_ips]
    )
    return [dict(r) for r in cur.fetchall()]


def _query_top_dns(cur, cutoff, scope=None):
    """Top DNS queries."""
    where, query_params = scope or ('timestamp >= %s', [cutoff])
    cur.execute(
        "SELECT dns_query, COUNT(*) as count FROM logs "
        f"WHERE {where} AND log_type = 'dns' AND dns_query IS NOT NULL "
        "GROUP BY dns_query ORDER BY count DESC LIMIT 10",
        query_params
    )
    return [dict(r) for r in cur.fetchall()]


def _query_top_active_internal_ips(cur, cutoff, scope=None):
    """Top active internal IPs (most allowed traffic, exclude gateway IPs)."""
    where, query_params = scope or ('timestamp >= %s', [cutoff])
    gateway_ips = get_config(enricher_db, 'gateway_ips') or []
    gw_filter = "  AND host(src_ip) != ALL(%s) " if gateway_ips else ""
    params = [*query_params, gateway_ips, cutoff] if gateway_ips else [*query_params, cutoff]
    cur.execute(
        "WITH top_ips AS ("
        "  SELECT src_ip, host(src_ip) as ip, COUNT(*) as count "
        "  FROM logs "
        f"  WHERE {where} AND rule_action = 'allow' AND src_ip IS NOT NULL "
        "  AND NOT is_public_inet(src_ip) "
        + gw_filter +
        "  GROUP BY src_ip ORDER BY count DESC LIMIT 10"
        ") SELECT t.ip, t.count, "
        + device_name_coalesce('c', column_alias='device_name') + " "
        "FROM top_ips t "
        + device_name_client_lateral('t.src_ip', 'c', recency_expr='%s') + " "
        "ORDER BY t.count DESC",
        params
    )
    return [dict(r) for r in cur.fetchall()]


def _get_bucket(time_range):
    """Return the adaptive time bucket for a given time_range string."""
    bucket_map = {
        '1h': 'hour', '6h': 'hour', '24h': 'hour',
        '7d': 'day', '30d': 'day', '60d': 'day',
        '90d': 'week',
        '180d': 'month', '365d': 'month',
    }
    return bucket_map.get(time_range, 'day')


def _query_logs_over_time(cur, cutoff, bucket, scope=None):
    """Logs over time with adaptive bucketing."""
    where, query_params = scope or ('timestamp >= %s', [cutoff])
    cur.execute(
        f"SELECT date_trunc('{bucket}', timestamp) as period, COUNT(*) as count "
        f"FROM logs WHERE {where} "
        "GROUP BY period ORDER BY period",
        query_params
    )
    return [
        {'period': r['period'].isoformat(), 'count': r['count']}
        for r in cur.fetchall()
    ]


def _query_traffic_by_action(cur, cutoff, bucket, scope=None):
    """Traffic by action over time (firewall logs only)."""
    where, query_params = scope or ('timestamp >= %s', [cutoff])
    cur.execute(
        f"SELECT date_trunc('{bucket}', timestamp) as period, "
        "rule_action, COUNT(*) as count "
        f"FROM logs WHERE {where} AND log_type = 'firewall' "
        "AND rule_action IS NOT NULL "
        "GROUP BY period, rule_action ORDER BY period",
        query_params
    )
    action_map = {}
    for r in cur.fetchall():
        p = r['period'].isoformat()
        if p not in action_map:
            action_map[p] = {'period': p, 'allow': 0, 'block': 0, 'redirect': 0}
        action = r['rule_action']
        if action in ('allow', 'block', 'redirect'):
            action_map[p][action] = r['count']
    return sorted(action_map.values(), key=lambda x: x['period'])


# TODO: Optimise /api/stats for dashboard load time.
#   - Option 1: Parallelise the ~12 sequential SQL queries (e.g. asyncio.gather or threaded cursor)
#   - Option 2: Have the dashboard call /api/stats/overview first to render summary cards instantly,
#     then backfill the rest from /api/stats asynchronously (lazy-load sections)
@router.get("/api/stats")
def get_stats(
    time_range: str = Query("24h", description="1h,6h,24h,7d,30d,60d"),
    exclude_groups: Optional[str] = None,
):
    cutoff = parse_time_range(time_range)
    if not cutoff:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    bucket = _get_bucket(time_range)

    scope = _stats_scope(cutoff, exclude_groups)
    where, query_params = scope
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Total logs
            cur.execute(f"SELECT COUNT(*) as total FROM logs WHERE {where}", query_params)
            total = cur.fetchone()['total']
            view_counts = _stats_view_counts(cur, cutoff, exclude_groups, total)

            # By type
            cur.execute(
                "SELECT log_type, COUNT(*) as count FROM logs "
                f"WHERE {where} GROUP BY log_type ORDER BY count DESC",
                query_params
            )
            by_type = {r['log_type']: r['count'] for r in cur.fetchall()}

            # Blocked count
            cur.execute(
                "SELECT COUNT(*) as count FROM logs "
                f"WHERE {where} AND rule_action = 'block'",
                query_params
            )
            blocked = cur.fetchone()['count']

            # Threat count (score > 50)
            cur.execute(
                "SELECT COUNT(*) as count FROM logs "
                f"WHERE {where} AND threat_score > 50",
                query_params
            )
            threats = cur.fetchone()['count']

            # Top blocked countries
            cur.execute(
                "SELECT geo_country as country, COUNT(*) as count FROM logs "
                f"WHERE {where} AND rule_action = 'block' AND geo_country IS NOT NULL "
                "GROUP BY geo_country ORDER BY count DESC LIMIT 10",
                query_params
            )
            top_blocked_countries = [dict(r) for r in cur.fetchall()]

            exclude_ips = _build_exclude_ips()
            top_blocked_ips = _query_top_blocked_ips(cur, cutoff, exclude_ips, scope=scope)
            top_blocked_internal_ips = _query_top_blocked_internal_ips(cur, cutoff, scope=scope)
            top_threat_ips = _query_top_threat_ips(cur, cutoff, exclude_ips, scope=scope)

            logs_over_time = _query_logs_over_time(cur, cutoff, bucket, scope=scope)
            traffic_by_action = _query_traffic_by_action(cur, cutoff, bucket, scope=scope)

            # Direction breakdown
            cur.execute(
                "SELECT direction, COUNT(*) as count FROM logs "
                f"WHERE {where} AND direction IS NOT NULL "
                "GROUP BY direction ORDER BY count DESC",
                query_params
            )
            by_direction = {r['direction']: r['count'] for r in cur.fetchall()}

            top_dns = _query_top_dns(cur, cutoff, scope=scope)

            # Top blocked services
            cur.execute(
                "SELECT service_name, COUNT(*) as count FROM logs "
                f"WHERE {where} AND rule_action = 'block' AND service_name IS NOT NULL "
                "GROUP BY service_name ORDER BY count DESC LIMIT 10",
                query_params
            )
            top_blocked_services = [dict(r) for r in cur.fetchall()]

            # Allowed count
            cur.execute(
                "SELECT COUNT(*) as count FROM logs "
                f"WHERE {where} AND log_type = 'firewall' AND rule_action = 'allow'",
                query_params
            )
            allowed = cur.fetchone()['count']

            top_allowed_destinations = _query_top_allowed_destinations(cur, cutoff, exclude_ips, scope=scope)

            # Top allowed countries (outbound destinations)
            cur.execute(
                "SELECT geo_country as country, COUNT(*) as count FROM logs "
                f"WHERE {where} AND rule_action = 'allow' "
                "AND geo_country IS NOT NULL AND direction = 'outbound' "
                "GROUP BY geo_country ORDER BY count DESC LIMIT 10",
                query_params
            )
            top_allowed_countries = [dict(r) for r in cur.fetchall()]

            # Top allowed services
            cur.execute(
                "SELECT service_name, COUNT(*) as count FROM logs "
                f"WHERE {where} AND rule_action = 'allow' AND service_name IS NOT NULL "
                "GROUP BY service_name ORDER BY count DESC LIMIT 10",
                query_params
            )
            top_allowed_services = [dict(r) for r in cur.fetchall()]

            top_active_internal_ips = _query_top_active_internal_ips(cur, cutoff, scope=scope)

            _annotate_internal_ips(top_blocked_internal_ips, top_active_internal_ips)

        conn.commit()
        return {
            'time_range': time_range,
            'total': total,
            'view_counts': view_counts,
            'by_type': by_type,
            'blocked': blocked,
            'threats': threats,
            'allowed': allowed,
            'by_direction': by_direction,
            'top_blocked_countries': top_blocked_countries,
            'top_blocked_ips': top_blocked_ips,
            'top_blocked_internal_ips': top_blocked_internal_ips,
            'top_threat_ips': top_threat_ips,
            'top_blocked_services': top_blocked_services,
            'top_allowed_destinations': top_allowed_destinations,
            'top_allowed_countries': top_allowed_countries,
            'top_allowed_services': top_allowed_services,
            'top_active_internal_ips': top_active_internal_ips,
            'top_dns': top_dns,
            'logs_per_hour': logs_over_time,  # backward-compat alias for logs_over_time
            'logs_over_time': logs_over_time,
            'traffic_by_action': traffic_by_action,
        }
    except Exception as e:
        conn.rollback()
        logger.exception("Error fetching stats")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


@router.get("/api/stats/overview")
def get_stats_overview(
    time_range: str = Query("24h", description="1h,6h,24h,7d,30d,60d"),
    exclude_groups: Optional[str] = None,
):
    """Lightweight traffic overview: total, allowed, blocked, threats, direction breakdown.

    Visibility totals cover the same time window before view exclusions.
    """
    cutoff = parse_time_range(time_range)
    if not cutoff:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    scope = _stats_scope(cutoff, exclude_groups)
    where, query_params = scope
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(f"""
                SELECT
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE log_type = 'firewall' AND rule_action = 'allow') AS allowed,
                    COUNT(*) FILTER (WHERE rule_action = 'block') AS blocked,
                    COUNT(*) FILTER (WHERE threat_score > 50) AS threats
                FROM logs WHERE {where}
            """, query_params)
            row = cur.fetchone()
            view_counts = _stats_view_counts(cur, cutoff, exclude_groups, row['total'])

            cur.execute(f"""
                SELECT direction, COUNT(*) AS count
                FROM logs
                WHERE {where} AND direction IS NOT NULL
                GROUP BY direction ORDER BY count DESC
            """, query_params)
            by_direction = {r['direction']: r['count'] for r in cur.fetchall()}

            cur.execute(f"""
                SELECT log_type, COUNT(*) AS count
                FROM logs
                WHERE {where}
                GROUP BY log_type ORDER BY count DESC
            """, query_params)
            by_type = {r['log_type']: r['count'] for r in cur.fetchall()}

        conn.commit()
        return {
            'time_range': time_range,
            'total': row['total'],
            'view_counts': view_counts,
            'allowed': row['allowed'],
            'blocked': row['blocked'],
            'threats': row['threats'],
            'by_direction': by_direction,
            'by_type': by_type,
        }
    except Exception as e:
        conn.rollback()
        logger.exception("Error fetching stats overview")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


@router.get("/api/stats/tables")
def get_stats_tables(
    time_range: str = Query("24h", description="1h,6h,24h,7d,30d,60d"),
    exclude_groups: Optional[str] = None,
):
    """Top-N table data: blocked/allowed countries, IPs, services, DNS, threats."""
    cutoff = parse_time_range(time_range)
    if not cutoff:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    scope = _stats_scope(cutoff, exclude_groups)
    where, query_params = scope
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # --- WAN IP exclusion (shared across multiple queries) ---
            exclude_ips = _build_exclude_ips()

            # --- Consolidated countries query (blocked + allowed) ---
            cur.execute(
                "SELECT geo_country AS country, rule_action, COUNT(*) AS count FROM logs "
                f"WHERE {where} AND rule_action IN ('block', 'allow') "
                "AND geo_country IS NOT NULL "
                "AND (rule_action = 'block' OR direction = 'outbound') "
                "GROUP BY geo_country, rule_action ORDER BY count DESC",
                query_params
            )
            blocked_countries_map = {}
            allowed_countries_map = {}
            for r in cur.fetchall():
                entry = {'country': r['country'], 'count': r['count']}
                if r['rule_action'] == 'block':
                    blocked_countries_map[r['country']] = entry
                else:
                    allowed_countries_map[r['country']] = entry
            top_blocked_countries = sorted(blocked_countries_map.values(), key=lambda x: -x['count'])[:10]
            top_allowed_countries = sorted(allowed_countries_map.values(), key=lambda x: -x['count'])[:10]

            # --- Consolidated services query (blocked + allowed) ---
            cur.execute(
                "SELECT service_name, rule_action, COUNT(*) AS count FROM logs "
                f"WHERE {where} AND rule_action IN ('block', 'allow') "
                "AND service_name IS NOT NULL "
                "GROUP BY service_name, rule_action ORDER BY count DESC",
                query_params
            )
            blocked_services_map = {}
            allowed_services_map = {}
            for r in cur.fetchall():
                entry = {'service_name': r['service_name'], 'count': r['count']}
                if r['rule_action'] == 'block':
                    blocked_services_map[r['service_name']] = entry
                else:
                    allowed_services_map[r['service_name']] = entry
            top_blocked_services = sorted(blocked_services_map.values(), key=lambda x: -x['count'])[:10]
            top_allowed_services = sorted(allowed_services_map.values(), key=lambda x: -x['count'])[:10]

            top_blocked_ips = _query_top_blocked_ips(cur, cutoff, exclude_ips, scope=scope)
            top_blocked_internal_ips = _query_top_blocked_internal_ips(cur, cutoff, scope=scope)
            top_threat_ips = _query_top_threat_ips(cur, cutoff, exclude_ips, scope=scope)
            top_allowed_destinations = _query_top_allowed_destinations(cur, cutoff, exclude_ips, scope=scope)
            top_dns = _query_top_dns(cur, cutoff, scope=scope)
            top_active_internal_ips = _query_top_active_internal_ips(cur, cutoff, scope=scope)

            _annotate_internal_ips(top_blocked_internal_ips, top_active_internal_ips)

        conn.commit()
        return {
            'top_blocked_countries': top_blocked_countries,
            'top_blocked_ips': top_blocked_ips,
            'top_blocked_internal_ips': top_blocked_internal_ips,
            'top_threat_ips': top_threat_ips,
            'top_blocked_services': top_blocked_services,
            'top_allowed_destinations': top_allowed_destinations,
            'top_allowed_countries': top_allowed_countries,
            'top_allowed_services': top_allowed_services,
            'top_active_internal_ips': top_active_internal_ips,
            'top_dns': top_dns,
        }
    except Exception as e:
        conn.rollback()
        logger.exception("Error fetching stats tables")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


@router.get("/api/stats/charts")
def get_stats_charts(
    time_range: str = Query("24h", description="1h,6h,24h,7d,30d,60d"),
    exclude_groups: Optional[str] = None,
):
    """Time-series chart data: logs over time and traffic by action."""
    cutoff = parse_time_range(time_range)
    if not cutoff:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    bucket = _get_bucket(time_range)

    scope = _stats_scope(cutoff, exclude_groups)
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            logs_over_time = _query_logs_over_time(cur, cutoff, bucket, scope=scope)
            traffic_by_action = _query_traffic_by_action(cur, cutoff, bucket, scope=scope)

        conn.commit()
        return {
            'logs_over_time': logs_over_time,
            'logs_per_hour': logs_over_time,  # backward-compat alias
            'traffic_by_action': traffic_by_action,
        }
    except Exception as e:
        conn.rollback()
        logger.exception("Error fetching stats charts")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)



@router.get("/api/stats/ip-pairs")
def get_ip_pairs(
    time_range: Optional[str] = Query("24h"),
    time_from: Optional[str] = Query(None),
    time_to: Optional[str] = Query(None),
    log_type: Optional[str] = Query("firewall"),
    rule_action: Optional[str] = Query(None),
    direction: Optional[str] = Query(None),
    interface: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    dst_ip: Optional[str] = Query(None),
    dst_port: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    interface_in: Optional[str] = Query(None),
    interface_out: Optional[str] = Query(None),
    filter_rules: Optional[str] = None,
    exclude_groups: Optional[str] = None,
    limit: int = Query(25, ge=1, le=100),
):
    time_range, time_from, time_to = validate_time_params(time_range, time_from, time_to)

    # Pass dst_port and protocol through build_log_query (they use = matching)
    where, params = build_log_query(
        log_type=log_type, time_range=time_range, time_from=time_from, time_to=time_to,
        src_ip=None, dst_ip=None, ip=None, direction=direction,
        rule_action=rule_action, rule_name=None, country=None, threat_min=None,
        search=None, service=service, interface=interface,
        dst_port=dst_port, protocol=protocol,
        filter_rules=filter_rules, exclude_groups=exclude_groups,
    )

    # Exact-match filters for cross-filtering (NOT through build_log_query LIKE path)
    where, params = _apply_ip_filters(where, params, src_ip, dst_ip, interface_in, interface_out)

    sql = f"""
    WITH pair_counts AS (
        SELECT
            src_ip, dst_ip, dst_port, LOWER(protocol) AS protocol,
            MAX(service_name) AS service_name,
            COUNT(*) AS total_count,
            COUNT(*) FILTER (WHERE rule_action = 'allow') AS allow_count,
            COUNT(*) FILTER (WHERE rule_action = 'block') AS block_count,
            MAX(threat_score) AS max_threat_score,
            MAX(asn_name) AS asn_name,
            MAX(direction) AS direction
        FROM logs
        WHERE {where}
          AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
          AND dst_port IS NOT NULL AND protocol IS NOT NULL
        GROUP BY src_ip, dst_ip, dst_port, LOWER(protocol)
        ORDER BY total_count DESC
        LIMIT %s
    )
    SELECT
        host(p.src_ip) AS src_ip, host(p.dst_ip) AS dst_ip,
        p.dst_port, p.protocol, p.service_name,
        p.total_count, p.allow_count, p.block_count, p.max_threat_score, p.asn_name, p.direction,
        """ + device_name_coalesce('cs', 'ds', 'src_device_name') + """,
        """ + device_name_coalesce('cd', 'dd', 'dst_device_name') + """
    FROM pair_counts p
    """ + device_name_client_lateral('p.src_ip', 'cs') + """
    """ + device_name_device_lateral('p.src_ip', 'ds') + """
    """ + device_name_client_lateral('p.dst_ip', 'cd') + """
    """ + device_name_device_lateral('p.dst_ip', 'dd') + """
    ORDER BY p.total_count DESC
    """
    params.append(limit)

    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            pairs = [dict(r) for r in cur.fetchall()]

        # Enrich with gateway + WAN + VPN device names
        cfg = load_identity_config(enricher_db)
        for pair in pairs:
            annotate_record(cfg, pair)

        conn.commit()
        return {"pairs": pairs}
    except Exception as e:
        conn.rollback()
        logger.exception("Error fetching IP pairs")
        raise HTTPException(status_code=500, detail="Internal server error") from e
    finally:
        put_conn(conn)


@router.get("/api/stats/ip-pairs/csv")
def get_ip_pairs_csv(
    time_range: Optional[str] = Query("24h"),
    time_from: Optional[str] = Query(None),
    time_to: Optional[str] = Query(None),
    log_type: Optional[str] = Query("firewall"),
    rule_action: Optional[str] = Query(None),
    direction: Optional[str] = Query(None),
    interface: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    dst_ip: Optional[str] = Query(None),
    dst_port: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    interface_in: Optional[str] = Query(None),
    interface_out: Optional[str] = Query(None),
    filter_rules: Optional[str] = None,
    exclude_groups: Optional[str] = None,
):
    """Stream all filtered IP pairs as CSV (hard cap 10,000 rows)."""
    time_range, time_from, time_to = validate_time_params(time_range, time_from, time_to)

    where, params = build_log_query(
        log_type=log_type, time_range=time_range, time_from=time_from, time_to=time_to,
        src_ip=None, dst_ip=None, ip=None, direction=direction,
        rule_action=rule_action, rule_name=None, country=None, threat_min=None,
        search=None, service=service, interface=interface,
        dst_port=dst_port, protocol=protocol,
        filter_rules=filter_rules, exclude_groups=exclude_groups,
    )

    where, params = _apply_ip_filters(where, params, src_ip, dst_ip, interface_in, interface_out)

    sql = f"""
    SELECT
        host(src_ip) AS source_ip, host(dst_ip) AS destination_ip,
        dst_port AS port, LOWER(protocol) AS protocol,
        MODE() WITHIN GROUP (ORDER BY service_name) AS service,
        COUNT(*) FILTER (WHERE rule_action = 'allow') AS allow_count,
        COUNT(*) FILTER (WHERE rule_action = 'block') AS block_count
    FROM logs
    WHERE {where}
      AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
      AND dst_port IS NOT NULL AND protocol IS NOT NULL
    GROUP BY src_ip, dst_ip, dst_port, LOWER(protocol)
    ORDER BY (COUNT(*)) DESC
    LIMIT 10000
    """

    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')

    def generate():
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                cols = [desc[0] for desc in cur.description]
                buf = io.StringIO()
                writer = csv.writer(buf)
                # Header row
                writer.writerow(cols)
                yield buf.getvalue()
                # Data rows
                for row in cur:
                    buf.seek(0)
                    buf.truncate()
                    writer.writerow([sanitize_csv_cell(str(v)) if v is not None else '' for v in row])
                    yield buf.getvalue()
            conn.commit()
        except Exception:
            conn.rollback()
            logger.exception("Error streaming CSV export")
            raise
        finally:
            put_conn(conn)

    return StreamingResponse(
        generate(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=ip_pairs_{timestamp}.csv"},
    )
