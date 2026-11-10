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
from dashboard_queries import (overview_query, overview_result, series_query,
                               series_result, dashboard_relation)
from dashboard_source import choose_dashboard_source
from request_work import phase
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


def _query_top_threat_ips(cur, cutoff, exclude_ips, scope=None, *, source='logs'):
    """Top scored remote IPs; outbound scores belong to the destination."""
    from request_work import phase
    where, query_params = scope or ('timestamp >= %s', [cutoff])
    query = (
        "WITH top_ips AS ("
        " SELECT remote_ip, COUNT(*) AS count, MAX(geo_country) AS country,"
        " MAX(asn_name) AS asn, MAX(geo_city) AS city, MAX(rdns) AS rdns,"
        " MAX(threat_score) AS threat_score, MAX(threat_categories) AS threat_categories,"
        " MAX(timestamp) AS last_seen"
        f" FROM {dashboard_relation(source)} WHERE {where} AND threat_score>50 AND remote_ip IS NOT NULL"
        " AND host(remote_ip)!=ALL(%s)"
        " GROUP BY remote_ip ORDER BY MAX(threat_score) DESC,count DESC,remote_ip LIMIT 10"
        ") SELECT host(s.remote_ip) AS ip,s.count,s.country,s.asn,s.city,s.rdns,"
        " s.threat_score,COALESCE(s.threat_categories,t.threat_categories) AS threat_categories,"
        " s.last_seen FROM top_ips s LEFT JOIN ip_threats t ON s.remote_ip=t.ip"
        " ORDER BY s.threat_score DESC,s.count DESC,s.remote_ip"
    )
    with phase('query'), phase('stats_threats'):
        cur.execute(query, [*query_params, exclude_ips])
        rows = cur.fetchall()
    results = []
    for r in rows:
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


def _query_dashboard_tables(cur, cutoff, scope=None, *, source='logs'):
    """Keep all top-N outputs with two broad scans and a selective threat scan."""
    from dashboard_tables import dimension_tables_sql, address_tables_sql
    from request_work import phase

    where, query_params = scope or ('timestamp >= %s', [cutoff])
    dimension_fields = {
        'top_blocked_countries': 'country', 'top_allowed_countries': 'country',
        'top_blocked_services': 'service_name', 'top_allowed_services': 'service_name',
        'top_dns': 'dns_query',
    }
    address_fields = {
        'top_blocked_ips': ('ip', 'count', 'country', 'asn', 'threat_score'),
        'top_blocked_internal_ips': ('ip', 'count', 'device_name'),
        'top_active_internal_ips': ('ip', 'count', 'device_name'),
        'top_allowed_destinations': ('ip', 'count', 'country', 'asn'),
    }
    result = {name: [] for name in (*dimension_fields, *address_fields, 'top_threat_ips')}
    with phase('query'), phase('stats_dimensions'):
        cur.execute(dimension_tables_sql(where, source=source), query_params)
        dimensions = cur.fetchall()
    for row in dimensions:
        result[row['category']].append({dimension_fields[row['category']]: row['label'],
                                        'count': row['count']})

    exclude_ips = _build_exclude_ips()
    gateway_ips = get_config(enricher_db, 'gateway_ips') or []
    with phase('query'), phase('stats_addresses'):
        cur.execute(address_tables_sql(where, source=source),
                    [*query_params, exclude_ips, gateway_ips, exclude_ips, cutoff])
        addresses = cur.fetchall()
    for row in addresses:
        result[row['category']].append({field: row[field] for field in address_fields[row['category']]})
    result['top_threat_ips'] = _query_top_threat_ips(
        cur, cutoff, exclude_ips, scope=scope, source=source)
    _annotate_internal_ips(result['top_blocked_internal_ips'], result['top_active_internal_ips'])
    return result


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


def _query_overview(cur, cutoff, scope=None, *, source='logs'):
    sql, params = overview_query(cutoff, scope, source=source)
    with phase('query'), phase('stats_overview'):
        cur.execute(sql, params)
        rows = cur.fetchall()
    return overview_result(rows)


def _query_timeseries(cur, cutoff, bucket, scope=None, *, source='logs'):
    sql, params = series_query(bucket, scope or ('timestamp >= %s', [cutoff]), source=source)
    with phase('query'), phase('stats_charts'):
        cur.execute(sql, params)
        rows = cur.fetchall()
    return series_result(rows)


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


# Reuse the same exact tier queries for legacy clients. Parallel scans of the
# same wide window compete for storage; reducing passes also helps ingestion.
@router.get("/api/stats")
def get_stats(
    time_range: str = Query("24h", description="1h,6h,24h,7d,30d,60d"),
    exclude_groups: Optional[str] = None,
):
    """Complete dashboard response, sharing the same exact tier queries."""
    cutoff = parse_time_range(time_range)
    if not cutoff:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    bucket = _get_bucket(time_range)
    _stats_scope(cutoff, exclude_groups)  # Reject malformed profiles before DB access.
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            source, scope = choose_dashboard_source(cur, cutoff, exclude_groups)
            summary = _query_overview(cur, cutoff, scope if exclude_groups else None, source=source)
            tables = _query_dashboard_tables(cur, cutoff, scope=scope, source=source)
            logs_over_time, traffic_by_action = _query_timeseries(
                cur, cutoff, bucket, scope=scope, source=source)
        with phase('commit'):
            conn.commit()
        return {
            'time_range': time_range, **summary, **tables,
            'logs_per_hour': logs_over_time, 'logs_over_time': logs_over_time,
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

    _stats_scope(cutoff, exclude_groups)
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            source, scope = choose_dashboard_source(cur, cutoff, exclude_groups)
            summary = _query_overview(cur, cutoff, scope if exclude_groups else None, source=source)

        with phase('commit'):
            conn.commit()
        return {
            'time_range': time_range,
            **summary,
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
    from request_work import phase
    cutoff = parse_time_range(time_range)
    if not cutoff:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    _stats_scope(cutoff, exclude_groups)
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            source, scope = choose_dashboard_source(cur, cutoff, exclude_groups)
            result = _query_dashboard_tables(cur, cutoff, scope=scope, source=source)
        with phase('commit'):
            conn.commit()
        return result
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

    _stats_scope(cutoff, exclude_groups)
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            source, scope = choose_dashboard_source(cur, cutoff, exclude_groups)
            logs_over_time, traffic_by_action = _query_timeseries(
                cur, cutoff, bucket, scope=scope, source=source)

        with phase('commit'):
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
