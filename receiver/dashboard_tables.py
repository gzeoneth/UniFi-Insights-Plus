"""Narrow shared aggregation passes for dashboard top-N tables.

Only aggregated groups are materialized. Raw events and exclusion payloads
remain in the base scan, and each result keeps its own predicates and top ten.
"""

from query_helpers import device_name_client_lateral, device_name_coalesce
from dashboard_queries import dashboard_relation


def dimension_tables_sql(where, *, source='logs'):
    """One base scan for country, service and DNS group counts."""
    branches = []
    for category, column, flag, count_column in (
        ('top_blocked_countries', 'geo_country', 'country_group', 'blocked'),
        ('top_allowed_countries', 'geo_country', 'country_group', 'allowed_outbound'),
        ('top_blocked_services', 'service_name', 'service_group', 'blocked'),
        ('top_allowed_services', 'service_name', 'service_group', 'allowed'),
        ('top_dns', 'dns_query', 'dns_group', 'dns'),
    ):
        branches.append(f"""(
            SELECT '{category}'::text AS category, {column} AS label,
                   {count_column} AS count
            FROM grouped
            WHERE {flag}=0 AND {column} IS NOT NULL AND {count_column}>0
            ORDER BY count DESC, label LIMIT 10
        )""")
    return f"""
        WITH grouped AS MATERIALIZED (
            SELECT geo_country, service_name, dns_query,
                   GROUPING(geo_country) AS country_group,
                   GROUPING(service_name) AS service_group,
                   GROUPING(dns_query) AS dns_group,
                   COUNT(*) FILTER(WHERE rule_action='block') AS blocked,
                   COUNT(*) FILTER(WHERE rule_action='allow') AS allowed,
                   COUNT(*) FILTER(WHERE rule_action='allow' AND direction='outbound') AS allowed_outbound,
                   COUNT(*) FILTER(WHERE log_type='dns') AS dns
            FROM {dashboard_relation(source)} WHERE {where}
              AND ((rule_action='block' AND (geo_country IS NOT NULL OR service_name IS NOT NULL))
                OR (rule_action='allow' AND (service_name IS NOT NULL
                    OR (direction='outbound' AND geo_country IS NOT NULL)))
                OR (log_type='dns' AND dns_query IS NOT NULL))
            GROUP BY GROUPING SETS ((geo_country), (service_name), (dns_query))
        )
        SELECT * FROM ({' UNION ALL '.join(branches)}) ranked
        ORDER BY category, count DESC, label
    """


def address_tables_sql(where, *, source='logs'):
    """One base scan for the four source/destination tables.

    Group by native INET, preserving masks. Public/private and exclusion tests
    depend only on a group key, so applying them after aggregation is exact.
    The three array parameters follow the scope: WAN, gateways, WAN again.
    Inventory recency is the final parameter and applies only to top-N rows.
    """
    return f"""
        WITH grouped AS MATERIALIZED (
            SELECT src_ip, dst_ip,
                   GROUPING(src_ip) AS source_group,
                   GROUPING(dst_ip) AS destination_group,
                   COUNT(*) FILTER(WHERE rule_action='block') AS blocked,
                   COUNT(*) FILTER(WHERE rule_action='allow') AS allowed,
                   MAX(geo_country) FILTER(WHERE rule_action='block') AS blocked_country,
                   MAX(asn_name) FILTER(WHERE rule_action='block') AS blocked_asn,
                   MAX(threat_score) FILTER(WHERE rule_action='block') AS blocked_score,
                   MAX(geo_country) FILTER(WHERE rule_action='allow') AS allowed_country,
                   MAX(asn_name) FILTER(WHERE rule_action='allow') AS allowed_asn
            FROM {dashboard_relation(source)} WHERE {where}
              AND rule_action IN ('block','allow')
              AND (src_ip IS NOT NULL OR dst_ip IS NOT NULL)
            GROUP BY GROUPING SETS ((src_ip), (dst_ip))
        ), top_ips AS (
            (SELECT 'top_blocked_ips'::text AS category, src_ip AS address, blocked AS count,
                    blocked_country AS country, blocked_asn AS asn, blocked_score AS threat_score
             FROM grouped WHERE source_group=0 AND src_ip IS NOT NULL AND blocked>0
               AND host(src_ip)!=ALL(%s) AND is_public_inet(src_ip)
             ORDER BY count DESC, address LIMIT 10)
            UNION ALL
            (SELECT 'top_blocked_internal_ips',src_ip,blocked,NULL::text,NULL::text,NULL::integer
             FROM grouped WHERE source_group=0 AND src_ip IS NOT NULL AND blocked>0
               AND NOT is_public_inet(src_ip)
             ORDER BY blocked DESC,src_ip LIMIT 10)
            UNION ALL
            (SELECT 'top_active_internal_ips',src_ip,allowed,NULL::text,NULL::text,NULL::integer
             FROM grouped WHERE source_group=0 AND src_ip IS NOT NULL AND allowed>0
               AND NOT is_public_inet(src_ip) AND host(src_ip)!=ALL(%s)
             ORDER BY allowed DESC,src_ip LIMIT 10)
            UNION ALL
            (SELECT 'top_allowed_destinations',dst_ip,allowed,allowed_country,allowed_asn,NULL::integer
             FROM grouped WHERE destination_group=0 AND dst_ip IS NOT NULL AND allowed>0
               AND host(dst_ip)!=ALL(%s) AND is_public_inet(dst_ip)
             ORDER BY allowed DESC,dst_ip LIMIT 10)
        )
        SELECT t.category,host(t.address) AS ip,t.count,t.country,t.asn,t.threat_score,
               {device_name_coalesce('c')}
        FROM top_ips t
        {device_name_client_lateral("CASE WHEN t.category IN ('top_blocked_internal_ips', 'top_active_internal_ips') THEN t.address END", 'c', recency_expr='%s')}
        ORDER BY t.category,t.count DESC,t.address
    """
