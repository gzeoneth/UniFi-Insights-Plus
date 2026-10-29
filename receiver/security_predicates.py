"""Security classification shared by filters, summaries and partial indexes.

SQL predicates use doubled percent signs for psycopg parameterized execution.
DDL with no parameters must use security_index_sql(), which unescapes them.
"""

# Keep security detections visible even when an Everyday profile is broad.
# Raw CEF protection also covers historical rows awaiting parser backfill.
# Deliberately conservative: keep Threat-prefixed names and explicit IPS
# metadata even when the old parser did not recognize the CEF header.
# Explicit NULL guards preserve two-valued classification while exposing
# column statistics to PostgreSQL. COALESCE(boolean, FALSE) otherwise falls
# back to a 50% selectivity estimate and can defeat even a partial index.
PARSED_IPS_SQL = (
    "((event_source IS NOT NULL AND event_source IN ('unifi_ips', 'ips')) "
    "OR ips_signature_id IS NOT NULL)"
)
UNPARSED_CEF_THREAT_SQL = (
    "((event_source IS NULL OR event_source NOT IN ('unifi_ips', 'ips')) "
    "AND ips_signature_id IS NULL "
    "AND raw_log IS NOT NULL AND raw_log LIKE '%%CEF:%%' AND ("
    "raw_log LIKE '%%|Threat%%' OR raw_log LIKE '%%UNIFIipsSignature%%' "
    "OR raw_log ILIKE '%%UNIFIpolicyType=IDS/IPS%%'))"
)
SECURITY_EVENT_PREDICATES = {
    'ips': PARSED_IPS_SQL,
    'unparsed_cef': UNPARSED_CEF_THREAT_SQL,
}


def security_index_sql(name, predicate):
    """Build concurrent index DDL from application-owned constants only."""
    return (f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {name} "
            f"ON logs (timestamp DESC, id DESC) WHERE {predicate}").replace("%%", "%")


SECURITY_INDEXES = [
    {"name": "idx_logs_security_ips_time",
     "sql": security_index_sql("idx_logs_security_ips_time", PARSED_IPS_SQL),
     "label": "parsed IPS including legacy source and signature-only rows"},
    {"name": "idx_logs_security_cef_time",
     "sql": security_index_sql("idx_logs_security_cef_time", UNPARSED_CEF_THREAT_SQL),
     "label": "unparsed CEF security candidates"},
]
