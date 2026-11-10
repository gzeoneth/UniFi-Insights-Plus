"""Choose exact dashboard storage inside the query's consistent snapshot.

Unfinished history and exclusions requiring omitted raw fields retain the raw
path. The analytics store is a transactionally maintained projection, not a TTL
response cache: coverage is the only readiness boundary, never an event-age cap.
"""

import logging

from psycopg2 import errors

from dashboard_store import enabled, snapshot_state
from field_filters import append_exclusions, parse_exclusion_groups
from request_work import phase

logger = logging.getLogger('api.dashboard')

PROJECTED_SECURITY = {'ips': 'security_ips', 'unparsed_cef': 'security_cef'}
SUPPORTED_EXCLUSION_FIELDS = frozenset((
    'src_ip', 'dst_ip', 'ip', 'remote_ip', 'src_port', 'dst_port', 'port',
    'protocol', 'log_type', 'direction', 'rule_action', 'country', 'service',
    'interface', 'interface_in', 'interface_out', 'event_source', 'source',
    'ips_risk', 'ips_signature_id', 'security_event', 'rule_name_exact',
    'hostname', 'hostname_exact', 'asn', 'threat_score', 'ips_severity',
))


def projection_eligible(exclude_groups):
    groups = parse_exclusion_groups(exclude_groups)
    return all(rule['field'] in SUPPORTED_EXCLUSION_FIELDS
               for group in groups for rule in group['conditions'])


def projection_scope(cutoff, exclude_groups):
    """Compile the same exclusions using exactly mirrored classifications."""
    return append_exclusions('timestamp >= %s', [cutoff], exclude_groups,
                             security_predicates=PROJECTED_SECURITY)


def choose_dashboard_source(cur, cutoff, exclude_groups):
    """Return a trusted relation and scope; missing/older stores fail to raw.

    Read coverage and events in one repeatable-read transaction. An insert,
    enrichment update, retention pass or TRUNCATE cannot become visible on
    only one side of the raw/projection readiness decision.
    """
    raw_scope = append_exclusions('timestamp >= %s', [cutoff], exclude_groups)
    if not enabled() or not projection_eligible(exclude_groups):
        return 'logs', raw_scope
    with phase('analytics_setup'):
        cur.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        # TRUNCATE is not MVCC-safe. Hold the same lightweight relation lock
        # as an ordinary raw SELECT before establishing the state snapshot.
        cur.execute('LOCK TABLE logs IN ACCESS SHARE MODE')
        cur.execute('SAVEPOINT dashboard_store_probe')
        try:
            # Repair/re-enable can clear only the derived relation while
            # ordinary writes continue. Lock it before the first snapshot
            # too, so old readiness cannot be paired with a truncated heap.
            cur.execute('LOCK TABLE dashboard_events IN ACCESS SHARE MODE')
            state = snapshot_state(cur)
        except (errors.UndefinedTable, errors.UndefinedColumn,
                errors.UndefinedFunction, errors.InsufficientPrivilege):
            # Do not swallow cancellation, connection failures or timeouts.
            cur.execute('ROLLBACK TO SAVEPOINT dashboard_store_probe')
            state = None
        cur.execute('RELEASE SAVEPOINT dashboard_store_probe')
    if (not state or state.get('schema_version') != 1
            or state.get('status') == 'disabled' or state.get('healthy') is not True):
        return 'logs', raw_scope
    coverage = state.get('coverage_from')
    if state.get('complete') is True or (coverage is not None and cutoff >= coverage):
        return 'dashboard_events', projection_scope(cutoff, exclude_groups)
    return 'logs', raw_scope
