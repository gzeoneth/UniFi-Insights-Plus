"""Bounded, parameterized include/exclude filters shared by UI, exports and MCP."""

import ipaddress
import json
import re

from fastapi import HTTPException

# SQL expressions are constants, never supplied by the caller.
FIELDS = {
    'src_ip': ('ip', ('src_ip',)), 'dst_ip': ('ip', ('dst_ip',)),
    'ip': ('ip', ('src_ip', 'dst_ip')), 'remote_ip': ('ip', ('remote_ip',)),
    'src_port': ('port', ('src_port',)), 'dst_port': ('port', ('dst_port',)),
    'port': ('port', ('src_port', 'dst_port')),
    'protocol': ('enum', ('protocol',)), 'log_type': ('enum', ('log_type',)),
    'direction': ('enum', ('direction',)), 'rule_action': ('enum', ('rule_action',)),
    'country': ('enum', ('geo_country',)), 'service': ('enum', ('service_name',)),
    'interface': ('enum', ('interface_in', 'interface_out')),
    'event_source': ('enum', ('event_source',)), 'source': ('enum', ('source',)),
    'ips_risk': ('enum', ('ips_risk',)),
    'ips_signature_id': ('enum', ('ips_signature_id',)),
    'security_event': ('security', ()),
    'rule_name': ('text', ('rule_name', 'rule_desc')),
    'rule_name_exact': ('exact', ('rule_name',)),
    'rule_desc_exact': ('exact', ('rule_desc',)),
    'hostname_exact': ('exact', ('hostname',)),
    'device': ('text', ('src_device_name', 'dst_device_name')),
    'src_device': ('text', ('src_device_name',)),
    'dst_device': ('text', ('dst_device_name',)),
    'hostname': ('text', ('hostname',)), 'asn': ('text', ('asn_name',)),
    'search': ('text', ('raw_log',)), 'ips_signature': ('text', ('ips_signature',)),
    'threat_score': ('score', ('threat_score',)),
    'ips_severity': ('severity', ('ips_severity',)),
}
MAX_RULES = 24
MAX_VALUES = 32
MAX_EXCLUSION_GROUPS = 12
MAX_GROUP_CONDITIONS = 8
MAX_EXCLUSION_CONDITIONS = 48
MAX_EXCLUSION_PAYLOAD = 16384


def _invalid(message):
    raise HTTPException(status_code=400, detail=f'Invalid field filter: {message}')


def parse_rules(value):
    if value is None or value == '':
        return []
    if isinstance(value, str):
        if len(value) > 16384:
            _invalid('filter payload is too large')
        try:
            value = json.loads(value)
        except (ValueError, TypeError, RecursionError):
            _invalid('expected a JSON array')
    if not isinstance(value, list) or len(value) > MAX_RULES:
        _invalid(f'expected at most {MAX_RULES} rules')
    for rule in value:
        if not isinstance(rule, dict) or set(rule) - {'field', 'operator', 'value'}:
            _invalid('each rule requires field, operator and value')
        if not isinstance(rule.get('field'), str) or rule['field'] not in FIELDS:
            _invalid('unknown field')
        if rule.get('operator') not in ('include', 'exclude', 'present', 'missing'):
            _invalid('unknown operator')
        if rule['operator'] in ('include', 'exclude'):
            text = rule.get('value')
            if not isinstance(text, str) or not text.strip() or len(text) > 1024:
                _invalid('value must be nonempty text, at most 1024 characters')
    return value


def compile_filters(value):
    """Rules AND together; comma-separated values OR within each rule.

    Excluding a value retains missing fields. Use present/missing explicitly
    to control NULLs. Text matches literal substrings (not wildcard patterns).
    Exact fields match the whole case-sensitive value, including commas and
    surrounding whitespace, rather than splitting comma-separated terms.
    security_event selects the fixed categories ips and unparsed_cef; its
    present/missing operators mean any/no security classification.
    """
    conditions, params = [], []
    for rule in parse_rules(value):
        kind, columns = FIELDS[rule['field']]
        operator = rule['operator']
        if kind == 'security':
            values = list(SECURITY_EVENT_PREDICATES) if operator in ('present', 'missing') else [
                term.strip().lower() for term in rule['value'].split(',')]
            if len(values) > MAX_VALUES or any(term not in SECURITY_EVENT_PREDICATES for term in values):
                _invalid('security_event accepts only ips or unparsed_cef')
            predicate = '(' + ' OR '.join(SECURITY_EVENT_PREDICATES[term] for term in values) + ')'
            if operator in ('exclude', 'missing'):
                predicate = f'NOT ({predicate})'
            conditions.append(predicate)
            continue
        if operator in ('present', 'missing'):
            join = ' OR ' if operator == 'present' else ' AND '
            suffix = 'IS NOT NULL' if operator == 'present' else 'IS NULL'
            conditions.append('(' + join.join(f'{c} {suffix}' for c in columns) + ')')
            continue
        # Recorded identifiers use the entire value; commas and whitespace
        # can belong to a gateway or rule name.
        values = [rule['value']] if kind == 'exact' else [v.strip() for v in rule['value'].split(',')]
        if len(values) > MAX_VALUES or any(not v for v in values):
            _invalid(f'use 1 to {MAX_VALUES} nonempty comma-separated values')
        matches = []
        for term in values:
            for column in columns:
                if kind == 'ip':
                    try:
                        if '%' in term:
                            raise ValueError('scoped addresses are not supported by PostgreSQL INET')
                        network = ipaddress.ip_network(term, strict=False)
                    except ValueError:
                        _invalid('IP fields require valid addresses or CIDRs')
                    matches.append(f'{column} <<= %s::inet')
                    params.append(str(network))
                elif kind in ('port', 'score', 'severity'):
                    upper = {'port': 65535, 'score': 100, 'severity': 10}[kind]
                    match = re.fullmatch(r'(\d+)(?:-(\d+))?', term)
                    if not match:
                        _invalid('numeric fields require an integer or inclusive range')
                    low, high = int(match[1]), int(match[2] or match[1])
                    if not 0 <= low <= high <= upper:
                        _invalid(f'numeric value must be within 0..{upper}')
                    matches.append(f'{column} BETWEEN %s AND %s')
                    params.extend((low, high))
                elif kind == 'exact':
                    matches.append(f'{column} = %s')
                    params.append(term)
                elif kind == 'enum':
                    matches.append(f'LOWER({column}) = LOWER(%s)')
                    params.append(term)
                else:
                    escaped = term.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
                    matches.append(f"{column} ILIKE %s ESCAPE '\\'")
                    params.append(f'%{escaped}%')
        predicate = '(' + ' OR '.join(matches) + ')'
        # COALESCE makes include/exclude exact complements even for NULLs.
        predicate = f'COALESCE({predicate}, FALSE)'
        if operator == 'exclude':
            predicate = f'NOT ({predicate})'
        conditions.append(predicate)
    return conditions, params


# Keep security detections visible even when an Everyday profile is broad.
# Raw CEF protection also covers historical rows awaiting parser backfill.
# Deliberately conservative: keep Threat-prefixed names and explicit IPS
# metadata even when the old parser did not recognize the CEF header.
PARSED_IPS_SQL = "(COALESCE(event_source IN ('unifi_ips', 'ips'), FALSE) OR ips_signature_id IS NOT NULL)"
UNPARSED_CEF_THREAT_SQL = (
    "(COALESCE(event_source NOT IN ('unifi_ips', 'ips'), TRUE) "
    "AND ips_signature_id IS NULL "
    "AND COALESCE(raw_log LIKE '%%CEF:%%' AND ("
    "raw_log LIKE '%%|Threat%%' OR raw_log LIKE '%%UNIFIipsSignature%%' "
    "OR raw_log ILIKE '%%UNIFIpolicyType=IDS/IPS%%'), FALSE))"
)
SECURITY_EVENT_PREDICATES = {
    'ips': PARSED_IPS_SQL,
    'unparsed_cef': UNPARSED_CEF_THREAT_SQL,
}
_SECURITY_VISIBLE = ' OR '.join(SECURITY_EVENT_PREDICATES.values())


def parse_exclusion_groups(value):
    """Validate query-only groups: AND conditions within, OR between groups."""
    if value is None or value == '':
        return []
    if isinstance(value, str):
        if len(value) > MAX_EXCLUSION_PAYLOAD:
            _invalid('exclusion payload is too large')
        try:
            value = json.loads(value)
        except (ValueError, TypeError, RecursionError):
            _invalid('exclusions must be a JSON array')
    try:
        if len(json.dumps(value)) > MAX_EXCLUSION_PAYLOAD:
            _invalid('exclusion payload is too large')
    except (ValueError, TypeError, RecursionError):
        _invalid('exclusions must contain JSON values')
    if not isinstance(value, list) or len(value) > MAX_EXCLUSION_GROUPS:
        _invalid(f'expected at most {MAX_EXCLUSION_GROUPS} exclusion groups')
    count = 0
    for group in value:
        if not isinstance(group, dict) or set(group) - {'name', 'conditions'}:
            _invalid('each exclusion group requires conditions and an optional name')
        if 'name' in group and (not isinstance(group['name'], str) or len(group['name']) > 100):
            _invalid('exclusion name must be text up to 100 characters')
        conditions = group.get('conditions')
        if not isinstance(conditions, list) or not 1 <= len(conditions) <= MAX_GROUP_CONDITIONS:
            _invalid(f'each exclusion group needs 1 to {MAX_GROUP_CONDITIONS} conditions')
        count += len(conditions)
        if count > MAX_EXCLUSION_CONDITIONS:
            _invalid(f'expected at most {MAX_EXCLUSION_CONDITIONS} exclusion conditions')
        # Also checks field-specific values, not just rule structure.
        compile_filters(conditions)
    return value


def compile_exclusions(value):
    """Return a SQL predicate retaining rows outside every matching group.

    Standard field filters are independent. These exclusions do not delete
    records and cannot hide IPS or historical unparsed CEF threat messages.
    """
    groups = parse_exclusion_groups(value)
    if not groups:
        return [], []
    matches, params = [], []
    for group in groups:
        conditions, group_params = compile_filters(group['conditions'])
        matches.append('(' + ' AND '.join(conditions) + ')')
        params.extend(group_params)
    predicate = '(' + ' OR '.join(matches) + ')'
    return [f'(({_SECURITY_VISIBLE}) OR NOT ({predicate}))'], params


def append_exclusions(where, params, value):
    """Append a profile to an existing base query without mutating its params."""
    conditions, extra_params = compile_exclusions(value)
    if not conditions:
        return where, list(params)
    return f'({where}) AND ' + ' AND '.join(conditions), list(params) + extra_params


def query_view_counts(cursor, base_where, base_params, value):
    """Count visible/hidden events in the base-filter scope, before pagination.

    One aggregate scan produces both counts when a profile is active. Callers
    must pass a query without profile exclusions as the base.
    """
    conditions, params = compile_exclusions(value)
    if conditions:
        cursor.execute(
            f"SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE {' AND '.join(conditions)}) AS visible "
            f"FROM logs WHERE {base_where}",
            params + list(base_params),
        )
        row = cursor.fetchone()
        total, visible = int(row['total']), int(row['visible'])
    else:
        cursor.execute(f'SELECT COUNT(*) AS total FROM logs WHERE {base_where}', base_params)
        total = visible = int(cursor.fetchone()['total'])
    return {'total': total, 'visible': visible, 'hidden': total - visible}
