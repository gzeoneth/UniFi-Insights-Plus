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
    'protocol': ('enum', ('protocol',)), 'log_type': ('enum', ('log_type',)),
    'direction': ('enum', ('direction',)), 'rule_action': ('enum', ('rule_action',)),
    'country': ('enum', ('geo_country',)), 'service': ('enum', ('service_name',)),
    'interface': ('enum', ('interface_in', 'interface_out')),
    'event_source': ('enum', ('event_source',)), 'source': ('enum', ('source',)),
    'ips_risk': ('enum', ('ips_risk',)),
    'ips_signature_id': ('enum', ('ips_signature_id',)),
    'rule_name': ('text', ('rule_name', 'rule_desc')),
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
        except (ValueError, TypeError):
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
    """
    conditions, params = [], []
    for rule in parse_rules(value):
        kind, columns = FIELDS[rule['field']]
        operator = rule['operator']
        if operator in ('present', 'missing'):
            join = ' OR ' if operator == 'present' else ' AND '
            suffix = 'IS NOT NULL' if operator == 'present' else 'IS NULL'
            conditions.append('(' + join.join(f'{c} {suffix}' for c in columns) + ')')
            continue
        values = [v.strip() for v in rule['value'].split(',')]
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
