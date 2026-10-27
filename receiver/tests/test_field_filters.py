"""Parameterized-filter validation plus optional PostgreSQL truth-table tests.

Set TEST_POSTGRES_DSN to a disposable local database to execute SQL tests.
All integration rows are synthetic and live in a connection-local temp table.
"""

import json
import os

import pytest
from fastapi import HTTPException

from field_filters import compile_filters


def rule(field, value=None, operator='include'):
    return {'field': field, 'operator': operator, 'value': value}


@pytest.mark.parametrize('value', [
    'not-json', {}, [None], [rule('unknown', 'x')],
    [rule([], 'x')], [rule({}, 'x')], [rule('src_ip', 'fe80::1%eth0')],
    [rule('src_ip', '10.0.0')], [rule('src_ip', "10.0.0.1' OR TRUE --")],
    [rule('dst_port', '-1')], [rule('dst_port', '65536')],
    [rule('dst_port', '80-79')], [rule('dst_port', '1.5')],
    [rule('ips_severity', '11')], [rule('threat_score', '101')],
    [rule('protocol', 'tcp,,udp')], [rule('protocol', 'x', 'sql')],
    [rule('protocol', ','.join(['tcp'] * 33))],
    [rule('search', 'x' * 1025)], [rule('search', 'x')] * 25,
    [{'field': 'search', 'operator': 'present', 'sql': '1=1'}],
])
def test_invalid_filters_fail_closed_as_400(value):
    with pytest.raises(HTTPException) as error:
        compile_filters(value)
    assert error.value.status_code == 400


def test_values_are_parameters_and_field_names_are_allowlisted():
    payload = "x' OR TRUE; DROP TABLE logs; --"
    conditions, params = compile_filters([rule('search', payload)])
    assert payload not in ' '.join(conditions)
    assert params == ['%' + payload + '%']
    with pytest.raises(HTTPException):
        compile_filters([rule('src_ip) OR TRUE --', '10.0.0.1')])


def test_like_metacharacters_and_backslashes_are_literal():
    _, params = compile_filters([rule('search', '%_\\')])
    assert params == [r'%\%\_\\%']


def test_json_and_structured_filter_forms_compile_identically():
    rules = [rule('ip', '2001:db8::/32', 'exclude'), rule('dst_port', '0,443,65535')]
    assert compile_filters(rules) == compile_filters(json.dumps(rules))


@pytest.fixture
def pg_rows():
    dsn = os.environ.get('TEST_POSTGRES_DSN')
    if not dsn:
        pytest.skip('set TEST_POSTGRES_DSN for disposable PostgreSQL integration tests')
    import psycopg2
    connection = psycopg2.connect(dsn)
    with connection.cursor() as cursor:
        cursor.execute('''CREATE TEMP TABLE filter_rows (
            id INTEGER, src_ip INET, dst_ip INET, src_port INTEGER, dst_port INTEGER,
            protocol TEXT, rule_name TEXT, rule_desc TEXT, raw_log TEXT,
            timestamp TIMESTAMPTZ DEFAULT NOW())''')
        cursor.executemany('INSERT INTO filter_rows (id,src_ip,dst_ip,src_port,dst_port,protocol,rule_name,rule_desc,raw_log) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)', [
            (1, '10.0.0.1', '198.51.100.7', 1234, 443, 'TCP', 'alpha', None, r'literal%_\value'),
            (2, '10.0.0.10', None, 1234, 8443, 'tcp', 'beta', None, 'literalXXvalue'),
            (3, None, '203.0.113.1', None, 53, 'udp', None, 'alpha', 'other'),
            (4, '2001:db8::1', None, None, 0, None, None, None, 'literalabvalue'),
            (5, None, None, None, None, None, None, None, None),
            (6, '2001:db8:ffff::1', None, None, 65535, 'udp', 'gamma', None, 'boundary'),
        ])
    yield connection
    connection.rollback()
    connection.close()


def selected(connection, rules):
    conditions, params = compile_filters(rules)
    with connection.cursor() as cursor:
        cursor.execute('SELECT id FROM filter_rows WHERE ' + ' AND '.join(conditions) + ' ORDER BY id', params)
        return [row[0] for row in cursor.fetchall()]


@pytest.mark.parametrize('rules,expected', [
    ([rule('src_ip', '10.0.0.1')], [1]),
    ([rule('ip', '10.0.0.99/24')], [1, 2]),
    ([rule('ip', '10.0.0.0/24', 'exclude')], [3, 4, 5, 6]),
    ([rule('ip', '10.0.0.1,2001:db8::/32')], [1, 4, 6]),
    ([rule('protocol', 'tcp,udp'), rule('dst_port', '443,53')], [1, 3]),
    ([rule('dst_port', '0,8000-9000,65535')], [2, 4, 6]),
    ([rule('dst_port', '1-65535', 'exclude')], [4, 5]),
    ([rule('rule_name', 'alpha')], [1, 3]),
    ([rule('rule_name', 'alpha', 'exclude')], [2, 4, 5, 6]),
    ([rule('rule_name', operator='present')], [1, 2, 3, 6]),
    ([rule('rule_name', operator='missing')], [4, 5]),
    ([rule('search', '%_\\')], [1]),
    ([rule('search', "x' OR TRUE --")], []),
])
def test_postgres_filter_truth_table(pg_rows, rules, expected):
    assert selected(pg_rows, rules) == expected


def test_existing_query_builder_keeps_basic_and_advanced_conditions_together(pg_rows):
    from query_helpers import build_log_query
    where, params = build_log_query(
        log_type=None, time_range='24h', time_from=None, time_to=None,
        src_ip=None, dst_ip=None, ip=None, direction=None, rule_action=None,
        rule_name=None, country=None, threat_min=None, search=None, service=None,
        interface=None, protocol='tcp', filter_rules=json.dumps([rule('dst_port', '443')]),
    )
    with pg_rows.cursor() as cursor:
        cursor.execute('SELECT id FROM filter_rows WHERE ' + where, params)
        assert cursor.fetchall() == [(1,)]
