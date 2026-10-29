"""Flow endpoints use the same view exclusions before aggregation and drill-down."""

import importlib
import json
import os
import sys
from unittest.mock import MagicMock

import pytest


PATHS = ('/api/flows/graph', '/api/flows/zone-matrix', '/api/flows/host-detail')
BOUNDS = {'time_from': '2026-01-01T00:00:00Z', 'time_to': '2026-01-03T00:00:00Z'}
EXCLUSIONS = [{
    'name': 'Routine allows from example gateway',
    'conditions': [
        {'field': 'rule_name_exact', 'operator': 'include', 'value': 'EXAMPLE-A-100'},
        {'field': 'hostname_exact', 'operator': 'include', 'value': 'example-gateway'},
        {'field': 'rule_action', 'operator': 'include', 'value': 'allow'},
    ],
}]
FILTERS = [{'field': 'protocol', 'operator': 'include', 'value': 'tcp'}]


def _load_flows(monkeypatch, connection):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    deps = MagicMock()
    deps.get_conn.return_value = connection
    monkeypatch.setitem(sys.modules, 'deps', deps)
    monkeypatch.delitem(sys.modules, 'routes.flows', raising=False)
    module = importlib.import_module('routes.flows')
    monkeypatch.setattr(module, 'get_config', lambda *args, **kwargs: None)
    monkeypatch.setattr(module, '_lookup_ip_info', lambda *args: ({}, {}, {}))
    monkeypatch.setattr(module, 'load_identity_config', lambda *args: {})
    monkeypatch.setattr(module, 'annotate_ip', lambda cfg, ip, name: (name, None, None))
    app = FastAPI()
    app.include_router(module.router)
    monkeypatch.delitem(sys.modules, 'routes.stats', raising=False)
    stats_module = importlib.import_module('routes.stats')
    monkeypatch.setattr(stats_module, 'load_identity_config', lambda *args: {})
    monkeypatch.setattr(stats_module, 'annotate_record', lambda *args: None)
    app.include_router(stats_module.router)
    return TestClient(app), module, deps


@pytest.fixture
def flow_client(monkeypatch):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchall.return_value = []
    cursor.fetchone.side_effect = [
        {'total_events': 0, 'allow_count': 0, 'block_count': 0,
         'unique_peers': 0, 'first_seen': None, 'last_seen': None,
         'asn_name': None, 'rdns': None},
        None,
        None,
    ]
    client, module, deps = _load_flows(monkeypatch, connection)
    return client, module, deps, cursor


@pytest.mark.parametrize('path', PATHS)
def test_flow_requests_forward_filters_and_exclusions(flow_client, monkeypatch, path):
    client, module, deps, cursor = flow_client
    builder = MagicMock(return_value=('protocol = %s', ['tcp']))
    monkeypatch.setattr(module, 'build_log_query', builder)
    encoded_groups, encoded_filters = json.dumps(EXCLUSIONS), json.dumps(FILTERS)
    response = client.get(path, params={
        **BOUNDS, 'ip': '192.0.2.10',
        'filter_rules': encoded_filters, 'exclude_groups': encoded_groups,
    })
    assert response.status_code == 200
    assert builder.call_args.kwargs['filter_rules'] == encoded_filters
    assert builder.call_args.kwargs['exclude_groups'] == encoded_groups
    log_queries = [call.args for call in cursor.execute.call_args_list
                   if 'FROM logs' in call.args[0]]
    assert log_queries
    for sql, params in log_queries:
        assert 'protocol = %s' in sql
        assert 'tcp' in params
    deps.put_conn.assert_called_once_with(deps.get_conn.return_value)


@pytest.mark.parametrize('path', PATHS)
@pytest.mark.parametrize('parameter', ['filter_rules', 'exclude_groups'])
def test_invalid_flow_filters_fail_before_database_access(flow_client, path, parameter):
    client, _, deps, _ = flow_client
    response = client.get(path, params={'ip': '192.0.2.10', parameter: '{invalid'})
    assert response.status_code == 400
    deps.get_conn.assert_not_called()


@pytest.fixture
def pg_flows(monkeypatch):
    dsn = os.environ.get('TEST_POSTGRES_DSN')
    if not dsn:
        pytest.skip('set TEST_POSTGRES_DSN for disposable PostgreSQL integration tests')
    import psycopg2

    connection = psycopg2.connect(dsn)
    with connection.cursor() as cur:
        cur.execute('''CREATE TEMP TABLE logs (
            id INTEGER, timestamp TIMESTAMPTZ, log_type TEXT,
            src_ip INET, dst_ip INET, protocol TEXT, dst_port INTEGER,
            rule_name TEXT, rule_desc TEXT, rule_action TEXT, hostname TEXT,
            interface_in TEXT, interface_out TEXT, service_name TEXT,
            direction TEXT, asn_name TEXT, rdns TEXT,
            event_source TEXT, ips_signature_id TEXT, raw_log TEXT, threat_score INTEGER)''')
        cur.execute('''CREATE TEMP TABLE unifi_clients (
            ip INET, device_name TEXT, hostname TEXT, oui TEXT,
            network TEXT, vlan INTEGER, mac TEXT, last_seen TIMESTAMPTZ)''')
        cur.execute('''CREATE TEMP TABLE unifi_devices (
            ip INET, device_name TEXT, model TEXT, mac TEXT, updated_at TIMESTAMPTZ)''')
        rows = [
            (1, '192.0.2.10', '198.51.100.20', 'tcp', 443, 'allow', 'example-gateway', None, None, '', 'firewall'),
            (2, '198.51.100.20', '192.0.2.10', 'tcp', 443, 'block', 'example-gateway', None, None, '', 'firewall'),
            (3, '192.0.2.10', '198.51.100.30', 'tcp', 443, 'allow', 'other-gateway', None, None, '', 'firewall'),
            (4, '192.0.2.10', '198.51.100.20', 'tcp', 443, 'allow', 'example-gateway', 'unifi_ips', '1234567', '', 'firewall'),
            (5, '192.0.2.10', '198.51.100.20', 'tcp', 443, None, 'example-gateway', None, None,
             'CEF:0|Ubiquiti|UniFi Network|10.0.0|200|Threat Detected|7|act=blocked', 'system'),
            (6, '192.0.2.10', '198.51.100.20', 'udp', 53, 'allow', 'other-gateway', None, None, '', 'firewall'),
        ]
        cur.executemany('''INSERT INTO logs
            (id,src_ip,dst_ip,protocol,dst_port,rule_action,hostname,
             event_source,ips_signature_id,raw_log,log_type,timestamp,
             rule_name,rule_desc,interface_in,interface_out,service_name,direction)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'2026-01-02T12:00:00Z',
                    'EXAMPLE-A-100','Example routine event','br-example','eth-example','Example','outbound')''', rows)
        cur.execute('''INSERT INTO logs
            SELECT 7,'2020-01-01T00:00:00Z',log_type,src_ip,dst_ip,protocol,dst_port,
                   rule_name,rule_desc,rule_action,hostname,interface_in,interface_out,
                   service_name,direction,asn_name,rdns,event_source,ips_signature_id,raw_log,threat_score
            FROM logs WHERE id=3''')
    connection.commit()
    client, _, _ = _load_flows(monkeypatch, connection)
    client.synthetic_connection = connection
    yield client
    connection.close()


def _flow_params(groups=EXCLUSIONS):
    return {**BOUNDS, 'log_type': 'firewall,system',
            'filter_rules': json.dumps(FILTERS), 'exclude_groups': json.dumps(groups)}


def test_graph_and_zone_totals_match_same_filtered_records(pg_flows):
    params = _flow_params()
    graph = pg_flows.get('/api/flows/graph', params=params)
    matrix = pg_flows.get('/api/flows/zone-matrix', params=params)
    assert graph.status_code == matrix.status_code == 200
    assert sum(node['value'] for node in graph.json()['nodes'] if node['type'] == 'src_ip') == 4
    cells = matrix.json()['cells']
    assert len(cells) == 1
    assert cells[0]['total'] == 4
    assert cells[0]['allow_count'] == 2
    assert cells[0]['block_count'] == 1


def test_host_summary_peers_and_ports_share_exclusion_scope(pg_flows):
    response = pg_flows.get('/api/flows/host-detail', params={**_flow_params(), 'ip': '192.0.2.10'})
    assert response.status_code == 200
    data = response.json()
    assert data['summary']['total_events'] == 4
    assert data['summary']['allow_count'] == 2
    assert data['summary']['block_count'] == 1
    assert {row['peer_ip']: row['count'] for row in data['peers_as_source']} == {
        '198.51.100.20': 2, '198.51.100.30': 1}
    assert {row['peer_ip']: row['count'] for row in data['peers_as_destination']} == {'198.51.100.20': 1}
    assert len(data['ports']) == 1
    assert data['ports'][0]['dst_port'] == 443
    assert data['ports'][0]['count'] == 4


@pytest.mark.parametrize('groups,expected', [([], 5), ([{
    'conditions': [{'field': 'hostname_exact', 'operator': 'include', 'value': 'example-gateway'}],
}], 3)])
def test_empty_profile_and_broad_profile_preserve_security_records(pg_flows, groups, expected):
    response = pg_flows.get('/api/flows/zone-matrix', params=_flow_params(groups))
    assert response.status_code == 200
    assert sum(cell['total'] for cell in response.json()['cells']) == expected


@pytest.mark.parametrize('excluded,expected', [('198.51.100.20', 1), ('198.51.100.0/24', 0)])
def test_exclude_host_matches_graph_matrix_pairs_csv_and_drilldown(pg_flows, excluded, expected):
    import csv
    import io
    filters = [*FILTERS, {'field': 'ip', 'operator': 'exclude', 'value': excluded}]
    params = {**BOUNDS, 'filter_rules': json.dumps(filters)}
    graph = pg_flows.get('/api/flows/graph', params=params)
    matrix = pg_flows.get('/api/flows/zone-matrix', params=params)
    pairs = pg_flows.get('/api/stats/ip-pairs', params=params)
    exported = pg_flows.get('/api/stats/ip-pairs/csv', params=params)
    detail = pg_flows.get('/api/flows/host-detail', params={**params, 'ip': '192.0.2.10'})
    for response in (graph, matrix, pairs, exported, detail):
        assert response.status_code == 200, response.text
    assert sum(node['value'] for node in graph.json()['nodes'] if node['type'] == 'src_ip') == expected
    assert sum(cell['total'] for cell in matrix.json()['cells']) == expected
    assert sum(pair['total_count'] for pair in pairs.json()['pairs']) == expected
    rows = list(csv.DictReader(io.StringIO(exported.text)))
    assert sum(int(row['allow_count']) + int(row['block_count']) for row in rows) == expected
    assert detail.json()['summary']['total_events'] == expected


@pytest.mark.parametrize('path', ['/api/stats/ip-pairs', '/api/stats/ip-pairs/csv'])
def test_invalid_pair_filters_fail_before_database_access(flow_client, path):
    client, _, deps, _ = flow_client
    response = client.get(path, params={'filter_rules': json.dumps([
        {'field': 'ip', 'operator': 'exclude', 'value': 'not-an-address'}])})
    assert response.status_code == 400
    deps.get_conn.assert_not_called()


def test_saved_flow_filters_validate_same_conditions():
    from query_helpers import validate_view_filters
    base = {'dims': ['src_ip', 'dst_port', 'dst_ip'], 'topN': 15,
            'activeActions': ['allow', 'block'], 'activeDirections': ['outbound'],
            'filter_rules': [{'field': 'ip', 'operator': 'exclude', 'value': '192.0.2.0/24'}]}
    assert validate_view_filters(base) is None
    assert validate_view_filters({**base, 'filter_rules': [
        {'field': 'ip', 'operator': 'exclude', 'value': 'invalid'}]}) is not None
    assert validate_view_filters({**base, 'filter_rules': '[]'}) == 'filter_rules must be an array'
    assert validate_view_filters({**base, 'exclude_groups': EXCLUSIONS}) is None
    assert validate_view_filters({**base, 'exclude_groups': [{'conditions': []}]}) is not None


def test_zone_pair_count_preserves_null_and_host_address_semantics(pg_flows):
    connection = pg_flows.synthetic_connection
    with connection.cursor() as cursor:
        cursor.execute('DELETE FROM logs')
        cursor.executemany("""INSERT INTO logs
            (id,timestamp,log_type,src_ip,dst_ip,interface_in,interface_out)
            VALUES (%s,'2026-01-02T12:00:00Z','firewall',%s,%s,'br-example','eth-example')""", [
            (1, '192.0.2.1/24', '198.51.100.2/24'),
            (2, '192.0.2.1/32', '198.51.100.2/32'),
            (3, '2001:db8::1/48', '2001:db8:1::2/64'),
            (4, '2001:db8::1/128', '2001:db8:1::2/128'),
            (5, None, '198.51.100.2'),
            (6, '192.0.2.1', None),
        ])
    connection.commit()
    response = pg_flows.get('/api/flows/zone-matrix', params=BOUNDS)
    assert response.status_code == 200
    assert response.json()['cells'][0]['unique_pairs'] == 2
    assert response.json()['cells'][0]['total'] == 6
