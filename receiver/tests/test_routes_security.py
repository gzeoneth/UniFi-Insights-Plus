"""Security counts verified with synthetic rows and real SQL aggregation."""

import sqlite3
import sys
from datetime import datetime
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def security_client(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    connection = sqlite3.connect(':memory:', check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute('''CREATE TABLE logs (
        id INTEGER PRIMARY KEY, timestamp TEXT, log_type TEXT, event_source TEXT,
        rule_action TEXT, threat_score INTEGER, ips_signature_id TEXT,
        ips_signature TEXT, ips_risk TEXT, ips_severity INTEGER, raw_log TEXT)''')
    executed = []

    class Cursor:
        def __enter__(self):
            self.inner = connection.cursor()
            return self

        def __exit__(self, *args):
            self.inner.close()

        def execute(self, query, params):
            executed.append((query, params))
            params = [value.isoformat() if hasattr(value, 'isoformat') else value for value in params]
            # SQLite LIKE is case-insensitive for the ASCII CEF fixtures.
            self.inner.execute(query.replace('%s', '?').replace(' ILIKE ', ' LIKE '), params)

        def fetchone(self):
            return dict(self.inner.fetchone())

        def fetchall(self):
            result = []
            for row in self.inner.fetchall():
                value = dict(row)
                value['last_seen'] = datetime.fromisoformat(value['last_seen'])
                result.append(value)
            return result

    pooled = MagicMock()
    pooled.cursor.side_effect = lambda **kwargs: Cursor()
    deps = MagicMock()
    deps.get_conn.return_value = pooled
    monkeypatch.setitem(sys.modules, 'deps', deps)
    monkeypatch.delitem(sys.modules, 'routes.security', raising=False)
    from routes.security import router
    app = FastAPI()
    app.include_router(router)
    yield TestClient(app), connection, executed, deps
    connection.close()


def add_row(connection, row_id, *, source=None, action=None, score=None,
            signature_id='1', signature='Synthetic signature', risk='high', severity=7,
            stamp='2026-01-02T12:00:00+00:00', log_type='firewall', raw_log=None):
    connection.execute('INSERT INTO logs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                       (row_id, stamp, log_type, source, action, score, signature_id, signature, risk, severity, raw_log))
    connection.commit()


def test_ips_reputation_and_plain_firewall_counts_are_independent(security_client):
    client, connection, executed, deps = security_client
    add_row(connection, 1, source='unifi_ips', action='block', score=None)
    add_row(connection, 2, source='unifi_ips', action='allow', score=80)
    add_row(connection, 3, source='unifi_ips', action=None, score=50)
    add_row(connection, 4, action='block', score=91, signature_id=None)
    add_row(connection, 5, action='block', log_type='dns', signature_id=None)
    add_row(connection, 6, source='unifi_ips', action='block', stamp='2025-12-01T00:00:00+00:00')
    response = client.get('/api/security/summary', params={
        'time_from': '2026-01-01T00:00:00+00:00', 'time_to': '2026-01-03T00:00:00+00:00'})
    assert response.status_code == 200
    data = response.json()
    assert {key: data[key] for key in ('ips_blocked', 'ips_allowed', 'ips_unknown',
                                     'firewall_blocks', 'reputation_alerts')} == {
        'ips_blocked': 1, 'ips_allowed': 1, 'ips_unknown': 1,
        'firewall_blocks': 1, 'reputation_alerts': 2}
    assert data['top_signatures'][0]['count'] == 3
    assert executed[0][1] == executed[1][1] * 4  # Identical bounds, captured only once.
    deps.put_conn.assert_called_once_with(deps.get_conn.return_value)


def test_signature_risk_and_severity_come_from_latest_row_not_alphabetical_max(security_client):
    client, connection, _, _ = security_client
    add_row(connection, 1, source='unifi_ips', action='block', risk='high', severity=9)
    add_row(connection, 2, source='unifi_ips', action='allow', risk='medium', severity=4,
            stamp='2026-01-02T13:00:00+00:00')
    data = client.get('/api/security/summary', params={'time_from': '2026-01-01T00:00:00Z'}).json()
    signature = data['top_signatures'][0]
    assert signature['count'] == 2
    assert signature['ips_risk'] == 'medium'
    assert signature['ips_severity'] == 4
    assert signature['rule_action'] == 'allow'
    assert signature['last_seen'] == '2026-01-02T13:00:00+00:00'


def test_invalid_time_defaults_to_bounded_range_and_empty_counts(security_client):
    client, _, executed, _ = security_client
    response = client.get('/api/security/summary', params={'time_range': 'all', 'time_from': 'invalid'})
    assert response.status_code == 200
    assert response.json()['time_range'] == '24h'
    assert response.json()['ips_blocked'] == 0
    assert response.json()['top_signatures'] == []
    assert len(executed[0][1]) == 4
    assert isinstance(executed[0][1][0], datetime)


def test_database_failure_is_reported_without_leaking_details_and_connection_returned(security_client):
    client, connection, _, deps = security_client
    connection.execute('DROP TABLE logs')
    response = client.get('/api/security/summary')
    assert response.status_code == 500
    assert response.json() == {'detail': 'Failed to load security summary'}
    deps.put_conn.assert_called_once()


@pytest.mark.parametrize('cef', [
    'CEF:0|Ubiquiti|UniFi Network|10.0.0|200|Threat Detected|7|act=blocked',
    'CEF:0|Ubiquiti|UniFi Network|10.0.0|200|Threat Detected and Blocked|7|act=blocked',
    'CEF:0|Ubiquiti|UniFi Network|10.0.0|200|Example event|7|UNIFIpolicyType=IDS/IPS',
])
def test_unparsed_cef_warning_is_separate_from_verified_ips_and_ignores_view_exclusions(security_client, cef):
    client, connection, _, _ = security_client
    add_row(connection, 1, log_type='system', raw_log=cef, signature_id=None)
    add_row(connection, 2, source='unifi_ips', action='block', raw_log=cef)
    add_row(connection, 3, log_type='system', raw_log='Ordinary status event', signature_id=None)
    add_row(connection, 4, log_type='system', raw_log=cef, signature_id=None, stamp='2025-12-01T00:00:00+00:00')
    response = client.get('/api/security/summary', params={
        'time_from': '2026-01-01T00:00:00Z', 'time_to': '2026-01-03T00:00:00Z',
        'exclude_groups': '[{"conditions":[{"field":"raw_log","operator":"present"}]}]',
    })
    assert response.status_code == 200
    assert response.json()['unparsed_cef_threats'] == 1
    assert response.json()['ips_blocked'] == 1
    assert response.json()['top_signatures'][0]['count'] == 1
