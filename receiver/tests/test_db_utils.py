"""Tests for db.py utility functions — encryption, connection params, external DB detection,
positive-int parsing, log presence."""

import pytest

from unittest.mock import MagicMock

from db import (
    _normalize_db_host,
    build_conn_params,
    decrypt_api_key,
    encrypt_api_key,
    has_logs,
    is_external_db,
    parse_positive_int,
)


# ── _normalize_db_host ───────────────────────────────────────────────────────

class TestNormalizeDbHost:
    def test_strip_whitespace(self):
        assert _normalize_db_host('  localhost  ') == 'localhost'

    def test_lowercase(self):
        assert _normalize_db_host('LOCALHOST') == 'localhost'

    def test_combined(self):
        assert _normalize_db_host('  DB.Example.COM  ') == 'db.example.com'


# ── encrypt_api_key / decrypt_api_key ────────────────────────────────────────

class TestApiKeyEncryption:
    def test_round_trip(self, monkeypatch):
        monkeypatch.setenv('SECRET_KEY', 'test-secret-key')
        original = 'my-api-key-12345'
        encrypted = encrypt_api_key(original)
        assert encrypted != original
        decrypted = decrypt_api_key(encrypted)
        assert decrypted == original

    def test_wrong_key_returns_empty(self, monkeypatch):
        monkeypatch.setenv('SECRET_KEY', 'key-one')
        encrypted = encrypt_api_key('my-api-key')
        monkeypatch.setenv('SECRET_KEY', 'key-two')
        assert decrypt_api_key(encrypted) == ''

    def test_empty_encrypted_returns_empty(self, monkeypatch):
        monkeypatch.setenv('SECRET_KEY', 'test')
        assert decrypt_api_key('') == ''

    def test_no_secret_raises(self):
        # Both SECRET_KEY and POSTGRES_PASSWORD are cleared by conftest
        with pytest.raises(ValueError, match='SECRET_KEY'):
            encrypt_api_key('test')

    def test_postgres_password_fallback(self, monkeypatch):
        monkeypatch.setenv('POSTGRES_PASSWORD', 'pg-pass')
        encrypted = encrypt_api_key('test-key')
        decrypted = decrypt_api_key(encrypted)
        assert decrypted == 'test-key'


# ── build_conn_params ────────────────────────────────────────────────────────

class TestBuildConnParams:
    def test_defaults(self):
        params = build_conn_params()
        assert params['host'] == '127.0.0.1'
        assert params['port'] == 5432
        assert params['dbname'] == 'unifi_logs'
        assert params['user'] == 'unifi'
        assert params['password'] == 'changeme'

    def test_custom_host(self, monkeypatch):
        monkeypatch.setenv('DB_HOST', 'db.example.com')
        params = build_conn_params()
        assert params['host'] == 'db.example.com'

    def test_custom_port(self, monkeypatch):
        monkeypatch.setenv('DB_PORT', '5433')
        params = build_conn_params()
        assert params['port'] == 5433

    def test_ssl_params(self, monkeypatch):
        monkeypatch.setenv('DB_SSLMODE', 'require')
        monkeypatch.setenv('DB_SSLROOTCERT', '/certs/ca.pem')
        params = build_conn_params()
        assert params['sslmode'] == 'require'
        assert params['sslrootcert'] == '/certs/ca.pem'

    def test_no_ssl_by_default(self):
        params = build_conn_params()
        assert 'sslmode' not in params

    def test_db_password_env(self, monkeypatch):
        monkeypatch.setenv('DB_PASSWORD', 'explicit-pass')
        params = build_conn_params()
        assert params['password'] == 'explicit-pass'

    def test_postgres_password_fallback(self, monkeypatch):
        monkeypatch.setenv('POSTGRES_PASSWORD', 'pg-pass')
        params = build_conn_params()
        assert params['password'] == 'pg-pass'


# ── is_external_db ───────────────────────────────────────────────────────────

class TestIsExternalDb:
    def test_default_is_local(self):
        assert is_external_db() is False

    def test_localhost(self, monkeypatch):
        monkeypatch.setenv('DB_HOST', 'localhost')
        assert is_external_db() is False

    def test_ipv6_loopback(self, monkeypatch):
        monkeypatch.setenv('DB_HOST', '::1')
        assert is_external_db() is False

    def test_remote_host(self, monkeypatch):
        monkeypatch.setenv('DB_HOST', 'db.example.com')
        assert is_external_db() is True

    def test_whitespace_stripped(self, monkeypatch):
        monkeypatch.setenv('DB_HOST', '  localhost  ')
        assert is_external_db() is False


# ── parse_positive_int ───────────────────────────────────────────────────────

class TestParsePositiveInt:
    @pytest.mark.parametrize('raw, expected', [(60, 60), ('90', 90), (' 7 ', 7), (1, 1)])
    def test_accepts_positive_coercible(self, raw, expected):
        assert parse_positive_int(raw) == expected

    @pytest.mark.parametrize('raw', [0, '0', -5, '-5', '', 'abc', None, '1.5', [1]])
    def test_rejects_non_positive_or_non_coercible(self, raw):
        assert parse_positive_int(raw) is None


# ── has_logs ─────────────────────────────────────────────────────────────────

class TestHasLogs:
    """has_logs(): EXISTS probe instead of an unbounded COUNT(*) (#103)."""

    @staticmethod
    def _db(exists):
        db = MagicMock()
        cur = MagicMock()
        cur.fetchone.return_value = (exists,)
        conn = db.get_conn.return_value.__enter__.return_value
        conn.cursor.return_value.__enter__.return_value = cur
        return db, cur

    @pytest.mark.parametrize('exists', [True, False])
    def test_returns_bool(self, exists):
        db, _ = self._db(exists)
        assert has_logs(db, 'firewall') is exists

    def test_uses_exists_not_count(self):
        db, cur = self._db(True)
        has_logs(db, 'dns')
        sql, params = cur.execute.call_args.args
        sql = ' '.join(sql.split())
        assert 'EXISTS (SELECT 1 FROM logs WHERE log_type = %s)' in sql
        assert 'COUNT(' not in sql
        assert params == ['dns']
