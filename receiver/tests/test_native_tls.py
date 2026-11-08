"""Native HTTPS certificates persist, fail closed and verify health probes."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import ssl
import stat
from threading import Thread

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import pytest

from api_server import server_options
import healthcheck
from tls_config import TLSConfigError, TLSSettings, prepare_tls, validate_certificate


def settings_at(tmp_path, **changes):
    return TLSSettings.from_env({
        'HTTPS_ENABLED': 'true', 'HTTPS_CERT_DIR': str(tmp_path / 'tls'),
        'HTTPS_HOSTNAMES': 'insights.example,203.0.113.5', **changes,
    })


def fingerprint(settings):
    return (settings.cert_file.read_bytes(), settings.key_file.read_bytes())


def write_test_pair(directory, *, expired=False, future=False, include_san=True):
    """Generate ephemeral key material; no key bytes are kept in fixtures."""
    directory.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'test.example')])
    builder = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now + timedelta(days=1) if future else now - timedelta(days=2))
        .not_valid_after(now - timedelta(days=1) if expired else now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if include_san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName('test.example')]), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    cert_path, key_path = directory / 'mounted.crt', directory / 'mounted.key'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                          serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return TLSSettings.from_env({'HTTPS_ENABLED': 'true', 'HTTPS_CERT_FILE': str(cert_path),
                                'HTTPS_KEY_FILE': str(key_path)})


def test_generation_has_sans_server_usage_and_private_permissions(tmp_path):
    settings = settings_at(tmp_path)
    prepare_tls(settings)
    cert = validate_certificate(settings)
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert set(names.get_values_for_type(x509.DNSName)) == {'localhost', 'insights.example'}
    assert set(names.get_values_for_type(x509.IPAddress)) == {
        ipaddress.ip_address(value) for value in ('127.0.0.1', '::1', '203.0.113.5')
    }
    assert cert.subject == cert.issuer
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert ExtendedKeyUsageOID.SERVER_AUTH in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert timedelta(days=364) < cert.not_valid_after_utc - datetime.now(timezone.utc) <= timedelta(days=365)
    assert stat.S_IMODE(settings.cert_file.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(settings.cert_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(settings.key_file.stat().st_mode) == 0o600


def test_restart_reuses_identity_and_repairs_loose_generated_permissions(tmp_path):
    settings = settings_at(tmp_path)
    prepare_tls(settings)
    original = fingerprint(settings)
    settings.key_file.chmod(0o644)
    settings.cert_file.parent.chmod(0o755)
    prepare_tls(settings_at(tmp_path, HTTPS_CERT_DAYS='730'))
    assert fingerprint(settings) == original
    assert stat.S_IMODE(settings.key_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(settings.cert_file.parent.stat().st_mode) == 0o700


def test_changed_hostnames_require_explicit_replacement(tmp_path):
    settings = settings_at(tmp_path)
    prepare_tls(settings)
    original = fingerprint(settings)
    changed = settings_at(tmp_path, HTTPS_HOSTNAMES='other.example')
    with pytest.raises(TLSConfigError, match='does not cover'):
        prepare_tls(changed)
    assert fingerprint(settings) == original


@pytest.mark.parametrize('missing', ['cert_file', 'key_file'])
def test_partial_pair_is_never_silently_overwritten(tmp_path, missing):
    settings = settings_at(tmp_path)
    prepare_tls(settings)
    remaining = settings.key_file if missing == 'cert_file' else settings.cert_file
    original = remaining.read_bytes()
    getattr(settings, missing).unlink()
    with pytest.raises(TLSConfigError, match='Incomplete'):
        prepare_tls(settings)
    assert remaining.read_bytes() == original
    assert not getattr(settings, missing).exists()


def test_mismatched_pair_fails_without_rotation(tmp_path):
    settings = settings_at(tmp_path)
    other = settings_at(tmp_path / 'other')
    prepare_tls(settings)
    prepare_tls(other)
    settings.key_file.write_bytes(other.key_file.read_bytes())
    original = fingerprint(settings)
    with pytest.raises(TLSConfigError, match='Cannot load'):
        prepare_tls(settings)
    assert fingerprint(settings) == original


@pytest.mark.parametrize('options', [{'expired': True}, {'future': True}, {'include_san': False}])
def test_invalid_custom_material_fails_closed_without_replacement(tmp_path, options):
    settings = write_test_pair(tmp_path, **options)
    original = fingerprint(settings)
    with pytest.raises(TLSConfigError):
        prepare_tls(settings)
    assert fingerprint(settings) == original


def test_custom_pair_is_used_without_chmod_or_regeneration(tmp_path):
    settings = write_test_pair(tmp_path)
    original = fingerprint(settings)
    settings.key_file.chmod(0o640)
    prepare_tls(settings)
    assert fingerprint(settings) == original
    assert stat.S_IMODE(settings.key_file.stat().st_mode) == 0o640
    options = server_options(settings)
    assert options['ssl_certfile'] == str(settings.cert_file)
    assert options['ssl_keyfile'] == str(settings.key_file)
    assert options['proxy_headers'] is False


def test_generated_symlink_is_rejected_without_touching_target(tmp_path):
    settings = settings_at(tmp_path)
    settings.cert_file.parent.mkdir()
    target = tmp_path / 'external'
    target.write_text('unchanged')
    settings.key_file.symlink_to(target)
    with pytest.raises(TLSConfigError, match='symlinks'):
        prepare_tls(settings)
    assert target.read_text() == 'unchanged'


@pytest.mark.parametrize('env', [
    {'HTTPS_ENABLED': 'typo'},
    {'HTTPS_CERT_FILE': '/certificate.pem'},
    {'HTTPS_KEY_FILE': '/private.key'},
    {'HTTPS_CERT_FILE': 'relative.pem', 'HTTPS_KEY_FILE': 'relative.key'},
    {'HTTPS_CERT_DIR': 'relative'},
    {'HTTPS_CERT_DAYS': '0'}, {'HTTPS_CERT_DAYS': '826'}, {'HTTPS_CERT_DAYS': 'abc'},
    {'HTTPS_HOSTNAMES': ''}, {'HTTPS_HOSTNAMES': 'https://test.example'},
    {'HTTPS_HOSTNAMES': 'test.example:8443'}, {'HTTPS_HOSTNAMES': '*.example'},
    {'HTTPS_HOSTNAMES': 'name,,other'}, {'HTTPS_HOSTNAMES': '-bad.example'},
])
def test_invalid_settings_are_rejected(tmp_path, env):
    with pytest.raises(TLSConfigError):
        settings_at(tmp_path, **env)


def test_http_default_creates_no_files_and_disables_implicit_proxy_trust(tmp_path):
    settings = TLSSettings.from_env({'HTTPS_CERT_DIR': str(tmp_path / 'not-created')})
    prepare_tls(settings)
    assert not settings.enabled
    assert not settings.cert_file.parent.exists()
    options = server_options(settings)
    assert options['port'] == 8000
    assert options['proxy_headers'] is False
    assert not any(key.startswith('ssl_') for key in options)


class Handler(BaseHTTPRequestHandler):
    status = 200

    def do_GET(self):
        assert self.path == '/api/health'
        self.send_response(self.status)
        self.end_headers()
        self.wfile.write(b'{}')

    def log_message(self, *args):
        pass


@contextmanager
def local_server(monkeypatch, settings=None, *, status=200):
    class LocalHandler(Handler):
        pass
    LocalHandler.status = status
    server = HTTPServer(('127.0.0.1', 0), LocalHandler)
    if settings:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(settings.cert_file, settings.key_file)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    port = server.server_address[1]
    original_connection = http.client.HTTPConnection

    class TestPortConnection(original_connection):
        def __init__(self, host, requested_port, **kwargs):
            assert host == '127.0.0.1' and requested_port == 8000
            super().__init__(host, port, **kwargs)

    monkeypatch.setattr(healthcheck.http.client, 'HTTPConnection', TestPortConnection)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_https_healthcheck_verifies_real_generated_certificate(tmp_path, monkeypatch):
    settings = settings_at(tmp_path)
    prepare_tls(settings)
    monkeypatch.setattr(healthcheck.TLSSettings, 'from_env', lambda: settings)
    with local_server(monkeypatch, settings):
        healthcheck.check_health()


def test_https_healthcheck_accepts_custom_cert_without_loopback_san(tmp_path, monkeypatch):
    settings = write_test_pair(tmp_path)
    monkeypatch.setattr(healthcheck.TLSSettings, 'from_env', lambda: settings)
    with local_server(monkeypatch, settings):
        healthcheck.check_health()


def test_https_healthcheck_rejects_another_certificate(tmp_path, monkeypatch):
    expected = settings_at(tmp_path)
    other = settings_at(tmp_path / 'other')
    prepare_tls(expected)
    prepare_tls(other)
    monkeypatch.setattr(healthcheck.TLSSettings, 'from_env', lambda: expected)
    with local_server(monkeypatch, other):
        with pytest.raises(ssl.SSLCertVerificationError):
            healthcheck.check_health()


@pytest.mark.parametrize('status', [200, 503])
def test_http_healthcheck_checks_response_status(tmp_path, monkeypatch, status):
    settings = TLSSettings.from_env({})
    monkeypatch.setattr(healthcheck.TLSSettings, 'from_env', lambda: settings)
    with local_server(monkeypatch, status=status):
        if status == 200:
            healthcheck.check_health()
        else:
            with pytest.raises(RuntimeError, match='503'):
                healthcheck.check_health()
