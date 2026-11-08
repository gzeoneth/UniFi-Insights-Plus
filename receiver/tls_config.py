"""Optional native TLS with a persistent, explicitly managed certificate."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import fcntl
import ipaddress
import logging
import os
from pathlib import Path
import re
import ssl
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

logger = logging.getLogger(__name__)


class TLSConfigError(ValueError):
    """TLS was requested but cannot be started safely."""


def _identities(value):
    result = []
    for item in value.split(','):
        name = item.strip().lower()
        if not name:
            raise TLSConfigError('HTTPS_HOSTNAMES must contain comma-separated DNS names or IP addresses.')
        try:
            identity = x509.IPAddress(ipaddress.ip_address(name))
        except ValueError:
            try:
                name = name.encode('idna').decode('ascii')
            except UnicodeError as exc:
                raise TLSConfigError('Invalid DNS name in HTTPS_HOSTNAMES.') from exc
            if len(name) > 253 or not all(
                re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                for label in name.split('.')
            ):
                raise TLSConfigError('HTTPS_HOSTNAMES accepts DNS names and IPs, without URLs, ports or wildcards.')
            identity = x509.DNSName(name)
        if identity not in result:
            result.append(identity)
    return result


@dataclass(frozen=True)
class TLSSettings:
    enabled: bool
    cert_file: Path
    key_file: Path
    generated: bool
    identities: tuple
    days: int

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        enabled = env.get('HTTPS_ENABLED', 'false').strip().lower()
        if enabled not in ('true', 'false', '1', '0', 'yes', 'no', 'on', 'off'):
            raise TLSConfigError('HTTPS_ENABLED must be true or false.')
        cert_dir = Path(env.get('HTTPS_CERT_DIR', '/var/lib/unifi-log-insight/tls'))
        if enabled in ('false', '0', 'no', 'off'):
            return cls(False, cert_dir / 'cert.pem', cert_dir / 'key.pem', True, (), 365)
        cert, key = env.get('HTTPS_CERT_FILE', ''), env.get('HTTPS_KEY_FILE', '')
        if bool(cert) != bool(key):
            raise TLSConfigError('Set HTTPS_CERT_FILE and HTTPS_KEY_FILE together, or leave both unset.')
        if cert:
            settings = cls(True, Path(cert), Path(key), False, (), 365)
        else:
            try:
                days = int(env.get('HTTPS_CERT_DAYS', '365'))
            except ValueError as exc:
                raise TLSConfigError('HTTPS_CERT_DAYS must be an integer from 1 to 825.') from exc
            if not 1 <= days <= 825:
                raise TLSConfigError('HTTPS_CERT_DAYS must be an integer from 1 to 825.')
            identities = _identities(env.get('HTTPS_HOSTNAMES', 'localhost,127.0.0.1'))
            # Always support a verified loopback health check.
            for identity in _identities('localhost,127.0.0.1,::1'):
                if identity not in identities:
                    identities.append(identity)
            settings = cls(True, cert_dir / 'cert.pem', cert_dir / 'key.pem', True, tuple(identities), days)
        if not settings.cert_file.is_absolute() or not settings.key_file.is_absolute():
            raise TLSConfigError('HTTPS certificate paths must be absolute.')
        return settings


def _atomic_write(path, content):
    fd, temp = tempfile.mkstemp(prefix='.tls-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def _generate(settings):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'UniFi Insights Plus')])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=settings.days))
        .add_extension(x509.SubjectAlternativeName(settings.identities), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                    key_encipherment=True, data_encipherment=False,
                                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                                    encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    _atomic_write(settings.key_file, key.private_bytes(serialization.Encoding.PEM,
                  serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    _atomic_write(settings.cert_file, cert.public_bytes(serialization.Encoding.PEM))
    logger.info('Generated a self-signed HTTPS certificate; persist HTTPS_CERT_DIR across upgrades.')


def validate_certificate(settings):
    """Check material without replacing it or silently falling back to HTTP."""
    try:
        cert = x509.load_pem_x509_certificate(settings.cert_file.read_bytes())
        now = datetime.now(timezone.utc)
        if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
            raise TLSConfigError('HTTPS certificate is expired or not yet valid; replace it and restart.')
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if not names.get_values_for_type(x509.DNSName) and not names.get_values_for_type(x509.IPAddress):
            raise TLSConfigError('HTTPS certificate must contain a DNS or IP subject alternative name.')
        if settings.generated and not set(settings.identities).issubset(set(names)):
            raise TLSConfigError('Saved certificate does not cover HTTPS_HOSTNAMES. Follow docs/https.md to replace it.')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(settings.cert_file, settings.key_file, password=lambda: '')
        if cert.not_valid_after_utc - now < timedelta(days=30):
            logger.warning('HTTPS certificate expires in less than 30 days; replace it before expiry.')
        return cert
    except TLSConfigError:
        raise
    except (OSError, ValueError, ssl.SSLError, x509.ExtensionNotFound) as exc:
        raise TLSConfigError('Cannot load HTTPS certificate/key. Check files, SANs, permissions and matching unencrypted key.') from exc


def prepare_tls(settings):
    if not settings.enabled:
        return
    if settings.generated:
        directory = settings.cert_file.parent
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
        with (directory / '.generate.lock').open('a') as lock:
            os.chmod(lock.name, 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX)
            if settings.cert_file.is_symlink() or settings.key_file.is_symlink():
                raise TLSConfigError('Generated TLS files must not be symlinks. Use HTTPS_CERT_FILE/HTTPS_KEY_FILE for mounted certificates.')
            exists = (settings.cert_file.exists(), settings.key_file.exists())
            if exists == (False, False):
                _generate(settings)
            elif exists != (True, True):
                raise TLSConfigError('Incomplete saved HTTPS certificate/key pair; restore both files or replace them explicitly.')
            settings.key_file.chmod(0o600)
            settings.cert_file.chmod(0o600)
            validate_certificate(settings)
    else:
        validate_certificate(settings)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    try:
        prepare_tls(TLSSettings.from_env())
    except (TLSConfigError, OSError) as exc:
        raise SystemExit(f'HTTPS startup failed: {exc}')
