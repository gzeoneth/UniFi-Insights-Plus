"""Opt-in, reversible buffering settings for the embedded PostgreSQL server."""

import argparse
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import tempfile


PREFIX = 'EMBEDDED_PG_'
MANAGED_NAME = 'unifi-insights-managed.conf'
MANAGED_HEADER = '# Managed by UniFi Insights Plus postgres_config.py; do not edit.\n'
INCLUDE_LINE = f"include_if_exists = '{MANAGED_NAME}'"
POSTGRES = '/usr/lib/postgresql/16/bin/postgres'
LOCAL_HOSTS = {'', '127.0.0.1', 'localhost', 'localhost.localdomain', '::1'}
# Environment suffix: (PostgreSQL name, default, minimum, maximum, unit).
INTEGER_SETTINGS = {
    'SHARED_BUFFERS_MB': ('shared_buffers', 512, 128, 2048, 'MB'),
    'EFFECTIVE_CACHE_SIZE_MB': ('effective_cache_size', 2048, 256, 8192, 'MB'),
    'WORK_MEM_MB': ('work_mem', 8, 1, 16, 'MB'),
    'MAINTENANCE_WORK_MEM_MB': ('maintenance_work_mem', 64, 16, 256, 'MB'),
    'WAL_BUFFERS_MB': ('wal_buffers', 16, 1, 64, 'MB'),
    'MAX_WAL_SIZE_MB': ('max_wal_size', 2048, 512, 8192, 'MB'),
    'CHECKPOINT_TIMEOUT_SECONDS': ('checkpoint_timeout', 900, 60, 1800, 's'),
}
DURABILITY = {'fsync': 'on', 'full_page_writes': 'on', 'synchronous_commit': 'on'}


class PostgresConfigError(ValueError):
    """Startup configuration is invalid or cannot be applied safely."""


@dataclass(frozen=True)
class PostgresSettings:
    profile: str
    values: dict
    external: bool = False

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        if env.get('DB_HOST', '127.0.0.1').strip().lower() not in LOCAL_HOSTS:
            return cls('off', {}, external=True)
        profile = env.get(PREFIX + 'PROFILE', 'off').strip().lower()
        if profile not in {'off', 'balanced'}:
            raise PostgresConfigError('EMBEDDED_PG_PROFILE must be off or balanced')
        allowed = {PREFIX + name for name in INTEGER_SETTINGS}
        allowed |= {PREFIX + 'PROFILE', PREFIX + 'CHECKPOINT_COMPLETION_TARGET',
                    PREFIX + 'WAL_COMPRESSION'}
        if any(name.startswith(PREFIX) and name not in allowed for name in env):
            raise PostgresConfigError('Unknown EMBEDDED_PG_ setting; check the documented names')
        overrides = {name: value for name, value in env.items()
                     if name in allowed and name != PREFIX + 'PROFILE' and value.strip()}
        if profile == 'off':
            if overrides:
                raise PostgresConfigError('EMBEDDED_PG_ overrides require EMBEDDED_PG_PROFILE=balanced')
            return cls(profile, {})

        values = {}
        numbers = {}
        for suffix, (name, default, minimum, maximum, unit) in INTEGER_SETTINGS.items():
            key = PREFIX + suffix
            raw = env.get(key, '').strip() or str(default)
            if not re.fullmatch(r'[0-9]{1,8}', raw):
                raise PostgresConfigError(f'{key} must be an integer between {minimum} and {maximum}')
            number = int(raw)
            if not minimum <= number <= maximum:
                raise PostgresConfigError(f'{key} must be between {minimum} and {maximum}')
            numbers[name] = number
            values[name] = f'{number}{unit}'
        if numbers['effective_cache_size'] < numbers['shared_buffers']:
            raise PostgresConfigError('Effective cache size must be at least shared buffers')

        key = PREFIX + 'CHECKPOINT_COMPLETION_TARGET'
        raw = env.get(key, '').strip() or '0.9'
        try:
            target = Decimal(raw)
            valid = bool(re.fullmatch(r'0\.[0-9]{1,4}', raw)) and Decimal('0.5') <= target <= Decimal('0.95')
        except InvalidOperation:
            valid = False
        if not valid:
            raise PostgresConfigError(f'{key} must be a decimal between 0.5 and 0.95')
        values['checkpoint_completion_target'] = str(target.normalize())
        compression = env.get(PREFIX + 'WAL_COMPRESSION', '').strip().lower() or 'on'
        if compression not in {'on', 'off'}:
            raise PostgresConfigError('EMBEDDED_PG_WAL_COMPRESSION must be on or off')
        values['wal_compression'] = compression
        values.update(DURABILITY)
        return cls(profile, values)

    def render(self):
        return MANAGED_HEADER + '# Disable with EMBEDDED_PG_PROFILE=off and restart.\n' + ''.join(
            f"{name} = '{value}'\n" for name, value in self.values.items())


def _read_regular(path):
    if path.is_symlink() or not path.is_file():
        raise PostgresConfigError(f'{path.name} must be a regular file')
    return path.read_bytes()


def _atomic_write(path, contents, metadata):
    """Replace one configuration file without changing its owner or permissions."""
    descriptor, temporary = tempfile.mkstemp(prefix=f'.{path.name}.', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), stat.S_IMODE(metadata.st_mode))
            if os.geteuid() == 0:
                os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def validate_effective(pgdata, values):
    """Ask PostgreSQL to parse its files without starting or connecting to it.

    Compare normalized values rather than trying to reproduce PostgreSQL's unit
    conversion. ALTER SYSTEM remains untouched, but cannot silently defeat the
    selected profile or its durability settings.
    """
    identity = {}
    if os.geteuid() == 0:
        account = pwd.getpwnam('postgres')
        identity = {'user': account.pw_uid, 'group': account.pw_gid, 'extra_groups': []}

    def read_setting(name, override=None):
        command = [POSTGRES, '-D', str(pgdata), '-C', name]
        if override is not None:
            command += ['-c', f'{name}={override}']
        try:
            result = subprocess.run(command, capture_output=True, text=True,
                                    timeout=10, check=False, **identity)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PostgresConfigError(f'Unable to validate PostgreSQL setting {name}') from exc
        if result.returncode:
            # Configuration errors can include user-supplied values; do not print stderr.
            raise PostgresConfigError(f'PostgreSQL rejected configuration while checking {name}')
        return result.stdout.strip()

    for name, expected in values.items():
        actual = read_setting(name)
        normalized_expected = read_setting(name, expected)
        if actual != normalized_expected:
            raise PostgresConfigError(
                f'{name} conflicts with the selected profile; check postgresql.auto.conf '
                'or later includes, or disable EMBEDDED_PG_PROFILE')


def apply_settings(pgdata, settings, validator=validate_effective):
    """Apply before PostgreSQL starts; restore prior bytes if validation fails."""
    if settings.external:
        return 'external database: embedded profile skipped'
    pgdata = Path(pgdata)
    managed = pgdata / MANAGED_NAME
    old_managed = None
    if managed.exists() or managed.is_symlink():
        old_managed = _read_regular(managed)
        if not old_managed.startswith(MANAGED_HEADER.encode()):
            raise PostgresConfigError(f'{MANAGED_NAME} is not an app-managed file; refusing to replace it')

    if settings.profile == 'off':
        if old_managed is not None:
            managed.unlink()
            return 'profile disabled; previous PostgreSQL settings restored'
        return 'profile off; PostgreSQL configuration unchanged'

    config = pgdata / 'postgresql.conf'
    original = _read_regular(config)
    metadata = config.stat()
    rendered = settings.render().encode()
    # Preserve all existing directives and comments; append one optional include.
    lines = original.decode().splitlines()
    if INCLUDE_LINE in lines:
        updated = original
    else:
        updated = original + (b'\n' if original and not original.endswith(b'\n') else b'')
        updated += b'\n# Optional UniFi Insights Plus buffering profile.\n' + INCLUDE_LINE.encode() + b'\n'
    try:
        if old_managed != rendered:
            _atomic_write(managed, rendered, metadata)
        if updated != original:
            _atomic_write(config, updated, metadata)
        validator(pgdata, settings.values)
    except Exception:
        if updated != original:
            _atomic_write(config, original, metadata)
        if old_managed is None:
            managed.unlink(missing_ok=True)
        elif old_managed != rendered:
            _atomic_write(managed, old_managed, metadata)
        raise
    return 'balanced profile validated; applies when embedded PostgreSQL starts'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--validate', action='store_true', help='validate environment without writing files')
    parser.add_argument('pgdata', nargs='?', default='/var/lib/postgresql/data')
    args = parser.parse_args()
    try:
        settings = PostgresSettings.from_env()
        if args.validate:
            return 0
        print(f'[postgres-config] {apply_settings(args.pgdata, settings)}')
    except (PostgresConfigError, OSError) as exc:
        # Deliberately omit exception values: filesystem errors can reveal paths.
        message = str(exc) if isinstance(exc, PostgresConfigError) else 'Unable to update PostgreSQL configuration files'
        print(f'[postgres-config] {message}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
