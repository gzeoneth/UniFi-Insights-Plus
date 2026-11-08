"""Managed PostgreSQL settings preserve existing clusters and reject unsafe input."""

from pathlib import Path
import subprocess
from unittest.mock import Mock

import pytest

import postgres_config as config


def balanced(**overrides):
    return config.PostgresSettings.from_env({'EMBEDDED_PG_PROFILE': 'balanced', **overrides})


def cluster(tmp_path):
    path = tmp_path / 'data'
    path.mkdir()
    (path / 'PG_VERSION').write_text('16\n')
    (path / 'postgresql.conf').write_text(
        "# Existing operator settings\nshared_buffers = '128MB'\n"
        "work_mem = '8MB'\nlisten_addresses = '127.0.0.1'\n")
    (path / 'postgresql.auto.conf').write_text('# Operator managed\n')
    (path / 'data-marker').write_text('synthetic database contents')
    return path


def test_default_is_opt_in_and_disabled_does_not_touch_cluster(tmp_path):
    settings = config.PostgresSettings.from_env({})
    assert settings.profile == 'off'
    assert settings.values == {}
    absent = tmp_path / 'not-initialized'
    assert 'unchanged' in config.apply_settings(absent, settings)
    assert not absent.exists()


def test_balanced_is_bounded_and_preserves_durability():
    settings = balanced()
    assert settings.values == {
        'shared_buffers': '512MB', 'effective_cache_size': '2048MB',
        'work_mem': '8MB', 'maintenance_work_mem': '64MB',
        'wal_buffers': '16MB', 'max_wal_size': '2048MB',
        'checkpoint_timeout': '900s', 'checkpoint_completion_target': '0.9',
        'wal_compression': 'on',
        'fsync': 'on', 'full_page_writes': 'on', 'synchronous_commit': 'on',
    }


@pytest.mark.parametrize('host', ['db.example', '  DB.EXAMPLE  ', 'postgres', '192.0.2.12'])
def test_external_database_skips_even_unused_invalid_profile(tmp_path, host):
    settings = config.PostgresSettings.from_env({
        'DB_HOST': host, 'EMBEDDED_PG_PROFILE': 'invalid',
        'EMBEDDED_PG_SHARED_BUFFERS_MB': 'not-a-number',
    })
    assert settings.external
    assert 'skipped' in config.apply_settings(tmp_path / 'absent', settings)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize('host', ['', ' localhost ', 'LOCALHOST.LOCALDOMAIN', '127.0.0.1', '::1'])
def test_embedded_host_normalization(host):
    assert not config.PostgresSettings.from_env({'DB_HOST': host}).external


@pytest.mark.parametrize('suffix,raw', [
    ('PROFILE', 'fast'), ('SHARED_BUFFERS_MB', '127'),
    ('SHARED_BUFFERS_MB', '2049'), ('SHARED_BUFFERS_MB', '512MB'),
    ('SHARED_BUFFERS_MB', "512\nfsync = 'off'"), ('WORK_MEM_MB', '-1'),
    ('WORK_MEM_MB', '1.5'), ('WORK_MEM_MB', '17'), ('MAX_WAL_SIZE_MB', '8193'),
    ('MAX_WAL_SIZE_MB', '0'), ('CHECKPOINT_TIMEOUT_SECONDS', '1801'),
    ('CHECKPOINT_COMPLETION_TARGET', 'NaN'), ('CHECKPOINT_COMPLETION_TARGET', 'Infinity'),
    ('CHECKPOINT_COMPLETION_TARGET', '0.49'), ('CHECKPOINT_COMPLETION_TARGET', '1.0'),
    ('CHECKPOINT_COMPLETION_TARGET', '0.90000'), ('WAL_COMPRESSION', 'zstd'), ('FSYNC', 'off'),
])
def test_invalid_environment_fails_without_echoing_input(suffix, raw):
    with pytest.raises(config.PostgresConfigError) as error:
        balanced(**{config.PREFIX + suffix: raw})
    assert "fsync = 'off'" not in str(error.value)


def test_valid_overrides_have_explicit_units():
    settings = balanced(EMBEDDED_PG_SHARED_BUFFERS_MB=' 1024 ',
                        EMBEDDED_PG_EFFECTIVE_CACHE_SIZE_MB='4096',
                        EMBEDDED_PG_CHECKPOINT_TIMEOUT_SECONDS='1200',
                        EMBEDDED_PG_CHECKPOINT_COMPLETION_TARGET='0.95')
    assert settings.values['shared_buffers'] == '1024MB'
    assert settings.values['effective_cache_size'] == '4096MB'
    assert settings.values['checkpoint_timeout'] == '1200s'
    assert settings.values['checkpoint_completion_target'] == '0.95'
    assert balanced(EMBEDDED_PG_WAL_COMPRESSION='off').values['wal_compression'] == 'off'


def test_cache_estimate_cannot_be_smaller_than_shared_buffers():
    with pytest.raises(config.PostgresConfigError, match='at least shared'):
        balanced(EMBEDDED_PG_SHARED_BUFFERS_MB='1024', EMBEDDED_PG_EFFECTIVE_CACHE_SIZE_MB='512')


def test_off_with_nonempty_override_is_not_silently_ignored():
    with pytest.raises(config.PostgresConfigError, match='require'):
        config.PostgresSettings.from_env({'EMBEDDED_PG_WORK_MEM_MB': '4'})
    assert config.PostgresSettings.from_env({'EMBEDDED_PG_WORK_MEM_MB': ''}).profile == 'off'


def test_existing_cluster_apply_is_idempotent_and_disable_restores_old_settings(tmp_path):
    path = cluster(tmp_path)
    main = path / 'postgresql.conf'
    original = main.read_bytes()
    auto = (path / 'postgresql.auto.conf').read_bytes()
    validator = Mock()
    config.apply_settings(path, balanced(), validator)
    updated = main.read_bytes()
    assert updated.startswith(original)
    assert updated.count(config.INCLUDE_LINE.encode()) == 1
    managed = path / config.MANAGED_NAME
    assert managed.read_text().startswith(config.MANAGED_HEADER)
    times = main.stat().st_mtime_ns, managed.stat().st_mtime_ns
    config.apply_settings(path, balanced(), validator)
    assert (main.stat().st_mtime_ns, managed.stat().st_mtime_ns) == times
    assert main.read_bytes() == updated
    assert validator.call_count == 2
    assert (path / 'postgresql.auto.conf').read_bytes() == auto
    assert (path / 'data-marker').read_text() == 'synthetic database contents'

    config.apply_settings(path, config.PostgresSettings.from_env({}))
    assert not managed.exists()
    assert main.read_bytes() == updated  # optional include is harmless when absent
    config.apply_settings(path, balanced(EMBEDDED_PG_SHARED_BUFFERS_MB='256'), validator)
    assert main.read_bytes() == updated
    assert "shared_buffers = '256MB'" in managed.read_text()


def test_validation_error_rolls_back_initial_apply_and_profile_update(tmp_path):
    path = cluster(tmp_path)
    original = (path / 'postgresql.conf').read_bytes()
    error = Mock(side_effect=config.PostgresConfigError('configuration conflict'))
    with pytest.raises(config.PostgresConfigError):
        config.apply_settings(path, balanced(), error)
    assert (path / 'postgresql.conf').read_bytes() == original
    assert not (path / config.MANAGED_NAME).exists()

    config.apply_settings(path, balanced(), Mock())
    files_before = {file.name: file.read_bytes() for file in path.iterdir()}
    with pytest.raises(config.PostgresConfigError):
        config.apply_settings(path, balanced(EMBEDDED_PG_WORK_MEM_MB='4'), error)
    assert {file.name: file.read_bytes() for file in path.iterdir()} == files_before


def test_unowned_managed_filename_and_symlinks_are_not_overwritten(tmp_path):
    path = cluster(tmp_path)
    managed = path / config.MANAGED_NAME
    managed.write_text('# Private operator configuration\n')
    for settings in (balanced(), config.PostgresSettings.from_env({})):
        with pytest.raises(config.PostgresConfigError, match='not an app-managed'):
            config.apply_settings(path, settings, Mock())
    managed.unlink()
    managed.symlink_to(path / 'postgresql.conf')
    with pytest.raises(config.PostgresConfigError, match='regular file'):
        config.apply_settings(path, balanced(), Mock())


def test_effective_validation_detects_higher_precedence_conflict_without_printing_values(monkeypatch, tmp_path):
    monkeypatch.setattr(config.os, 'geteuid', lambda: 1000)
    run = Mock(side_effect=[
        subprocess.CompletedProcess([], 0, 'off\n', ''),
        subprocess.CompletedProcess([], 0, 'on\n', ''),
    ])
    monkeypatch.setattr(config.subprocess, 'run', run)
    with pytest.raises(config.PostgresConfigError, match='fsync conflicts'):
        config.validate_effective(tmp_path, {'fsync': 'on'})
    assert run.call_args_list[0].args[0][-2:] == ['-C', 'fsync']
    assert run.call_args_list[1].args[0][-2:] == ['-c', 'fsync=on']


@pytest.mark.parametrize('error', [
    subprocess.CompletedProcess([], 1, '', 'secret-setting-value'),
    subprocess.TimeoutExpired('postgres', 10),
    FileNotFoundError('secret-setting-value'),
])
def test_postgresql_parse_failure_or_timeout_stops_startup_without_config_leak(monkeypatch, tmp_path, error):
    monkeypatch.setattr(config.os, 'geteuid', lambda: 1000)
    run = Mock(side_effect=error) if isinstance(error, Exception) else Mock(return_value=error)
    monkeypatch.setattr(config.subprocess, 'run', run)
    with pytest.raises(config.PostgresConfigError) as caught:
        config.validate_effective(tmp_path, {'shared_buffers': '512MB'})
    assert 'secret-setting-value' not in str(caught.value)


def test_effective_validation_accepts_postgresql_normalized_units(monkeypatch, tmp_path):
    monkeypatch.setattr(config.os, 'geteuid', lambda: 1000)
    run = Mock(return_value=subprocess.CompletedProcess([], 0, '65536\n', ''))
    monkeypatch.setattr(config.subprocess, 'run', run)
    config.validate_effective(tmp_path, {'shared_buffers': '512MB'})
    assert run.call_count == 2


def test_entrypoint_validates_before_init_and_applies_to_existing_clusters():
    source = (Path(__file__).parents[2] / 'entrypoint.sh').read_text()
    external_end = source.index('else\n\n# Reject invalid opt-in settings')
    validation = source.index('postgres_config.py --validate')
    initialization = source.index('if [ ! -s "$PGDATA/PG_VERSION" ]')
    apply = source.index('postgres_config.py "$PGDATA"')
    embedded_end = source.index('fi  # end external_db else block')
    assert external_end < validation < initialization < apply < embedded_end
