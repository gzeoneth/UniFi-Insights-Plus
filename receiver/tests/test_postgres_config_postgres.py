"""Optional real PostgreSQL 16 startup/rollback test against a disposable cluster.

Set TEST_EMBEDDED_PG_CONFIG=1 inside the application image with pytest installed.
No existing server, network listener, credentials or production data are used.
"""

import os
from pathlib import Path
import pwd
import shutil
import subprocess
import tempfile

import pytest

from postgres_config import (
    MANAGED_NAME, PostgresConfigError, PostgresSettings, apply_settings,
)


pytestmark = pytest.mark.skipif(
    os.environ.get('TEST_EMBEDDED_PG_CONFIG') != '1',
    reason='set TEST_EMBEDDED_PG_CONFIG=1 in a disposable PostgreSQL 16 environment',
)
BIN = Path('/usr/lib/postgresql/16/bin')


@pytest.fixture
def disposable_cluster():
    if not (BIN / 'postgres').is_file():
        pytest.skip('embedded PostgreSQL 16 binaries unavailable')
    data = Path(tempfile.mkdtemp(prefix='insights-pg-profile-'))
    identity = {}
    if os.geteuid() == 0:
        account = pwd.getpwnam('postgres')
        os.chown(data, account.pw_uid, account.pw_gid)
        identity = {'user': account.pw_uid, 'group': account.pw_gid, 'extra_groups': []}

    def run(binary, *args, check=True):
        return subprocess.run([str(BIN / binary), *map(str, args)], check=check,
                              capture_output=True, text=True, timeout=30, **identity)

    run('initdb', '-D', data, '--no-locale', '--auth=trust')
    try:
        yield data, run
    finally:
        run('pg_ctl', '-D', data, '-m', 'immediate', '-w', 'stop', check=False)
        shutil.rmtree(data)


def test_existing_cluster_profile_startup_disable_and_conflict_preserve_data(disposable_cluster):
    data, run = disposable_cluster
    base = data / 'postgresql.conf'
    with base.open('a') as stream:
        stream.write("\n# Synthetic existing settings\nshared_buffers = '128MB'\n"
                     "work_mem = '8MB'\nsynchronous_commit = off\n"
                     "listen_addresses = ''\n")

    def start():
        run('pg_ctl', '-D', data, '-l', data / 'test.log', '-w',
            '-o', f'-c unix_socket_directories={data} -p 55497', 'start')

    def query(sql):
        return run('psql', '-h', data, '-p', '55497', '-U', 'postgres',
                   '-d', 'postgres', '-At', '-c', sql).stdout.strip()

    start()
    query('CREATE TABLE preserved (id integer); INSERT INTO preserved VALUES (7)')
    run('pg_ctl', '-D', data, '-m', 'fast', '-w', 'stop')
    original = base.read_bytes()
    auto_before = (data / 'postgresql.auto.conf').read_bytes()
    settings = PostgresSettings.from_env({'EMBEDDED_PG_PROFILE': 'balanced'})
    apply_settings(data, settings)
    start()
    assert query('SHOW shared_buffers') == '512MB'
    assert query('SHOW max_wal_size') == '2GB'
    assert query('SHOW checkpoint_timeout') == '15min'
    assert query('SHOW wal_compression') == 'pglz'
    assert query('SHOW fsync') == query('SHOW full_page_writes') == query('SHOW synchronous_commit') == 'on'
    assert query('SELECT id FROM preserved') == '7'
    run('pg_ctl', '-D', data, '-m', 'fast', '-w', 'stop')

    apply_settings(data, settings)
    assert base.read_bytes().startswith(original)
    assert (data / 'postgresql.auto.conf').read_bytes() == auto_before
    apply_settings(data, PostgresSettings.from_env({}))
    assert not (data / MANAGED_NAME).exists()
    start()
    assert query('SHOW shared_buffers') == '128MB'
    assert query('SHOW synchronous_commit') == 'off'  # original config restored
    assert query('SELECT id FROM preserved') == '7'
    run('pg_ctl', '-D', data, '-m', 'fast', '-w', 'stop')

    auto = data / 'postgresql.auto.conf'
    with auto.open('a') as stream:
        stream.write("fsync = 'off'\n")
    before = base.read_bytes(), auto.read_bytes()
    with pytest.raises(PostgresConfigError, match='fsync conflicts'):
        apply_settings(data, settings)
    assert (base.read_bytes(), auto.read_bytes()) == before
    assert not (data / MANAGED_NAME).exists()
    # No unsafe database server was started during effective-config validation.
    assert not (data / 'postmaster.pid').exists()
