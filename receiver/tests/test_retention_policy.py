"""Retention safety checks using temporary archives and isolated DB doubles."""

from contextlib import contextmanager
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from retention import (DEFAULT_POLICY, POLICY_KEY, _delete_batch, load_policy,
                       retention_passes, run_retention_cleanup, summarize_rows,
                       validate_policy, write_archive)


def event(**overrides):
    return {'id': 42, 'timestamp': '2026-07-01T01:02:03+08:00', 'log_type': 'firewall',
            'rule_action': 'allow', 'source': 'syslog', 'event_source': None,
            'rule_name': 'LAN → Internet', 'raw_log': '<134> example', **overrides}


def archive_policy(tmp_path, **overrides):
    tmp_path.chmod(0o700)
    return validate_policy({'enabled': True, 'archives_enabled': True,
                            'archive_directory': str(tmp_path.resolve()), **overrides})


def db_double(policy, rows=(), rowcount=1):
    cur = MagicMock()
    cur.fetchone.return_value = (True,)
    cur.fetchall.return_value = list(rows)
    cur.rowcount = rowcount
    conn = MagicMock()
    conn.cursor.return_value.__enter__.return_value = cur
    db = MagicMock()
    db.RETENTION_BATCH_SIZE = 5000
    db.get_config.return_value = policy
    state = {'commits': 0, 'rollbacks': 0}

    @contextmanager
    def get_conn():
        try:
            yield conn
        except Exception:
            state['rollbacks'] += 1
            raise
        else:
            state['commits'] += 1

    db.get_conn = get_conn
    return db, cur, state


def sql_statements(cur):
    return [str(call.args[0]) for call in cur.execute.call_args_list]


def test_defaults_inherit_existing_retention_without_side_effects():
    db, _, _ = db_double(None)
    policy = load_policy(db, 120, 30)
    db.get_config.assert_called_once_with(POLICY_KEY)
    assert policy['enabled'] is False
    assert policy['summaries_enabled'] is False
    assert policy['archives_enabled'] is False
    assert retention_passes(policy, 120, 30) == [
        ('dns', "log_type = 'dns'", [], 30),
        ('non_dns', "log_type != 'dns'", [], 120)]


def test_mutating_returned_policy_does_not_mutate_defaults():
    policy = validate_policy({})
    policy['type_days']['dns'] = 12
    assert DEFAULT_POLICY['type_days'] == {}


@pytest.mark.parametrize('override', [
    {'enabled': 'true'}, {'batch_size': True}, {'batch_size': 5001},
    {'max_batches': 0}, {'security_days': -1}, {'type_days': {'typo': 3}},
    {'type_days': {'dns': False}}, {'type_days': {'ips': 365}},
    {'summary_retention_days': 0}, {'archive_directory': 'relative'},
    {'archive_directory': '/data/../etc'}, {'archive_directory': '/'},
    {'archive_directory': str(Path(__file__).resolve().parents[2] / 'archives')},
    {'archive_max_bytes': 0}, {'archive_max_files': 0}, {'unexpected': True},
    {'enabled': True, 'security_days': 30, 'firewall_allow_days': 30},
])
def test_invalid_policy_is_rejected(override):
    with pytest.raises(ValueError):
        validate_policy(override)


def test_policy_has_disjoint_security_and_type_passes():
    policy = validate_policy({'enabled': True, 'security_days': 365,
                              'firewall_allow_days': 30, 'type_days': {'system': 90, 'dns': 20}})
    passes = retention_passes(policy, 60, 10)
    assert passes[0][0] == 'security'
    assert passes[0][3] == 365
    assert "event_source = 'unifi_ips'" in passes[0][1]
    assert 'rule_action' not in passes[0][1]  # IPS events saying ALLOW are retained.
    for _, predicate, _, _ in passes[1:]:
        assert 'NOT COALESCE(' in predicate
    by_name = {name: days for name, _, _, days in passes}
    assert by_name['firewall_allow'] == 30
    assert by_name['system'] == 90
    assert by_name['dns'] == 20


def test_corrupt_saved_policy_fails_closed_before_any_delete():
    db, cur, _ = db_double({'enabled': True, 'security_days': -1})
    result = run_retention_cleanup(db)
    assert result['status'] == 'failed'
    assert result['deleted_so_far'] == 0
    cur.execute.assert_not_called()


def test_summaries_use_utc_days_and_distinguish_sources_and_rule_mode():
    rows = [event(), event(id=43, timestamp='2026-06-30T19:00:00Z'),
            event(id=44, source='pihole'), event(id=45, event_source='unifi_ips')]
    groups = summarize_rows(rows, False)
    assert len(groups) == 3
    syslog = [row for row in groups if row[3:5] == ('syslog', '')][0]
    assert syslog[0].isoformat() == '2026-06-30'
    assert syslog[5] is False and syslog[6] == '' and syslog[7] == 2
    assert syslog[8].tzinfo is timezone.utc
    grouped = summarize_rows(rows[:1], True)[0]
    assert grouped[5] is True and grouped[6] == 'LAN → Internet'


def test_archive_contains_all_fields_and_identical_retry_reuses_file(tmp_path):
    policy = archive_policy(tmp_path)
    rows = [event(), event(id=43, ips_signature='test rule')]
    path, created = write_archive(rows, policy)
    assert created
    assert Path(path).stat().st_mode & 0o077 == 0
    with gzip.open(path, 'rt') as archive:
        assert [json.loads(line) for line in archive] == rows
    retry_path, retry_created = write_archive(rows, policy)
    assert retry_path == path and retry_created is False
    assert len(list(tmp_path.iterdir())) == 1


def test_archive_corruption_stops_retry(tmp_path):
    policy = archive_policy(tmp_path)
    path, _ = write_archive([event()], policy)
    with gzip.open(path, 'wt') as archive:
        archive.write('{}\n')
    with pytest.raises(ValueError, match='checksum'):
        write_archive([event()], policy)


def test_archive_directory_must_be_private_and_exist(tmp_path):
    policy = archive_policy(tmp_path)
    tmp_path.chmod(0o755)
    with pytest.raises(ValueError, match='private permissions'):
        write_archive([event()], policy)
    policy['archive_directory'] = str(tmp_path / 'not-provisioned')
    with pytest.raises(FileNotFoundError):
        write_archive([event()], policy)


def test_archive_never_follows_a_symlink(tmp_path):
    private = tmp_path / 'private'
    private.mkdir(mode=0o700)
    linked = tmp_path / 'linked'
    linked.symlink_to(private, target_is_directory=True)
    policy = archive_policy(tmp_path, archive_directory=str(linked))
    with pytest.raises(ValueError, match='symlinks'):
        write_archive([event()], policy)


def test_archive_limits_stop_new_files_but_allow_idempotent_retry(tmp_path):
    policy = archive_policy(tmp_path, archive_max_files=1)
    original, _ = write_archive([event()], policy)
    assert write_archive([event()], policy) == (original, False)
    with pytest.raises(ValueError, match='file limit'):
        write_archive([event(id=99)], policy)
    assert Path(original).exists()
    assert len(list(tmp_path.iterdir())) == 1


def test_archive_space_error_removes_only_unpublished_tempfile(tmp_path):
    policy = archive_policy(tmp_path, archive_max_bytes=1024)
    # Non-repeating content cannot compress below the 1 KiB quota.
    payload = ''.join(__import__('hashlib').sha256(str(n).encode()).hexdigest() for n in range(1000))
    with pytest.raises(ValueError, match='disk budget'):
        write_archive([event(raw_log=payload)], policy)
    assert list(tmp_path.iterdir()) == []


def test_archive_failure_rolls_back_without_summarizing_or_deleting(tmp_path):
    policy = archive_policy(tmp_path, summaries_enabled=True)
    db, cur, state = db_double(policy, rows=[(event(),)])
    with patch('retention.write_archive', side_effect=OSError('disk full')):
        with patch('retention._write_summaries') as summaries:
            with pytest.raises(OSError, match='disk full'):
                _delete_batch(db, "log_type = 'firewall'", [], datetime.now(timezone.utc), 10, policy)
    assert state == {'commits': 0, 'rollbacks': 1}
    summaries.assert_not_called()
    assert not any(sql.startswith('DELETE') for sql in sql_statements(cur))


def test_summary_and_delete_commit_together_after_durable_archive(tmp_path):
    policy = archive_policy(tmp_path, summaries_enabled=True)
    db, cur, state = db_double(policy, rows=[(event(),)])
    with patch('retention._write_summaries', return_value=1) as summaries:
        result = _delete_batch(db, "log_type = 'firewall'", [], datetime.now(timezone.utc), 10, policy)
    assert result == {'count': 1, 'dns': 0, 'archives': 1, 'summaries': 1}
    assert state == {'commits': 1, 'rollbacks': 0}
    summaries.assert_called_once()
    sql = sql_statements(cur)
    assert any('LIMIT %s FOR UPDATE SKIP LOCKED' in query for query in sql)
    assert sql[-1] == 'DELETE FROM logs WHERE id = ANY(%s)'


def test_delete_count_mismatch_rolls_back_summaries_and_preserves_archive(tmp_path):
    policy = archive_policy(tmp_path, summaries_enabled=True)
    db, cur, state = db_double(policy, rows=[(event(),)], rowcount=0)
    with patch('retention._write_summaries', return_value=1):
        with pytest.raises(RuntimeError, match='rolled back'):
            _delete_batch(db, "log_type = 'firewall'", [], datetime.now(timezone.utc), 10, policy)
    assert state == {'commits': 0, 'rollbacks': 1}
    assert len(list(tmp_path.iterdir())) == 1
    # An exact batch retry reuses that durable file instead of consuming quota.
    assert write_archive([event()], policy)[1] is False


def test_concurrent_cleanup_skips_locked_policy_batch():
    policy = validate_policy({'enabled': True})
    db, cur, state = db_double(policy)
    cur.fetchone.return_value = (False,)
    result = run_retention_cleanup(db)
    assert result['skipped_locked'] is True
    assert result['deleted_so_far'] == 0
    assert not any(sql.startswith('DELETE') for sql in sql_statements(cur))


def test_max_batches_bounds_work_and_progress_tracks_committed_counts():
    policy = validate_policy({'enabled': True, 'max_batches': 2})
    db, _, _ = db_double(policy)
    progress = MagicMock()
    with patch('retention._delete_batch', return_value={'count': 1, 'dns': 0, 'archives': 0, 'summaries': 0}) as batch:
        result = run_retention_cleanup(db, progress_cb=progress)
    assert result['status'] == 'partial'
    assert result['deleted_so_far'] == 2
    assert batch.call_count == 2
    assert progress.call_args.args[0]['deleted_so_far'] == 2


def test_failed_commit_is_not_counted_as_deleted():
    policy = validate_policy({'enabled': True})
    db, _, _ = db_double(policy)
    with patch('retention._delete_batch', side_effect=OSError('commit failed')):
        result = run_retention_cleanup(db)
    assert result['status'] == 'failed'
    assert result['deleted_so_far'] == 0


@pytest.mark.parametrize('module_file, app_directory', [
    ('/opt/insights/receiver/retention.py', '/opt/insights'),
    ('/app/retention.py', '/app'),
])
def test_archive_guard_supports_checkout_and_flat_container_layout(monkeypatch, module_file, app_directory):
    monkeypatch.setattr('retention.__file__', module_file)
    assert validate_policy({})['archive_directory'] == '/data/archives'
    assert validate_policy({'archive_directory': '/data/private-archive'})['archive_directory'] == '/data/private-archive'
    for directory in (app_directory, f'{app_directory}/archives', f'{app_directory}/receiver/archives'):
        with pytest.raises(ValueError, match='outside the application repository'):
            validate_policy({'archive_directory': directory})
