"""Tests for the periodic jobs registered by main.run_scheduler() (issue #103).

Covers:
- log_stats only touches the database when DEBUG logging is enabled
- the WAN/gateway refresh job runs on WAN_REFRESH_INTERVAL_MINUTES,
  independently of STATS_INTERVAL_MINUTES
- a SIGUSR2 config reload requests an identity refresh (WAN set changed,
  UniFi enabled flag changed, or no identity learned yet), and the
  scheduler tick runs it on the scheduler thread
"""
import logging
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import schedule


class _StopScheduler(Exception):
    """Raised from the patched sleep to leave run_scheduler() after setup."""


@pytest.fixture(autouse=True)
def reset_schedule():
    schedule.clear()
    yield
    schedule.clear()


@pytest.fixture
def main_module(monkeypatch):
    """Import main.py with routes.auth stubbed (it opens the deps DB pool)."""
    monkeypatch.setitem(sys.modules, 'routes.auth', MagicMock())
    monkeypatch.delitem(sys.modules, 'main', raising=False)
    import main
    main.Database = MagicMock()
    main.Database.resolve_retention_time.return_value = SimpleNamespace(
        time='03:00', source='default')
    return main


def _register_jobs(main_module, monkeypatch, db, enricher=None):
    """Run run_scheduler() up to its first sleep, leaving the jobs registered."""
    def _stop(_seconds):
        raise _StopScheduler
    monkeypatch.setattr(main_module, 'time', SimpleNamespace(sleep=_stop))
    with pytest.raises(_StopScheduler):
        main_module.run_scheduler(db, enricher or MagicMock())


@pytest.fixture
def logger_level(main_module):
    """Set the receiver logger level via setLevel (clears the isEnabledFor cache)."""
    original = main_module.logger.level
    yield main_module.logger.setLevel
    main_module.logger.setLevel(original)


def _job(name):
    matches = [j for j in schedule.get_jobs() if getattr(j.job_func.func, '__name__', None) == name]
    assert len(matches) == 1, f'expected exactly one {name} job, got {len(matches)}'
    return matches[0]


def test_log_stats_skips_db_at_info(main_module, monkeypatch, logger_level):
    db = MagicMock()
    enricher = MagicMock()
    _register_jobs(main_module, monkeypatch, db, enricher)
    logger_level(logging.INFO)

    _job('log_stats').job_func()

    db.get_stats.assert_not_called()
    enricher.get_stats.assert_not_called()


def test_log_stats_queries_db_at_debug(main_module, monkeypatch, logger_level):
    db = MagicMock()
    db.get_stats.return_value = {'total': 1, 'last_hour': {}}
    _register_jobs(main_module, monkeypatch, db)
    logger_level(logging.DEBUG)

    _job('log_stats').job_func()

    db.get_stats.assert_called_once()


def test_log_stats_runs_on_stats_interval(main_module, monkeypatch):
    _register_jobs(main_module, monkeypatch, MagicMock())
    job = _job('log_stats')
    assert job.interval == main_module.STATS_INTERVAL_MINUTES
    assert job.unit == 'minutes'


def test_wan_refresh_runs_on_its_own_interval(main_module, monkeypatch):
    monkeypatch.setattr(main_module, 'WAN_REFRESH_INTERVAL_MINUTES', 123)
    _register_jobs(main_module, monkeypatch, MagicMock())
    job = _job('refresh_wan_ip')
    assert job.interval == 123
    assert job.unit == 'minutes'


def _set_env(monkeypatch, env_value):
    if env_value is None:
        monkeypatch.delenv('WAN_REFRESH_INTERVAL_MINUTES', raising=False)
    else:
        monkeypatch.setenv('WAN_REFRESH_INTERVAL_MINUTES', env_value)


def _interval_warnings(caplog):
    return [r for r in caplog.records
            if r.levelno == logging.WARNING and 'WAN_REFRESH_INTERVAL_MINUTES' in r.getMessage()]


@pytest.mark.parametrize('env_value, expected', [(None, 360), ('', 360), ('90', 90)])
def test_wan_refresh_interval_valid_or_unset(main_module, monkeypatch, caplog, env_value, expected):
    caplog.set_level(logging.WARNING)
    _set_env(monkeypatch, env_value)
    assert main_module._wan_refresh_interval_from_env() == expected
    assert not _interval_warnings(caplog)


@pytest.mark.parametrize('env_value', ['0', '-5', 'abc'])
def test_wan_refresh_interval_invalid_falls_back_with_warning(main_module, monkeypatch, caplog, env_value):
    """0 or negative would spin schedule.every() forever; non-integers crashed int()."""
    caplog.set_level(logging.WARNING)
    _set_env(monkeypatch, env_value)
    assert main_module._wan_refresh_interval_from_env() == 360
    assert len(_interval_warnings(caplog)) == 1


def test_wan_refresh_interval_read_at_import(monkeypatch):
    """The module constant comes from the env parser, with no parse globals left behind."""
    monkeypatch.setitem(sys.modules, 'routes.auth', MagicMock())
    _set_env(monkeypatch, '45')
    monkeypatch.delitem(sys.modules, 'main', raising=False)
    import main
    assert main.WAN_REFRESH_INTERVAL_MINUTES == 45
    assert not hasattr(main, '_wan_refresh_env')
    assert not hasattr(main, '_wan_refresh_parsed')


# ── Identity refresh on config reload ───────────────────────────────────────

def test_tick_runs_identity_refresh_when_requested(main_module, monkeypatch):
    refresh = MagicMock()
    monkeypatch.setattr(main_module, '_refresh_network_identity_from_logs', refresh)
    db = MagicMock()
    enricher = MagicMock()

    main_module._identity_refresh_requested.set()
    main_module._scheduler_tick(db, enricher)

    refresh.assert_called_once_with(db, enricher)
    assert not main_module._identity_refresh_requested.is_set()


def test_scheduled_wan_refresh_passes_enricher(main_module, monkeypatch):
    refresh = MagicMock()
    monkeypatch.setattr(main_module, '_refresh_network_identity_from_logs', refresh)
    db, enricher = MagicMock(), MagicMock()
    _register_jobs(main_module, monkeypatch, db, enricher)

    _job('refresh_wan_ip').job_func()

    refresh.assert_called_once_with(db, enricher)


def _db_down():
    db = MagicMock()
    db.get_config.side_effect = Exception('db down')
    return db


def test_tick_survives_failing_identity_gate(main_module):
    """A DB error in the UniFi gate must not kill the scheduler loop."""
    ran = MagicMock()
    schedule.every(1).seconds.do(ran)
    schedule.jobs[0].next_run = schedule.jobs[0].next_run.replace(year=2000)

    main_module._identity_refresh_requested.set()
    main_module._scheduler_tick(_db_down())

    ran.assert_called_once()
    assert not main_module._identity_refresh_requested.is_set()


def test_scheduled_wan_refresh_survives_failing_identity_gate(main_module, monkeypatch):
    """schedule.run_pending() does not catch job exceptions, so the job must not raise."""
    db = _db_down()
    _register_jobs(main_module, monkeypatch, db)
    _job('refresh_wan_ip').job_func()  # must not raise
    db.detect_wan_ip.assert_not_called()


def test_tick_skips_identity_refresh_when_not_requested(main_module, monkeypatch):
    refresh = MagicMock()
    monkeypatch.setattr(main_module, '_refresh_network_identity_from_logs', refresh)

    main_module._scheduler_tick(MagicMock())

    refresh.assert_not_called()


def _reload(main_module, monkeypatch, *, wan_after, map_after,
            unifi_before=False, unifi_after=False):
    """Run _reload_config() with parsers/unifi reloads that apply the 'after' state.

    The trigger reads only reloaded in-memory state, never the DB.
    """
    parsers = SimpleNamespace(WAN_INTERFACES={'ppp0'}, WAN_IP_BY_IFACE={})

    def reload_from_db(_db):
        parsers.WAN_INTERFACES = set(wan_after)
        parsers.WAN_IP_BY_IFACE = dict(map_after)

    parsers.reload_config_from_db = reload_from_db
    monkeypatch.setattr(main_module, 'parsers', parsers)

    unifi_api = MagicMock()
    unifi_api.enabled = unifi_before
    unifi_api.reload_config.side_effect = lambda: setattr(unifi_api, 'enabled', unifi_after)

    db = MagicMock()
    main_module._reload_config(db, unifi_api, MagicMock(), MagicMock(), MagicMock())
    db.get_config.assert_not_called()
    return main_module._identity_refresh_requested.is_set()


def test_reload_requests_identity_refresh_when_unifi_flag_changes(main_module, monkeypatch):
    assert _reload(main_module, monkeypatch, wan_after={'eth8'}, map_after={'eth8': '1.1.1.1'},
                   unifi_before=True, unifi_after=False)


def test_reload_requests_identity_refresh_when_interface_has_no_ip(main_module, monkeypatch):
    assert _reload(main_module, monkeypatch, wan_after={'eth8', 'eth9'},
                   map_after={'eth8': '1.1.1.1'})


def test_reload_skips_identity_refresh_when_every_interface_known(main_module, monkeypatch):
    """WAN set changed (ppp0 -> eth8), but eth8 already has a learned IP:
    the wizard already ran detection, so the receiver does not repeat it."""
    assert not _reload(main_module, monkeypatch, wan_after={'eth8'},
                       map_after={'eth8': '1.1.1.1', 'ppp0': '9.9.9.9'})


def test_unrelated_reload_does_not_request_identity_refresh(main_module, monkeypatch):
    assert not _reload(main_module, monkeypatch, wan_after={'ppp0'},
                       map_after={'ppp0': '1.1.1.1'})
    assert main_module._retention_reload_requested.is_set()


def test_config_reload_signal_never_raises(main_module, monkeypatch, caplog):
    """A failing reload must not unwind into the receiver's recvfrom loop."""
    monkeypatch.setattr(main_module, '_reload_config',
                        MagicMock(side_effect=Exception('db down')))
    caplog.set_level(logging.ERROR)

    main_module._handle_config_reload_signal(
        MagicMock(), MagicMock(), MagicMock(), MagicMock(), MagicMock())

    assert any(r.getMessage() == 'Config reload failed' and r.exc_info
               for r in caplog.records)
