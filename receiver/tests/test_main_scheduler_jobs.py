"""Tests for the periodic jobs registered by main.run_scheduler() (issue #103).

Covers:
- log_stats only touches the database when DEBUG logging is enabled
- the WAN/gateway refresh job runs on WAN_REFRESH_INTERVAL_MINUTES,
  independently of STATS_INTERVAL_MINUTES
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


def _import_main(monkeypatch, env_value):
    """Fresh import of main with WAN_REFRESH_INTERVAL_MINUTES set (None = unset)."""
    monkeypatch.setitem(sys.modules, 'routes.auth', MagicMock())
    if env_value is None:
        monkeypatch.delenv('WAN_REFRESH_INTERVAL_MINUTES', raising=False)
    else:
        monkeypatch.setenv('WAN_REFRESH_INTERVAL_MINUTES', env_value)
    monkeypatch.delitem(sys.modules, 'main', raising=False)
    import main
    return main


def _interval_warnings(caplog):
    return [r for r in caplog.records
            if r.levelno == logging.WARNING and 'WAN_REFRESH_INTERVAL_MINUTES' in r.getMessage()]


@pytest.mark.parametrize('env_value, expected', [(None, 360), ('', 360), ('90', 90)])
def test_wan_refresh_interval_valid_or_unset(monkeypatch, caplog, env_value, expected):
    caplog.set_level(logging.WARNING)
    assert _import_main(monkeypatch, env_value).WAN_REFRESH_INTERVAL_MINUTES == expected
    assert not _interval_warnings(caplog)


@pytest.mark.parametrize('env_value', ['0', '-5', 'abc'])
def test_wan_refresh_interval_invalid_falls_back_with_warning(monkeypatch, caplog, env_value):
    """0 or negative would spin schedule.every() forever; non-integers crashed int()."""
    caplog.set_level(logging.WARNING)
    assert _import_main(monkeypatch, env_value).WAN_REFRESH_INTERVAL_MINUTES == 360
    assert len(_interval_warnings(caplog)) == 1
