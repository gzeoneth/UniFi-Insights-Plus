"""Safety/fixture checks for the opt-in disposable PostgreSQL benchmark."""

import importlib.util
import ipaddress
from pathlib import Path

import pytest


spec = importlib.util.spec_from_file_location(
    "ingest_io_benchmark", Path(__file__).resolve().parents[2] / "scripts" / "benchmark-ingest-io.py")
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


def test_fixture_is_deterministic_and_uses_documentation_addresses():
    rows = list(benchmark.synthetic_rows(1100, 900))
    assert rows == list(benchmark.synthetic_rows(1100, 900))
    assert len({row["ingest_id"] for row in rows}) == len(rows)
    assert {row["log_type"] for row in rows} == {"firewall", "dns", "system"}
    assert any(row["event_source"] == "unifi_ips" for row in rows)
    for row in rows:
        assert len(row["raw_log"].encode()) == 900
        assert row["hostname"].endswith(".example.test")
        for key, network in (("src_ip", "192.0.2.0/24"), ("dst_ip", "203.0.113.0/24")):
            if key in row:
                assert ipaddress.ip_address(row[key]) in ipaddress.ip_network(network)


@pytest.mark.parametrize("argv", [["--rows", "0"], ["--rows", "1000001"],
                                  ["--seed-rows", "-1"], ["--batch-sizes", "0"],
                                  ["--batch-sizes", "1001"], ["--raw-bytes", "1"],
                                  ["--repetitions", "0"], ["--dsn", "anything"]])
def test_invalid_or_external_database_options_are_rejected(argv):
    with pytest.raises(SystemExit):
        benchmark.parse_args(argv)


def test_profiles_preserve_durability_and_isolate_compression():
    for key in ("fsync", "full_page_writes", "synchronous_commit"):
        assert benchmark.COMMON_SETTINGS[key] == "on"
    assert benchmark.PROFILES["compression"] == {
        **benchmark.PROFILES["baseline"], "wal_compression": "on"}
    assert benchmark.parse_args([]).index_profile == "current"
    assert benchmark.INDEX_PROFILES["current"] == ()


def test_combined_fixture_budget_is_checked_before_allocation():
    with pytest.raises(SystemExit):
        benchmark.parse_args(["--rows", "100000", "--seed-rows", "100000", "--raw-bytes", "16000"])
    # Default case is deliberately bounded but still exercises real indexes.
    assert benchmark.parse_args([]).rows == 50000


def test_worker_cannot_connect_to_a_host_database(monkeypatch):
    monkeypatch.setattr(benchmark.sys, "argv", ["benchmark", "--worker"])
    with pytest.raises(RuntimeError, match="isolated benchmark container"):
        benchmark.main()


@pytest.mark.parametrize("fail", [False, True])
def test_docker_isolated_and_cleanup_is_limited_to_generated_resources(monkeypatch, fail):
    calls, cleanup = [], []

    def fake_docker(*argv, **kwargs):
        calls.append(argv)
        if argv[:2] == ("run", "--rm"):
            if fail:
                raise RuntimeError("Synthetic worker failure")
            return '{"profile":"baseline","results":[]}'
        return "ready"

    monkeypatch.setattr(benchmark, "docker", fake_docker)
    monkeypatch.setattr(benchmark.subprocess, "run", lambda argv, **kwargs: cleanup.append(argv))
    args = benchmark.parse_args(["--rows", "10", "--seed-rows", "0", "--repetitions", "1"])
    if fail:
        with pytest.raises(RuntimeError, match="Synthetic worker failure"):
            benchmark.run_profile(args, "baseline")
    else:
        assert benchmark.run_profile(args, "baseline")["profile"] == "baseline"
    name = calls[0][2].removesuffix("-data")
    assert name.startswith("uli-ingest-io-")
    postgres = next(call for call in calls if call[:2] == ("run", "-d"))
    worker = next(call for call in calls if call[:2] == ("run", "--rm"))
    assert postgres[postgres.index("--network") + 1] == "none"
    assert worker[worker.index("--network") + 1] == "container:" + name
    assert worker[worker.index("--memory") + 1] == "2g"
    assert "-p" not in postgres and "--publish" not in postgres
    assert "readonly" in " ".join(worker)
    assert cleanup == [["docker", "rm", "-f", name + "-worker"],
                       ["docker", "rm", "-f", name],
                       ["docker", "volume", "rm", name + "-data"]]
