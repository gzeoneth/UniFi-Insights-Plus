#!/usr/bin/env python3
"""Benchmark real log inserts in disposable, network-isolated PostgreSQL 16.

Requires Docker and already-built app/PostgreSQL images. Never loads application
environment files, publishes a database port, or accepts a database DSN. Sources
are mounted read-only into the app image; only synthetic events are generated.

Example:
  python3 scripts/benchmark-ingest-io.py \
    --app-image unifi-insights-plus:benchmark --rows 50000 > benchmark.json

The results measure the Docker host's storage, not production capacity. RAM
profiles are comparisons, not deployment recommendations. No durability setting
is disabled. Includes index/heap sizes, WAL, ingestion commits, batch latency and
an explicit checkpoint; excludes schema creation and event generation timings.
"""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
from pathlib import Path
import statistics
import subprocess
import sys
import time
import uuid


PROFILES = {
    "baseline": {"shared_buffers": "128MB", "effective_cache_size": "256MB",
                 "wal_buffers": "8MB", "max_wal_size": "512MB",
                 "wal_compression": "off"},
    "cache512": {"shared_buffers": "512MB", "effective_cache_size": "2048MB",
                 "wal_buffers": "16MB", "max_wal_size": "2GB",
                 "wal_compression": "on"},
}
PROFILES["compression"] = {**PROFILES["baseline"], "wal_compression": "on"}
INDEX_PROFILES = {
    "current": (),
    "without-simple": ("idx_logs_direction", "idx_logs_protocol", "idx_logs_service_name"),
    "without-covering": ("idx_logs_flow_agg", "idx_logs_zone_matrix"),
}
COMMON_SETTINGS = {"fsync": "on", "full_page_writes": "on",
                   "synchronous_commit": "on", "work_mem": "8MB",
                   "maintenance_work_mem": "64MB", "checkpoint_timeout": "15min",
                   "checkpoint_completion_target": "0.9", "track_wal_io_timing": "on"}
MAX_FIXTURE_ESTIMATE = 512 * 1024 * 1024


def synthetic_rows(count, raw_bytes):
    """Deterministic mixed events; documentation-only IPs and names."""
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for i in range(count):
        kind = "firewall" if i % 10 < 8 else ("dns" if i % 10 == 8 else "system")
        ips = i % 1000 == 0
        block = i % 5 == 0
        src = f"192.0.2.{i % 250 + 1}"
        dst = f"203.0.113.{(i // 3) % 250 + 1}"
        prefix = f"synthetic-gateway event={i} SRC={src} DST={dst} "
        if ips:
            prefix += "CEF:0|Example|Synthetic|1|1|Threat Detected|7|UNIFIipsSignature=test "
        filler = hashlib.shake_256(str(i).encode()).hexdigest(raw_bytes)
        row = {"timestamp": base + timedelta(milliseconds=i), "log_type": kind,
               "raw_log": (prefix + filler)[:raw_bytes], "source": "syslog",
               "ingest_id": str(uuid.UUID(int=i + 1)), "event_source": "kernel",
               "hostname": "synthetic-gateway.example.test"}
        if kind == "firewall":
            row.update(src_ip=src, dst_ip=dst, src_port=40000 + i % 10000,
                       dst_port=(443, 53, 22, 5353)[i % 4], protocol="tcp" if i % 2 else "udp",
                       service_name="synthetic", direction="outbound",
                       rule_name="synthetic-rule", rule_desc="Synthetic benchmark event",
                       rule_action="block" if block else "allow",
                       interface_in="br20", interface_out="eth0",
                       src_device_name=f"client-{i % 250}.example.test", remote_ip=dst)
            if block and i % 3 == 0:
                row.update(threat_score=20, threat_categories=["synthetic"],
                           asn_number=64500, asn_name="Documentation AS")
        elif kind == "dns":
            row.update(src_ip=src, dns_query=f"service-{i % 500}.example.test",
                       dns_type="A", dns_answer=dst)
        if ips:
            row.update(event_source="unifi_ips", event_id="1", event_name="Threat Detected",
                       ips_signature="Synthetic detection", ips_signature_id="1000001",
                       ips_severity=7, ips_risk="medium")
        yield row


def percentile(values, fraction):
    return sorted(values)[min(len(values) - 1, int((len(values) - 1) * fraction))]


def worker(args):
    """Runs only inside our image sharing the isolated PG network namespace."""
    sys.path.insert(0, "/benchmark/receiver")
    import psycopg2
    from psycopg2 import sql
    from db import Database

    logging.disable(logging.CRITICAL)
    params = {"host": "127.0.0.1", "port": 5432, "user": "postgres", "dbname": "postgres"}
    admin = psycopg2.connect(**params)
    admin.autocommit = True
    events = list(synthetic_rows(args.seed_rows + args.rows, args.raw_bytes))
    results = []
    with admin.cursor() as cur:
        cur.execute("SELECT version()")
        server_version = cur.fetchone()[0]
        cur.execute("SELECT name, setting, unit FROM pg_settings WHERE name = ANY(%s)",
                    [list(COMMON_SETTINGS) + list(PROFILES[args.profile])])
        settings = {name: {"value": value, "unit": unit} for name, value, unit in cur.fetchall()}
    for key in ("fsync", "full_page_writes", "synchronous_commit"):
        if settings[key]["value"] != "on":
            raise RuntimeError(f"Unsafe durability setting: {key}")
    try:
        for repetition in range(args.repetitions):
            # Alternate order to avoid always favoring the second batch size.
            batches = args.batch_sizes if repetition % 2 == 0 else list(reversed(args.batch_sizes))
            for batch_size in batches:
                name = "synthetic_ingest_" + uuid.uuid4().hex
                with admin.cursor() as cur:
                    cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
                database = Database({**params, "dbname": name}, min_conn=1, max_conn=2)
                try:
                    database.connect()
                    database.ensure_post_boot_indexes()
                    # Optional write-cost experiments only in this freshly
                    # created database. Never migrations or recommendations:
                    # dropping these indexes can make reads much slower.
                    with database.get_conn() as conn:
                        with conn.cursor() as cur:
                            for index in INDEX_PROFILES[args.index_profile]:
                                cur.execute(sql.SQL("DROP INDEX {}").format(sql.Identifier(index)))
                            cur.execute("SELECT c.relname, i.indisvalid AND i.indisready "
                                        "FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid "
                                        "WHERE i.indrelid='logs'::regclass")
                            ready = dict(cur.fetchall())
                            expected = {item["name"] for item in database._POST_BOOT_INDEXES}
                            if not all(ready.values()) or not expected.issubset(ready):
                                raise RuntimeError("Benchmark indexes are incomplete or invalid")
                    # Seed touched index pages, then checkpoint. This includes
                    # full-page images typical of appends after a checkpoint,
                    # rather than comparing only inserts into empty relations.
                    for offset in range(0, args.seed_rows, 1000):
                        batch = events[offset:min(offset + 1000, args.seed_rows)]
                        if database.insert_logs_batch(batch).inserted != len(batch):
                            raise RuntimeError("Could not seed synthetic events")
                    with admin.cursor() as cur:
                        cur.execute("CHECKPOINT")
                        cur.execute("SELECT pg_current_wal_insert_lsn()")
                        lsn = cur.fetchone()[0]
                    latencies = []
                    started = time.perf_counter()
                    for offset in range(0, args.rows, batch_size):
                        batch = events[args.seed_rows + offset:args.seed_rows + offset + batch_size]
                        one_start = time.perf_counter()
                        result = database.insert_logs_batch(batch)
                        latencies.append(time.perf_counter() - one_start)
                        if result.inserted != len(batch) or result.retryable or result.dropped:
                            raise RuntimeError("Synthetic batch was not durably inserted")
                    elapsed = time.perf_counter() - started
                    with admin.cursor() as cur:
                        cur.execute("SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(), %s)", [lsn])
                        wal_bytes = int(cur.fetchone()[0])
                        checkpoint_start = time.perf_counter()
                        cur.execute("CHECKPOINT")
                        checkpoint_seconds = time.perf_counter() - checkpoint_start
                    with database.get_conn() as conn:
                        with conn.cursor() as cur:
                            cur.execute("SELECT COUNT(*), COUNT(DISTINCT ingest_id), "
                                        "SUM(octet_length(raw_log)), SUM(pg_column_size(logs)) FROM logs")
                            count, unique_count, raw_size, logical_size = cur.fetchone()
                            if (count, unique_count) != (args.seed_rows + args.rows,) * 2:
                                raise RuntimeError("Stored row count or ingest IDs differ")
                            cur.execute("SELECT pg_relation_size('logs'), pg_indexes_size('logs'), "
                                        "pg_total_relation_size('logs')")
                            heap_size, index_size, total_size = cur.fetchone()
                            cur.execute("SELECT c.relname, pg_relation_size(c.oid), "
                                        "pg_get_indexdef(c.oid), i.indisvalid FROM pg_index i "
                                        "JOIN pg_class c ON c.oid=i.indexrelid "
                                        "WHERE i.indrelid='logs'::regclass ORDER BY c.relname")
                            indexes = [{"name": n, "bytes": b, "definition": d, "valid": v}
                                       for n, b, d, v in cur.fetchall()]
                    rewrite_probe = None
                    if args.rewrite_probe:
                        # Existing heap/index pages generate more full-page
                        # images than append-only traffic. This is a deliberately
                        # separate stress probe, not simulated normal ingestion.
                        with admin.cursor() as cur:
                            cur.execute("CHECKPOINT")
                            cur.execute("SELECT pg_current_wal_insert_lsn()")
                            rewrite_lsn = cur.fetchone()[0]
                        rewrite_start = time.perf_counter()
                        with database.get_conn() as conn:
                            with conn.cursor() as cur:
                                cur.execute("SET LOCAL synchronous_commit = on")
                                cur.execute("UPDATE logs SET hostname='changed.example.test' WHERE id % 13 = 0")
                                rewritten = cur.rowcount
                        rewrite_seconds = time.perf_counter() - rewrite_start
                        with admin.cursor() as cur:
                            cur.execute("SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(), %s)", [rewrite_lsn])
                            rewrite_wal = int(cur.fetchone()[0])
                        rewrite_probe = {"rows": rewritten, "seconds": rewrite_seconds,
                                         "wal_bytes": rewrite_wal,
                                         "wal_bytes_per_updated_row": rewrite_wal / max(1, rewritten)}
                    results.append({"batch_size": batch_size, "repetition": repetition + 1,
                                    "rows": args.rows, "total_rows": count,
                                    "ingest_commits": len(latencies),
                                    "seconds": elapsed, "rows_per_second": args.rows / elapsed,
                                    "batch_median_ms": statistics.median(latencies) * 1000,
                                    "batch_p95_ms": percentile(latencies, .95) * 1000,
                                    "wal_bytes": wal_bytes, "wal_bytes_per_row": wal_bytes / args.rows,
                                    "checkpoint_seconds": checkpoint_seconds,
                                    "raw_text_bytes": raw_size, "logical_row_bytes": logical_size,
                                    "heap_bytes": heap_size, "index_bytes": index_size,
                                    "total_relation_bytes": total_size, "indexes": indexes,
                                    "rewrite_probe": rewrite_probe})
                finally:
                    database.close()
                    with admin.cursor() as cur:
                        cur.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))
    finally:
        admin.close()
    print(json.dumps({"profile": args.profile, "index_profile": args.index_profile,
                      "server_version": server_version,
                      "settings": settings, "results": results}, indent=2))


def docker(*argv, **kwargs):
    return subprocess.run(["docker", *argv], check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs).stdout.strip()


def run_profile(args, profile):
    name = "uli-ingest-io-" + uuid.uuid4().hex[:12]
    volume = name + "-data"
    root = Path(__file__).resolve().parents[1]
    created_volume = False
    try:
        docker("volume", "create", volume)
        created_volume = True
        command = ["run", "-d", "--name", name, "--network", "none", "--memory", "2g",
                   "--shm-size", "768m", "--mount", f"type=volume,source={volume},target=/var/lib/postgresql/data",
                   "-e", "POSTGRES_HOST_AUTH_METHOD=trust", args.postgres_image, "postgres"]
        for key, value in {**COMMON_SETTINGS, **PROFILES[profile]}.items():
            command.extend(["-c", f"{key}={value}"])
        docker(*command)
        deadline = time.monotonic() + 60
        while True:
            try:
                docker("exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres")
                break
            except subprocess.CalledProcessError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Disposable PostgreSQL did not start within 60 seconds")
                time.sleep(.25)
        output = docker("run", "--rm", "--name", name + "-worker", "--memory", "2g",
                        "--network", f"container:{name}",
                        "--mount", f"type=bind,source={root / 'receiver'},target=/benchmark/receiver,readonly",
                        "--mount", f"type=bind,source={Path(__file__).resolve()},target=/benchmark/run.py,readonly",
                        "--entrypoint", "/app/venv/bin/python", args.app_image,
                        "/benchmark/run.py", "--worker", "--profile", profile,
                        "--rows", str(args.rows), "--raw-bytes", str(args.raw_bytes),
                        "--seed-rows", str(args.seed_rows),
                        "--repetitions", str(args.repetitions),
                        "--index-profile", args.index_profile,
                        *(["--rewrite-probe"] if args.rewrite_probe else []),
                        "--batch-sizes", *map(str, args.batch_sizes), timeout=args.timeout)
        return json.loads(output)
    finally:
        # Names are generated here, never accepted from environment or caller.
        subprocess.run(["docker", "rm", "-f", name + "-worker"], capture_output=True, check=False)
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
        if created_volume:
            subprocess.run(["docker", "volume", "rm", volume], capture_output=True, check=False)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--app-image", default="unifi-insights-plus:benchmark")
    parser.add_argument("--postgres-image", default="postgres:16-alpine")
    parser.add_argument("--rows", type=int, default=50000)
    parser.add_argument("--seed-rows", type=int, default=10000,
                        help="Unmeasured rows before CHECKPOINT to exercise existing index pages")
    parser.add_argument("--raw-bytes", type=int, default=900)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--batch-sizes", type=int, nargs="+", default=[40, 80, 200, 1000])
    parser.add_argument("--index-profile", choices=INDEX_PROFILES, default="current",
                        help="Disposable write-cost experiment only; no read performance endorsement")
    parser.add_argument("--rewrite-probe", action="store_true",
                        help="Also measure a separate post-checkpoint row-update/FPI stress probe")
    parser.add_argument("--timeout", type=int, default=900, help="Maximum seconds per profile")
    parser.add_argument("--profiles", nargs="+", choices=PROFILES, default=list(PROFILES))
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--profile", choices=PROFILES, default="baseline", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if not all(1 <= batch <= 1000 for batch in args.batch_sizes):
        parser.error("--batch-sizes values must be 1–1000")
    for field, low, high in (("rows", 1, 1000000), ("seed_rows", 0, 1000000), ("raw_bytes", 200, 16000),
                             ("repetitions", 1, 10), ("timeout", 30, 7200)):
        if not low <= getattr(args, field) <= high:
            parser.error(f"--{field.replace('_', '-')} must be {low}–{high}")
    # Events are prepared outside the timed insert loop. Bound their combined
    # estimated footprint before creating Docker resources (and in the worker).
    # Dicts, parsed fields and Python object overhead need more than raw bytes.
    if (args.rows + args.seed_rows) * (args.raw_bytes + 4096) > MAX_FIXTURE_ESTIMATE:
        parser.error("Combined rows/raw size exceeds the 512 MiB fixture budget; reduce --rows or --raw-bytes")
    return args


def main():
    args = parse_args()
    if args.worker:
        if Path(__file__).resolve() != Path("/benchmark/run.py"):
            raise RuntimeError("Worker mode is only valid in the isolated benchmark container")
        return worker(args)
    # Inspection fails before allocating anything if an image is unavailable.
    for image in (args.app_image, args.postgres_image):
        docker("image", "inspect", image)
    root = Path(__file__).resolve().parents[1]
    source_hashes = {name: hashlib.sha256((root / "receiver" / name).read_bytes()).hexdigest()
                     for name in ("db.py", "security_predicates.py", "retention.py", "read_cache.py")}
    results = [run_profile(args, profile) for profile in args.profiles]
    if any(hashlib.sha256((root / "receiver" / name).read_bytes()).hexdigest() != digest
           for name, digest in source_hashes.items()):
        raise RuntimeError("Database sources changed during the benchmark; rerun for comparable results")
    print(json.dumps({"fixture": {"rows": args.rows, "raw_bytes": args.raw_bytes,
                                  "seed_rows": args.seed_rows, "batch_sizes": args.batch_sizes,
                                  "index_profile": args.index_profile,
                                  "repetitions": args.repetitions},
                      "scope": "Disposable local PostgreSQL; no production capacity claim",
                      "source_sha256": source_hashes,
                      "notes": ["WAL includes all index changes; excludes schema creation and final checkpoint",
                                "ingest_commits counts acknowledged application insert transactions",
                                "Small fixtures may fit baseline RAM; cache profiles also differ in WAL settings",
                                "Index-removal profiles measure write cost only, not query regressions",
                                "No concurrent dashboard, enrichment, retention or durable SQLite spool workload"],
                      "profiles": results}, indent=2))


if __name__ == "__main__":
    main()
