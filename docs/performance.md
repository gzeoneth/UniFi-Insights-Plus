# Collection and query performance

Log Stream requests rows without an exact count by default. A filter matching millions of records no longer needs to count all of them before showing its first page. Use **Count matching events** when you need an exact total; counting pauses automatic refresh, and changing filters or refreshing invalidates that total. An unknown total is shown as unknown, not zero.

Choose 50, 100, 200, 500 or 1,000 rows per page. The default remains 50; larger pages require more transfer and browser rendering work. Changing page size starts a new traversal. API and MCP requests also accept up to 1,000 rows per page.

Timestamp sorting uses a cursor containing the last timestamp and row ID. The ID makes equal timestamps deterministic. Each traversal fixes its time window so moving to the next page does not slide a relative time filter forward. Refresh to start a new traversal and see newer records. Other sorts retain offset pagination. Cursor traversal is not a database snapshot: retention, backfill or edits can still change the records between requests.

Pausing Log Stream stops its automatic row requests. Hidden tabs also suspend polling. Refreshes run serially, with the next scheduled after the current request finishes. Changing filters cancels or discards obsolete browser responses. A browser abort does not guarantee that an already submitted database statement stopped immediately; database statement timeouts still bound that work.

API and MCP callers retain exact counts and offset pagination by default. Opt into `count_mode=none` and `pagination=cursor` for timestamp browsing. Use `next_cursor` to advance and `page_cursor` to repeat or count the current page, keeping the original filters. `total`, `pages` and `view_counts` are null when counts are skipped. `timings.query_ms` measures page-query work and the initial cursor boundary lookup; `timings.count_ms` measures the optional count. Neither includes HTTP transit or serialization.

## Address filters

Complete addresses use PostgreSQL's native IP equality, and CIDRs use subnet containment. For example, `203.0.113.7` matches that address and `203.0.113.0/24` matches that subnet. Both IPv4 and IPv6 are supported. Use `contains:203.0.113.` for an explicit partial text search; incomplete legacy address searches remain supported. Text searches can require more work than exact addresses or CIDRs.

Exclusions retain records whose excluded field is missing. Use the separate missing/present operators when you need different behavior. View exclusions still retain raw data and do not change the independent Security view.

Source and destination port parameters accept comma-separated values and inclusive ranges, such as `443,8000-8010`. Prefix the whole expression with `!` to exclude it. Invalid expressions return HTTP 400; they no longer silently remove the port condition. This applies to shared log, export and MCP queries.

## Security searches

The parsed-IPS and retained-CEF predicates have matching partial indexes on timestamp and row ID. Explicit NULL checks preserve classification while letting PostgreSQL use column statistics; wrapping a boolean predicate in `COALESCE` had caused poor selectivity estimates and full chronological scans. Security summaries count their separate candidate sets without applying raw CEF text matching to every ordinary event.

Indexes build concurrently in a background worker after UDP intake starts. The worker uses a separate connection, an advisory lock, a five-second lock timeout and a thirty-minute statement timeout. An interrupted invalid index is rebuilt on the next startup. Check the container's index-maintenance messages and the diagnostic script's `indisvalid` values before assuming the new indexes are available. Queries remain correct while an index is absent, but can remain slow. Concurrent builds still consume I/O and memory.

## Browsing and rule investigation

Flow View has the same advanced include/exclude conditions as Log Stream. For example, choose **Either IP / subnet**, **Exclude**, and `192.0.2.10` to remove flows involving that host. Conditions apply before aggregation to the Sankey graph, zone matrix, endpoint table, host details and CSV exports, and follow a flow into Log Stream. Flow saved views retain them; loading an older view clears conditions that it did not contain. Use exact IPs or CIDRs when recorded device labels are incomplete.

Flow panels serialize changes, defer endpoint aggregation until the matching graph query finishes, and reuse identical results for at most 30 seconds. Manual Refresh bypasses the cache. The cache key includes advanced conditions and view exclusions. A changed filter cannot display data from the previous scope as a current result.

Dashboard tiers, Security and Threat Map serialize their own requests across filter changes and stop starting work while the tab is hidden. Old-scope responses are discarded. Map failures show an error and a Retry button; an unsuccessful new filter cannot leave old-scope points on the map. A browser abort alone does not establish that a database query stopped.

Map and chart dependencies load when their panels are opened. Their loading placeholders no longer import those dependencies into the initial bundle.

Rule Usage starts with **Rule totals**. It groups by recorded gateway, rule, description and action, avoiding a separate group for every endpoint/port combination. Switch to **Endpoint details** to inspect those combinations. A rule-name edit is submitted with **Apply rule filter**, rather than querying after every keystroke. The UI skips an extra total-count scan unless **Count matching events** is selected. API defaults remain endpoint grouping and exact counts; opt into `group_by=rule&count_mode=none` for the new behavior.

These aggregations still inspect the selected time window. A top-200 result does not mean only 200 underlying events were read. Start with a short period, especially for broad exclusions or text matching.

## Ingestion

UDP reception, parsing/staging and database delivery have separate workers. A slow PostgreSQL batch no longer holds up the worker writing new records to the SQLite retry spool. Staging and acknowledgement retain durable SQLite commits, and database commits remain synchronous before spool acknowledgement. Ingest IDs prevent duplicate rows after a retry or crash following a database commit.

Version `.7` uses SQLite WAL with `synchronous=FULL`, batched insert/delete/lookups, and a bounded cache of committed retry payloads. It removes an unused retry-time index: delivery uses FIFO row order instead. WAL reduces journal creation and synchronization overhead while preserving durable admission. The page cache defaults to 16 MiB; the head cache holds at most 512 rows and 1 MiB of serialized payloads, plus Python object overhead. Cached payloads are decoded into independent rows for each delivery attempt.

Keep the spool on a local persistent volume. It is **not** an in-memory database. One receiver owns each spool, with one locked connection shared by its workers. Writes and checkpoints use that same connection. Checkpoints run near 4 MiB of WAL; if an external reader pins the WAL, new writes stop at a 16 MiB threshold until it can be checkpointed. One bounded transaction may exceed the threshold. Inspect checkpoint and storage-error metrics if this happens; do not leave a diagnostic read transaction open.

The WAL file is part of the database. For a live backup use SQLite's backup API; for a filesystem copy stop the receiver cleanly first and retain the whole spool directory. Do not copy only `retry.sqlite3` from a running receiver or delete its `-wal` file. See SQLite's [WAL documentation](https://www.sqlite.org/wal.html) and [synchronous settings](https://www.sqlite.org/pragma.html#pragma_synchronous).

The in-memory queue and the current uncommitted batch remain volatile. The disk spool has finite capacity. UDP cannot report packets lost before the receiver sees them, so zero application drops does not establish lossless transport.

| Variable | Default | Purpose |
| --- | --- | --- |
| `INGEST_BATCH_SIZE` | `200` | Maximum records per staging/delivery batch; capped at 1,000 |
| `INGEST_FLUSH_INTERVAL_SECONDS` | `1.0` | Flush partial staging batches; valid values are bounded to 0.05–5 seconds |
| `INGEST_QUEUE_CAPACITY` | `16384` | Maximum volatile intake messages; up to 128 MiB of UDP payload plus Python overhead at the 8 KiB receive limit |
| `INGEST_SPOOL_MAX_ROWS` | `100000` | Maximum disk-spool records |
| `INGEST_SPOOL_MAX_BYTES` | `67108864` | Maximum disk-spool payload bytes |
| `INGEST_SPOOL_CACHE_KIB` | `16384` | SQLite page-cache target in KiB; capped at 65,536 |
| `INGEST_SPOOL_HEAD_CACHE_BYTES` | `1048576` | Serialized retry-head cache limit; capped at 8 MiB and 512 rows |

Larger batches amortize commit cost but use more memory and can increase latency. Queue and spool capacity absorb a burst; they do not fix sustained intake exceeding delivery. Start with the defaults and compare received, staged and inserted rates over a representative busy period before increasing limits. Spool byte limits describe stored payloads, not an exact bound on SQLite filesystem usage.

Existing environment overrides still apply after upgrading. An installation explicitly using `INGEST_QUEUE_CAPACITY=4096` will keep that value until changed. The larger default buys time during a finite storage pause; queued packets and uncommitted batches can still be lost if the process exits before staging. It does not make UDP reliable.

Display labels use one batched configuration read cached for ten seconds, bounded to 1 MiB per database instance. Local committed configuration writes invalidate that cache; writes from another process become visible within the TTL. Concurrent readers share a load for the same key. Authorization, filtering policies and event/security query results do not use this cache. Existing metadata endpoint caches now include all arguments in their keys and have entry/byte limits.

When reputation quota is exhausted, confirmed cache misses have a fifteen-second retry delay, bounded to 1,024 addresses. This avoids reading the same missing database record for each repeated packet. Positive in-memory results, renewed quota and explicit manual refresh bypass that delay. A missing reputation score remains unknown; the cooldown does not create a score or bypass the provider's quota.

## Health

The database-independent `/api/health/ingest` snapshot includes rolling rates, queue/spool age, producer and delivery worker state, batch settings and stage timings. Older snapshots report unavailable new metrics as unknown. Stale snapshots do not claim a current throughput rate.

The Collection Health panel polls receiver metrics independently every ten seconds and the database summary every minute. A pending database request cannot hide a completed receiver snapshot or stop its next refresh. Manual refresh still works for the receiver while the database request is pending, without starting another database request.

By default health snapshots use `/dev/shm/unifi-log-insight/receiver-health.json` where shared memory exists, with `/run` as the fallback. Docker provides `/dev/shm` as tmpfs, so two-second health publication does not require persistent-volume writes. The receiver and API run in the same container and use the same path. `INGEST_STATUS_PATH` still overrides the default: remove an old `/run` override or update it to use shared memory. Only these disposable metrics move to RAM; the retry spool stays persistent.

Worker phases include opening, staging, reading and acknowledging the spool, so a partial-batch commit or acknowledgement wait cannot appear idle. Storage metrics separate lock wait, SQL work, commit and checkpoint time. Maximum timings have timestamps, and the last 32 completed operations taking at least one second remain available until restart. The Collection Health panel shows these recent delays separately from current collection status. These timings narrow an investigation; they do not identify a host disk fault by themselves.

Recent queued, batched or currently writing events show **Processing recent events** without an amber warning. Pending counts and completeness metadata remain available. Attention is required when recorded waiting time exceeds the greater of ten seconds or twice the flush interval, when the intake queue reaches 80% of capacity, or when retries, worker/storage failure, stalls or stale/missing health data prevent a healthy assessment.

Current drop rate and cumulative dropped records have different meanings. A rate returning to zero means new loss has stopped during the sampled window; it does not restore missing history. Historical loss stays visible separately from current processing. Failed workers or spool errors require investigation even if the API still answers. The public snapshot contains only allowlisted metrics, never raw events, query text, device names or credentials.

An empty filtered view is not proof that traffic did not occur. Check collection health, time range, view exclusions and gateway logging before using absence as evidence for a firewall change.

## Database checks

Run [query-diagnostics.sql](../scripts/query-diagnostics.sql) through `psql` against the intended database. It uses a read-only transaction with short timeouts and reads catalog statistics: table/index sizes, estimated rows, index validity, maintenance timestamps and connection waits. It does not read event payloads or change the database. The reported statement timeout belongs to that diagnostic session.

Check actual plans on a disposable restored database with representative filters. Compare row retrieval separately from exact counts. Use `EXPLAIN (ANALYZE, BUFFERS)` only when ready to execute the query; it is not a cost-free preview. Measure both warm and cold-cache behavior where practical, along with insert throughput and index size.

Avoid adding an index for every filter. Indexes cost disk space and insert work; a broad text index can be particularly expensive. The earlier pagination work favored native address predicates, cursor paging and optional counts. This release adds small indexes for sparse security candidates, based on measured query plans. Synthetic timings do not establish production capacity or predict a long-retention database.

See [query and index coverage](query-indexes.md) for the field-by-field audit, measured improvements and remaining scan costs.

Memory settings also need measurement. PostgreSQL `work_mem` applies per sort/hash operation and concurrent queries can use several such allocations. Disk capacity is not a reason to increase it or the connection pool. Keep searchable retention separate from optional archives and summaries.

## Upgrade verification

Back up the database and preserve encryption keys before staging an upgrade. Verify new count/cursor behavior and a fresh event through receipt, parsing, durable staging, database insertion and the intended filtered view. Confirm queue/spool ages settle after a burst and drop counters stop increasing. Compare actual filter latency and memory against the previous version before switching production traffic.
