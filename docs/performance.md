# Collection and query performance

Log Stream requests rows without an exact count by default. A filter matching millions of records no longer needs to count all of them before showing its first page. Use **Count matching events** when you need an exact total; counting pauses automatic refresh, and changing filters or refreshing invalidates that total. An unknown total is shown as unknown, not zero.

Timestamp sorting uses a cursor containing the last timestamp and row ID. The ID makes equal timestamps deterministic. Each traversal fixes its time window so moving to the next page does not slide a relative time filter forward. Refresh to start a new traversal and see newer records. Other sorts retain offset pagination. Cursor traversal is not a database snapshot: retention, backfill or edits can still change the records between requests.

Pausing Log Stream stops its automatic row requests. Hidden tabs also suspend polling. Refreshes run serially, with the next scheduled after the current request finishes. Changing filters cancels or discards obsolete browser responses. A browser abort does not guarantee that an already submitted database statement stopped immediately; database statement timeouts still bound that work.

API and MCP callers retain exact counts and offset pagination by default. Opt into `count_mode=none` and `pagination=cursor` for timestamp browsing. Use `next_cursor` to advance and `page_cursor` to repeat or count the current page, keeping the original filters. `total`, `pages` and `view_counts` are null when counts are skipped. `timings.query_ms` measures page-query work and the initial cursor boundary lookup; `timings.count_ms` measures the optional count. Neither includes HTTP transit or serialization.

## Address filters

Complete addresses use PostgreSQL's native IP equality, and CIDRs use subnet containment. For example, `203.0.113.7` matches that address and `203.0.113.0/24` matches that subnet. Both IPv4 and IPv6 are supported. Use `contains:203.0.113.` for an explicit partial text search; incomplete legacy address searches remain supported. Text searches can require more work than exact addresses or CIDRs.

Exclusions retain records whose excluded field is missing. Use the separate missing/present operators when you need different behavior. View exclusions still retain raw data and do not change the independent Security view.

## Ingestion

UDP reception, parsing/staging and database delivery have separate workers. A slow PostgreSQL batch no longer holds up the worker writing new records to the SQLite retry spool. Staging and acknowledgement retain durable SQLite commits, and database commits remain synchronous before spool acknowledgement. Ingest IDs prevent duplicate rows after a retry or crash following a database commit.

The in-memory queue and the current uncommitted batch remain volatile. The disk spool has finite capacity. UDP cannot report packets lost before the receiver sees them, so zero application drops does not establish lossless transport.

| Variable | Default | Purpose |
| --- | --- | --- |
| `INGEST_BATCH_SIZE` | `200` | Maximum records per staging/delivery batch; capped at 1,000 |
| `INGEST_FLUSH_INTERVAL_SECONDS` | `1.0` | Flush partial staging batches; valid values are bounded to 0.05–5 seconds |
| `INGEST_QUEUE_CAPACITY` | `4096` | Maximum volatile intake messages |
| `INGEST_SPOOL_MAX_ROWS` | `100000` | Maximum disk-spool records |
| `INGEST_SPOOL_MAX_BYTES` | `67108864` | Maximum disk-spool payload bytes |

Larger batches amortize commit cost but use more memory and can increase latency. Queue and spool capacity absorb a burst; they do not fix sustained intake exceeding delivery. Start with the defaults and compare received, staged and inserted rates over a representative busy period before increasing limits. Spool byte limits describe stored payloads, not an exact bound on SQLite filesystem usage.

## Health

The database-independent `/api/health/ingest` snapshot includes rolling rates, queue/spool age, producer and delivery worker state, batch settings and stage timings. Older snapshots report unavailable new metrics as unknown. Stale snapshots do not claim a current throughput rate.

Current drop rate and cumulative dropped records have different meanings. A rate returning to zero means new loss has stopped during the sampled window; it does not restore missing history. Backlog means the view may be delayed. Failed workers or spool errors require investigation even if the API still answers. The public snapshot contains only allowlisted metrics, never raw events, query text, device names or credentials.

An empty filtered view is not proof that traffic did not occur. Check collection health, time range, view exclusions and gateway logging before using absence as evidence for a firewall change.

## Database checks

Run [query-diagnostics.sql](../scripts/query-diagnostics.sql) through `psql` against the intended database. It uses a read-only transaction with short timeouts and reads catalog statistics: table/index sizes, estimated rows, index validity, maintenance timestamps and connection waits. It does not read event payloads or change the database. The reported statement timeout belongs to that diagnostic session.

Check actual plans on a disposable restored database with representative filters. Compare row retrieval separately from exact counts. Use `EXPLAIN (ANALYZE, BUFFERS)` only when ready to execute the query; it is not a cost-free preview. Measure both warm and cold-cache behavior where practical, along with insert throughput and index size.

Avoid adding an index for every filter. Indexes cost disk space and insert work; a broad text index can be particularly expensive. This release keeps the existing indexes. Its synthetic checks favored native address predicates, cursor paging and optional counts over adding more indexes. Synthetic timings do not establish production capacity or predict a long-retention database.

Memory settings also need measurement. PostgreSQL `work_mem` applies per sort/hash operation and concurrent queries can use several such allocations. Disk capacity is not a reason to increase it or the connection pool. Keep searchable retention separate from optional archives and summaries.

## Upgrade verification

Back up the database and preserve encryption keys before staging an upgrade. Verify new count/cursor behavior and a fresh event through receipt, parsing, durable staging, database insertion and the intended filtered view. Confirm queue/spool ages settle after a burst and drop counters stop increasing. Compare actual filter latency and memory against the previous version before switching production traffic.
