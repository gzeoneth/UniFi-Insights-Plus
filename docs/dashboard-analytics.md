# Optional Dashboard analytics

Version `3.7.2-gzeon.13` adds a narrow, logged PostgreSQL event table for Dashboard queries. It is **disabled by default**. This is an additional durable copy of selected event fields, with two indexes; allow disk space and measure ingestion before enabling it on a busy installation.

## Why a separate table

A time index finds the relevant events, but an exact 24-hour aggregate still examines the events in that window. Adding indexes for every categorical filter increases insertion, enrichment, retention and WAL work. A wide covering index containing arbitrary text can also exceed PostgreSQL's index-tuple limit; included columns disable B-tree deduplication, and index-only scans still depend on heap visibility. See [PostgreSQL's index-only scan guidance](https://www.postgresql.org/docs/16/indexes-index-only-scans.html) and [CREATE INDEX](https://www.postgresql.org/docs/16/sql-createindex.html).

Large observability systems change the storage layout as well as their indexes. Datadog describes time-bucketed columnar files and compaction that improves locality and prunes irrelevant fragments in [Husky's storage design](https://www.datadoghq.com/blog/engineering/husky-storage-compaction/). Its time-series tag search also uses [inverted indexes](https://www.datadoghq.com/blog/engineering/timeseries-indexing-at-scale/). Those are distinct workloads and storage designs, rather than a B-tree on every log attribute.

This release retains PostgreSQL and the raw event table. `dashboard_events` stores 28 selected fields and two precomputed security classifications, without raw messages. Its primary key is `id`; its only additional index is `(timestamp DESC, id DESC)`. Broad Dashboard scans read a narrower heap. This is a row-store projection, not a column store or a preaggregated rollup. Exact counts and distinct-address calculations still cost work proportional to the selected window.

## Enable and observe

1. Keep a tested database backup and the currently deployed image. Restoring a backup is a separate operation from changing the image.
2. Add `DASHBOARD_ANALYTICS_ENABLED=true` to the private Compose environment and recreate the application container with the new image. With `compose.gzeon.yml`, set it in `.env` and run `docker compose -f compose.gzeon.yml up -d`. A container restart alone does not reload changed environment variables.
3. Open **Collection Health → Dashboard acceleration**. Recent history becomes ready before older history. Until the requested cutoff is covered, queries automatically use `logs`. “Historical rows checked” measures backfill progress, not an exact current event count.
4. Compare the same Dashboard range/profile, ingestion rates, pending age, storage consumption and PostgreSQL WAL over a representative busy period. The five `stats_*` Server-Timing fields identify the expensive stage independently of HTTP transit and browser rendering.

The API adds an allowlisted `dashboard_analytics` object to `/api/health`: enablement, status, healthy/complete flags, earliest covered timestamp, historical progress, update time and a bounded error code. It does not scan events or expose payloads, addresses, filters or credentials. A healthy API alone does not prove analytics readiness or healthy ingestion.

Initial setup creates empty derived tables, two indexes and four statement triggers under a short, bounded writer lock. It does not scan retained history before intake starts. A dedicated worker copies at most 1,000 events per transaction, waits 250 ms between batches and works from recent hour bands toward older history. Historical copying pauses during initial index maintenance or collection delays. Trigger work on new writes continues while copying is paused. A local development copy can finish much faster than this throttled production worker.

All retained events are eventually copied, so disk usage continues growing until backfill completes. The extra table is not a retention policy. Existing raw retention deletes corresponding derived rows transactionally. Normal PostgreSQL vacuum and disk-capacity planning still apply.

## Pause older-history preparation

Version `.14` can pause historical copying independently of analytics capture and reads:

```yaml
environment:
  DASHBOARD_ANALYTICS_ENABLED: "true"
  DASHBOARD_ANALYTICS_BACKFILL_ENABLED: "false"
```

Recreate the application container after changing these variables. Existing facts, published coverage, cursor position and capture triggers remain intact. New events and changes to existing events continue synchronizing transactionally. Covered Dashboard ranges still use analytics; unprepared older ranges use raw queries. Collection Health reports that older-history preparation is paused. No migration, index rebuild or historical restart is required.

This control is useful when historical copying competes with foreground queries or current ingestion. It does not establish that copying caused a slowdown, eliminate live capture's write cost or override other query limits. Compare the same range and profile after pending ingestion drains; change cache settings separately so their effects are distinguishable.

Set `DASHBOARD_ANALYTICS_BACKFILL_ENABLED=true` and recreate to resume from the saved cursor. The default is `true`, preserving existing behavior. Pausing before any historical coverage is prepared does not create coverage. The original `DASHBOARD_ANALYTICS_ENABLED=false` still disables the whole feature and invalidates coverage; use it for full disable/downgrade, not for this comparison.

## Exactness and fallback

Actual inserts, projected-field changes, deletes and truncations synchronize in the raw writer's transaction using PostgreSQL statement-level transition triggers. Ingest duplicates do not create additional facts. Enrichment changes, backdated events, changed timestamps and retention are included. Security classifications preserve both parsed IPS events and historical raw CEF threat candidates.

Backfill uses bounded repeatable-read transactions and row locks. It retries a concurrent timestamp update instead of advancing a cursor past unvisited events. Coverage is published only after a complete hour band. A reader locks both raw and derived relations before its repeatable-read snapshot, avoiding PostgreSQL's non-MVCC-safe `TRUNCATE` behavior. See [row locking](https://www.postgresql.org/docs/16/sql-select.html#SQL-FOR-UPDATE-SHARE) and [TRUNCATE](https://www.postgresql.org/docs/16/sql-truncate.html).

Overview, Tables and Charts, the combined `/api/stats` response and its MCP tool use this path when ready. Common structured exclusions use the same predicates with stored security classifications. Profiles that require raw messages, rule descriptions, device-name lookups or other omitted fields use raw queries. Flow, Operations, Security and Log Stream retain their existing paths. Inventory labels and threat-cache joins remain live; there is no TTL cache of event results.

Missing or invalid coverage, unsupported historical infinite timestamps, unavailable derived tables or mismatched catalog definitions keep requests on raw queries. Cancellation and statement timeouts are not hidden by starting a second expensive fallback query. A damaged derived schema can require operator repair; it is not permission to delete raw data.

## Disable or downgrade

Set `DASHBOARD_ANALYTICS_ENABLED=false` and **recreate the container while still running this release**. The worker disables the four capture triggers and invalidates coverage; it retries if a short lock timeout prevents the first attempt. Derived table data is retained. Check that health reports analytics disabled, and verify the database triggers before downgrading:

```sql
SELECT tgname, tgenabled
FROM pg_trigger
WHERE tgrelid = 'logs'::regclass
  AND tgname IN ('dashboard_store_insert', 'dashboard_store_update',
                 'dashboard_store_delete', 'dashboard_store_truncate')
ORDER BY tgname;
```

Every returned trigger must have `tgenabled = 'D'`; zero rows is also safe if the feature was never installed. **An older image alone does not disable persistent database triggers.** Keep the current release running until disable succeeds. Dropping the derived tables while capture triggers are active can break raw inserts.

Re-enabling after a disabled interval clears only derived facts and coverage, then rebuilds them from raw data. It never assumes stale facts cover writes made while capture was disabled. Disabling does not shrink database files or remove raw indexes. Reclaiming derived-table disk is separate maintenance after capture is confirmed disabled.

## Validation limits

Transactional tests exercise deduplicated inserts, malformed batch rollback, enrichment, ID/timestamp edits, retention, truncation, interrupted copying, disabled intervals, catalog damage, security exclusions and concurrent readers/writers. Large synthetic measurements and their storage/write costs are recorded in [fork validation](fork-validation.md). Local results are not a NAS storage benchmark or proof that a particular production timeout is resolved.
