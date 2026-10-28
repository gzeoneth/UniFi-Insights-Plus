# Fork validation

The changes were tested against the upstream v3.7.2 base using synthetic events and disposable local databases. No live collector, gateway or production database was modified for these checks.

## Browser-preferences release: 3.7.2-gzeon.6

- All 327 UI tests and the production UI build passed. This release changes browser state handling, documentation and version references; backend code and database schema are unchanged, so backend and container checks were not repeated.
- Tests cover local persistence, migration from session storage, malformed and oversized values, unavailable storage, explicit drilldown precedence, custom dates, relative ranges, saved-view labels, view exclusions and per-view settings. Remembered filters are applied before the first query; result rows and pagination cursors are not restored.
- A local browser using synthetic API fixtures retained Log Stream's IP exclusion, six-hour range, paused updates, 200-row page size and hidden country column after closing the tab and opening a new one. The export URL retained the same scope. Flow retained its selected tab, exclusion, expanded filter panel, matrix view and 50-pair limit across another tab closure.
- Independent review found and fixed stale saved-view labels, legacy custom dates carrying a relative range, and invalid stored Rule Usage scopes. Shared filter validation enforces the backend's size and field limits.

These browser checks verify persistence and request scope with fixtures, not live ingestion or production filtering. The release does not change gateway rules, collection, retention or server settings. See [browser preferences](browser-preferences.md) for the saved choices and their limits.

## Flow and query performance release: 3.7.2-gzeon.5

- 1,264 backend tests passed with all disposable PostgreSQL checks enabled. All 275 UI tests, the production UI build and a local ARM64 image build passed. All 48 runtime receiver files matched the tested checkout by SHA-256.
- A disposable container received and inserted 1,207 synthetic firewall events and three DNS query events through UDP, with zero reported drops, parsing failures or flush errors. Both new security indexes were valid after startup.
- Excluding a synthetic host removed its 1,205 firewall records consistently from the graph, matrix, pairs, host details, CSV and Log Stream, leaving two events between other endpoints. Rule totals returned one group without an implicit exact-count query. Port-list filters and 1,000-row cursor pagination returned the expected results.
- Browser checks against that container confirmed the host exclusion, remaining graph/table entries and Flow-to-Log Stream drilldown with the exclusion and row protocol intact. Shared-hook tests cover rapid filter changes, deferred panels, hidden tabs, cache expiry and explicit refresh.
- PostgreSQL tests cover full security-predicate equivalence, index-backed plans, qualified repair of a genuinely interrupted concurrent index, repeat upgrades, and IPv4/IPv6/masked/NULL zone pairs. Directional interface filters preserve reverse-path distinctions.
- Independent review found and fixed lost drilldown scope and ambiguous empty-interface matrix selection. Empty-interface cells retain counts but cannot be selected. Oversized drill scopes fail validation instead of silently dropping conditions.

Synthetic query measurements and field coverage are documented in [query indexes](query-indexes.md). The initial JavaScript bundle fell from approximately 2.03 MB to 613 KB before compression by loading map/chart dependencies only with their panels. The map chunk remains large when opened. None of these tests establishes production capacity or proves an image was published or deployed.

## Collection-status release: 3.7.2-gzeon.4

- 1,226 backend tests passed with all disposable PostgreSQL checks enabled. All 243 UI tests and the production UI build passed. A local ARM64 image build passed.
- A disposable container received 1,205 synthetic firewall events and three dnsmasq queries through UDP. All 1,208 were parsed and inserted, with zero reported drops, parse errors or flush errors. Ten observed snapshots of ordinary processing had pending records without requiring attention.
- REST cursor pagination returned 1,000 and 205 firewall rows with 1,205 unique IDs. The browser displayed 1,000 rows on the first page and the remaining 208 mixed firewall/DNS rows on the next page. The page-size control and version label matched the build.
- Health tests cover normal batching, aged queues/spools/batches, queue pressure, retries, worker/storage failures, stale snapshots and historical loss. Empty-batch timestamps cannot incorrectly classify newly queued work as stalled. The public endpoint recomputes collection status from allowlisted fields.
- UI tests cover neutral processing, delayed collection, historical loss, older snapshots, persisted page size, cursor resets and DNS-only empty-state guidance. Synthetic A, AAAA and HTTPS query messages reached the DNS view through the built container's parser and database.

These checks validate application behavior with supplied query messages. They do not establish that a particular gateway exports DNS query names. See [DNS logging](dns-logging.md) for source-side diagnosis.

## Performance release: 3.7.2-gzeon.3

- 1,179 backend tests passed with all disposable PostgreSQL checks enabled. 218 UI tests and the production UI build passed. A local ARM64 container build passed; its application source hashes matched the tested checkout.
- A disposable container received 2,000 synthetic UDP firewall events at about 400 packets/second. All 2,000 reached PostgreSQL, with zero reported drops and an empty queue/spool afterwards. Cursor traversal returned 2,000 unique row IDs. Exact IP, CIDR, partial-text and negative filters returned the expected counts.
- Browser checks against that container confirmed unknown totals, explicit counting with automatic updates paused, Next/Previous cursor navigation, and the new collection metrics/timing details. Unit tests cover hidden tabs, slow requests, rapid filter changes and stale-response handling.
- PostgreSQL tests cover both timestamp orders, ties, late-arriving rows, frozen recounts, cursor/filter mismatches, NULL complements and unchanged legacy API defaults. Query timings separate page retrieval from exact counts.
- Ingestion tests cover a blocked database while the producer continues durable staging, concurrent spool stage/acknowledgement, SQLite-full rollback, ambiguous commits, failed acknowledgements, malformed results and bounded shutdown with volatile work reported.
- Health tests verify unknown metrics from older snapshots, stale rates, separate worker stalls, recently started work after idle, parser losses and public-field sanitization. Independent review found two incorrect stall classifications; regression tests cover both fixes.

On a 200,000-row synthetic PostgreSQL 16 fixture, median exact IP lookup was 1.34 ms versus 38.65 ms for the previous substring query. These queries intentionally have different matching semantics. A deep offset query took 33.41 ms versus 0.040 ms for a cursor query. An exact raw-text count took 360.86 ms; the corresponding first page without counting took 0.196 ms. Existing indexes were retained: extra composites increased index storage without enough evidence to justify their ongoing write cost.

A separate 4,000-event ingestion microbenchmark used real parsing, SQLite FULL durability and synchronous PostgreSQL commits, with network enrichment disabled. Batches of 200 reduced database transactions from 80 to 20 compared with batches of 50. Across two runs each, throughput was approximately 12,700–12,900 versus 8,200–9,200 rows/second. With an injected 25 ms database delay, it was approximately 3,200–3,800 versus 1,300–1,400. All runs retained exactly 4,000 unique events without reported drops.

These small local benchmarks compare code paths; they do not establish production throughput, peak memory or performance over long retention. No production memory settings, retention, indexes or gateway logging policies were changed. See [performance guidance](performance.md) for deployment checks and limits.

## View-exclusion release: 3.7.2-gzeon.2

- 1,097 backend tests passed, including disposable PostgreSQL queries, upgrade/restore, replay, retention and TLS checks.
- 204 UI tests passed. The production UI build and a local ARM64 Docker image build passed.
- PostgreSQL tests verified AND-within/OR-between group matching, NULL behavior, literal comma/case matching, counts before pagination, and parity across logs, CSV, Rule Usage, stats, flows and MCP.
- Parsed IPS records and raw CEF candidates remained visible under broad profiles. Fixtures include `Threat Detected and Blocked` and explicit IPS metadata, plus the separate unparsed-candidate warning.
- Twelve built-in views reset conflicting filters and preserve page size/sort. Discovery includes replies, and private-traffic blocks include gateway-local paths. Security classifications use the same predicate across views and counters.
- New firewall records retain their reported emitter without replacing DHCP client names. Delivery/retry counters distinguish ordinary batch sends from retries; old snapshots report unknown actual retries.
- UI tests cover preview invalidation, delayed requests, profile loading/saving/deletion, browser defaults, delayed deletion, reversible Show all, scoped caches, collection-loss alerts and Security independence.
- A local browser with synthetic API fixtures confirmed rule-scoped drafting, preview/save/apply, restoration through Show all, export parameters, default reload, built-in private/discovery filter selection and the unparsed-CEF warning. Backend behavior was tested separately against PostgreSQL; the browser fixture is not a live-gateway ingestion test.
- Privacy review covered the outgoing source and new files. Exact private-value checks found only an unchanged upstream example URL. Gitleaks found the same two `retention_policy_v1` identifier false positives. Local test caches are excluded from Docker builds.

No production workload, long-retention query benchmark or new image publication was performed for these checks. Active profiles inspect raw CEF text and add count-query work; measure latency and memory against a restored database before changing production retention.

## Earlier release checks: 3.7.2-gzeon.1

- 1,004 backend tests passed, including explicit PostgreSQL integration tests.
- 167 UI tests passed.
- Vite production build and a local ARM64 Docker build passed.
- A tagged v3.7.2 schema was populated, dumped with `pg_dump`, restored into a separate database, and migrated twice without losing row IDs or raw messages.
- CEF preview, apply and repeat repaired the expected records once, preserving raw text, reputation data and recorded labels.
- Duplicate insertion and crash-after-commit replay were acknowledged without inserting duplicate rows.
- Invalid IPs, integers and NUL-containing fields were isolated without blocking valid records.
- Insert transactions flushed WAL before acknowledging the retry spool, including when the database session's default used asynchronous commit.
- Retention tests verified archive-before-delete behavior, rollback, summary idempotence, capacity failure and longer security-event retention.

PostgreSQL tests are opt-in: see `test_upgrade_restore_postgres.py`, `test_retention_identity_postgres.py`, and `test_field_filters.py` for their explicit test-environment variables. They never infer a production database connection.

## Container and browser checks

Synthetic RFC5424/CEF events traveled through UDP reception, parsing, persistence and the HTTP API. The dashboard displayed blocked, allowed and unknown IPS actions separately from reputation. Browser checks confirmed that excluding a destination port changed the rows, carried through to the CSV URL, and could be saved as a log view. Operations displayed collector counters and optional retention settings.

A local container received 3,000 synthetic firewall packets at 100 packets/second. All 3,000 were committed with zero reported drops. A resource snapshot after the run showed about 210 MiB of container memory. This was a small database with external enrichment providers unconfigured; it does not establish production throughput, peak memory, or long-term storage requirements.

The in-memory UDP queue remains volatile until parsed batches reach the spool. UDP cannot report events lost before reception. Archive quotas stop affected deletion when exhausted; operators must manage archive storage separately.

## Native HTTPS

TLS tests cover generated SANs and permissions, stable certificate reuse, supplied certificates, and startup rejection of invalid, incomplete, expired or mismatched material. Loopback health checks verify the configured certificate, including custom certificates without loopback SANs, and reject an unexpected server certificate.

A disposable container served HTTPS using a generated certificate trusted explicitly by the test client. Administrator setup, login and authenticated API requests succeeded with Secure/HttpOnly cookies. The listener rejected plaintext HTTP and ignored an untrusted forwarded scheme header. A container restart preserved the certificate. The final AMD64 image also passed certificate-verified HTTPS and container health checks. A separate default-HTTP container passed health checks, rejected an unauthenticated forwarded-HTTPS header, and accepted the existing authenticated proxy header.

## Publication review

Only source, documentation and synthetic fixtures are included. The candidate changes were reviewed independently, checked against known private values, and scanned with Gitleaks. Its two generic-key findings were the literal configuration identifier `retention_policy_v1`, not credentials. Site-specific defaults were removed. Deployment secrets, data, logs, screenshots, database dumps and image exports remain outside Git.

Container publishing runs after a pull request merges into `main` or an explicit manual `workflow_dispatch`. The workflow builds AMD64 and ARM64 images from the exact merge commit or the selected ref's commit SHA at dispatch time. Branch and tag pushes do not publish automatically. Both paths publish only to this fork's GHCR package and require a `X.Y.Z-gzeon.N` version. Browser-extension publishing and upstream service integrations remain disabled in this fork. Tests can run in GitHub Actions. Build and export staging images locally with `scripts/build-local.sh` when a registry publication is not wanted.
