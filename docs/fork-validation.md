# Fork validation

The changes were tested against the upstream v3.7.2 base using synthetic events and disposable local databases. No live collector, gateway or production database was modified for these checks.

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
