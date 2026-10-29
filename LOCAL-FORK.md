# Fork maintenance and deployment

This fork is based on UniFi Insights Plus v3.7.2, commit `4f218128b9159e67095a37796f10dbdfa441b099`.

This fork publishes source code and synthetic test fixtures only. Keep deployment configuration, credentials, logs, backups, database exports, screenshots and built image archives out of Git. The upstream remote is for fetching; its push URL is disabled. Build images locally with `scripts/build-local.sh`, or pull a version published after a reviewed PR merge or manual workflow run. Keep the upstream license and attribution.

## Changes

- Parse UniFi CEF IPS events and preserve their signature, action, risk, severity and timestamp. IP reputation remains a separate signal. The dashboard and event details display both.
- Prefer the actual IP when naming routed clients. Do not name a remote client after the transit router's MAC. IP reputation lists use the remote endpoint.
- Persist pending batches in a bounded SQLite spool before database delivery. UUIDs make retries idempotent. Count committed rows, duplicates, failures and queue overflow separately.
- Receive UDP independently of slow enrichment/database work. Bound enrichment workers and queues. MCP dispatch and authentication use worker threads.
- Apply structured include/exclude filters consistently in log queries and CSV exports. Save log views separately from flow views.
- Choose built-in views for security, blocked private traffic, discovery replies, NAT mapping attempts and other common investigations. They do not hide events by default.
- Save previewed exclusion profiles for routine events. Apply them to traffic views, charts and exports while retaining raw logs and keeping Security independent. See [view exclusions](docs/view-exclusions.md).
- Browse observed rule usage, collector health, per-type retention and older-event summaries in Operations.
- Optionally archive records to gzip JSONL before retention deletion. Archive failure or capacity exhaustion prevents affected raw-data deletion.
- Browse logs without counting all matches on every refresh. Timestamp cursors, exact IP/CIDR filters and serialized polling reduce repeated database work. See [performance and collection health](docs/performance.md).
- Stage received logs independently of database delivery, with bounded configurable batches and separate worker/rate/backlog metrics.

## Build and test

Use Python 3.12 or newer with `receiver/requirements.txt` and `receiver/requirements-test.txt`. Run `pytest receiver/tests` with `receiver` on `PYTHONPATH`. From `ui`, run `npm ci`, `npm test`, and `npm run build`.

`scripts/build-local.sh linux/amd64` builds and exports a local image for an x86 NAS. Use `linux/arm64` for an ARM host. The script never pushes an image. Set `DOCKER_CONTEXT=orbstack` when using that local runtime. Archives and checksums are in `.local/artifacts/`.

PostgreSQL integration tests use explicit `UNIFI_TEST_DB_DSN` or `TEST_POSTGRES_DSN` variables, as documented in each test file. Point these only to disposable local test databases. The upgrade/restore test also requires an explicit disposable Docker container. Tests do not use production database variables.

The UDP intake queue is volatile until its parsed batches reach the SQLite spool. Queue overflow and unfinished shutdown work are counted as drops. The spool has bounded capacity; it is not a substitute for a reliable transport. Cached enrichment keeps reception independent of network lookups, but a cold reverse-DNS result may appear only on later events.

`/api/health/ingest` is public, like `/api/health`, and remains readable during a database outage. It exposes only collection counters, queue sizes, timing and provider status; it includes no event IPs, device names, credentials or raw messages. Protected log and settings endpoints retain their authentication requirements.

## Branch and image workflow

Develop on a branch and squash related changes for review. The image workflow runs automatically when a pull request is merged into `main`, and can also be started manually with `workflow_dispatch`. Branch pushes, ordinary main pushes, tags and unmerged PR closures do not publish images automatically.

After a merge, the workflow checks out the exact merge commit and publishes AMD64 and ARM64 images to `ghcr.io/gzeoneth/unifi-insights-plus`. For a manual run, open Actions → Publish fork image → Run workflow, select the reviewed branch under Use workflow from, and run it. GitHub CLI/API dispatch also supports tags. The checkout is pinned to the selected ref's commit SHA at dispatch time. GitHub shows the manual run control once this workflow exists on the default branch.

Both paths publish the version in `VERSION`, the rolling `gzeon` tag, and a commit-SHA tag. A manual run also updates the version and rolling tags, so increment `VERSION` when publishing different release content. Pin deployments to a version or digest. The first GHCR package may need its visibility set to public in GitHub package settings before unauthenticated pulls work.

Before merging, use a local build for staging or explicitly dispatch the workflow for the reviewed branch. No new registry tag is available merely because a branch exists.

## Deployment

`compose.gzeon.yml` starts a separate instance with its own database and persistent ingestion/archive volumes. It defaults to loopback ports 8091 and 1514, so it does not replace or compete with the existing collector. A four-GiB container limit is a resource ceiling, not a throughput guarantee.

1. After a merged-PR or manual image workflow succeeds, pull the versioned GHCR image used by `compose.gzeon.yml`. For local staging, build locally, copy its archive privately to the Docker host, and load it with `docker image load -i <archive>`. Set `INSIGHTS_IMAGE=unifi-insights-plus:3.7.2-gzeon.9` and `INSIGHTS_PULL_POLICY=never` in the private `.env` for that local image.
2. Create a private `.env` from the upstream `.env.example`. Set a new database password for staging. When restoring production data, preserve the existing database password and encryption `SECRET_KEY`; changing the encryption key prevents saved credentials from decrypting.
3. Take a PostgreSQL custom-format backup of the existing database using `pg_dump -Fc`. Keep its configuration, image version, secret file, and MaxMind mounts together in private storage. The app's JSON configuration export is not a database backup.
4. Restore into the separate database volume, then start the custom image. Verify schema migration, counts, raw messages, credentials and CEF backfill there first. Never attach two running PostgreSQL processes to the same data directory.
5. Set `WEB_BIND_IP` to the intended private interface only when connecting the reverse proxy. Keep the existing HTTPS hostname and proxy mapping, or configure [native HTTPS](docs/https.md). Set `SYSLOG_BIND_IP` and `SYSLOG_PORT` explicitly when ready to receive real logs.
6. Switch the gateway's syslog destination only after the replacement is healthy and a fresh test event reaches it. Retain the original image and database volume for rollback. Reverting the syslog destination restores the old collection path; events received only by the new instance are not automatically copied back.

No live gateway rules, syslog destination, collector settings, or production database are changed by building this fork. The deployment configuration is a staging setup until the operator selects the production bindings.

## HTTPS

Optional native HTTPS serves the UI, API and MCP endpoint on the existing container port. It generates a persistent self-signed certificate or loads a supplied certificate/key pair. See [HTTPS setup](docs/https.md) for hostname configuration, client trust, renewal and reverse-proxy compatibility.

## CEF backfill

Run `python cef_backfill.py --help` inside the app container. The default is read-only. Run the preview on restored data before applying changes. The tool prints a resume cursor and scans bounded ID batches; it updates existing rows, preserves raw text and reputation fields, and does no network enrichment.

## Filters and rule observations

Add conditions in Log Stream's Include / exclude panel. All conditions combine with AND. Comma-separated values within a condition combine with OR. Exclude retains rows with missing fields; Has value and Missing value control that explicitly.

Filters, time selections and browsing preferences survive reloads in this browser. See [browser preferences](docs/browser-preferences.md) for the choices saved locally and how to reset them.

IP fields use exact addresses or CIDRs. Ports and scores accept inclusive ranges. Text matches literal substrings, not SQL wildcard patterns. Categorical fields match complete values. Invalid filters are rejected instead of silently broadened.

View exclusions are a separate, opt-in profile: conditions within each group combine with AND, and an event is hidden if any group matches. Exact recorded-rule and gateway fields use case-sensitive, whole-string matching, including literal commas. A preview is required before applying a profile in the UI. Counts and Show all make the effect visible; Security and the threat map remain independent. Historical CEF threat candidates stay visible and produce a Security warning until backfilled.

Device-name conditions match names recorded with an event. A newer controller name displayed by a live lookup can differ; use the IP condition when targeting a renamed device or historical records.

Collection health distinguishes API availability from cumulative packet loss. The header flags known drops; skipped enrichment is reported separately. Delivery attempts count all database batches, while retries count batches with recorded prior failures. Legacy snapshots report the actual retry count as unknown.

Rule usage counts observed log entries, not network flows or exact packet totals. Gateway rate limits, disabled logging and receiver loss can hide activity. Use these observations to propose narrower A/V rules, then test those rules separately; the app does not change firewall policy.

See [retention policy](docs/retention-policy.md) for archive limits, retention defaults, and summary semantics. Retention changes and archives are opt-in. Summaries count only records deleted by cleanup, not live raw records.

## Credentials

Store credentials in private, ignored files outside the image build context. Never copy live credentials or configuration into fixtures, reports, Git commits or published artifacts. Tests use synthetic addresses and environment-supplied credentials for disposable local databases.
