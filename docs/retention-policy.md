# Event retention, archives, and daily summaries

The local fork keeps the upstream retention defaults: general logs retain their resolved general period, DNS logs retain their resolved DNS period. Existing environment variables and Settings values still apply. The new policy starts disabled. It does not rewrite or copy the logs table.

`GET /api/config/retention/policy` returns the policy and inherited periods. `PUT` or `POST` to the same path replaces the policy as one validated `system_config.retention_policy_v1` JSON value. Omitted fields return to their defaults. These endpoints require settings read/write permission. The existing Settings cleanup button and daily scheduler use the saved policy when enabled.

## Raw retention

`type_days` accepts `dns`, `firewall`, `dhcp`, `wifi`, `system`, and `unknown`. Unspecified types inherit the general period, except DNS, which inherits its DNS period. `security_days` applies to `event_source = unifi_ips` and the `ips`, `security`, and `threat` log types, regardless of action. Security events are excluded from every shorter pass. `firewall_allow_days` optionally gives ordinary firewall ALLOW/ACCEPT events their own period. An explicitly configured allow period must be shorter than the effective security period.

All periods accept integers from 1 to 3650. Null security/allow periods mean inheritance. Invalid saved policies stop cleanup; they do not fall back to a shorter period. Changing periods does not delete immediately: cleanup runs at its existing scheduled time, or from the cleanup button.

This example keeps the existing 60-day general and 10-day DNS settings, extends security records to 180 days, and enables summaries. It is an example, not a storage recommendation:

```json
{
  "enabled": true,
  "security_days": 180,
  "type_days": {},
  "summaries_enabled": true,
  "summary_retention_days": 365
}
```

Cleanup selects at most `batch_size` rows per transaction, defaults to 1000, and accepts 1–5000. `max_batches` defaults to 1000 and caps work in one policy cleanup run. Reaching that cap reports partial completion; remaining expired rows are eligible next run. The original upstream engine remains in use while the policy is disabled.

## Daily summaries

Summaries are optional and disabled by default. They count events deleted by retention cleanup, grouped by UTC event day, log type, action, ingestion source, and event source. `summary_group_by_rule: true` adds the rule name. The stored grouping flag distinguishes grouped and ungrouped records if that setting changes.

Summary upserts and raw-row deletion commit in the same database transaction. A rollback rolls back both. Re-running cleanup cannot recount deleted rows. Summaries cover expired events processed after this feature was enabled; they are not a count of the current raw table and do not reconstruct previously deleted history. The source fallback for older rows without a stored source is `syslog`.

`summary_retention_days` defaults to 365 days measured from the event day. Expired summary rows are removed in bounded batches while summaries are enabled. Choose a summary period longer than raw retention to preserve useful history after raw deletion.

`GET /api/retention/summaries?start=2026-01-01&end=2026-01-31` requires logs read permission. Dates are inclusive UTC days, with a maximum 366-day window. Optional filters are `log_type`, `source`, and `event_source`. `limit` defaults to 500 and is capped at 5000. A `truncated` response means the caller should narrow the date window or filters. These summaries are separate from the existing live dashboards.

## Private gzip archives

Archives are optional and disabled by default. Provision a persistent directory outside the repository and mount it into the application, for example at `/data/archives`. Set ownership to the application's runtime user and permissions to `0700`. The directory must already exist; the application does not create a mount or choose a host destination. The path and its parents must not be symlinks. Archive files use `0600` permissions and contain the full database row, including raw logs and addresses.

To enable archives, send the complete desired policy, including:

```json
{
  "enabled": true,
  "archives_enabled": true,
  "archive_directory": "/data/archives",
  "archive_max_bytes": 21474836480,
  "archive_max_files": 100000,
  "archive_min_free_bytes": 1073741824
}
```

Each batch is written as gzip JSON Lines. The filename contains a SHA-256 hash of the uncompressed canonical JSONL content. The file and directory are synced before any rows are deleted. Archive failure, checksum mismatch, quota exhaustion, or insufficient free space stops cleanup before deleting the affected batch. Previously committed batches remain committed and appear in the progress totals.

The default budget is 20 GiB, 100,000 files, and 1 GiB of free space reserved. These values are limits, not preallocated space. All regular files in the archive directory consume its budget, including temporary files left by a process crash. Store nothing else there. The application never automatically deletes published archives. When a limit is reached, move verified files to other private storage or explicitly adjust the limits before resuming cleanup.

Identical batch retries reuse an existing file after verifying its content hash. A file can survive a database rollback; it remains valid and still counts toward disk usage. If the selected batch or enrichment fields change before retry, another valid file can contain overlapping event IDs. Consumers combining archives should deduplicate by event `id` within the same database lineage. Database summaries remain exactly once because their update and the deletion share a transaction. Restoring an unrelated database into the same archive destination requires a separate directory to keep event-ID lineages distinct.

This is export-before-deletion, not a backup of application settings or the entire database. Restoring JSONL to PostgreSQL is an operator task; no automatic import or archive deletion endpoint is provided.
