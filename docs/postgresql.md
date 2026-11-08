# Embedded PostgreSQL buffering

The optional `balanced` profile gives PostgreSQL more cache and more time to spread checkpoint writes. It works with existing embedded databases as well as new installations. It is disabled by default and does not move the database, change indexes, delete records or change retention.

Enable it only after checking that the host has spare memory and disk space. The application, SQLite spool, PostgreSQL sessions and filesystem cache all share those resources. A 2–4 GiB container budget is a starting point for measurement, not a guarantee that a particular workload fits. Larger caches cannot fix a failing device, sustained storage overload or a blocking transaction.

```yaml
environment:
  EMBEDDED_PG_PROFILE: balanced
```

Before recreating an existing container, verify that **both the PostgreSQL data and ingestion spool are persistent**. The default spool path is `/var/lib/unifi-log-insight/ingest/retry.sqlite3`; `compose.gzeon.yml` mounts that directory. A database volume alone does not preserve pending spool records. Back up the database and preserve any pending spool before a storage or container change. A live copy of a SQLite database without its WAL can be inconsistent; use a stopped-service copy or SQLite's backup facilities. Do not mount an empty directory over a pending spool and assume it migrated.

Restart or recreate the container in a maintenance window after updating its environment. The helper runs before the supervised PostgreSQL server starts; a new cluster's temporary initialization server runs first. Reloading the application or PostgreSQL alone does not apply the environment, and some settings require a PostgreSQL restart.

## Profile settings

Each override is optional. Memory overrides are integer **MiB** values, rendered as PostgreSQL `MB` units; timeout is an integer number of seconds. Empty overrides use the profile default. Invalid, misspelled or out-of-range settings stop startup before a new cluster is initialized. Overrides require `EMBEDDED_PG_PROFILE=balanced`.

The accepted ranges guard configuration input; they do not measure available memory or make every combination safe for every container limit. For example, a 2 GiB shared-buffer override needs substantially more than a 2 GiB total container budget.

| Environment variable | Default | Accepted range |
| --- | ---: | --- |
| `EMBEDDED_PG_SHARED_BUFFERS_MB` | 512 | 128–2048 |
| `EMBEDDED_PG_EFFECTIVE_CACHE_SIZE_MB` | 2048 | 256–8192; at least shared buffers |
| `EMBEDDED_PG_WORK_MEM_MB` | 8 | 1–16 |
| `EMBEDDED_PG_MAINTENANCE_WORK_MEM_MB` | 64 | 16–256 |
| `EMBEDDED_PG_WAL_BUFFERS_MB` | 16 | 1–64 |
| `EMBEDDED_PG_MAX_WAL_SIZE_MB` | 2048 | 512–8192 |
| `EMBEDDED_PG_CHECKPOINT_TIMEOUT_SECONDS` | 900 | 60–1800 |
| `EMBEDDED_PG_CHECKPOINT_COMPLETION_TARGET` | 0.9 | 0.5–0.95 |
| `EMBEDDED_PG_WAL_COMPRESSION` | `on` | `on` or `off` |

`shared_buffers` allocates PostgreSQL cache. `effective_cache_size` is a planner estimate of available database and filesystem cache; it allocates no memory. `work_mem` applies per sort/hash operation, and concurrent queries can use several multiples. Keep it modest rather than interpreting it as a total query-memory limit. These settings follow PostgreSQL's [memory guidance](https://www.postgresql.org/docs/16/runtime-config-resource.html) and [planner documentation](https://www.postgresql.org/docs/16/runtime-config-query.html).

The 15-minute checkpoint target and larger WAL allowance can reduce repeated checkpoint work and spread writes. `max_wal_size` is a **soft checkpoint threshold**, not a disk quota; WAL may grow beyond it. Longer intervals can increase crash-recovery time. WAL compression uses PostgreSQL 16's built-in `pglz` for full-page images, trading CPU for less WAL traffic; it does not compress every record or guarantee a particular saving. See PostgreSQL's [WAL and checkpoint settings](https://www.postgresql.org/docs/16/runtime-config-wal.html).

The profile keeps `fsync`, `full_page_writes` and `synchronous_commit` **on**. There is no environment override to weaken these safeguards. Raw-log insertion also explicitly commits synchronously before acknowledging spool rows. This change does not alter database checksums, archiving, replication, autovacuum or the insert path's durability policy.

## Existing configuration and rollback

The helper writes one app-owned file, `unifi-insights-managed.conf`, inside the PostgreSQL data directory and appends one `include_if_exists` directive to `postgresql.conf`. Existing directives and comments remain intact. Repeated starts do not append duplicate directives or rewrite unchanged files. The helper refuses to overwrite an unrelated file with the same name.

The include takes precedence over earlier `postgresql.conf` values while enabled. `postgresql.auto.conf` and later includes retain PostgreSQL's normal precedence. The helper asks PostgreSQL to parse the effective settings without starting a server; if a selected setting is overridden, startup fails with its name. It does not overwrite `ALTER SYSTEM` settings. Resolve the conflict through the operator's existing configuration procedure, use a matching supported override, or disable the profile. Failed validation restores the prior configuration files. See PostgreSQL's [configuration precedence](https://www.postgresql.org/docs/16/config-setting.html).

To roll back, remove the optional overrides, set `EMBEDDED_PG_PROFILE=off` (or remove it), and restart the container. Startup removes only the app-owned include file. The harmless optional include remains, and the previous PostgreSQL settings take effect again. Database and spool contents are unchanged. If rolling back to an image older than this helper, first start the current image with the profile off; an older image does not know to remove the managed file.

With an external `DB_HOST`, the helper is skipped entirely. Configure the external PostgreSQL server through its own administration system. The embedded profile does not connect to it or change its files.

## Verify the result

Use an existing local administrator session to inspect effective values after startup:

```sql
SELECT name, setting, unit, source, pending_restart
FROM pg_settings
WHERE name IN (
  'shared_buffers', 'effective_cache_size', 'work_mem', 'maintenance_work_mem',
  'wal_buffers', 'max_wal_size', 'checkpoint_timeout',
  'checkpoint_completion_target', 'wal_compression',
  'fsync', 'full_page_writes', 'synchronous_commit'
)
ORDER BY name;
```

Compare received/inserted event rates, oldest spool age, database insert latency, host I/O wait, disk latency and checkpoint statistics under similar traffic. Check memory pressure as well as process memory. A successful restart establishes that the profile loaded; an emptying backlog and improved latency establish whether it helped.

Synthetic validation covers environment bounds, external-database bypass, repeat startup, rollback, rejected configuration and preserved data in a disposable PostgreSQL 16 cluster. It is not a production throughput claim.
