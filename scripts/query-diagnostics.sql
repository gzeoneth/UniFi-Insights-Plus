-- Run with psql against the intended database. This reads catalog statistics;
-- it does not scan logs, change settings, create indexes or print query text.
\set ON_ERROR_STOP on
BEGIN READ ONLY;
SET LOCAL statement_timeout = '5s';
SET LOCAL lock_timeout = '1s';

SELECT name, setting, unit, source
FROM pg_settings
WHERE name IN ('shared_buffers', 'work_mem', 'maintenance_work_mem',
               'effective_cache_size', 'max_connections', 'synchronous_commit',
               'statement_timeout', 'autovacuum')
ORDER BY name;

SELECT c.reltuples::bigint AS estimated_rows,
       pg_size_pretty(pg_relation_size(c.oid)) AS table_size,
       pg_size_pretty(pg_indexes_size(c.oid)) AS index_size,
       pg_size_pretty(pg_total_relation_size(c.oid)) AS total_size,
       s.n_live_tup, s.n_dead_tup, s.last_analyze, s.last_autoanalyze,
       s.last_vacuum, s.last_autovacuum
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
WHERE c.relname = 'logs' AND n.nspname = 'public';

SELECT ci.relname AS index_name, i.indisvalid, i.indisready,
       pg_size_pretty(pg_relation_size(ci.oid)) AS index_size,
       pg_get_indexdef(ci.oid) AS index_definition,
       s.idx_scan, s.idx_tup_read, s.idx_tup_fetch
FROM pg_index i
JOIN pg_class ct ON ct.oid = i.indrelid
JOIN pg_namespace n ON n.oid = ct.relnamespace
JOIN pg_class ci ON ci.oid = i.indexrelid
LEFT JOIN pg_stat_user_indexes s ON s.indexrelid = ci.oid
WHERE ct.relname = 'logs' AND n.nspname = 'public'
ORDER BY ci.relname;

-- Distribution estimates help explain whether a narrow filter can use an
-- index effectively. Do not print most-common values or histogram payloads.
SELECT attname AS column_name, null_frac, n_distinct, avg_width
FROM pg_stats
WHERE schemaname = 'public' AND tablename = 'logs'
ORDER BY attname;

SELECT state, wait_event_type, wait_event, COUNT(*) AS connections
FROM pg_stat_activity
WHERE datname = current_database() AND pid <> pg_backend_pid()
GROUP BY state, wait_event_type, wait_event
ORDER BY connections DESC;
COMMIT;
