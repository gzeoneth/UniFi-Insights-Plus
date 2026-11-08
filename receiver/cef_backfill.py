"""Explicit, bounded reclassification of historical UniFi IPS CEF records.

Run from the receiver directory (or inside the receiver container)::

    python cef_backfill.py                         # read-only dry run
    python cef_backfill.py --apply --batch-size 500 --max-batches 20

Each committed batch prints a JSON progress record. Resume using its
``after_id`` and ``through_id`` values. The upper bound is captured once so
new ingestion cannot extend a run indefinitely. No network enrichment or
schema migration is performed. Apply the application schema migration first.
"""

import argparse
import json

from parsers import parse_cef_log


# A strict allowlist protects reputation, client identity, raw evidence and
# row IDs. CEF's explicit UTC event time may correct the stored timestamp;
# otherwise the existing historical timestamp remains unchanged.
BACKFILL_COLUMNS = (
    'log_type', 'source', 'event_source', 'event_id', 'event_name', 'ips_signature',
    'ips_signature_id', 'ips_severity', 'ips_risk', 'src_ip', 'src_port',
    'dst_ip', 'dst_port', 'protocol', 'service_name', 'rule_name', 'rule_desc',
    'rule_action', 'direction',
)
ELIGIBLE_SQL = "event_source IS NULL AND log_type IN ('system', 'unknown')"
SELECT_SQL = f"""
    SELECT id, CASE WHEN {ELIGIBLE_SQL} THEN raw_log ELSE NULL END AS raw_log
    FROM logs WHERE id > %s AND id <= %s
    ORDER BY id LIMIT %s
"""
UPDATE_SQL = f"""
    UPDATE logs SET {', '.join(column + ' = %s' for column in BACKFILL_COLUMNS)},
        timestamp = COALESCE(%s, timestamp)
    WHERE id = %s AND raw_log = %s AND {ELIGIBLE_SQL}
"""


def run_backfill(connection, *, apply=False, after_id=0, through_id=None,
                 batch_size=500, max_batches=20, progress=None) -> dict:
    """Scan at most batch_size * max_batches rows, committing by batch.

    A failed batch rolls back entirely and raises. The last emitted cursor
    always represents a completed batch. Repeating a committed range is safe:
    reclassified rows are excluded by event_source, and updates recheck the
    original type/source/raw condition in case another writer changed the row.
    The primary-key scan includes ineligible rows so finding sparse CEF
    records cannot cause an unbounded table scan inside a nominally small batch.
    """
    if not 1 <= batch_size <= 5000 or not 1 <= max_batches <= 10000:
        raise ValueError('batch_size must be 1..5000 and max_batches 1..10000')
    if after_id < 0 or (through_id is not None and through_id < after_id):
        raise ValueError('IDs must satisfy 0 <= after_id <= through_id')
    summary = {'apply': apply, 'scanned': 0, 'matched': 0, 'updated': 0,
               'batches': 0, 'after_id': after_id, 'through_id': through_id,
               'complete': False}
    try:
        if through_id is None:
            with connection.cursor() as cursor:
                cursor.execute('SELECT COALESCE(MAX(id), 0) FROM logs')
                through_id = max(after_id, cursor.fetchone()[0])
            summary['through_id'] = through_id
            connection.commit()
        for _ in range(max_batches):
            with connection.cursor() as cursor:
                cursor.execute(SELECT_SQL, (summary['after_id'], through_id, batch_size))
                rows = cursor.fetchall()
                if not rows:
                    summary['complete'] = True
                    connection.commit()
                    break
                matched = updated = 0
                for row_id, raw_log in rows:
                    if not raw_log or 'CEF:' not in raw_log:
                        continue
                    parsed = parse_cef_log(raw_log)
                    if parsed is None:
                        continue
                    matched += 1
                    if apply:
                        values = [parsed.get(column) for column in BACKFILL_COLUMNS]
                        cursor.execute(UPDATE_SQL, values + [parsed.get('timestamp'), row_id, raw_log])
                        updated += cursor.rowcount
            connection.commit()
            summary.update(
                scanned=summary['scanned'] + len(rows),
                matched=summary['matched'] + matched,
                updated=summary['updated'] + updated,
                batches=summary['batches'] + 1,
                after_id=rows[-1][0],
                complete=len(rows) < batch_size or rows[-1][0] >= through_id,
            )
            if progress:
                progress(dict(summary))
            if summary['complete']:
                break
    except Exception:
        connection.rollback()
        raise
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--apply', action='store_true', help='commit updates (default: dry run)')
    parser.add_argument('--after-id', type=int, default=0, help='resume after this committed cursor')
    parser.add_argument('--through-id', type=int, help='reuse the original run upper bound')
    parser.add_argument('--batch-size', type=int, default=500, help='rows scanned per batch, 1..5000')
    parser.add_argument('--max-batches', type=int, default=20, help='maximum batches in this invocation')
    args = parser.parse_args(argv)
    if not 1 <= args.batch_size <= 5000 or not 1 <= args.max_batches <= 10000:
        parser.error('batch-size must be 1..5000 and max-batches 1..10000')
    if args.after_id < 0 or (args.through_id is not None and args.through_id < args.after_id):
        parser.error('IDs must satisfy 0 <= after-id <= through-id')

    # Delay DB imports until CLI validation, and bypass Database.connect(),
    # which runs schema migrations even when the caller only wants a preview.
    import psycopg2
    from db import build_conn_params
    connection = psycopg2.connect(**build_conn_params())
    try:
        connection.set_session(readonly=not args.apply)
        result = run_backfill(connection, apply=args.apply, after_id=args.after_id,
                              through_id=args.through_id, batch_size=args.batch_size,
                              max_batches=args.max_batches,
                              progress=lambda value: print(json.dumps(value), flush=True))
        print(json.dumps(result), flush=True)
    finally:
        connection.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
