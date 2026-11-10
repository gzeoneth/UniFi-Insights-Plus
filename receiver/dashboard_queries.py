"""Exact dashboard summaries with one scoped event scan per response tier."""


def dashboard_relation(source):
    """Only fixed application relations may enter generated dashboard SQL."""
    if source not in ('logs', 'dashboard_events'):
        raise ValueError('unsupported dashboard source')
    return source


def overview_query(cutoff, scope=None, *, source='logs'):
    """Group visibility and dimensions together, including hidden-row totals.

    The optional scope is a trusted, compiled exclusion predicate and parameters.
    Hidden groups contribute only to visibility totals, never visible metrics.
    """
    visible = 'TRUE'
    params = []
    if scope is not None:
        visible, params = scope
    return f"""
        SELECT CASE WHEN ({visible}) THEN TRUE ELSE FALSE END AS visible,
               log_type, direction, COUNT(*) AS total,
               COUNT(*) FILTER (WHERE log_type = 'firewall' AND rule_action = 'allow') AS allowed,
               COUNT(*) FILTER (WHERE rule_action = 'block') AS blocked,
               COUNT(*) FILTER (WHERE threat_score > 50) AS threats
        FROM {dashboard_relation(source)} WHERE timestamp >= %s
        GROUP BY visible, log_type, direction
    """, [*params, cutoff]


def overview_result(rows):
    summary = {'total': 0, 'allowed': 0, 'blocked': 0, 'threats': 0}
    by_type, by_direction = {}, {}
    all_rows = 0
    for row in rows:
        count = row['total']
        all_rows += count
        if not row['visible']:
            continue
        for key in summary:
            summary[key] += row[key]
        kind, direction = row['log_type'], row['direction']
        by_type[kind] = by_type.get(kind, 0) + count
        if direction is not None:
            by_direction[direction] = by_direction.get(direction, 0) + count
    return {
        **summary,
        'by_type': dict(sorted(by_type.items(), key=lambda item: -item[1])),
        'by_direction': dict(sorted(by_direction.items(), key=lambda item: -item[1])),
        'view_counts': {'total': all_rows, 'visible': summary['total'],
                        'hidden': all_rows - summary['total']},
    }


def series_query(bucket, scope, *, source='logs'):
    if bucket not in ('hour', 'day', 'week', 'month'):
        raise ValueError('unsupported dashboard bucket')
    where, params = scope
    return f"""
        SELECT date_trunc('{bucket}', timestamp) AS period, COUNT(*) AS total,
               COUNT(*) FILTER (WHERE log_type = 'firewall' AND rule_action IS NOT NULL) AS action_events,
               COUNT(*) FILTER (WHERE log_type = 'firewall' AND rule_action = 'allow') AS allow,
               COUNT(*) FILTER (WHERE log_type = 'firewall' AND rule_action = 'block') AS block,
               COUNT(*) FILTER (WHERE log_type = 'firewall' AND rule_action = 'redirect') AS redirect
        FROM {dashboard_relation(source)} WHERE {where}
        GROUP BY period ORDER BY period
    """, params


def series_result(rows):
    totals, actions = [], []
    for row in rows:
        period = row['period'].isoformat()
        totals.append({'period': period, 'count': row['total']})
        # Unknown non-NULL actions used to produce a zero-valued period.
        # NULL actions and non-firewall events alone did not produce one.
        if row['action_events']:
            actions.append({'period': period, **{k: row[k] for k in ('allow', 'block', 'redirect')}})
    return totals, actions


def zone_query(where):
    """Count repeated endpoint pairs before the small per-zone aggregation.

    Normalization matches the previous DISTINCT row expression, including INET
    mask handling. NULL endpoints remain in totals but not unique-pair counts.
    """
    return f"""
        SELECT interface_in, interface_out, SUM(total)::bigint AS total,
               SUM(allow_count)::bigint AS allow_count,
               SUM(block_count)::bigint AS block_count,
               COUNT(*) FILTER (WHERE src_host IS NOT NULL AND dst_host IS NOT NULL) AS unique_pairs
        FROM (
            SELECT interface_in, interface_out,
                   set_masklen(src_ip, -1) AS src_host,
                   set_masklen(dst_ip, -1) AS dst_host,
                   COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE rule_action = 'allow') AS allow_count,
                   COUNT(*) FILTER (WHERE rule_action = 'block') AS block_count
            FROM logs WHERE {where}
                AND interface_in IS NOT NULL AND interface_out IS NOT NULL
            GROUP BY interface_in, interface_out,
                     set_masklen(src_ip, -1), set_masklen(dst_ip, -1)
        ) pairs
        GROUP BY interface_in, interface_out ORDER BY total DESC
    """
