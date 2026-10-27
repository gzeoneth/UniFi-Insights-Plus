# View exclusions

Use an exclusion profile to hide routine events while continuing to collect and retain them. This changes the app's query results; it does not suppress a gateway signature, alter firewall policy, delete rows or change retention.

## Create a profile

1. Open **View exclusions → New profile**, or choose **Hide matching allow events** on a Log Stream or Rule Usage row that has a recorded rule and gateway hostname.
2. Review the conditions. Every condition in a group must match. An event is hidden if any group matches.
3. Select **Preview matches** to see visible/hidden totals and up to five examples. The preview states its time window and whether it inherits the source view's filters. It predicts only that window, not future traffic.
4. Apply the previewed profile for this session, or name it and select **Save as new profile and apply**. Editing conditions invalidates the preview.
5. Optionally choose **Make default in this browser**. Only the saved profile ID is stored in the browser. Other browsers do not inherit this preference.

**Show all (ignore profile)** bypasses the active profile while preserving your other search and time filters. Delete a saved profile to remove it from the saved list, or clear the browser default to stop automatic loading. If a stored default is missing or cannot load, the app shows all events and reports the problem.

## Scope and safety

Log Stream, Rule Usage, Dashboard traffic statistics, Flow View, host details and their exports use the selected profile. Filtering happens before pagination and aggregation. Visible/hidden counts describe the matching events before pagination, including records outside the displayed page. Rule Usage counts log entries, not unique connections or packets.

Security summaries and the threat map remain independent. Profiles cannot hide parsed IPS records, signature-bearing records or raw CEF threat candidates awaiting backfill. Security warns about those unparsed candidates separately; it does not invent an allowed/blocked action for them. Run the [CEF backfill preview](../LOCAL-FORK.md#cef-backfill) before applying a historical repair.

Ordinary include/exclude search conditions remain separate and can deliberately narrow results, including security records. Show all bypasses only the profile. An unrelated search or log-type filter may still keep a record out of Log Stream.

The rule-row shortcut creates a draft matching the exact recorded rule, gateway hostname and `allow` action, plus a recorded description when available. It requires a preview and does not create an exclusion for unknown rules. Policy indexes can be reused; this is a match on the recorded labels, not a permanent controller policy UUID. Recheck a profile after firewall edits, gateway renames or rule reordering.

Profiles are stored through the existing saved-views API and follow its access controls. They are not a mandatory organization-wide policy. Exported app configuration can contain saved profiles and their network-specific values; treat deployment exports as private.

## Built-in Log Stream views

The view selector includes built-in queries alongside your saved views. They replace conflicting search filters, use the last 24 hours and return to page one. Page size and sort order are preserved. Nothing is installed as a browser default automatically.

- All events, Firewall blocks, Inter-VLAN traffic and Blocked inter-VLAN.
- Blocked private traffic: recorded blocks with RFC1918 or IPv6 ULA addresses at both ends, including gateway-local traffic. This does not cover every possible internal address range.
- IPS detections and Unparsed CEF candidates, independent of log type.
- DNS and Firewall action missing, for visibility checks.
- A/V discovery: UDP with source **or** destination port 5353 or 1900, so replies to high ports are included.
- NAT-PMP/PCP attempts: UDP destination port 5351.
- High destination ports: 49152–65535, including return traffic.

All events, IPS and Unparsed CEF bypass the selected profile without deleting it. Other presets preserve the current profile state. The visible scope note states which query is active; changing a search filter clears the preset label. Port labels are hints, not proof of the application or a reason to allow a blocked connection. Same-subnet traffic and events the gateway did not emit may be absent.

New firewall events retain the syslog emitter in `hostname`, allowing the row shortcut to scope a rule to its reported gateway. This is not authenticated device identity. DHCP hostname remains the lease client's name. Historical firewall rows with no emitter remain unchanged; use reviewed manual conditions or collect fresh events rather than assuming a gateway.

## API

The `exclude_groups` query parameter contains a JSON array. For example:

```json
[
  {
    "name": "Example routine allows",
    "conditions": [
      {"field": "rule_name_exact", "operator": "include", "value": "EXAMPLE-A-100"},
      {"field": "hostname_exact", "operator": "include", "value": "example-gateway"},
      {"field": "rule_action", "operator": "include", "value": "allow"}
    ]
  }
]
```

The exact fields `rule_name_exact`, `rule_desc_exact` and `hostname_exact` match whole strings, are case-sensitive, and treat commas literally. The `port` field matches either source or destination port. `security_event` accepts `ips` and `unparsed_cef`, with comma-separated OR. Existing substring, categorical, address/CIDR, range, presence and absence filters keep their normal semantics. Missing values do not match an include condition. An exclude condition is its complement and therefore includes missing values; use presence conditions when that matters.

Limits: 12 groups, eight conditions per group, 48 conditions total and a 16,384-character serialized payload. Group names allow 100 characters and values allow 1,024. Invalid filters return HTTP 400 instead of broadening the query.

`GET /api/logs/exclusion-preview` accepts the source-view filters and returns `view_counts` (`total`, `visible`, `hidden`) plus at most five hidden examples without raw payloads. Logs, Rule Usage and Dashboard overview also return counts. Save a profile as a saved view with `filters.view_type` set to `exclusions` and the group array in `filters.exclude_groups`.

Log, aggregate, CSV, flow and IP-pair endpoints accept the same profile parameter. Dashboard stats accept `exclude_groups`; their fixed dashboard queries do not accept arbitrary `filter_rules`. Supported MCP log/stat tools expose the same optional parameter. Existing clients that omit it continue to see unfiltered results.

Broad profiles can add query work, particularly when inspecting raw historical CEF candidates. Begin with a bounded time range and narrow exact conditions, then measure on the deployed database before increasing searchable retention.
