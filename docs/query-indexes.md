# Query and index coverage

Indexes should follow query predicates and measured plans. A filter being available does not mean an index can make every use of it cheap. In particular, excluding a common host or counting every matching event can still require reading most of a time window.

## Current coverage

| Query fields | Available access paths | Limits |
| --- | --- | --- |
| Timestamp, log type, action | Timestamp index; type/time and action/time composite indexes; non-DNS timestamp partial index | Broad windows and exact counts still read many entries. Timestamp cursors avoid progressively larger offsets. |
| Source/destination IP | Native INET equality with source/destination B-tree indexes; destination firewall CIDR queries also have SP-GiST support | Source CIDR queries and negative conditions may favor a time or covering-index scan. Partial address text searches do not use INET equality. |
| Source/destination port | Partial B-tree indexes on each non-null port; validated equality, lists and ranges | Either-endpoint searches combine conditions. Broad ranges and exclusions can have low selectivity. |
| Flow endpoints, ports, protocol | Partial covering flow index led by timestamp | Aggregation must inspect the selected events before applying the top-N limit. |
| Ingress/egress interface, action | Partial zone-matrix covering index led by timestamp | It covers the aggregation, rather than providing a separate leading-key lookup for every interface. |
| Protocol, direction, service | Existing scalar indexes, plus time/flow access paths | Case-insensitive predicates using `LOWER` do not directly match the plain scalar indexes. A bounded time scan can be cheaper than maintaining more indexes for these low-cardinality fields. |
| Threat score | Partial B-tree index on non-null scores | Relevance depends on the selected range and time window. |
| Parsed IPS and unparsed CEF | Matching partial timestamp/ID indexes using the same classification predicates as searches | Builds run concurrently after intake starts. Missing or invalid indexes affect speed, not classification. Check maintenance completion. |
| Country, event source, collector source, IPS signature/risk/severity | Time-bounded scans; security candidate indexes when the query also selects that classification | No separate index for each sparse or low-cardinality attribute. Select the security class and a bounded time range first. |
| Rule name, rule description, gateway, recorded device name, ASN text, raw message | Time-bounded scans; inventory tables have their own address/name indexes | Literal substring and arbitrary text predicates have no general text index on the event table. Inventory indexes do not accelerate historical event-label searches. |

Use exact IP/CIDR conditions for host investigations. Recorded device names may be missing or stale, and a text search is not equivalent to resolving a current device name to all its addresses. Source/destination IP exclusions use the same validated predicates in Flow View, Log Stream and exports.

The diagnostic script reports index definitions, validity, sizes, usage and selected column statistics without exposing event payloads. Before adding a large text or composite index, measure representative plans, insert throughput, memory and index size on a disposable copy. No production database is rewritten by the validation described below.

## Release 3.7.2-gzeon.5 measurements

Tests used PostgreSQL 16 and synthetic data. Figures are warm-cache medians on one development machine, not production latency or capacity guarantees. Results were checked for equivalence.

| Security query, 3 million rows | Before | After |
| --- | ---: | ---: |
| Parsed IPS candidates | 419 ms | 0.083 ms |
| Legacy CEF candidates | 1,426 ms | 0.029 ms |
| Security summary | 604 ms | 167 ms |

Each new candidate index was 16 KB on this deliberately sparse fixture. Real size depends on the number of security candidates. The important changes were matching partial predicates, removing a planner-hostile boolean wrapper, and separating candidate counts from ordinary traffic scans.

A separate two-million-row Flow fixture covered roughly 23 days. Its measured 24-hour queries inspected approximately 86,400 events, **not the entire two-million-row table**. Existing indexes served exact-host and port queries in under 1 ms and an exclude-host graph in about 12 ms. Replacing string concatenation with normalized INET tuples reduced zone pair counting from 136 ms to 89 ms while preserving IPv4, IPv6, mask and NULL semantics.

An experimental case-insensitive protocol index improved one query from about 12 ms to 4 ms, but added approximately 14 MB to that fixture. It was not included: the modest absolute gain did not justify another index's write/storage cost without a demonstrated production bottleneck. No general-purpose raw-message trigram index or extra index for every filter was added.

Flow requests are serialized per panel, reuse matching results for at most 30 seconds, and do not start while the page is hidden. Manual Refresh bypasses that cache. These controls reduce repeated work independently of database indexes. A long retention period still requires bounded filters and measured resource limits.
