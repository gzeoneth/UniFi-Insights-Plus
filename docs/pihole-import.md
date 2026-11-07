# Pi-hole query import

Insights imports queries from the configured Pi-hole v6 API. Importing does not change client DNS routing or capture queries that bypass that resolver.

The receiver process owns the polling worker. Saving settings in the web API signals that receiver; it does not start a second collector. Reload cancels the old worker before a replacement can poll. Fetched events are committed in ascending query-ID batches, and the cursor advances only with committed events.

New imports receive a deterministic event identity based on the persisted source identity and original query fields. The existing ingest-ID uniqueness index prevents replayed or concurrently fetched events from being inserted twice. Changing an API hostname to its IP preserves that source identity. A transaction also prevents an older worker from moving the saved cursor backward or committing events for a replaced source generation.

Existing duplicate rows are retained. Upgrading does not scan or delete historical events, and old rows without import identities are not retrospectively deduplicated. A Pi-hole database reset can reuse query IDs; do not assume a bounded query response proves a reset. The collector retains its existing ID-cursor behavior until the integration is deliberately reset.

## DNS enrichment

Selecting **None** imports queries without issuing extra DNS lookups or calling GeoIP/threat enrichment. Original answer IPs supplied by the API can still be retained.

With GeoIP or threat enrichment enabled, Insights can resolve current destination IPs when the API does not supply an answer. These results support enrichment; they do not prove what the original client received. `dns_answer` holds only an original API-provided answer. Current lookup results can populate destination/enrichment fields while the original API record remains in `raw_log`.

Resolver endpoint lookups have a separate bounded cache, so a batch of different queried domains does not resolve the Pi-hole API hostname once per domain. Numeric endpoints require no hostname lookup. Current domain results remain cached, and active DNS work per poll is bounded so importing events can continue when DNS is slow or unavailable. Missing enrichment remains unknown.

If the Pi-hole web URL uses a reverse proxy, set **DNS server for enrichment** to the resolver's numeric IPv4 or IPv6 address. The HTTP proxy may not serve DNS. An empty value uses the web URL's hostname. The optional `PIHOLE_DNS_SERVER` environment variable overrides the saved address, following the integration's existing environment precedence.

API connection tests check web authentication. They do not prove that the separate DNS endpoint is reachable or that every original query answer is available.
