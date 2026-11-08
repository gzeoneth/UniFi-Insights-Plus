# DNS query logging

The DNS view displays parsed query records supplied by a resolver. Firewall records for TCP or UDP port 53 remain firewall records: they identify endpoints and ports but usually contain no queried domain or DNS answer.

Enabling a gateway's DNS **flow** logging does not establish that it exports resolver query logs over syslog. Confirm a fresh query end to end before treating an empty DNS view as an application parsing problem.

## Check the source

1. Check collection health, the time window and active view exclusions. Clear unrelated filters.
2. Make a uniquely named test query through the intended resolver, such as `dns-check-<unique-id>.example.test`. Record the time, client address and whether the resolver replied. An NXDOMAIN reply still proves the query received a DNS response.
3. Search **all log types** for the exact name. Also check for raw `dnsmasq` and `query[` messages. A matching firewall port-53 event alone does not contain enough information to reconstruct the name.
4. If the name appears in raw data but not the DNS view, retain a sanitized sample and investigate parsing. If no raw query reaches the collector, inspect resolver query logging and its export path first.

For dnsmasq, query logging and log destination are separate settings (`log-queries` and `log-facility`). Process arguments and included configuration files determine the effective behavior. Inspect them before changing anything. Gateway-generated configuration may be rewritten during provisioning or upgrades; this project does not enable query logging or edit managed gateway files automatically.

## Supported inputs

- Exported dnsmasq query, reply, forwarded and cached syslog messages are parsed as DNS records. A synthetic example is `dnsmasq[123]: query[A] check.example.test from 192.0.2.10`.
- The existing Pi-hole v6 integration can import queries from a configured Pi-hole instance. It observes queries that reach that resolver; installing or connecting Pi-hole does not capture traffic that bypasses it.

Changing a site's resolver can affect split DNS, domain-based routing and device discovery. Verify those dependencies before migrating DNS solely for logging. Encrypted DNS and queries sent to other resolvers are not made visible by enabling gateway syslog.

Query logs expose browsing-related domain names and can add substantial volume. Choose retention and access controls for those records separately from general firewall history.

References: [dnsmasq manual](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html), [UniFi system logs and SIEM integration](https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration).
