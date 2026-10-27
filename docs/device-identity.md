# Device names on routed traffic

A firewall packet's source MAC can belong to the router that forwarded it. It does not prove that the packet's source IP belongs to that router.

During ingestion, a supplied IP is resolved through the UniFi IP-to-name cache. If that IP is unknown, the event stays unnamed. MAC lookup is used only when no IP was supplied. The existing client-name feature toggle still applies.

Log lists, detailed logs, and CSV exports resolve source names through current UniFi client/device records for the actual source IP. Each lookup selects one record, so reused IPs do not multiply log rows. Destination lookup remains by destination IP.

Old stored source names are retained as a fallback unless the controller gives evidence of a MAC attribution error: the logged MAC belongs to a known record with a different, non-null IP, and the stored name matches that record's name, hostname, vendor, or model. Such a name is suppressed in the response. A current name for the correct source IP takes precedence. Gateway/WAN annotations can still label a gateway's actual configured address.

This change does not rewrite historical rows. Names that cannot be checked against a controller record remain unchanged. The original stored value remains available in raw database backups and retention archives.

The top-threat-IP query now groups by `remote_ip` and joins its reputation categories using that same address. For outbound traffic, this assigns the score to the remote destination. Rows without a known `remote_ip` are omitted from that table; they are not guessed to belong to the local source.

## Verification

The unit tests cover IP precedence, unknown routed IPs, MAC-only lookup, source-name query behavior, and CSV limits. The optional PostgreSQL tests check persisted-name suppression and outbound reputation attribution against real rows. They also verify archive rollback/retry and exactly-once summary counts.

Run the integration file with an explicit `UNIFI_TEST_DB_DSN` pointing to a disposable local PostgreSQL database whose name ends in `_tests`:

```sh
PYTHONPATH=receiver python -m pytest receiver/tests/test_retention_identity_postgres.py -q
```

The test role needs permission to create databases. Each run creates a randomly named test database, applies the application schema there, and drops it on completion. Without the explicit DSN, these tests skip. They do not use application database environment variables.
