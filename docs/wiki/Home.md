# UniFi Log Insight Wiki

Welcome to the UniFi Log Insight wiki. These guides cover advanced topics beyond the main [README](https://github.com/jmasarweh/unifi-log-insight#readme).

## Prerequisites: gateway syslog on UniFi Network 10.x

<!-- toggle names to be verified by the owner on a Network 10.x controller -->
> **UniFi Network 10.x: enable SIEM-mode activity logging.** The gateway only emits the firewall and system syslog that Insights Plus parses when **Activity Logging** is set to **SIEM Server** (pointed at the Docker host, UDP port 514) with **Devices: Gateway** and **System Log: Firewall Default Policy** enabled. These settings live under **Settings > Integrations > Syslog** (`https://<controller-hostname-or-ip>/network/default/integrations/syslog`). If Insights Plus shows raw packet counts but nothing parses, disable SIEM, reboot the gateway, re-enable it, and re-check those two toggles.

See the [README prerequisites](https://github.com/jmasarweh/UniFi-Insights-Plus#-prerequisites) for the full list.

## Guides

- [External PostgreSQL Migration Guide](External-PostgreSQL-Migration-Guide) — Migrate from the embedded database to an external PostgreSQL server, with Docker networking guidance and a step-by-step walkthrough of the in-app migration wizard.

## Quick Links

| | |
|---|---|
| [Quick Start](https://github.com/jmasarweh/unifi-log-insight#-quick-start) | Get up and running in minutes |
| [Configuration Reference](https://github.com/jmasarweh/unifi-log-insight#%EF%B8%8F-configuration-reference) | Environment variables and options |
| [Troubleshooting](https://github.com/jmasarweh/unifi-log-insight#-troubleshooting) | Common issues and fixes |
| [Releases](https://github.com/jmasarweh/unifi-log-insight/releases) | Changelog and downloads |
| [Report an Issue](https://github.com/jmasarweh/unifi-log-insight/issues) | Bug reports and feature requests |
