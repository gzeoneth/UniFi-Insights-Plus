# UniFi Log Insight Wiki

Welcome to the UniFi Log Insight wiki. These guides cover advanced topics beyond the main [README](https://github.com/jmasarweh/unifi-log-insight#readme).

## Prerequisites: gateway syslog on UniFi Network 10.x

> **UniFi Network 10.x: enable SIEM-mode activity logging.** Open **Settings > Integrations > Syslog** in the UniFi Network controller (on the default site: `https://<controller-hostname-or-ip>/network/default/integrations/syslog`; multi-site controllers use their own site id in place of `default`). Under **Activity Logging** choose **SIEM Server** and point it at the Insights Plus host, UDP port 514. Then select the log categories to forward. As of UniFi Network 10.6.106 they are **Client**, **Security Detections**, **VPN** and **Firewall Default Policy** (older 10.x builds may label them differently). Insights Plus needs **Firewall Default Policy** for firewall logs; the other categories are optional and forward those event types as well. If Insights Plus shows raw packet counts but nothing parses, disable SIEM, reboot the gateway, re-enable it, and re-check the categories.

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
