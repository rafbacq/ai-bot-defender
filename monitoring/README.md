# `monitoring/` — self-hosted observability stack

Configuration for `docker-compose.monitoring.yml` (`make monitoring`):
Prometheus, node-exporter, cAdvisor, Loki, Promtail, Alertmanager, and Grafana.
All published ports are loopback-bound; the app's **Admin panel → Monitoring**
page is the intended way to view it (it renders the panels natively and gates
`/grafana/` behind the admin session).

| File | Role |
|---|---|
| `prometheus.yml` | Scrape config (node-exporter, cAdvisor, collectors, blackbox probes). |
| `alerts.yml` | Static alert rules (host disk/memory/CPU, targets down, containers gone, collector insert failures). |
| `alerts.d/`, `targets.d/` | **Rendered per-site** alert rules and blackbox targets (written by the playbook, withdrawn on site take-down — do not edit by hand). |
| `blackbox.yml` | Blackbox-exporter modules for the synthetic site health probes. |
| `alertmanager.yml` | Safe default: grouping + silences, no off-host delivery (point `ALERTMANAGER_CONFIG` in `.env` at a private file to add channels). |
| `loki-config.yml`, `promtail-config.yml` | Log store + shipper (nginx access logs, container logs). |
| `grafana/` | Provisioned datasources + the "AI Bot Defender — Instance Overview" dashboard. |

Operational gotchas (why some pins exist) are documented in
[docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md#monitoring) — notably: **cAdvisor is
pinned to `ghcr.io/google/cadvisor:v0.60.5` and must not be rolled back below
v0.56** — older releases can't talk to a Docker 29 daemon and silently blank
every per-container metric. The monitoring network (`monitoring_bridge`) never
connects to honeypot site stacks.
