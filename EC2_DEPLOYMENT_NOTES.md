# EC2 deployment notes (18.206.209.106)

Living notes for the AWS deployment of AI Bot Defender on this instance.
Last verified: 2026-07-14.

## URLs

| What | URL | Reachable from |
|---|---|---|
| Honeypot site-001 | `http://site-001.18.206.209.106.sslip.io/` (and `https://`) | Any browser, **once the security group opens 80/443** |
| Honeypot via raw IP | `http://18.206.209.106/` | Same — the IP is a `server_aliases` entry, so raw-IP visitors/scanners reach the honeypot, not the catch-all |
| Dashboard app | `http://localhost:8000` | SSH tunnel only (deliberate — it's an admin panel; protected by the sign-in system, see `SIGNIN_README.md`) |
| Grafana | `http://localhost:3000` | SSH tunnel only (`admin` / `GRAFANA_ADMIN_PASSWORD` in `.env`) |
| Prometheus | `http://localhost:9090` | SSH tunnel only (`/alerts` shows the alert rules) |

SSH tunnel for the private surfaces:

```bash
ssh -i <key> -L 8000:localhost:8000 -L 3000:localhost:3000 -L 9090:localhost:9090 ubuntu@18.206.209.106
```

## Why sslip.io hostnames

`*.18.206.209.106.sslip.io` is public wildcard DNS: any name ending in the
instance's IP + `.sslip.io` resolves to that IP from every resolver on the
internet. This gives the honeypot a real hostname (required for name-based
virtual hosting to look like a normal website) without buying a domain.
Configured in `ansible/group_vars/all.yml` → `proxy.base_domain`, so every
future site deployed from the Site Configurator automatically gets
`<site-id>.18.206.209.106.sslip.io`.

The self-signed wildcard cert covers `*.18.206.209.106.sslip.io` plus the raw
IP as an IP SAN (`proxy/gen-cert.sh`, `EXTRA_SAN` env in
`docker-compose.proxy.yml`). Browsers show the usual one-time self-signed
warning; crawlers and `curl -k` don't care.

## Still blocked on the manager (AWS console access)

1. **Security group** (`launch-wizard-1`): allow inbound TCP **80** and **443**
   from `0.0.0.0/0` (and `::/0`). Keep 22 restricted. Do **not** open anything
   else — every other service is bound to 127.0.0.1.
2. **Elastic IP**: allocate one and associate it with this instance so the
   address survives stop/start.

Until #1 is done, nothing on 80/443 is reachable from outside — the containers
listen on `0.0.0.0:80/443` and were verified working locally, so the security
group is the only blocker.

## If the public IP ever changes (before the Elastic IP exists)

One command syncs everything (Ansible vars, `.env`/certgen, the TLS cert,
every rendered nginx block) and verifies the result:

```bash
make set-public-host                # auto-detects the EC2 public IP
make set-public-host HOST=3.85.1.2  # or pass it explicitly
```

Implemented by `scripts/set-public-host.sh`; it is idempotent and refuses to
finish silently if a site fails its post-change HTTP/HTTPS check. Tested both
ways (idempotent re-run and a full change to a test IP and back).

## Upgrading to a real domain later

Point the domain (or a wildcard record) at the Elastic IP, then:

```bash
make set-public-host HOST=your-domain.example
```

(it keeps the raw public IP as an alias/SAN automatically). Then swap the
self-signed cert for Let's Encrypt (mount real cert/key over `proxy/certs/`,
or run an ACME client; HTTP-01 works once port 80 is open). Everything else —
routing, logging, canaries — is hostname-agnostic.

## Monitoring stack (docker-compose.monitoring.yml + monitoring/)

Prometheus (30d retention) + node-exporter + cAdvisor + Loki (31d retention)
+ Promtail + Grafana, all loopback-bound. Grafana has provisioned Prometheus +
Loki datasources and the "AI Bot Defender — Instance Overview" dashboard
(host CPU/mem/disk, per-container CPU/mem, honeypot request rate, live access
log).

- **Alert rules** live in `monitoring/alerts.yml` (host disk/memory/CPU,
  scrape-target down, and container-gone alerts for proxy-nginx, logdb,
  collector, site-001-web, and the app). No Alertmanager yet — firing alerts
  are visible at Prometheus `/alerts` and in Grafana → Alerting. Add an
  alertmanager service when there's a notification channel to send to.
- **cAdvisor is pinned to `ghcr.io/google/cadvisor:v0.60.5`** — do not roll it
  back: v0.49–v0.52 cannot talk to this box's Docker 29 daemon (old API client
  / classic-layerdb assumption vs. the containerd image store) and every
  per-container metric silently loses its `name` label, blanking the
  per-container panels and container alerts. Distribution moved to ghcr.io.
- **nginx access logs rotate** via the `logrotate` sidecar in the proxy stack
  (`proxy/logrotate.conf`: daily or 100MB, 14 kept, copytruncate — safe for
  Promtail, never touches the stock `access.log`/`error.log` symlinks, and
  rotated names don't match Promtail's glob so nothing double-ingests).

## Hardening applied on 2026-07-13/14 (also fix-worthy upstream)

- **Site DB ports are loopback-only.** The Ansible template
  (`docker-compose.yml.j2`) previously rendered `"<port>:5432"`, exposing each
  site's Postgres (user/password `password`) on `0.0.0.0`. Now
  `127.0.0.1:<port>:5432`.
- **`restart: unless-stopped` everywhere** (proxy nginx/collectors/logdb, app,
  site web/db via the template, monitoring already had it) — the whole
  deployment now survives an instance reboot. `certgen` stays one-shot on
  purpose; the cert persists on disk.
- **Site Configurator preserves per-site `proxy:` overrides**
  (`app/services/sites.py`) instead of dropping them on every UI redeploy.
- `configs/sites/site-001.yaml` no longer pins `server_name` to the raw IP;
  the canonical name comes from the global base_domain, the IP is an alias.

## Sync back to the git repo

This EC2 copy is **not** a git checkout. Files created/changed here that the
real repo should get: `docker-compose.monitoring.yml`, `monitoring/`,
`SIGNIN_README.md` + the sign-in code under `app/`, this file, and the fixes
listed above (`ansible/roles/configure/templates/docker-compose.yml.j2`,
`ansible/roles/configure/templates/site.conf.j2`, `ansible/group_vars/all.yml`,
`docker-compose.proxy.yml`, `docker-compose.app.yml`, `proxy/gen-cert.sh`,
`app/services/sites.py`), plus the cloud-readiness batch:
`scripts/set-public-host.sh`, `proxy/logrotate.conf`, the `set-public-host`
Makefile target, `.env.example` (PROXY_* + GRAFANA_ADMIN_PASSWORD docs),
`app/templates/sites.html` (public URLs in links), and
`ansible/roles/deploy/tasks/main.yml` (public URL in the deploy message).
Machine-local state (`configs/`, `proxy/conf.d/*.conf`, `proxy/certs/*`,
`.env`) stays out of git as usual.

## Verified working (2026-07-14)

Canary page renders with real tokens over HTTP + HTTPS under the sslip
hostname, the raw IP, and the `*.localhost` alias; same UA ⇒ identical canary
set on repeat visits, different UA ⇒ different set; bogus Host dropped (444)
on both schemes; visits land in `all_visits` tagged
`site-001.18.206.209.106.sslip.io` (older rows keep the raw-IP tag and show as
"historical" in the Request Log); fingerprint beacon path routed; all 6
Prometheus targets up; all 9 alert rules loaded and inactive; per-container
metrics named; nginx access log flows to Loki (verified with a live request);
Grafana panels return data for both datasources.

Cloud-readiness round (same date): `make set-public-host` tested three ways
(idempotent re-run, full change to a test IP, change back) with per-site
HTTP/HTTPS verification passing each time; log rotation forced and verified
(nginx keeps writing after copytruncate, Loki ingests post-rotation lines, no
double-ingest); **Docker daemon restart = reboot simulation**: all 16
containers self-recovered (incl. the netns-dependent tls-capture), honeypot +
stable canaries + catch-all + fp beacon (204) + `all_visits` writes + app +
all Prometheus targets confirmed healthy afterwards; Docker service is
boot-enabled and the 8GB swapfile is in `/etc/fstab`; the offline regression
suite passes 125/0/3-skipped (`testsuite/reports/latest.html`). External DNS
for the sslip hostname confirmed resolving from outside AWS; end-to-end
public access still pends only the security-group change.
