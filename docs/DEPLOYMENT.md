# Public deployment (AWS EC2)

The whole system runs on a single Linux VM with Docker. This guide covers
making that VM's honeypots reachable from the public internet — real hostnames,
trusted TLS, a hardened public control center, and monitoring. Everything below
was built and verified on an Ubuntu EC2 instance; nothing is EC2-specific
beyond the IP auto-detection in `make set-public-host`.

Concrete instance details (current IP, verification history) are operational
state, not source — they live in the operator's machine-local
`EC2_DEPLOYMENT_NOTES.md` at the repository root (git-ignored) and are handed
over with the instance itself.

## What a public deployment looks like

| Surface | URL shape | Exposure |
|---|---|---|
| Honeypot sites | `http(s)://<site-id>.<base-domain>/` | Public — the whole point. Both schemes serve the page (no redirect: bots that don't follow redirects must still get canaries). |
| Honeypot via raw IP | `http://<public-ip>/` | Public — the IP is a `server_aliases` entry so raw-IP scanners reach the honeypot, not the catch-all. |
| Control center (the app) | `https://admin.<base-domain>/` | Public but hardened (see below). HTTPS-only vhost. |
| Grafana (view-only) | `https://admin.<base-domain>/grafana/` | Public path, but every request is re-authorized against the app's signed admin session. |
| App / Grafana / Prometheus via SSH tunnel | `http://localhost:8000` / `:3000/grafana/` / `:9090` | Loopback-only; the tunnel is the private path and always works. |

Everything except nginx's :80/:443 binds to `127.0.0.1`. On AWS that means the
security group only needs inbound TCP 80 + 443 (plus restricted 22).

## Host prerequisites

- Docker Engine + compose plugin, boot-enabled (`systemctl enable docker`) so
  the deployment survives a reboot; every long-running service uses
  `restart: unless-stopped`.
- A static public IP (an Elastic IP on EC2) — otherwise every stop/start
  changes the address and you must re-run `make set-public-host`.
- Swap if the instance is small (the app image's ML stack is large; an 8 GB
  swapfile in `/etc/fstab` has been enough).
- Security group / firewall: inbound 80 + 443 open to the world, 22 restricted.

## Public hostnames without buying a domain (sslip.io)

`*.<public-ip>.sslip.io` is public wildcard DNS: any name ending in the
instance's IP + `.sslip.io` resolves to that IP from every resolver on the
internet. This gives each honeypot a real hostname — required for the
name-based virtual hosting to look like a normal website — with zero DNS setup.
The base domain is configured in `ansible/group_vars/all.yml` →
`proxy.base_domain`, so every site deployed from the Site Configurator
automatically gets `<site-id>.<public-ip>.sslip.io`.

**One command syncs the machine's whole public identity** (Ansible vars,
`.env`/certgen, the TLS cert, every rendered nginx block) and verifies each
site over HTTP + HTTPS afterwards:

```bash
make set-public-host                    # auto-detects the EC2 public IP
make set-public-host HOST=203.0.113.7   # or pass an IP explicitly
make set-public-host HOST=example.org   # or a real domain, once you have one
```

Implemented by `scripts/set-public-host.sh`; idempotent, and it refuses to
finish silently if a site fails its post-change check. Run it after every IP
change and when upgrading to a real domain (the raw public IP stays as an
alias/SAN automatically — everything else is hostname-agnostic).

## TLS: self-signed by default, Let's Encrypt for the public

Out of the box the proxy serves a self-signed wildcard cert (fine for bots and
`curl -k`, one-time warning for browsers). For a clean padlock:

```bash
LE_DRY_RUN=1 make letsencrypt   # staging dry-run first
make letsencrypt                # production issuance
```

`scripts/setup-letsencrypt.sh` manages the whole thing:

- **Issuance/expansion**: HTTP-01 webroot via the shared `certbot_webroot`
  volume; every vhost serves `/.well-known/acme-challenge/` from it (never
  mirrored into `all_visits`). One cert covers every public hostname — each
  honeypot site plus `admin.<base>`. Re-run after adding a site or changing the
  public host; `--expand --keep-until-expiring` makes re-runs free.
- **Wiring**: the script sets `proxy.tls_fullchain`/`tls_key` in `all.yml`
  (per-site blocks pick it up on render) and manages the `ssl_certificate`
  lines in `proxy/admin.d/admin.conf`. The self-signed wildcard stays as the
  fallback for the catch-all, `*.localhost`, and `https://<raw-ip>/` (LE does
  not issue for bare IPs). Roll back by removing the two keys from `all.yml`
  and re-running the playbook.
- **Renewal is automatic**: the `certbot-renew` sidecar runs `certbot renew`
  every 12h; nginx reloads itself gracefully every 6h to pick up renewed files.
- **sslip.io caveat**: sslip.io is not on the Public Suffix List, so all
  sslip.io users worldwide share LE's per-domain rate limit. Renewals get an
  exemption, but if a future re-issue hits "too many certificates", the
  deployment keeps the current cert and the script says so — retry later or
  move to a real domain.
- **Gotcha (learned the hard way)**: nginx config files that scripts edit with
  `sed -i` must be **directory** mounts (`conf.d/`, `admin.d/`) — sed replaces
  the inode, and a single-file bind mount freezes the container on the pre-edit
  version while `nginx -t` on the host-side file happily passes.

## The public control center

`https://admin.<base-domain>/` serves the dashboard app through the reverse
proxy (`proxy/admin.d/admin.conf` — the only non-honeypot vhost). Layered
security, outermost first:

1. **nginx vhost**: HTTPS-only (`:80` = ACME + 301), HSTS + nosniff /
   same-origin-frame / referrer headers, **no mirror** (admin traffic never
   enters `all_visits` — it would pollute crawler research data and record
   session cookies), XFF/X-Real-IP overwritten (anti-spoof), and rate limits:
   credential/code POSTs at 5/min/IP, everything else at 20 r/s (zones in
   `nginx.conf`).
2. **App sign-in** ([AUTHENTICATION.md](AUTHENTICATION.md)): admin-approved
   registration only, bcrypt passwords, signed sessions, Secure cookies
   (`SESSION_HTTPS_ONLY=true`).
3. **TOTP two-factor** (self-hosted RFC 6238, `app/services/totp_service.py`,
   stdlib-only — works with Google Authenticator, Authy, 1Password, …):
   self-service enrollment at `/account` (or forced org-wide via
   `REQUIRE_2FA=true`). Once enrolled, every password login requires a current
   code, and disabling requires one too. Codes are rate-limited in the app;
   unknown usernames burn a dummy bcrypt so there is no timing oracle.

The SSH tunnel (`http://localhost:8000`) keeps working unchanged — same app,
same accounts. Prometheus stays tunnel-only.

Before exposing the app, set real values in `.env`:

```dotenv
APP_BASE_URL=https://admin.<base-domain>
SESSION_HTTPS_ONLY=true
SECRET_KEY=<fresh strong value>
ADMIN_SECRET=<fresh strong value>
```

(`make set-public-host` keeps `APP_BASE_URL` in sync with the base domain.)

## Monitoring

`docker-compose.monitoring.yml` + `monitoring/` run Prometheus (30d retention),
node-exporter, cAdvisor, Loki (31d), Promtail, Alertmanager, and Grafana — all
published ports loopback-bound. A private external `monitoring_bridge` network
connects only Prometheus, Loki, Grafana, `proxy-nginx`, and the app; honeypot
site stacks never join it and monitoring never joins the honeypot-routing
network. The app's **Admin panel → Monitoring** page renders health/KPI/alert
panels natively and gates `/grafana/` behind the signed admin session (Grafana
itself is anonymous-Viewer behind that gate).

```bash
make monitoring        # after `make proxy` has created the nginx-log volume
make monitoring-logs
make monitoring-down
```

Operational notes:

- Alert rules live in `monitoring/alerts.yml` plus per-site generated rules in
  `monitoring/alerts.d/` (rendered by the playbook; withdrawn on site
  take-down so an `absent()`-based rule doesn't page forever).
- **cAdvisor is pinned to `ghcr.io/google/cadvisor` ≥ v0.56** — older releases
  cannot talk to a Docker 29 daemon and every per-container metric silently
  loses its `name` label, blanking the per-container panels and alerts. Do not
  roll it back.
- nginx access logs rotate via the `logrotate` sidecar in the proxy stack
  (`proxy/logrotate.conf`: daily or 100 MB, 14 kept, copytruncate — safe for
  Promtail, and rotated names don't match its glob so nothing double-ingests).

## Hardening that is easy to regress

- **Site DB ports are loopback-only.** The compose template renders
  `127.0.0.1:<port>:5432` — never expose a site's Postgres on `0.0.0.0`.
- **`restart: unless-stopped` everywhere** except the one-shot `certgen`
  (whose cert persists on disk). A full Docker-daemon restart must bring every
  container back by itself — treat that as a reboot test and verify it after
  structural changes.
- **The Zeek TLS capture must follow nginx replacements.**
  `network_mode: service:nginx` resolves to nginx's concrete container ID when
  the sidecar is created; if nginx is recreated, both containers can say "Up"
  while Zeek silently sniffs a retired network namespace and TLS/TCP analytics
  stop moving. `make proxy` / `make proxy-build` run
  `scripts/sync-tls-capture-netns.sh`, which recreates only the sidecar when
  needed — keep using the make targets.
- The app container bind-mounts the working tree, so **uncommitted edits on the
  server affect the live app immediately**. Review `git status`, test, and
  commit intentional changes so the deployment stays reproducible.

## Verifying a deployment

The checklist that has caught real problems, end to end:

1. From an external network (or an online checker), fetch
   `http://<site>.<base>/` and `https://<site>.<base>/` — expect 200 and a page
   whose canary slots are filled (not `{{ varN }}`, not all `Null`).
2. Fetch twice with the same User-Agent — the canary values must be identical.
3. `curl -k -H "Host: bogus.example" https://<public-ip>/` — the catch-all must
   drop the connection (no response), on both schemes.
4. Confirm the visits landed in `all_visits` with real client IPs, and that
   `https://admin.<base>/` serves the login page with the trusted cert.
5. Confirm zero `admin.<base>` rows in `all_visits` (the no-mirror rule holds).
6. Check Admin panel → Monitoring: all scrape targets up, alert rules loaded,
   capture integrity healthy.
7. Run the offline suite (`make test-suite`) and, with the stack up, the live
   suite (`python testsuite/run_app_tests.py`).
