# `proxy/` — reverse proxy + central logging stack

The single entry point for all traffic (`docker-compose.proxy.yml`, `make
proxy`): nginx terminates HTTP/HTTPS, routes by hostname, and mirrors every
honeypot request into the central `logdb` Postgres. Several decisions in here
are security-load-bearing — read "Reverse proxy" in
[docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) before changing routing, TLS,
headers, or logging.

## Services

| Service | Source | Role |
|---|---|---|
| `nginx` (`proxy-nginx`) | `nginx.conf`, `snippets/mirror.conf`, `conf.d/*.conf`, `admin.d/admin.conf` | TLS termination (SNI), host-based routing, JSON access logs, request mirror, catch-all `444` for unmatched Hosts, rate limits on the admin vhost only. |
| `certgen` | `gen-cert.sh` | One-shot init container: writes the self-signed wildcard cert into `certs/` if missing. |
| `collector` | `collector/` | Receives the request mirror → `logdb.all_visits`. Fire-and-forget: never blocks or fails a real response. |
| `fp-collector` | `fp-collector/` | Receives `fp.js` beacons on `/__fpbeacon` → `logdb.browser_fingerprints`. Same contract. |
| `logdb` | postgres:16 | The cross-site aggregate log store (`site_logs`). |
| `tls-capture` | `tls-capture/` | Passive Zeek sidecar sharing nginx's network namespace: raw ClientHello (JA3/JA4) + client SYN capture, never in the request path. |
| `tls-shipper` | `tls-shipper/` | Streams Zeek's JSON logs into `logdb.tls_handshakes` / `tcp_fingerprints`. |
| `logrotate` / `certbot-renew` | `logrotate.conf`, `certbot-renew.sh` | Access-log rotation (Promtail-safe) and automatic Let's Encrypt renewal. |

## Do not regress

- The **catch-all default server** and the **X-Forwarded-For overwrite** keep
  canary attribution and the central log trustworthy.
- `conf.d/*.conf` per-site blocks are **rendered by Ansible** — edit
  `ansible/roles/configure/templates/site.conf.j2`, never the output.
- The mirror is best-effort by design (short timeouts, GET-only); admin-vhost
  traffic is **never** mirrored.
- Changing this stack's compose file / `nginx.conf` / certs requires
  *recreating* the nginx container (`make proxy`), not just a reload — and
  `make proxy` also re-syncs the Zeek sidecar's network namespace (a recreated
  nginx otherwise leaves Zeek sniffing a retired namespace).
