# `scripts/` — deployment helper scripts

Cloud/host-level helpers invoked by make targets; see
[docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md) for when to use each.

| Script | Make target | What it does |
|---|---|---|
| `set-public-host.sh` | `make set-public-host [HOST=...]` | Syncs the machine's whole public identity — `all.yml` base domains, `.env`/certgen, the TLS cert, every rendered nginx block — to a new public IP or domain, then verifies each site over HTTP + HTTPS. Idempotent; refuses to finish silently on a failed check. |
| `setup-letsencrypt.sh` | `make letsencrypt` | Issues/expands the publicly-trusted Let's Encrypt certificate covering every public hostname and wires nginx to it (`LE_DRY_RUN=1` for staging). Verification retries connection-level (`000`) results — nginx's reload is asynchronous — but never retries a real HTTP answer. |
| `sync-tls-capture-netns.sh` | run by `make proxy` / `make proxy-build` / `make monitoring` | Recreates the Zeek `tls-capture` sidecar when the nginx container has been replaced; `network_mode: service:nginx` pins the sidecar to a concrete container ID, so without this Zeek can silently sniff a retired network namespace. |
