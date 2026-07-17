# Development guide

Everything here runs from the repository root unless noted. For what the pieces
*are*, see [ARCHITECTURE.md](ARCHITECTURE.md); for the cloud deployment, see
[DEPLOYMENT.md](DEPLOYMENT.md).

## Prerequisites

- **Docker daemon running** (Docker Desktop, `colima start`, or the system
  service) before any deploy. On macOS the `prereqs` Ansible role checks for
  Homebrew, installs the Docker CLI + compose plugin if missing, and verifies
  the daemon is reachable.
- **Node.js + npm** for the Tailwind CSS build (`make app` runs it
  automatically and only when a template or frontend input changed; the
  generated `app/static/css/tailwind.css` is tracked so production never needs
  Node at runtime).
- Ansible runs **inside the app container** — you don't need it on the host.
  The inventory targets `localhost` with a local connection; there is no remote
  SSH deployment.

First-time setup:

```bash
cp .env.example .env    # then set SECRET_KEY and ADMIN_SECRET (see docs/AUTHENTICATION.md)
make proxy              # reverse proxy + central logging (generates a TLS cert)
make app                # control-center web app -> http://localhost:8000
```

## Make targets

| Command | What it does |
|---|---|
| `make up-all` | Bring up everything in dependency order: proxy, monitoring (best-effort), app + every site in `configs/sites/`, then a campaign build and a best-effort provenance pass. |
| `make down-all` | Tear down the app, sites, monitoring, proxy, and the shared networks. |
| `make app` | Build CSS if needed, ensure networks, start the web app → http://localhost:8000. Rebuilds the image **only** when a build input (Dockerfile / a requirements file) changed — code is picked up from the runtime bind mount. |
| `make app-build` | Force a full app-image rebuild, then start it. Run after editing a requirements file or the Dockerfile. |
| `make app-down` / `make app-logs` | Stop / follow logs for the web app. |
| `make app-dev` | Run the app on the host with `--reload` (needs `pip install -r app/requirements.txt -r app/requirements-autoquery.txt -r app/requirements-auth.txt`). |
| `make proxy` | Ensure networks, start the reverse-proxy stack (TLS cert, nginx, collectors, logdb, Zeek capture) → :80 + :443. Same rebuild-only-when-needed logic as `make app`; also syncs the Zeek sidecar's network namespace. |
| `make proxy-build` | Force a rebuild of the proxy service images, then start the stack. |
| `make proxy-down` / `make proxy-logs` | Stop the proxy stack / follow nginx logs. |
| `make monitoring` | Start Prometheus + Grafana + Loki + exporters (needs `make proxy` to have created the nginx-log volume once). `make monitoring-down` / `make monitoring-logs` to stop / follow. |
| `make playbook site_id=<id>` | Deploy a single site by id (starts the app container first — it runs Ansible). |
| `make stack-up` / `make stack-down` | Deploy / stop every site in `configs/sites/*.yaml`. |
| `make intel` | Build crawler campaigns from the central log → `crawler_graph/output/campaigns.json`. Flags via `INTEL_ARGS` (e.g. `INTEL_ARGS=--gnn`). `make intel-selftest` runs the offline synthetic check. |
| `make selfplay-train` | Train the self-play attacker + robust detector in the dedicated `trainer` container. Also `selfplay-coevolve`, `selfplay-ingest`, `selfplay-calibrate`, `selfplay-selftest`, `selfplay-up`/`selfplay-down`. Args via `SP_ARGS`. |
| `make provenance site_id=<id> db_name=<scraperN-db>` | Probe a deployed site's canaries across the model-version timeline. `make provenance-all` runs a best-effort pass for every site. |
| `make set-public-host [HOST=<ip-or-domain>]` | Cloud only: sync every hostname-bearing config (all.yml, `.env`/certgen, TLS cert, rendered nginx blocks) to the machine's public address. See [DEPLOYMENT.md](DEPLOYMENT.md). |
| `make letsencrypt` | Cloud only: issue/refresh the publicly-trusted Let's Encrypt cert for every public hostname. `LE_DRY_RUN=1` for a staging dry-run. |
| `make test-suite` | Run the offline, deterministic pytest suite (see Testing below). |
| `make ensure-net` / `make net-down` | Create / remove the shared Docker networks (idempotent). |

## Running pieces directly

**The Ansible playbook** (the `deploy` role creates `proxy_net` itself, so this
works standalone on a fresh machine):

```bash
cd ansible && ansible-playbook site.yml -e site_id=site-001
cd ansible && ansible-playbook site.yml -e site_id=site-001 -e reset_db=true   # recreate the DB volume
```

**The legacy querying CLI** (offline demo needs no API keys):

```bash
python -m querying.main --url https://example.com/ --models mock/scraper-sim mock/honest-llm
python -m querying.main --site site-001 --db-name scraper1-db --db-user user --models mock/scraper-sim
```

**The honeypot Flask app standalone** (no Docker), from `website/`:

```bash
python server.py           # genmode on (generates canaries for new visitors)
python server.py nogen     # genmode off (serves "Null" vars, stores nothing new)
```

Serves on `0.0.0.0:8080`; needs reachable Postgres via `DB_USER` / `DB_PASS` /
`DB_HOST` and `SCRAPER_VERSION`.

**The template generator** (own venv — see `template_generator/README.md`):

```bash
cd template_generator
python prepare_data.py --wiki-limit 3000           # build data/sft.jsonl
python train.py --dtype bfloat16 --max-steps 800   # LoRA fine-tune -> models/
python generate_templates.py                       # one template per category (all 20)
python generate_templates.py --category towns      # a single category
```

## Testing routing without real DNS

Host header / SNI selects the site:

```bash
# Plain HTTP:
curl -H "Host: site-001.dukecodeplus.example" http://localhost/
# HTTPS (-k accepts the self-signed cert; --resolve maps the SNI hostname to loopback):
curl -k --resolve site-001.dukecodeplus.example:443:127.0.0.1 \
     https://site-001.dukecodeplus.example/
# Inspect the presented cert:
openssl s_client -connect localhost:443 -servername site-001.dukecodeplus.example </dev/null \
  | openssl x509 -noout -subject -ext subjectAltName
```

For browser testing add `/etc/hosts` entries or use the `*.localhost` alias
(browsers resolve it to loopback automatically).

## Testing

There are two test runners in `testsuite/` (own venv:
`pip install -r testsuite/requirements.txt`; the optional GNN tests also need
`testsuite/requirements-gnn.txt` + a torch wheel, else they skip cleanly):

- **`python testsuite/run_tests.py`** (= `make test-suite`) — the **offline,
  deterministic** suite. No Docker daemon, no Postgres, no API keys, no
  network: the Docker CLI, `psql`, the playbook, and model providers are all
  stubbed, and traffic is synthesized in-process. It exercises every
  user-visible feature against the project's own code and writes a per-feature
  pass/fail/skip table plus `testsuite/reports/latest.{json,html}`. Run one
  feature with `python testsuite/run_tests.py <feature>`, or `--list`.
- **`python testsuite/run_app_tests.py`** — the **live** suite: the same
  features exercised against the actually-running stack. It mass-simulates a
  bot fleet through the real proxy, then verifies the real databases,
  pipelines, and web app. Read-mostly and never destructive; anything not up
  causes its tests to skip with a clear reason.

There is no linter, type checker, or CI. Do not invent other test commands.

The offline suite is fast regression coverage — it does **not** replace the
live verification loop below (it stubs Docker/nginx/Postgres, so it can't catch
routing, TLS, or real-DB-write regressions).

### After changing the website / Ansible / proxy layers

1. `make proxy` (once) and `make playbook site_id=site-001` (or `make up-all`).
   Changing the proxy stack itself (`nginx.conf`, `docker-compose.proxy.yml`,
   certs) needs the nginx container **recreated** (`make proxy`), not just an
   `nginx -s reload` — port mappings and the cert mount are set at
   container-create time. Re-rendering a per-site block (`site.conf.j2`) needs
   the playbook.
2. `curl -H "Host: site-001.dukecodeplus.example" http://localhost/` **and**
   the HTTPS form — confirm both render the page with filled-in canary values
   (not literal `{{ varN }}`, not all `Null` unless genmode is off).
3. Hit it twice with the same UA and confirm the **same** canaries come back
   (stability), and that the request shows up in Crawler Analytics /
   `all_visits`.
4. Confirm the catch-all drops an unknown Host over both schemes
   (`curl -k -H "Host: bogus.example" https://localhost/` → connection dropped).
5. Check `make proxy-logs` for nginx errors and the collector logs for insert
   failures.

To verify per-site DB writes: exec into the site's `db` container and query
`new_visits` / `new_agents_vars`. To verify central logging: query `logdb`'s
`all_visits` (the Crawler Analytics page does exactly this).

## Dependency layout

Each layer pins its own deps and is normally installed inside its Docker image:

- `website/requirements.txt` — Flask, SQLAlchemy, psycopg2-binary, faker (+
  faker-edu, faker_food), ipwhois, user_agents.
- `app/requirements.txt` — fastapi, uvicorn, jinja2, python-multipart,
  ruamel.yaml, the querying deps (requests, beautifulsoup4, httpx,
  python-dotenv), and psycopg2-binary. The app image also layers in `ansible-core` +
  `community.general` + the Docker CLI, the ML stack
  (`app/requirements-ml.txt`: torch from PyTorch's cu128 index +
  transformers/peft/accelerate), `torch_geometric`,
  `crawler_graph/requirements.txt`, `app/requirements-autoquery.txt` (litellm,
  openai, rapidfuzz, openpyxl) and `app/requirements-auth.txt`.
  **Keep `app/requirements.txt` byte-stable and add new app deps in one of the
  late-layer files**: the early `COPY app/requirements.txt` sits before the
  torch install, so touching it forces the multi-GB ML re-download.
- `querying/requirements.txt` — requests, beautifulsoup4, httpx (spaCy
  optional).
- `proxy/collector/requirements.txt` (and the other proxy services') —
  fastapi, uvicorn, psycopg2-binary.
- `template_generator/requirements.txt` — torch, transformers, peft,
  accelerate, numpy, faker. Use its own venv; do not mix it with the website
  env.
- `testsuite/requirements.txt` — the offline suite's deps.

## Coding conventions

- Python throughout the runtime layers; Jinja2 for Ansible templates; YAML for
  config. Match the surrounding file's style — the proxy/app modules use clear
  docstrings and explanatory comments on load-bearing decisions; keep that.
- **`scraper_version` is never a literal in source.** Read it from the
  `SCRAPER_VERSION` env var (the playbook enforces this in `server.py`).
- **Per-site ports must be unique** (`website.port`, `database.host_port`); the
  playbook refuses the deploy otherwise.
- **nginx config is generated, never hand-maintained.** All per-site blocks
  come from `site.conf.j2` and are reloaded (`nginx -s reload`), never
  restarted, so adding a site never drops the others.
- **Canary tokens live in `all.yml`** (or the per-site YAML), rendered into
  `website/varLists/*.txt`.
- Adding a honeypot flavor: bump `scraper_version` (per-site yaml or default)
  and let the configure role scaffold `scraper{N}.html` / `scraper{N}.txt`,
  then edit the new HTML — or author one on the Generator page.

### Generated / build artifacts — do not edit by hand

| Path | Generated by |
|---|---|
| `website/varLists/scraper{N}.txt` | `configure` role from `canary_tokens`; also written at install time by the Generator page |
| `configs/generated_templates.json` | the Generator page on every install |
| `website/sites/<site_id>/docker-compose.yml` | `configure` role from `docker-compose.yml.j2` |
| `proxy/conf.d/<site_id>.conf` | `configure` role from `site.conf.j2` |
| `proxy/certs/wildcard.{crt,key}` | `certgen` init container from `proxy/gen-cert.sh` |
| `monitoring/alerts.d/*.yml`, `monitoring/targets.d/*.yml` | `configure` role (per-site alert rules + probe targets) |
| `configs/sites/<site_id>.yaml` | the Site Configurator page |
| `configs/history/applies.jsonl` | the web app on every apply |
| `querying/runs/<run_id>.json` | the querying/auto_query engines on every run |
| `app/static/css/tailwind.css` | `make frontend-css` (tracked so production needs no Node) |
| `template_generator/data/sft.jsonl`, `generated_templates/*`, `models/*`, `template_registry.jsonl` | the template-generator pipeline |

To change canary tokens, edit `canary_tokens` in `all.yml` (or the per-site
list in `configs/sites/<id>.yaml`) and re-run the playbook — never edit the
varLists. To change routing, edit the per-site yaml (`proxy.server_name`) and
re-run — never edit `proxy/conf.d/*.conf`.

## Project-specific warnings

- **Unique ports per site.** The most common deploy failure; the playbook
  validates and aborts on a collision.
- **DB credentials are fixed at volume-creation time.** Postgres only applies
  `POSTGRES_USER`/`POSTGRES_PASSWORD`/`POSTGRES_DB` when it initializes an
  empty data dir. Re-applying a site with changed credentials reuses the old
  volume → the healthcheck fails. To change DB credentials on an existing site
  you must recreate the volume (the UI checkbox, or `-e reset_db=true`) —
  **this wipes that site's stored visits and canary tokens.**
- **The catch-all nginx server and XFF overwrite are security-load-bearing.**
  Removing the default `server {}`, marking a per-site block `default_server`,
  or switching XFF to `$proxy_add_x_forwarded_for` reintroduces canary
  misattribution / IP spoofing.
- **The TLS cert is shared.** If you change `proxy.base_domain` /
  `proxy.local_base_domain` in `all.yml`, update the matching env in the
  `certgen` service (or delete `proxy/certs/*` and recreate the proxy) so the
  wildcard still covers every site. On the cloud deployment, run
  `make set-public-host`, which handles all of this.
- **`app/services/sites.py`'s ruamel `YAML()` instance is shared and NOT
  thread-safe.** Every load/dump goes through `_yaml_load`/`_yaml_dump`, which
  hold `_yaml_lock`. Do not call `_yaml.load`/`_yaml.dump` directly — this
  module is read concurrently, and sharing the parser once let loads interleave
  into a bogus `ParserError` that silently dropped every site from the
  monitoring inventory on roughly a third of refreshes.
- **`scripts/setup-letsencrypt.sh` verification retries a 000
  (connection-level) result.** `nginx -s reload` is asynchronous: for about a
  second the outgoing worker still accepts a connection and then closes it.
  Never retry a real HTTP answer; an unexpected status is a definitive verdict.
- **The honeypot web container ignores SIGTERM** (`python server.py` is PID 1),
  so it always waits out the stop timeout and is killed. Harmless — it is
  stateless and postgres:16 shuts down fast. Keep the compose stop timeout
  small.
- **Shared `proxy_net` must exist before any site comes up.** The `deploy` role
  creates it idempotently; `make ensure-net` covers the make-driven flow.
- **Per-site reload uses `failed_when: false`.** Deploying a site before the
  proxy stack is up won't fail the playbook — but the route won't be live until
  `make proxy` (or a re-run with the proxy up).
- **Each site's host port is bound to `127.0.0.1`.** Reach sites through the
  proxy, not their raw ports (the raw port bypasses the central request log).
- **Secrets live in the git-ignored project-root `.env`** (see `.env.example`).
  Provider API keys can also be managed from the LLM Forensics page, which
  writes the same file. Never hardcode real secrets in source.
