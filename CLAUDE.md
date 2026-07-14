# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this
repository. It is the single most useful thing to read before changing anything here.

---

## 1. Project overview

### What this is
**AI Bot Defender** is a Duke Code+ 2026 / Argus Lab research project for studying and
defending against AI scraper bots (the crawlers LLM providers use to harvest web content).
The core defensive idea is a **honeypot website seeded with canary tokens**: each unique
visitor (keyed by a browser-fingerprint device cookie when available, else `User-Agent +
ASN`) is served a page containing uniquely generated fake facts (names, cities,
institutions, years, etc.). If those fabricated tokens later surface inside an LLM's output,
you have evidence that a specific scraper ingested the page. Because one physical device
keeps **one** canary set even across UA/IP/ASN rotation, a single canary set appearing under
several claimed identities is itself a **disguise** signal (surfaced on Crawler Analytics).
Every visit is also logged to Postgres for traffic analysis.

The system is built to run **many independent honeypot sites at once**, each a self-contained
Docker Compose stack, all sitting behind one local nginx reverse proxy that does host-based
routing and centralized cross-site request logging.

### Repository layout

| Path | What it is |
|---|---|
| `website/` | The Flask honeypot app (`server.py`) + per-site Postgres model — the thing bots hit. |
| `ansible/` | Automation that renders and deploys per-site stacks via Docker Compose, plus per-site nginx config. |
| `proxy/` + `docker-compose.proxy.yml` | The nginx reverse proxy + centralized cross-site logging stack (the single local entry point). |
| `app/` + `docker-compose.app.yml` | The **unified web application** (FastAPI + Jinja2 + Tailwind): five top-nav pages — landing/**Overview** (`/`), **Site Configurator** (`/sites`), **Template Generator** (`/generator`), **Crawler Analytics** (`/logs`: request log + device fingerprints + campaign intelligence), and **LLM Forensics** (`/query`: detection + provenance + membership inference). The older `/fingerprints`, `/intel`, `/provenance` URLs 307-redirect into the two merged pages. Light/dark theme toggle. Replaces the old Streamlit UI. |
| `testsuite/` | **Pytest suite** (`testsuite/run_tests.py`, `testsuite/tests/`) covering the FastAPI routes, request-log/fingerprint enrichment, crawler-graph on synthetic traffic, proxy collectors + shipper, querying/provenance, sites/templates, and static contracts. Self-contained (own `requirements.txt` + `pytest.ini`); see `testsuite/README.md`. |
| `auto_query/` | The **LLM detection engine** (vendored from the team's `auto-query-integrate` branch): four independent pipelines — prompt → (LiteLLM API query \| manual query) → evaluation — with a RapidFuzz attribution matcher producing per-crawler attribution profiles + a cross-model ranking. Driven by the app's LLM Forensics page through `app/services/auto_query_adapter.py`; offline `mock/*` + heuristic fallbacks keep it demoable with no API keys. |
| `querying/` | The **legacy querying pipeline** (package) — superseded as the detection engine by `auto_query/` but still load-bearing: it hosts the **training-data provenance** layer (Direction 6b: `model_timeline.py`, `provenance.py`, `membership.py`, `rag_disambiguation.py`), the **run store** (`store.py`, which auto_query runs persist through) and the **ground-truth loaders** (`ground_truth.py`) the adapter reuses. Also still runnable as a CLI. |
| `crawler_graph/` | **Crawler-infrastructure graph intelligence** (Direction 6a): clusters the central request log (+ passively captured TLS fingerprints) into attributable *campaigns* via community detection and an optional GraphSAGE GNN, flagging disguised/undeclared crawlers and agentic browsers. Surfaced in the app's Crawler Analytics page (`/logs`; the old `/intel` redirects there). See `crawler_graph/README.md`. |
| `selfplay/` | **Adversarial self-play (Direction 2):** a co-evolving crawler ⇄ honeypot RL layer. A learned crawler (PPO-Lagrangian over a constrained MDP) is trained in a calibrated traffic simulator to harvest content while evading the **production `crawler_graph` detector** (the reward oracle = `crawler_graph.pipeline.run_intel` on synthetic traffic). Its discovered evasions harden a **robust detector** that runs as a second opinion on `/logs`; the infra cost it must pay to defeat each fingerprint layer becomes a **cost-to-evade curve**. v2 adds PSRO co-evolution + a content-policy bandit rewarded by *provable ingestion* (`querying.membership`). Additive & read-only over `crawler_graph`/`querying`; surfaced at `/selfplay`. |
| `configs/` | Machine-local deployment state (git-ignored): `sites/<id>.yaml` per-site overrides + `history/applies.jsonl`. Written by the app. |
| `template_generator/` | A self-contained sidecar that LoRA-fine-tunes Qwen3-1.7B to *generate* new honeypot HTML templates across **20 content categories** (towns, movies, biography, animals, ...), each with its own category-typed varList, deduped against a title/content **registry** (local JSONL or the optional `registry_api/` FastAPI service). Additive — does not touch the other layers. |
| `data/`, `cleaned_intros/`, `wikipedia_towns_text/` | Research datasets / experiment output. **Committed to git**, not git-ignored. |
| `venv/`, `.venv-app/` | Local Python virtualenvs (git-ignored). |

The runtime layers — `website/`, `ansible/`, `proxy/`, `app/`, `auto_query/`, `querying/` —
cooperate; `template_generator/` is an offline content-generation tool; the data dirs are corpora.
**Everything lives at the repository root** (the project was previously nested under
`site_Tristan/` with `auto-querying/` as a sibling; both have been flattened and merged here).

### Big-picture architecture

#### Multi-site deployment model
Sites are identified by a `site_id` (e.g. `site-001`). Each is its own isolated Docker
Compose stack (own `web` + `db` containers, volumes, network). The flow:

```
configs/sites/<site_id>.yaml      (per-site overrides, written by the web app)
        +  ansible/group_vars/all.yml   (global defaults)
        |
        v  ansible-playbook site.yml -e site_id=<id>   (merges overrides over defaults)
        |
        v  renders website/sites/<site_id>/docker-compose.yml   (from j2 template)
        +  renders proxy/conf.d/<site_id>.conf                  (from j2 template)
        |
        v  docker compose up -d --build   (one stack per site)
        +  docker exec proxy-nginx nginx -s reload   (pick up the new route)
```

Because each site is a separate stack, **`website.port` and `database.host_port` must be
unique per site** — `ansible/site.yml` pre_tasks actively validate this (it slurps every
other `sites/*.yaml`, computes claimed ports, and fails the run on a collision). **This is
the single most common source of deploy failures.**

#### Reverse proxy + centralized logging (`proxy/`)
A single nginx (stack name `proxy`, container `proxy-nginx`) is the **only locally exposed
entry point** — it terminates both **plain HTTP (`:80`)** and **HTTPS (`:443`)**. Every
per-site stack binds its host port to `127.0.0.1` only — the sites are reachable from the
public network *only* through the proxy. Like a normal website, a site is reached at
`https://<hostname>/`: nginx selects the TLS cert by **SNI** during the handshake, then
routes the decrypted request by **Host** header (name-based virtual hosting). The proxy
stack (`docker-compose.proxy.yml`) has these core logging services (plus the passive Zeek
TLS/TCP capture sidecar + shipper described under Direction 6a):

- **`certgen`** (`proxy/gen-cert.sh`, one-shot `alpine` init container) — writes a
  self-signed **wildcard** TLS cert into the shared `proxy/certs/` dir if one isn't there
  yet, then exits. Idempotent (a present cert is left in place). nginx `depends_on` it with
  `condition: service_completed_successfully`, so the cert always exists before nginx starts.
  A single `*.<base_domain>` / `*.<local_base_domain>` cert covers **every** site because all
  site hostnames are subdomains of the base domains.
- **`nginx`** (`proxy-nginx`) — terminates TLS, routes, and logs. Config split across
  `proxy/nginx.conf` (base: global `ssl_certificate`/`http2 on`, JSON `siteaccess` log
  format, `resolver 127.0.0.11`, the **default catch-all server**, and `include
  conf.d/*.conf`), `proxy/snippets/mirror.conf` (the shared `/_mirror` target), and
  Ansible-rendered `proxy/conf.d/<site_id>.conf` (one `server {}` per site).
- **`collector`** (`proxy/collector/app.py`, FastAPI + psycopg2) — receives nginx's request
  mirror and writes one row per request into the central `all_visits` table, then returns
  204 as fast as possible. Fire-and-forget: any DB error is swallowed and the connection reset.
- **`fp-collector`** (`proxy/fp-collector/app.py`, FastAPI + psycopg2) — receives the Layer-1
  browser-fingerprint beacon that `website/static/js/fp.js` POSTs to `/__fpbeacon` (routed by an
  additive exact-match `location` in each per-site block) and writes one row per beacon into
  `logdb.browser_fingerprints`. Same never-block/fire-and-forget contract as `collector`; caps
  body size. See "Device fingerprinting (Layer 1/2/3)" below.
- **`logdb`** (postgres:16, database `site_logs`, user/pass `logger`) — the cross-site
  aggregate log store.

Key decisions (load-bearing — do not silently change these):

- **Host-based routing (name-based virtual hosting).** One `server {}` per site,
  `server_name {{ site_id }}.{{ proxy.base_domain }}` (or a per-site `proxy.server_name`
  override) plus a browser-friendly `{{ site_id }}.{{ proxy.local_base_domain }}` alias,
  each rooted at `/`. The block also does `set $site_name <canonical hostname>;` and the
  mirror tags requests with `X-Site $site_name`, so **even requests that arrive via the
  `*.localhost` alias are recorded under the canonical hostname** in `all_visits.site`. No
  path-based routing — that would leak `/site-xxx/` and break Flask's root-relative
  links/static paths. Per-site blocks listen on **both** `listen 80;` and `listen 443 ssl;`
  (never `default_server`), so the same site answers over HTTP and HTTPS.
- **TLS termination via SNI (HTTPS, name-based virtual hosting).** nginx terminates TLS at
  the proxy and serves the honeypot over both `:80` and `:443`. One shared, self-signed
  **wildcard** cert (written by `certgen`, set globally at `http{}` scope in `nginx.conf`, so
  every `server {}` inherits it) is presented for any SNI; nginx then routes by Host header —
  so a site looks like a normal `https://<hostname>/` website. The backend is still plain
  HTTP (`proxy_pass http://...:8080`); `X-Forwarded-Proto $scheme` carries the original
  scheme. **Both schemes serve the site on purpose** (not an HTTP→HTTPS redirect): the
  project rule that *all crawlers must reach the site* means a redirect would drop bots that
  don't follow redirects. To switch to redirect-to-HTTPS behavior, change the per-site block
  in `site.conf.j2` per the comment there (drop `listen 80;` from the main block, add a tiny
  `return 301 https://$host$request_uri;` HTTP block). The wildcard cert is **self-signed**
  (one-time browser warning, harmless to bots/`curl -k`); for a zero-warning local experience
  use mkcert, and for a real public deployment swap in ACME/Let's Encrypt certs (mount real
  cert/key over `proxy/certs/`).
- **Default catch-all server (in `proxy/nginx.conf`).** A `listen 80 default_server; listen
  443 ssl default_server;` block with `server_name _;` absorbs every request whose Host/SNI
  doesn't match a configured site — raw-IP scans, spoofed/junk Host values, no-Host requests.
  It `return 444`s (drops the connection; swap to `404` to answer) and **neither proxies nor
  mirrors**, so scan noise never reaches a real site's Flask backend (no canaries assigned to
  scanners) and never enters `all_visits`. (Over HTTPS the TLS handshake still completes with
  the inherited wildcard cert before the 444 — unavoidable for TLS — but nothing is proxied
  or mirrored.) Because of this block, any request that *does* reach a per-site block has a
  Host matching that site, so `all_visits.site` is never an arbitrary client value. Unmatched
  traffic is still logged — separately, to `/var/log/nginx/unmatched.access.log`. **Do not
  remove this block or mark a per-site block `default_server`.**
- **Shared external network `proxy_net`.** nginx reaches each site at
  `http://{{ site_id }}-web:8080` via a network **alias** (the bare service name `web` is
  ambiguous across stacks on a shared network). The site joins both its own `default`
  network and `proxy_net`.
- **Anti-spoof XFF.** nginx **overwrites** `X-Forwarded-For` with `$remote_addr` (never
  `$proxy_add_x_forwarded_for`). `server.py` trusts the first XFF entry for ASN lookup and
  canary keying, so appending would let a bot prepend a fake IP the app would believe.
- **Dynamic upstream resolution.** `resolver 127.0.0.11` (Docker embedded DNS) + a
  `set $upstream ...; proxy_pass http://$upstream:8080$request_uri;` variable means
  `nginx -s reload` never fails just because a site container is momentarily down — names
  are resolved at request time, not config-load time.
- **Best-effort mirror.** The mirror uses `mirror_request_body off` (GET-only) and short
  timeouts (`proxy_connect_timeout 200ms`, `proxy_read_timeout 500ms`,
  `proxy_next_upstream off`); the collector failing or being slow can never stall the real response.
- **No rate limiting** on the main path — all traffic, including crawlers, must reach the site.
- **TLS is self-signed and local.** The proxy serves HTTPS for a real-website feel, but the
  cert is self-signed and the build is still local-only (sites bound to `127.0.0.1`, no real
  DNS, no public exposure). Real publicly-trusted certs (ACME) are a deliberate, larger
  change — see the TLS-termination decision above.

Two logging paths run in parallel:
1. nginx `access_log` (JSON, `siteaccess` format, includes a `scheme` field recording
   http vs https) → `/var/log/nginx/dukecodeplus.access.log` inside the `nginx_logs` volume.
   (Unmatched/scan traffic goes to `unmatched.access.log`.)
2. nginx `mirror /_mirror` → `collector:8000` → `logdb` table `all_visits`
   (`site, client_ip, user_agent, method, uri, headers jsonb, ts`), tagged per site via the
   `X-Site` header. Only matched (real-site) requests are mirrored.

#### The `scraper_version` indirection
`scraper_version` (an int, default 1) selects a whole "flavor" of the honeypot in lockstep
across three places:
- `website/varLists/scraper{N}.txt` — the 10 canary-token Python expressions.
- `website/templates/scraper{N}.html` — the HTML page rendered to visitors.
- the Postgres database name `scraper{N}-db`.

It must **not** be hardcoded. `server.py` reads it from the `SCRAPER_VERSION` env var; the
compose template passes it in; the Ansible `configure` role even self-heals `server.py` with
a `replace` task to guarantee the env-var form. When `scraper_version != 1`, the configure
role copies `scraper1.html` → `scraper{N}.html` if one doesn't already exist (so a new
version boots with a working template you can then customize).

#### Config precedence (Ansible)
`ansible/group_vars/all.yml` holds global defaults: `website_dir`, `website` (port, genmode),
`database` (user, password, host_port), `scraper_version`, `proxy` (enabled, base_domain,
local_base_domain, container, conf_dir), and `canary_tokens` (a list of ≥10 Python
expressions). `configs/sites/<site_id>.yaml` holds per-site overrides. `site.yml` merges
the site file *over* the defaults with `combine` (for `website`, `database`, `proxy`),
coerces `genmode` to a real bool, and asserts `canary_tokens | length >= 10`. A site may
override `proxy.server_name` to use a custom canonical address, and may carry a per-site
`canary_tokens` list (written automatically by the Site Configurator for generator-authored
flavors — see the Canary tokens section) that replaces the global default for that site.

#### Canary tokens (`var1`..`var10`)
`canary_tokens` in `all.yml` is the **global default**. The configure role renders the
first 10 entries into `website/varLists/scraper{N}.txt` via `canary_vars.txt.j2`. A
generator-authored flavor overrides this per site: installing a generated template records
its category-typed varList in `configs/generated_templates.json`, `sites.py` embeds it as
`canary_tokens` in that site's `configs/sites/<id>.yaml`, and `site.yml` prefers the
per-site list over the global default — so a movies page deploys with movie-shaped tokens
while hand-made flavors keep following `all.yml`. **Do not
edit `website/varLists/*.txt` by hand — they are generated build artifacts.** Each line is a
Python expression `eval`'d server-side in `gen_vars()` with the `fake` (Faker) object in
scope. Available providers: base Faker `en_US`, plus `faker_edu` (`institution_name()`) and
`faker_food` (`dish()`, `ingredient()`, `fruit()`). These 10 values become
`{{ var1 }}`..`{{ var10 }}` in the HTML template.

#### Request handling in `server.py`
Single route `GET /`. On each request `update_page()`:
1. Resolves client IP via `get_client_ip()` — the **first** `X-Forwarded-For` entry if
   present, else `request.remote_addr`. Hashes it (SHA-256), derives the network address
   (IP minus last segment), and looks up the ASN via `ipwhois`. Behind the proxy, nginx sets
   XFF to the real client; standalone it falls back to `remote_addr`. **The proxy must
   overwrite, not append, XFF** or this IP is spoofable.
2. Parses the User-Agent (`user_agent_info.parse_user_agent`, backed by `user_agents`).
3. **Always** inserts a row into `new_visits` (the raw visit log).
4. Looks up `new_agents_vars` **by the device cookie `__abd_fp` (a `fp_id`) when the
   browser sent one, else by `(user_agent, asn)`** (falling back to the classic key; the
   first time a cookie appears for an existing `(user_agent, asn)` row its null `fp_id` is
   backfilled, binding the device to its canary set):
   - **Seen before** → reuse the stored `var1..var10`, increment `view_count`, refresh
     `last_visited`/asn/ip. This makes canary tokens *stable per device* — one physical
     machine keeps **one** canary set even as it rotates its UA / exit IP (a browser VPN) /
     ASN, so a canary set surfacing under several claimed identities is the **disguise**
     signal (and a leaked set attributes to one device, not N fragments).
   - **New visitor + genmode on** → `set_vars()` generates a unique canary set (retrying to
     avoid duplicates) and stores a new row (with `fp_id = __abd_fp`, possibly null).
   - **New visitor + genmode off** → renders all vars as `"Null"` and stores nothing.
   The `fp_id` column is added by an additive startup `ALTER TABLE ... ADD COLUMN IF NOT
   EXISTS` (mirrors the collector). `fp.js` sets the `__abd_fp` cookie *after* it runs, so
   the first contact and non-JS scrapers use the `(user_agent, asn)` keying unchanged.
5. Renders `scraper{N}.html` with the vars.

`genmode` is controlled at runtime by the `nogen` CLI arg (`python server.py nogen`); the
compose template injects this command when `website.genmode` is false.

#### Databases
Two distinct Postgres stores:
- **Per-site `scraper{N}-db`** (inside each site stack's `db` container). Two tables,
  auto-created on boot via `Base.metadata.create_all`:
  - `new_visits` — append-only log of every request (UA breakdown, ASN, hashed IP, timestamp).
  - `new_agents_vars` — one row per unique `(user_agent, asn)` with its assigned canary
    tokens and `view_count`.
- **Central `site_logs`** (the proxy stack's `logdb`). One table `all_visits` — the
  cross-site aggregate the collector writes, tagged per site. The only place that joins
  traffic across every honeypot site, and what the UI Request Log reads.

`server.py` also contains Cloud Run / Cloud SQL connection logic (used when `PORT` env is
set); locally/Docker it connects to `DB_HOST:5432`. Note: there is leftover `openai` client
setup with a `'null'` api key — currently unused dead scaffolding (and `openai` is still in
`website/requirements.txt`).

#### The web app (`app/`) — FastAPI + Jinja2 + Tailwind, Docker-out-of-Docker
`docker-compose.app.yml` runs the FastAPI container with the host Docker socket mounted
**and the project bind-mounted at the same absolute path** (`${PWD}:${PWD}`,
`PROJECT_ROOT=${PWD}`). This "path mirroring" is deliberate (inherited from the old UI):
when the container runs `docker compose` / `ansible-playbook` against the host daemon,
build contexts resolve identically inside and out. The image (`app/Dockerfile`, build
context = repo root so it can copy `app/`, `querying/`, `auto_query/`, and `crawler_graph/`)
bakes in the Docker CLI + compose plugin **and** `ansible-core` + `community.general`. It also
bakes in the **template-generator ML stack** (torch from PyTorch's cu128 index + transformers/
peft/accelerate, `app/requirements-ml.txt`) so the Template Generator page authors pages in a
container subprocess, **and `torch_geometric`** (a small late layer on top of that torch) so
the Crawler Analytics page (`/logs`) can **train the GraphSAGE GNN in-process** — no separate
environment — **and the auto_query engine deps** (`app/requirements-autoquery.txt`: litellm,
openai, rapidfuzz, openpyxl; another late layer so they never invalidate the torch cache). The container also joins `proxy_net` and sets
`PROXY_HTTP_ENTRY=http://proxy-nginx` so the Query Console can scrape honeypot sites through
the proxy by container name. Served on **http://localhost:8000**.

`app/main.py` defines the routes; business logic lives in `app/services/`; pages are
server-rendered Jinja2 templates (`app/templates/`) styled with Tailwind (Play CDN) +
`app/static/css/app.css`. **Note the Starlette signature**: call
`templates.TemplateResponse(request, "name.html", {context})` — request first (the legacy
`(name, context)` form silently treats the context dict as the template name and 500s).

The UI is **five top-nav pages** (`base.html` nav: Overview `/`, Sites `/sites`, Generator
`/generator`, Crawler Analytics `/logs`, LLM Forensics `/query`). Two of these are
**consolidated** pages that merge what used to be separate views, and the old URLs now
**307-redirect** into them (so deep links / muscle memory still work):
- `GET /fingerprints` and `GET /intel` → **redirect to `/logs`** (folded into Crawler Analytics).
- `GET /provenance` → **redirects to `/query`** (folded into LLM Forensics).

A sub-view sets `active_section` (`traffic` | `forensics`) so its parent top-nav item stays
highlighted. The pages:
- **Landing / Overview (`/`, `index.html`)** — hero + live statistics (websites live, LLM
  models, queries completed, matches found, requests logged, query runs, plus **campaigns**
  and **disguised crawlers** from `graph_intel.summary()`) polled from `GET /api/stats`
  (`services/stats.py`), plus navigation cards and a "how detection works" explainer.
- **Site Configurator (`/sites`, `sites.html`, `services/sites.py`)** — edits the global
  `website_dir` in `all.yml`; `scraper_version` is a dropdown of the `scraper<N>.html`
  flavors in `website/templates/` with a live iframe preview (served by
  `GET /sites/template/{version}`); collects per-site website/database settings; suggests
  non-colliding ports; `POST /sites/deploy` writes `configs/sites/<id>.yaml` and runs
  `ansible-playbook site.yml -e site_id=<id> [reset_db=true]`. Lists configured sites with
  live/deployed/config-only status. Every apply appends to `configs/history/applies.jsonl`.
- **Template Generator (`/generator`, `generator.html`, `services/template_gen.py`)** —
  authors new honeypot page flavors with the fine-tuned Qwen3-1.7B + LoRA model, run as an
  **in-container subprocess** (`template_generator/generate_templates.py` via
  `TEMPLATE_GEN_PYTHON`, default `python3` — the app image bakes the ML stack). The UI
  offers one flavor per generator **category** (the `CATEGORIES` registry, read out of the
  script via AST — never imported) plus an "All categories" run; there is no count/seed
  knob (the generator makes one deduped template per category per run, checking titles +
  content hashes against its registry — local `template_registry.jsonl` by default, or the
  central registry API when `TEMPLATE_GEN_REGISTRY_URL` [+ `TEMPLATE_GEN_REGISTRY_API_KEY`,
  `TEMPLATE_GEN_INSTITUTION_ID`] is set; `TEMPLATE_GEN_SKIP_REGISTRY=1` skips the check).
  `POST /generator/run` installs each generated page into `website/templates/` as the next
  free `scraper<N>.html` (immediately selectable in the Site Configurator), **injecting the
  `/js/fp.js` beacon tag** (the generator's HTML shell predates the fingerprinting layer),
  and carries the page's category-typed varList into `website/varLists/scraper<N>.txt` +
  `configs/generated_templates.json` (the manifest behind the per-site `canary_tokens`
  override); lists existing flavors with their categories. The page also has an **inline
  editor** for the text of an already-stored flavor: pick a `scraper<N>.html`, rewrite its
  HTML in a textarea with a live preview, and `POST /generator/edit` (→ `template_gen.save_template`)
  overwrites it. Editing is guarded so it can never break the live honeypot — the save
  **validates Jinja syntax** (`server.py` renders the page with Flask's Jinja, so an
  unbalanced `{{ }}`/`{% %}` would 500 every visitor), **re-injects `/js/fp.js`** if the edit
  dropped it, and writes **atomically**; it only edits the page text (the varList /
  `canary_tokens` a deploy mints are untouched, and a dropped `{{ varN }}` slot is surfaced,
  not blocked). Takes effect on the next redeploy of a site using that flavor.
- **Crawler Analytics (`/logs`, `analytics.html`, `services/request_log.py` +
  `fingerprint_service.py` + `graph_intel.py`)** — the merged **traffic** view. Three things
  on one page:
  1. *Request log* — read-only viewer of the central `all_visits` table; queries `logdb` by
     shelling `psql` in the logdb container via the shared `services/logdb.py` fast path
     (a cached-container-id `docker exec`, ~0.2s cheaper per query than the old
     `docker compose exec` form, which remains the self-healing fallback) and parsing
     `json_build_object(...)` (filter/paginate/search in SQL; strings escaped via
     `_sql_literal`). Marks each site **active** vs **historical** from `set $site_name` in
     `proxy/conf.d/*.conf`. Search, site/method filters, pagination, CSV export
     (`GET /logs/export.csv`), per-request header inspector (in a **full-width expandable
     row** beneath each request, not the old narrow right-hand cell). The top KPI strip is
     trimmed to the **four** essential tiles (Requests · Last 24h · Live routes · Unique
     devices); pagination links append `#traffic` so the page doesn't jump to the top. **Each
     request row is fingerprint-enriched**: `request_log` LEFT-JOINs the browser fingerprint
     that actually belongs to that request — the beacon from the same IP **and matching UA**,
     **within a ±`FP_JOIN_WINDOW_MIN` (30-min) window**, **preferring the richer `unload`
     beacon** (which carries the real click/scroll/keystroke biometrics; the `load` beacon
     is empty), and **pageview-aware**: fp.js stamps every beacon of one page load with a
     shared random `pv_id` (read from the collector's `raw` jsonb — no schema change), and
     the join first identifies the request's *own* pageview (nearest beacon at/after it),
     then attaches that pageview's **latest cumulative** unload beacon — so re-armed beacons
     (see fp.js below) keep the row's biometrics current, and a request never inherits the
     *previous* page's unload beacon (which fires the instant that page is left, i.e.
     closest-in-time to the new GET). Falls back to nearest-unload for pre-`pv_id` rows.
     Never blindly glues one device's fingerprint onto every IP-sharing request, nor an
     unrelated session hours away. It also adds the per-IP
     TCP/IP-OS inference and runs **every** row (beacon or not) through the cross-layer
     consistency engine for a per-request **verdict** (reusing `fingerprint_service.verdict_for`
     → `crawler_graph.analysis.consistency`), so a browser-UA request that never ran JS
     surfaces the `browser_no_js` signal. Rows whose device is identity-rotating are flagged
     **disguised**. The CSV export path (`enrich=False`) returns just the raw request columns.
     Degrades gracefully when the fingerprint tables don't exist yet.
     `fingerprint_service.severity_of(row)` collapses each verdict into a **3-tier row color**
     — green (`clean`) / orange (`suspicious`) / red (`malicious`, = disguised **or**
     cross-layer-inconsistent). **There is no Device/verdict column** — the whole row is
     tinted, the verdict + short reason live on the row's hover `title` and at the top of the
     expandable Detail panel (a legend above the table explains the colors).
     The **Time** column is localized to the *viewer's* timezone in a short form by a
     client-side script (full ISO kept on hover). **Prev/Next page instantly** via
     `GET /logs/fragment` (renders only the `_traffic_rows.html` `<tbody>` and swaps it in
     place with `history.pushState` — no full-page reload, no scroll jump; the `<a href>` is
     the no-JS fallback). The pager also **prefetches the neighbouring pages** into a small
     client-side cache after every render, so a click usually swaps with zero latency, and
     `disguise_summary` is briefly TTL-cached (`max_age`) so paging costs one psql
     round-trip, not two. The stylesheet link is cache-busted by mtime (`?v=`), so CSS
     changes always reach the browser.
  2. *Device fingerprints* — KPI strip from `fingerprint_service.summary_counts()`, plus a
     **Disguised-devices panel** (`fingerprint_service.disguise_summary()`): each row is one
     physical device (`fp_id`) flagged on one of two **bases with different severities**.
     `basis="identities"` (≥2 claimed identities → its requests go **red**): identities are
     counted **version- and brand-insensitively** (`known_crawlers.ua_identity`: browser
     **engine** family + OS family, e.g. `chromium:Windows`; bots by provider; tools by
     product token) because the fp_id hashes engine-rendered surfaces with nothing
     brand-specific — a browser auto-update (Edg/149 → Edg/150) and a second same-engine
     browser (Chrome + Edge on one machine; all iOS shells are WebKit) are ONE identity,
     while a second engine (chromium↔gecko/webkit), another claimed OS, headed→HeadlessChrome,
     browser→tool, or a bot UA still count. `basis="networks"` (one identity, ≥2 public
     netblocks → its requests only go **orange**): that shape is proxy/VPN rotation but
     equally a phone hopping Wi-Fi/LTE. Blocks are counted in Python
     (`_public_netblock_count`) per address family as max(v4 `/24`s, v6 `/48`s) over
     **public** addresses only — dual-stack is one network, v6 privacy-extension churn stays
     inside its /48, and private/loopback/CGNAT sources never count (behind the local Docker
     hop the proxy sees the *gateway's* address, and recreating the stacks renumbers it —
     172.18.0.1 one week, 172.19.0.1 the next). This is the canary-token disguise signal seen
     through the device layer (the honeypot now serves one device one canary set), listing
     the UAs and source IPs it wore. The campaign-level device-stitch rule has the matching
     guard: a shared fingerprint across ASNs only reads as a disguise campaign at crawl
     volume, with automation tells, or ≥`DISGUISE_DEVICE_MIN_ASNS` (default 4) ASNs — a
     commuting phone on 2-3 ASNs at casual volume is mobility, not proxy rotation.
  3. *Campaign Intelligence* — an insights band plus a collapsible full breakdown (the
     `_campaigns.html` partial): GraphSAGE GNN attribution, **disguised infrastructure**,
     **agentic browsers**, **cross-layer contradictions**, **VM/container cohorts**, and the
     all-campaigns table, read from the persisted `crawler_graph/output/campaigns.json`
     (`graph_intel.load_report()`). **Recompute** (`POST /intel/recompute`) re-runs the
     pipeline against the live `logdb` and redirects back to `/logs`; ticking **GraphSAGE
     GNN** (`use_gnn=True`) also trains + applies the provider-attribution model **in-process**
     (needs torch_geometric, baked into the image; `gnn_available()`/`gnn_status()` gate it),
     surfacing train/val accuracy + provider classes via `meta.gnn`. The network graph renders
     two ways: `GET /intel/graph.png` (static PNG) and `GET /intel/graph.html` (a
     **self-contained interactive** HTML graph — per-cluster colour + hover rundown, no
     external libs/CDNs — embedded as an iframe; `reporting.render_interactive`).
- **LLM Forensics (`/query`, `forensics.html`, `services/querying_service.py` +
  `auto_query_adapter.py` + `provenance_service.py`)** — the merged **forensics** view:
  detection + manual evaluation + provenance + membership inference on one page.
  0. *Provider API keys* — a collapsible card (`keys_service.provider_rows()`) manages the
     keys the engine queries with. `POST /query/keys` writes the **git-ignored project-root
     `.env`** (only the allowlisted `WRITABLE_KEY_VARS` — never arbitrary vars) and updates
     the live process env, so a saved key takes effect on the next run with **no restart**
     (the engine also re-reads `.env` before every query via `refresh_env()`; compose reads
     the same file on `up`). Keys are shown masked, never in full.
  1. *Run an investigation (detection)* — runs on the **`auto_query` engine** (see its
     section below) via the dashboard adapter, **in the background**. Pick a **local honeypot
     site** (template + varList read from `website/`, page scraped through the proxy for the
     subject, ground truth from its `new_agents_vars` table) or a **custom URL** (matched
     against a bundled CSV). The launcher has a **querying-mode toggle**: *Offline demo*
     (only the `mock/*` simulators — no API keys used) vs *Use API keys* (a key-aware model
     list: models whose provider key is configured are selectable/pre-checked, keyless ones
     are shown locked with a "no key" badge). The choice is **enforced server-side** by
     `querying_service.resolve_model_choice(key_mode, models)` (offline drops live ids and
     falls back to the mocks; api keeps mocks + key-ready ids and rejects an empty choice
     back to the launcher with a banner) — the same gate governs the provenance/RAG buttons,
     which share the form. `POST /query/run` starts the run on a worker thread
     (`run_manager`) and **redirects immediately** to `GET /query/runs/{run_id}`, which
     renders a **live view** — a stage stepper and per-model cards that fill in as each
     model answers — polling `GET /query/runs/{run_id}/status` (JSON). When the run
     completes the page swaps to the **final results only**: matched canary tokens, the
     per-crawler **attribution profile**, the cross-model **ranking** table, and the
     human-readable attribution summary. The **intermediate pipeline stages are deliberately
     not rendered inline** — the composed retrieval prompt, raw per-model responses, and the
     content-extraction output live on the run page's **Downloads card**, served by
     `GET /query/runs/{run_id}/download/{artifact}` (`results` full-record json ·
     `results.csv` per-model summary · `prompt` · `raw_responses` · `extraction`; built by
     `querying_service.run_artifact`, available for detection **and** manual runs). A
     per-model provider failure is shown with a **classified reason** (API-key problem /
     out of credits / rate limited / model unavailable / network) + the raw provider detail.
     A run whose process was killed mid-flight is detected and shown as **interrupted**
     (the page never spins forever).
  2. *Manual evaluation* — for providers without a suitable search API (ERNIE, Kimi, Meta
     AI…): `POST /query/prompt` generates the site's retrieval prompt (shown inline +
     `GET /query/prompt.txt` download), the researcher runs it in each chatbot by hand, then
     `POST /query/manual` accepts a `Model`/`Responses` spreadsheet (xlsx/csv, parsed by
     `auto_query/manual_io.py` with openpyxl — no pandas) or inline pairs and evaluates them
     **identically** to API runs (a `kind="manual"` run, same run-detail page — including the
     same Downloads card, minus the prompt artifact a manual run doesn't generate).
  3. *Membership inference* — `POST /provenance/membership-demo` runs the offline
     served-vs-control Min-K% demo (score distribution + p-value); the result survives the
     post/redirect and renders inline.
  4. *Model-version timeline (provenance)* — `POST /provenance/run` (kind=`provenance`) runs
     the crawl-to-train latency probe (ingestion windows from model-version cutoffs) and the
     RAG-vs-training experiment (browsing off/on + live-fetch correlation). Both probes now
     run **in the background** like detection (the service persists a `running` placeholder
     report, spawns a worker thread, and redirects at once; the report page polls
     `GET /provenance/runs/{id}/status` and reloads when done, and a probe killed by an app
     restart is shown as **interrupted**). The launcher's querying-mode toggle gates these
     buttons too, and per-model provider failures are *reported in the results*
     (`probe_models` records an error per model; a RAG model whose passes all fail is
     verdict `provider error`, and an on-only leak with a failed off-pass is
     `inconclusive` — never a silent "no evidence"). Reports persist
     under `querying/provenance/` (written atomically — the live poller may read mid-run)
     and the per-run detail page is `GET /provenance/runs/{run_id}`
     (`provenance_detail.html`, showing the adversarial probe used + per-crawler canary mint
     times). A "Recent investigations" list spans detection + manual runs and provenance reports.

#### The auto_query detection engine (`auto_query/`)
The **current detection engine** — vendored from the team's `auto-query-integrate` GitLab
branch (commit `e2d055dd`), which was designed to be embedded in a host application: HTML,
the faker template text, and ground-truth rows are **supplied by the caller**, never loaded
from its own disk layout. The app's `app/services/auto_query_adapter.py` is that host-side
caller (the analogue of the branch's `adapters/local_adapter.py`). Four independent
pipelines (`auto_query/pipelines/`):

```
generate_prompt_pipeline(html, faker_template [, rendered_html])
    parser -> template_analyzer -> attribute_generator -> prompt_generator
    (one composed retrieval prompt; rendered_html supplies the subject when the
     template's title is a {{ varN }} placeholder)
        |
        v
api_query_pipeline(artifacts, models [, context])     OR    manual_query_pipeline(records)
    LiteLLM completion per model (web_search_options),      normalize hand-collected
    mock/* ids answered by an offline simulator             Model/Responses records
        |                                                          |
        +------------------ raw_responses ------------------------+
        v
evaluate_pipeline(raw_responses, faker_template, database_rows)
    schema_generator -> content_extractor_llm -> matcher_v4 (RapidFuzz: exact +
    containment + fuzzy>=95) -> per-crawler attribution profiles (compressed/deduped)
    -> cross-model ranking -> human-readable attribution summary
```

Two LLM roles, both offline-safe:
- **Target models** go through LiteLLM (`src/llm_client_litellm.py`): any provider = its
  standard API-key env var + one line in `auto_query/config/models.py`. `mock/scraper-sim` /
  `mock/honest-llm` are handled by a built-in simulator (never sent to LiteLLM), keeping the
  positive/negative demo working with no keys. `litellm.drop_params` is on so providers that
  reject `web_search_options` still answer.
- **Internal processing** (attribute generation, schema generation, content extraction) runs
  on GPT-4.1 via `src/openai_client.py` (`OPENAI_API_KEY_INTERNAL`, optional
  `OPENAI_API_BASE_INTERNAL`); with no key each step falls back to a **deterministic
  heuristic**, which is what `make test-suite` exercises.

**Live querying, keys & errors.** Real queries take many seconds per model, so detection
runs execute on a **background worker thread** (`app/services/run_manager.py`): the POST
returns at once and the run page polls a small status endpoint, revealing attribution only
when the run finishes. Keys reach the container the standard way — env vars passed through
`docker-compose.app.yml` and substituted from the project-root `.env` — and are managed from
the dashboard (`app/services/keys_service.py` writes that `.env`); `config.models.refresh_env()`
re-reads it before every readiness check and query so a saved key applies with no restart.
Provider failures are classified by `llm_client_litellm.classify_error` into
auth / quota / rate_limit / model_not_found / network / provider_error, each with a
human-readable hint carried into the run record and the live view. `querying.store.save_run`
writes atomically (temp + `os.replace`) so the live poller never reads a half-written run.

The adapter maps the evaluation output onto a **legacy-superset run record** persisted via
`querying.store.save_run` — every key the UI/stats/testsuite already read
(`results[].best_match.{bot,matches,jaccard_score}`, `summary.{models_tested,matches_found,
best_score,ground_truth_rows,threshold}`) is preserved (`jaccard_score` now carries the
engine's *coverage*, same 0..1 scale); `attribution_profile`, `summary.ranking`,
`summary.attribution_summary`, `kind` (`detection`|`manual`) and `engine: "auto_query"` are
added alongside. A model counts as a **leak** at coverage ≥ `HIGH_RISK_THRESHOLD` (0.3) or
≥2 canaries recovered from one crawler row. Deps live in `app/requirements-autoquery.txt`
(litellm, openai, rapidfuzz, openpyxl — deliberately **not** langchain/pandas/spaCy),
installed as a late Docker layer. The branch's legacy `src/pipeline.py` monolith and its
disk-based demo driver were deliberately not vendored.

#### The legacy querying pipeline (`querying/`)
A Python **package** (run from the repo root: `python -m querying.main ...`, or imported by
the app). Refactored from the old standalone `auto-querying/` prototype to be
location-independent, persistent, and offline-safe. **No longer the engine behind the
`/query` detection UI** (that's `auto_query/` above), but still load-bearing: it hosts the
Direction-6b **provenance/membership layer**, the **run store** + **ground-truth loaders**
the adapter reuses, and remains the CLI + rollback path. Flow (`pipeline.run_query`):

```
parser.parser(url, host_header)   scrape page (1 request; optional Host for proxy routing;
        |                          spaCy NER if installed, else a title/heading heuristic)
        v
prompt_generator.generate_probes  pick an adversarial role prompt + retrieval questions (seedable)
        v
ground_truth.load_*               canary rows from the site DB (docker) or a CSV
        v
llm_client.llm_responses          query each target model (provider by id prefix)
        v
extractor.extract_info            normalize each answer into list-valued evidence fields
        v
matcher.matcher                   exact-set Jaccard of evidence vs. var1..var10 per row
        v
store.save_run                    persist one JSON per run under querying/runs/ (git-ignored)
```

Provider routing is by **model-id prefix**, with no API key required for the offline path:
- `mock/scraper-sim` — simulates a model that *ingested* the page; its answer leaks the
  site's canary tokens (passed as `context.leak_candidates`), so the matcher reports a high
  Jaccard. This is what a positive detection looks like end to end.
- `mock/honest-llm` — simulates a model that never saw the page; generic answer, no leak.
- `openrouter/<model>` — OpenRouter's OpenAI-compatible API (`OPENROUTER_API_KEY`).
- `anthropic/<model>` — the Anthropic Messages API (`ANTHROPIC_API_KEY`); default Claude
  model is the latest (`claude-fable-5`).

The **extractor** (`querying/extractor.py`) is a separate role, selected by
`QUERY_EXTRACTOR_PROVIDER` (`mock` heuristic / `openai`-compatible / `anthropic`). Keep the
target-vs-extractor distinction. Matching only scores **list-valued** extractor fields
against **`var1`..`var10`** — the contract the old prototype relied on. `jeniffer.csv` and
`21.csv` are bundled sample ground-truth datasets; `create_csv.py` regenerates `21.csv`
from `21.xlsx` (import side effect — don't import it as a module).

#### Crawler intelligence & training-data provenance (Direction 6)
Two additive research layers on top of the existing logging + querying.

**6a — crawler graph (`crawler_graph/`, app Crawler Analytics `/logs`).** Clusters the central
`all_visits` log into attributable *campaigns*. TLS fingerprints (JA3/JA4) are
captured **passively** by a **Zeek sidecar that shares nginx's network namespace**
(`proxy/tls-capture/`, `network_mode: "service:nginx"`, `cap_add: NET_RAW`), so it
reads the raw ClientHello *before* nginx terminates TLS — a true fingerprint with
**no nginx rebuild**. Zeek writes JSON `ssl.log`; `proxy/tls-shipper/` streams it
into a new `logdb.tls_handshakes` table. nginx now also forwards the client source
port (`X-Client-Port` → `all_visits.client_port`, an **additive** column added by
the collector via `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`) so each handshake
joins to the HTTP requests its connection carried by the `(client_ip, client_port)`
4-tuple. The graph (IP nodes linked through shared JA4/UA/`/24`/ASN attribute hubs)
is partitioned by Louvain/Leiden; an optional **GraphSAGE GNN** (`ml/gnn.py`, torch +
torch_geometric, **baked into the app image** so it trains in-process from the
Crawler Analytics (`/logs`) "Recompute with GraphSAGE GNN" button — torch already ships for the
template generator, `torch_geometric` is added in a late Docker layer) attributes
providers. It requires **≥2 declared-provider classes** to train (a single-class
model is degenerate and is deliberately skipped). Output:
`crawler_graph/output/campaigns.json` (+ `gnn_model.pt`, `gnn_predictions.json`).
The point is catching crawlers that
**disguise** themselves (undeclared infra on browser UAs; agentic browsers) — honest
declared crawlers need only UA + published IP ranges.

**6b — provenance (`querying/{model_timeline,provenance,membership,rag_disambiguation}.py`,
app LLM Forensics `/query`).** Dates *when* a model ingested a site's canaries: derive each
crawler's mint/crawl time from `new_visits` (no schema change), probe successive
model versions (`model_timeline.py` cutoffs), and from which versions reproduce a
canary set bound the ingestion window + crawl-to-train latency. `membership.py`
adds Min-K%/Min-K%++ membership inference (served vs. never-served watermark
controls → a p-value) for guarded models that won't regurgitate;
`rag_disambiguation.py` separates training-memorization from live retrieval
(browsing off/on + `all_visits` live-fetch correlation). `llm_client` gained an
additive `options={"browsing": True}` path; the normal pipeline is unchanged.
**Provider routing note (load-bearing):** `llm_client` routes any *other*
`<provider>/<model>` id (`gemini/...`, `openai/...` — the auto_query registry
ids the launcher pool shares) through **LiteLLM**, and a failure there raises
into a per-question error. It must **never** fall back to the offline mock for
a prefixed id — `mock/scraper-sim`'s answer deliberately fabricates a leak,
which would attribute false ingestion evidence to a real model (this was a real
bug: the old bare fallback sent unknown prefixes to the leak simulator).

**Load-bearing notes:** the `client_port` log field + `X-Client-Port` mirror header
are additive and do **not** touch routing/XFF/the catch-all/TLS. The Zeek sidecar
is passive (never in the request path). Verify once that Zeek's `id.orig_h` equals
nginx's `$remote_addr` (Docker DNAT vs. userland-proxy) — see
`crawler_graph/README.md`.

#### Adversarial self-play (Direction 2, `selfplay/`, app `/selfplay`)
An **additive, read-only** RL layer that turns the `crawler_graph` detector into the
reward channel of a two-player game. It never edits the runtime layers and writes
only under `selfplay/output/` (its own dir — **never** `crawler_graph/output/`, so a
training loop can't clobber the live `/logs` artifacts).

- **The oracle is the production detector.** `selfplay/defender.py` scores a synthetic
  attacker cohort by calling `crawler_graph.pipeline.run_intel(visits=…,
  resolve_asn=False, use_gnn=False, write=False)` — the *same* rule ensemble
  (`graphing.campaigns._summarize`) + cross-layer consistency (`analysis.consistency`)
  the live page uses — plus a dense per-endpoint consistency signal. So an evasion the
  agent finds is a real adversarial example against the live pipeline. (Frozen-GNN
  folding is **off by default**: the real-data GraphSAGE model doesn't transfer to the
  synthetic feature distribution — `SP_USE_GNN=1` only with a calibrated real-data sim.)
- **Constrained MDP.** `selfplay/traffic_model.py` simulates a *campaign operator*
  (a pool of public-IP proxy identities) in `all_visits`-shaped rows; the attacker's
  4-factor `MultiDiscrete` action (`actions.py`: identity rotation, timing, fetch,
  **stack rung**) walks a **cost-to-evade ladder** grounded in `consistency.py` (each
  cheaper rung trips a specific contradiction; only a residential-consistent stack at
  full infra cost evades). PPO-Lagrangian (`ppo.py`, a GRU policy in `policy.py` with
  reward + cost value heads + a learned dual λ) maximizes harvest s.t. a detection
  budget; risk-sensitive **CVaR** mode is a config flag.
- **Phase-0 calibration** (`calibration.py`) gates training: per-feature KS + an
  adversarial-AUC classifier (pure numpy) confirm the sim is indistinguishable from
  real `all_visits` on the exact `features.node_vector` the detector consumes.
- **The v1 deliverable** is a **robust detector** (`robust_detector.py`: a 2-layer MLP
  over `node_vector` — an MLP, not a GNN, because the evader deliberately breaks graph
  edges) trained on the attacker's hard-negatives, saved to `robust_detector.pt` and
  run as a **second opinion** on `/logs` (`score_live` → `robust_predictions.json`,
  refreshed by `POST /intel/recompute`). It never silently replaces the live detector.
- **v2:** `coevolve.py` runs PSRO (best-response attacker ⇄ best-response robust
  detector, defense-in-depth folded into the oracle) tracking **exploitability**;
  `ingestion.py` closes the D5/D4 loop — a Thompson-sampling content bandit rewarded by
  **provable ingestion** (`querying.membership` Min-K% p-value), emitting a
  human-in-the-loop content-policy recommendation for the Site Configurator.
- **Dependency-light:** torch + numpy + networkx + stdlib only (no gymnasium/scipy/
  sklearn/RLlib) — all already in the app image. Training runs in the dedicated
  `trainer` compose service (profile `trainer`, CPU-only) via `make selfplay-*`, or as
  a background subprocess from the `/selfplay` page. `python -m selfplay selftest` is
  the offline end-to-end check (core + a short PPO run + v2 + isolation assertions).

#### Device fingerprinting (Layer 1/2/3)
Three additive fingerprint surfaces extend Direction 6a's TLS layer (all flow through the
same `logdb → crawler_graph → /logs` pipeline; all degrade gracefully when their table is
empty):

- **Layer 1 — browser fingerprints.** Honeypot pages embed `website/static/js/fp.js` (a
  one-line `<script src="/js/fp.js" defer>` in each `scraper{N}.html`). It reads the JS-visible
  surfaces (canvas, WebGL/WebGPU, AudioContext, fonts, screen/window geometry, navigator/UA-CH,
  automation tells) plus behavioral biometrics (mouse/scroll/keystroke + synthetic-humanization
  detection; idle gaps > `IDLE_GAP_MS` are excluded from the timing distributions so reading
  pauses / tab-aways don't corrupt the regularity stats) and POSTs JSON payloads via
  fetch/`sendBeacon` to **`/__fpbeacon`**: a `load` beacon ~1.2s in (zero behavior) and
  **re-armable cumulative `unload` beacons** — each tab-hide/pagehide flushes the updated
  totals *iff* new interaction accumulated since the last flush (the old one-shot `flushed`
  boolean silently lost everything after the first tab-away). All beacons of one page load
  share a random **`pv_id`** so the request log can attach the newest beacon of the right
  pageview. nginx routes
  that **exact path** (additive `location = /__fpbeacon` in `site.conf.j2`, tagged with
  `X-Site`/`X-Real-IP`/`X-Client-Port`, XFF overwritten) to the new **`fp-collector`** service →
  `logdb.browser_fingerprints`. The payload schema in `fp.js` is the contract shared with the
  collector and `crawler_graph.ingest.enrich.join_browser_fingerprints`. Canvas/WebGL/audio/font
  hashes + the composite `fp_id` become the strongest graph attribute hubs (cross-IP/proxy device
  stitching). A non-JS scraper never beacons — that *absence* is itself a signal. `fp.js` also
  writes the composite `fp_id` into an `__abd_fp` cookie so `server.py` can serve a returning
  device its **stable canary set** across UA/IP/ASN rotation (see §"Request handling"); the async
  surfaces (audio/webgpu/ua-CH/**permissions**) each use a once-only settle guard so the beacon
  is assembled only after all four resolve (a missing guard on `permissionAnomaly` used to fire
  finalize early and intermittently drop WebGPU). The request↔beacon join is by
  `(client_ip, user_agent)` within a time window, pageview-aware via `pv_id` (from the
  collector's `raw` jsonb) and preferring the latest cumulative `unload` beacon (**not** the
  `(client_ip, client_port)` 4-tuple, which is unreliable here since the beacon rides a separate
  connection).
- **Layer 2 — TCP/IP OS inference + JA4H.** The Zeek sidecar also logs each client SYN
  (`proxy/tls-capture/scripts/tcp-fingerprint.zeek`, loaded separately + guarded so it can't
  break the SSL path); the (now multi-log) `tls-shipper` computes a p0f-style OS guess
  (TTL+window/scale) + a JA4T-style signature into `logdb.tcp_fingerprints`, joined by 4-tuple.
  **JA4H** (an HTTP-header signature) is computed purely from the already-stored
  `all_visits.headers` (no new capture). The SYN's source is only the real client when the proxy
  receives connections directly / via source-preserving DNAT (the same caveat as the TLS-IP match
  — behind a userland docker-proxy the client SYN may not be visible; the script filters to
  service ports 80/443 so it never logs nginx's own egress).
- **Layer 3 — cross-layer consistency.** `crawler_graph/analysis/consistency.py` scores each
  endpoint's *internal contradictions* (claimed UA/JS OS vs. the TCP/IP kernel, WebGL VM/software
  renderer cohorts, automation/behavioral tells). Automation uses **strong/weak tell weighting**
  (`automated_from_tells`: a strong tell like `webdriver`/`cdc`/`headlessUA` alone, or ≥2 weak
  tells — not any single benign tell), and `VM_RENDERER_MARKERS` is deliberately narrow (no broad
  `software`/`gallium`/`virgl`/ANGLE-Vulkan substrings that match real Linux/Android GPUs), both
  to bound false positives on privacy-hardened / VM / WebView real users. Folded into campaign
  disguise detection and
  surfaced on the **Crawler Analytics** page (`/logs`) — both per-request (the fingerprint-enriched
  request log calls the same engine for a per-row verdict) and per-campaign (the campaign
  intelligence breakdown). Validated by the offline selftest
  (`python -m crawler_graph selftest`), which now also asserts device-stitching, the OS
  contradiction, and VM-cohort detection.

#### Template generation (`template_generator/`)
An **additive, self-contained** sidecar that fine-tunes **Qwen3-1.7B** with **LoRA** and
uses it to author honeypot pages across **20 content categories** (`CATEGORIES` in
`generate_templates.py`: towns, movies, biography, animals, books, ...). It writes only
inside `template_generator/` — it never modifies the website, Ansible, or UI layers. Pipeline:

```
scraper.py             -> data/text_generator_dataset/    (Wikipedia scrape into 20 category folders; needs `datasets`)
prepare_data.py        -> data/sft.jsonl                  (corpora masked to [[NAME]]/[[NUM]])
train.py               -> models/Qwen3-1.7B-lora/         (LoRA adapter only; base model from HF cache)
generate_templates.py  -> generated_templates/scraper_gen_<category>.{html,txt}  (+ raw_<category>.txt)
```

`generate_templates.py` makes **one template per category per run** (`--category <id>` for
just one; no `--num`/`--seed`). Numbers/dates are stripped entirely; each `[[NAME]]` is
type-classified (place/person/org) and routed to a matching noun slot, so every template is
a pair: `scraper_gen_<category>.html` (page with `{{ var1 }}..{{ var10 }}` slots) and
`scraper_gen_<category>.txt` (its **category-typed varList** — one base-Faker expression per
slot). Titles + content hashes + SimHash near-duplicates are **deduped through a registry**:
the local `template_registry.jsonl` by default, or the central **`registry_api/`** FastAPI
service (`--registry-url` + `--registry-api-key`, per-institution keys; its own
docker-compose, SQLite state) so multiple institutions never publish the same fake facts;
`--skip-registry-check` for offline dev, `--reprocess` to rebuild pages from saved
`raw_*.txt` without torch. The folder also carries `server.py`/`honeypot.db` — a standalone
Flask demo server (SQLite, per-category `templates/` + `varLists/`) from the upstream
branch; the deployed honeypot remains `website/server.py`. **Deploying a generated template
is automatic through the app**: the `/generator` page installs the HTML as
`website/templates/scraper<N>.html` and records the varList for the per-site
`canary_tokens` override (see Canary tokens). See `template_generator/README.md` for
training and cross-machine notes.

---

## 2. Development commands

### Prerequisites
- **Docker daemon must be running** (Docker Desktop or `colima start`) before any deploy. On
  macOS the `prereqs` Ansible role (gated on `os_family == 'Darwin'`) checks for Homebrew,
  installs the Docker CLI + compose plugin if missing, and verifies the daemon is reachable.
- Inventory targets `localhost` with a **local connection** only — there is no remote SSH
  deployment. This is a **local-only** build (no cloud, load-balancer, or remote-DNS logic).

### Top-level `make` targets (run from project root)

| Command | What it does |
|---|---|
| `make up-all` | Bring up everything: the proxy stack, the web app, **and** every site in `configs/sites/`. |
| `make down-all` | Tear down the web app, the proxy, and every site stack. |
| `make app` | Ensure `proxy_net`, then start the unified web app → http://localhost:8000. **Builds the image only when it's missing or a build input (Dockerfile / a `requirements-*.txt`) changed; otherwise just `up -d` (code is picked up from the runtime bind mount, so code edits need no rebuild).** |
| `make app-build` | Force a full rebuild of the app image, then start it. Run after editing a requirements file or the Dockerfile. |
| `make app-down` / `make app-logs` | Stop / follow logs for the web app. |
| `make app-dev` | Run the app on the host with `--reload` (needs `pip install -r app/requirements.txt`). |
| `make proxy` | Ensure `proxy_net`, then start the reverse-proxy stack (generates the TLS cert) → http://localhost:80 + https://localhost:443. Same rebuild-only-when-needed logic as `make app` (rebuilds a proxy service image only when its source changed). |
| `make proxy-build` | Force a rebuild of the proxy service images (collector/fp-collector/tls-shipper/tls-capture), then start the stack. |
| `make proxy-down` / `make proxy-logs` | Stop the proxy stack / follow nginx logs. |
| `make ensure-net` | Create the shared external `proxy_net` network (idempotent). |
| `make playbook site_id=<id>` | Start the app container and deploy a single site by id (fails if `site_id` is omitted). |
| `make stack-up` | Start the app container and run its playbook for **every** `configs/sites/*.yaml`. |
| `make stack-down` | `docker compose down` every rendered site in `website/sites/*/`. |
| `make intel` | Build crawler campaigns from the central log → `crawler_graph/output/campaigns.json` (run in the app container). `make intel-selftest` runs the offline synthetic check. |
| `make selfplay-train` | Train the adversarial self-play attacker + robust detector (Direction 2) in the dedicated `trainer` container → `selfplay/output/`. Also `selfplay-coevolve` (PSRO v2), `selfplay-ingest` (content-policy bandit), `selfplay-calibrate`, and `selfplay-selftest` (offline check). Override args via `SP_ARGS`. |
| `make provenance site_id=<id> db_name=<scraperN-db>` | Probe a deployed site's canaries across the model-version timeline to date ingestion (Direction 6b). |
| `make test-suite` | Run the offline, deterministic pytest suite (`testsuite/run_tests.py`) — no Docker/Postgres/keys needed; writes a per-feature report to `testsuite/reports/`. |

`app` and `proxy` depend on `ensure-net`; `stack-up` and `playbook` depend on `app` because
Ansible is installed in that container. `up-all` brings the proxy up **before** the app and
sites so the per-site `nginx -s reload` succeeds.

### Running the legacy querying pipeline CLI (from the repo root)
The `/query` page's detection runs on the `auto_query` engine (real providers: set
`OPENAI_API_KEY_INTERNAL` + the LiteLLM provider keys, e.g. `GEMINI_API_KEY` /
`OPENAI_API_KEY`; offline it falls back to `mock/*` + heuristics automatically). The old
pipeline is still runnable directly:
```
# Offline demo (no API keys) against any URL, matched to the bundled sample dataset:
python -m querying.main --url https://example.com/ --models mock/scraper-sim mock/honest-llm
# Against a locally-deployed honeypot site through the reverse proxy:
python -m querying.main --site site-001 --db-name scraper1-db --db-user user --models mock/scraper-sim
```
Real providers: set `OPENROUTER_API_KEY` / `ANTHROPIC_API_KEY` and pass `--models openrouter/<id>`
or `anthropic/<id>`. Set `QUERY_EXTRACTOR_PROVIDER=anthropic|openai` (+ keys) for LLM extraction.

### Running the playbook directly
The `deploy` role ensures `proxy_net` itself, so this works standalone on a fresh machine
without `make ensure-net` first:
```
cd ansible && ansible-playbook site.yml -e site_id=site-001
# extra overrides forward as -e key=value, e.g.:
cd ansible && ansible-playbook site.yml -e site_id=site-001 -e reset_db=true
```

### Testing routing without real DNS (Host header / SNI selects the site)
```
# Plain HTTP:
curl -H "Host: site-001.dukecodeplus.example" http://localhost/
# HTTPS (-k to accept the self-signed cert; --resolve maps the SNI hostname to loopback so
# the TLS handshake and Host both carry the real site name, like a normal https request):
curl -k --resolve site-001.dukecodeplus.example:443:127.0.0.1 \
     https://site-001.dukecodeplus.example/
# Or, equivalently, force Host + SNI by hand:
curl -k -H "Host: site-001.dukecodeplus.example" https://localhost/
# Inspect the presented cert:
openssl s_client -connect localhost:443 -servername site-001.dukecodeplus.example </dev/null \
  | openssl x509 -noout -subject -ext subjectAltName
```
For browser testing add `/etc/hosts` entries (`127.0.0.1 site-001.dukecodeplus.example`) or
use the `*.localhost` alias (browsers resolve it to loopback automatically). Over HTTPS the
self-signed cert triggers a one-time browser warning (expected for the local build).

### Running the Flask app standalone (no Docker), from `website/`
```
python server.py           # genmode on (generates canaries for new visitors)
python server.py nogen     # genmode off (serves "Null" vars, stores nothing new)
```
Serves on `0.0.0.0:8080` and needs reachable Postgres via `DB_USER` / `DB_PASS` / `DB_HOST`
and `SCRAPER_VERSION`.

### Installing dependencies
Each layer pins its own deps and is normally installed inside its Docker image:
- `website/requirements.txt` (Flask 3.1, SQLAlchemy 2, psycopg2-binary, faker + faker-edu +
  faker_food, ipwhois, user_agents, python-dotenv; `openai` is present but dead).
- `app/requirements.txt` (fastapi, uvicorn, jinja2, python-multipart, ruamel.yaml, plus the
  querying deps requests/beautifulsoup4/httpx). The app image also installs
  `ansible-core==2.17.4` + `community.general` and the Docker CLI, the **template-generator
  ML stack** (`app/requirements-ml.txt`: transformers/peft/accelerate/numpy, with torch from
  PyTorch's cu128 index) for the `/generator` page, and **`torch_geometric`** (a late layer
  on the baked torch) for the Crawler Analytics (`/logs`) GraphSAGE GNN — both run in-container, no extra env.
  `crawler_graph/requirements.txt` (networkx, python-louvain, ipwhois, matplotlib) installs
  in a late layer too, as does `app/requirements-autoquery.txt` (litellm, openai, rapidfuzz,
  openpyxl — the auto_query detection engine). **Keep `app/requirements.txt` byte-stable and
  add new app deps in one of the late-layer files**: the early `COPY app/requirements.txt`
  sits before the torch install, so touching it forces the multi-GB ML re-download. For host
  runs (`make app-dev`): `pip install -r app/requirements.txt -r app/requirements-autoquery.txt`.
- `querying/requirements.txt` (requests, beautifulsoup4, httpx; spaCy is optional — without
  it the parser falls back to a title/heading heuristic).
- `proxy/collector/requirements.txt` (fastapi, uvicorn, psycopg2-binary).
- `template_generator/requirements.txt` (torch, transformers ≥4.56, peft, accelerate, numpy,
  faker, spaCy [optional]; `scraper.py` additionally needs `datasets`). Use its own venv —
  see its README; do not mix it with the website env. `registry_api/requirements.txt`
  (fastapi, uvicorn, pydantic, faker) is the optional central dedup registry service.

### Template generator (its own env; from `template_generator/`)
```
python prepare_data.py --wiki-limit 3000           # build data/sft.jsonl
python train.py --dtype bfloat16 --max-steps 800   # LoRA fine-tune -> models/
python generate_templates.py                       # one template per category (all 20)
python generate_templates.py --category towns      # a single category
python generate_templates.py --reprocess           # rebuild html/txt from raw_*.txt (no torch)
python generate_templates.py --skip-registry-check # offline dev: skip dedup registry
```
`run_all.sh` (macOS/Linux) and `run_windows.ps1` (Windows/NVIDIA) wrap the whole pipeline.

### Build / package / deploy
There is no separate build/package step beyond Docker. "Deploy" = run the Ansible playbook,
which renders the per-site compose + nginx config and runs `docker compose up -d --build`.
Deployment is local-only.

---

## 3. Coding conventions

- **Language / style.** Python throughout the runtime layers; Jinja2 for Ansible templates;
  YAML for Ansible vars/config. Match the surrounding file's style — the proxy/UI modules use
  clear docstrings and explanatory comments on load-bearing decisions; keep that.
- **`scraper_version` is never a literal in source.** Read it from the `SCRAPER_VERSION` env
  var (the playbook enforces this in `server.py` via a `replace` task).
- **Per-site ports must be unique** (`website.port`, `database.host_port`); the playbook
  refuses the deploy otherwise.
- **nginx config is generated, never hand-maintained.** All per-site blocks come from
  `site.conf.j2` and are reloaded (`nginx -s reload`), never restarted, so adding a site
  never drops the others.
- **Canary tokens live in `all.yml`**, rendered into `website/varLists/*.txt`.
- **Adding a honeypot flavor:** bump `scraper_version` (per-site yaml or default) and let the
  configure role scaffold `scraper{N}.html` / `scraper{N}.txt`, then edit the new HTML.

### Generated / build artifacts — DO NOT EDIT BY HAND
| Path | Generated by |
|---|---|
| `website/varLists/scraper{N}.txt` | `configure` role from `canary_tokens` (per-site override, else `all.yml`); also written at install time by the app's Template Generator |
| `configs/generated_templates.json` | the web app's Template Generator page on every install (version -> category + varList) |
| `website/sites/<site_id>/docker-compose.yml` | `configure` role from `docker-compose.yml.j2` |
| `proxy/conf.d/<site_id>.conf` | `configure` role from `site.conf.j2` |
| `proxy/certs/wildcard.{crt,key}` | `certgen` init container from `proxy/gen-cert.sh` |
| `configs/sites/<site_id>.yaml` | the web app's Site Configurator page |
| `configs/history/applies.jsonl` | the web app on every apply |
| `querying/runs/<run_id>.json` | the querying pipeline on every run |
| `template_generator/data/sft.jsonl` | `prepare_data.py` |
| `template_generator/generated_templates/*` | `generate_templates.py` |
| `template_generator/models/*` | `train.py` (LoRA adapters) |
| `template_generator/template_registry.jsonl` | `generate_templates.py` (local dedup registry; appended on every accepted template) |

To change canary tokens, edit `canary_tokens` in `all.yml` (or, for a generator-authored
flavor, the per-site list in `configs/sites/<id>.yaml`) and re-run the playbook — never
edit the varLists. To change routing, edit the per-site yaml (`proxy.server_name`) and re-run
— never edit `proxy/conf.d/*.conf`.

---

## 4. Testing and verification

- **There is a pytest suite (`testsuite/`) but no linter, type checker, or CI.** Run it with
  `make test-suite` (or `python testsuite/run_tests.py`) — it runs **offline and
  deterministically** (no Docker daemon, no Postgres, no API keys, no network: the host
  Docker CLI, the `psql` calls, the Ansible playbook, and model providers are all stubbed,
  and traffic is synthesized in-process). It exercises every user-visible feature against the
  project's *own* code (canary generators, UA parser, the crawler-graph clustering + real
  GraphSAGE GNN, the cross-layer consistency engine, querying/provenance, the proxy
  collectors, and the FastAPI routes) and writes a per-feature pass/fail/skip table plus
  `testsuite/reports/latest.{json,html}`. Install into its own venv from
  `testsuite/requirements.txt` (the GNN feature needs the extra `testsuite/requirements-gnn.txt`
  + a torch wheel, else it skips cleanly); run one feature with
  `python testsuite/run_tests.py <feature>` or `--list` to enumerate them. See
  `testsuite/README.md`. This suite is **fast offline regression coverage** — it does **not**
  replace the live-deploy verification loop below (it stubs Docker/nginx/Postgres, so it can't
  catch routing, TLS, or real-DB-write regressions). Do not invent other test commands.
- **After changing the website / Ansible / proxy layers**, the realistic verification loop is:
  1. `make proxy` (once) and `make playbook site_id=site-001` (or `make up-all`). Changing
     the proxy stack itself (`nginx.conf`, `docker-compose.proxy.yml`, certs) needs the nginx
     container **recreated** (`make proxy` / `docker compose -f docker-compose.proxy.yml up
     -d`), not just an `nginx -s reload` — port mappings and the cert mount are set at
     container-create time. Re-rendering a per-site block (`site.conf.j2`) needs the playbook.
  2. `curl -H "Host: site-001.dukecodeplus.example" http://localhost/` **and** the HTTPS form
     `curl -k -H "Host: site-001.dukecodeplus.example" https://localhost/` — confirm both
     render the page with filled-in canary values (not literal `{{ varN }}`, not all `Null`
     unless genmode is off).
  3. Hit it twice with the same UA and confirm the **same** canaries come back (stability),
     and that the request shows up in the UI Request Log / `all_visits` (the JSON access log
     `scheme` field shows whether it arrived over http or https).
  4. Confirm the catch-all drops an unknown Host over both schemes (`curl -k -H "Host:
     bogus.example" https://localhost/` → connection dropped / 444).
  5. Check `make proxy-logs` for nginx errors and the collector logs for insert failures.
- **To verify per-site DB writes**: exec into the site's `db` container and query
  `new_visits` / `new_agents_vars`. **To verify central logging**: query `logdb`'s
  `all_visits` (the UI Request Log page does exactly this).
- **template_generator** has no automated checks either — judge quality by inspecting
  `generated_templates/raw_*.txt` (raw model output) and `scraper_gen_*.html` (assembled
  pages). Use `--reprocess` to iterate on assembly logic without re-running the model.
- **Required services for testing**: the Docker daemon must be up; the proxy stack must be up
  for routing and the Request Log to work; a site stack must be deployed to serve pages.

---

## 5. Agent workflow rules

- **Inspect existing patterns before adding code.** This repo has strong, deliberate
  conventions (the indirections above). Read the relevant template/role/module and mirror it
  rather than introducing a parallel approach.
- **Make minimal, focused changes.** Touch only what the task needs. Do not reformat or
  "clean up" unrelated files.
- **Do not rewrite unrelated files**, and prefer **updating existing code over creating a
  duplicate system** (e.g. extend the existing collector/UI module rather than adding a new one).
- **Do not change public surfaces unless explicitly asked**: the request/response contract of
  `server.py`, the `all_visits` / `new_visits` / `new_agents_vars` schemas, env-var names,
  the Ansible variable contract (`all.yml` keys, per-site yaml shape), Make targets, or the
  load-bearing nginx decisions listed in §1.
- **Explain risky changes before making them** — anything that alters deployment behavior,
  database schemas, the proxy's security properties (XFF handling, the catch-all server,
  `X-Site` tagging), or that could wipe data.
- **Respect the layering.** `template_generator/` is additive and must not modify
  `website/`, `ansible/`, `app/`, or `querying/`. The data dirs are read-only corpora.
- **Don't edit generated artifacts** (see §3) — change the source and re-render.

---

## 6. Project-specific warnings

- **Unique ports per site.** The most common deploy failure. The playbook validates
  `website.port` and `database.host_port` against every other site config and aborts on a
  collision.
- **DB credentials are fixed at volume-creation time.** Postgres only applies
  `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` when it initializes an empty data
  dir. Re-applying a site with changed `database.user` / `database.password` reuses the old
  `pgdata` volume → the healthcheck fails → `up -d` errors. To change DB credentials on an
  existing site you must recreate the volume (UI "Recreate database volume" checkbox, or
  `-e reset_db=true`), which the `deploy` role handles via `docker compose down -v`. **This
  wipes that site's stored visits and canary tokens.**
- **The catch-all nginx server and XFF overwrite are security-load-bearing.** Removing the
  default `server {}`, marking a per-site block `default_server`, or switching XFF to
  `$proxy_add_x_forwarded_for` reintroduces canary misattribution / IP spoofing. The catch-all
  must stay `default_server` on **both** `:80` and `:443` so unknown SNI/Host over HTTPS is
  caught too. The mirror's `X-Site $site_name` (canonical hostname) is what keeps
  `all_visits.site` trustworthy.
- **TLS is self-signed and the cert is shared.** `certgen` generates one wildcard cert
  covering `*.<base_domain>` / `*.<local_base_domain>`; it is set globally in `nginx.conf` and
  inherited by every block. If you change `proxy.base_domain` / `proxy.local_base_domain` in
  `all.yml`, update the matching env in the `certgen` service (or delete `proxy/certs/*` and
  recreate the proxy) so the wildcard still covers every site — otherwise clients see a name
  mismatch. A per-site `proxy.server_name` outside the base domains is **not** covered by the
  wildcard. The key never leaves `proxy/certs/` (git-ignored). Browser warnings are expected
  for the self-signed cert; swap in mkcert (local, trusted) or ACME (public) to remove them.
- **`scraper_version` must come from the env var**, never a hardcoded literal — the playbook
  rewrites `server.py` to enforce this, so a hardcoded value will be silently reverted.
- **Shared `proxy_net` must exist before any site comes up.** The `deploy` role creates it
  idempotently, so the bare `ansible-playbook` path works on a fresh machine; `make
  ensure-net` covers the make-driven flow.
- **Per-site reload uses `failed_when: false`.** Deploying a site **before** the proxy stack
  is up won't fail the playbook — but the route won't be live until `make proxy` (or a re-run
  with the proxy up).
- **Each site's host port is bound to `127.0.0.1`.** Reach sites through the proxy, not their
  raw ports (the raw port is for local debugging and bypasses the central Request Log).
- **Environment variables / secrets** (set in compose templates / `docker-compose.proxy.yml`;
  do not hardcode real secrets in source): website needs `DB_USER`, `DB_PASS`, `DB_HOST`,
  `SCRAPER_VERSION` (and `PORT` only on Cloud Run). The collector and `logdb` use `DB_HOST`,
  `DB_USER`, `DB_PASS`, `DB_NAME` (defaults `logger`/`logger`/`site_logs`). The UI uses
  `PROJECT_ROOT`. The auto_query engine uses `OPENAI_API_KEY_INTERNAL` (+ optional
  `OPENAI_API_BASE_INTERNAL`) for its internal GPT-4.1 steps and the standard LiteLLM
  provider vars (`GEMINI_API_KEY`/`GOOGLE_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, …)
  for target models — all pass through `docker-compose.app.yml` defaulting empty, so the app
  boots and demos offline. Those keys are stored in the **git-ignored project-root `.env`**
  (compose substitutes them on `up`; the app also re-reads the file at runtime): edit it by
  hand (see `.env.example`) or from the LLM Forensics "Provider API keys" card, which writes
  the same file. DB passwords here are local-dev defaults, not real secrets.
- **`template_generator` lives in its own Python environment.** Its torch/transformers/spaCy
  stack is heavy and unrelated to the website env — don't install it into the website venv.
  spaCy is optional (`prepare_data.py` falls back to `cleaned_intros` alone without it).
- **Git-ignored machine-local state (don't commit):** `configs/sites/`,
  `configs/history/`, `querying/runs/`, `querying/provenance/` (provenance reports),
  `crawler_graph/output/*` (campaigns.json, campaigns.png, `gnn_model.pt`,
  `gnn_predictions.json`, asn_cache.json; `.gitkeep` keeps the dir),
  `website/sites/`, `proxy/conf.d/*.conf` (the
  `.gitkeep` keeps the dir), `proxy/certs/*` (the generated TLS cert/key; `.gitkeep` keeps
  the dir), and `venv/` / `.venv-app/`. **Committed (do not assume they're ignored):** the corpora (`data/`,
  `cleaned_intros/`, `wikipedia_towns_text/`), `template_generator/generated_templates/`,
  `template_generator/data/sft.jsonl`, `template_generator/template_registry.jsonl` (the
  local dedup registry — runs append to it), **and the LoRA adapter under
  `template_generator/models/Qwen3-1.7B-lora/`** (tracked in this repo even though the
  `template_generator/README.md` describes `models/` as git-ignored — trust git, not the
  README). `template_generator/.gitignore` excludes only `preview_output/` and
  `text_generator_dataset/` (the raw Wikipedia scrape).
- **`.mcp.json` / `.claude/`** configure local Claude/MCP tooling and are git-ignored.

---

## 7. Useful references

Read these before changing the corresponding area:

- **Request handling & canary logic:** `website/server.py`, `website/user_agent_info.py`,
  `website/templates/scraper1.html`, `website/varLists/scraper1.txt`.
- **Deployment automation:** `ansible/site.yml` (merge + port validation),
  `ansible/group_vars/all.yml` (the variable contract), `ansible/roles/configure/tasks/main.yml`,
  `ansible/roles/deploy/tasks/main.yml`, and the templates
  `ansible/roles/configure/templates/{docker-compose.yml.j2,site.conf.j2,canary_vars.txt.j2}`
  + `handlers/main.yml` (the nginx reload).
- **Reverse proxy & central logging:** `proxy/nginx.conf` (catch-all + global TLS + log
  format), `proxy/snippets/mirror.conf` (`X-Site`/mirror), `proxy/gen-cert.sh` (the
  self-signed wildcard cert), `proxy/collector/app.py`, `docker-compose.proxy.yml`.
- **Web app:** `app/main.py` (routes), `app/services/{sites,template_gen,request_log,fingerprint_service,querying_service,auto_query_adapter,run_manager,keys_service,graph_intel,provenance_service,stats}.py`
  (business logic), `app/templates/*.html` (Jinja2 + Tailwind; the two merged pages are
  `analytics.html` for `/logs` — with the `_campaigns.html` partial — and `forensics.html`
  for `/query`), `app/static/css/app.css`, `docker-compose.app.yml`, `app/Dockerfile`
  (+ `app/requirements-ml.txt`, `app/requirements-autoquery.txt`).
- **Detection engine:** `auto_query/pipelines/{prompt,api_query,manual_query,evaluation}_pipeline.py`,
  `auto_query/src/{parser,template_analyzer,attribute_generator,prompt_generator,
  llm_client_litellm,openai_client,schema_generator,content_extractor_llm,matcher_v4}.py`,
  `auto_query/config/models.py` (model registry), `auto_query/manual_io.py`, and the host-side
  driver `app/services/auto_query_adapter.py`.
- **Legacy querying pipeline:** `querying/pipeline.py` (orchestrator), `querying/{parser,prompt_generator,
  llm_client,extractor,matcher,ground_truth,store}.py`, `querying/config.py`, `querying/main.py` (CLI).
- **Crawler intelligence (6a):** the `crawler_graph/` package (`config,pipeline,cli,reporting` +
  `ingest/`, `graphing/`, `ml/gnn.py`, `tests/`) + `crawler_graph/README.md`; the passive capture
  path `proxy/tls-capture/` (Zeek) + `proxy/tls-shipper/`, wired in `docker-compose.proxy.yml`.
- **Training-data provenance (6b):** `querying/{model_timeline,provenance,membership,rag_disambiguation}.py`.
- **Template generator:** `template_generator/README.md`, `scraper.py`, `prepare_data.py`,
  `train.py`, `generate_templates.py` (the `CATEGORIES` registry + registry clients),
  `registry_api/main.py` (central dedup API).
- **Test suite:** `testsuite/README.md`, `testsuite/run_tests.py` (the runner + feature
  registry), `testsuite/tests/` (one file per feature), `make test-suite`.
- **Orchestration:** the root `Makefile` (every workflow has a target) and `README.md`
  (project framing / stakeholders).
```
