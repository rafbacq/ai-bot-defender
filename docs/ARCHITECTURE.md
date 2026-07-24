# Architecture

This document is the deep dive into how AI Bot Defender is put together and,
more importantly, *why* it is put together that way. Several decisions below are
load-bearing for the research (canary attribution, log trustworthiness, TLS
fingerprint capture) — each of those is called out explicitly. Read the section
for the layer you are about to change before changing it.

For a shorter orientation, start with the root [README](../README.md). For
day-to-day commands, see [DEVELOPMENT.md](DEVELOPMENT.md).

## Contents

- [The core idea](#the-core-idea)
- [Multi-site deployment model](#multi-site-deployment-model)
- [Reverse proxy + centralized logging (`proxy/`)](#reverse-proxy--centralized-logging-proxy)
- [The honeypot application (`website/`)](#the-honeypot-application-website)
- [Device fingerprinting (Layers 1/2/3)](#device-fingerprinting-layers-123)
- [The control-center web app (`app/`)](#the-control-center-web-app-app)
- [The auto_query detection engine (`auto_query/`)](#the-auto_query-detection-engine-auto_query)
- [The legacy querying pipeline (`querying/`)](#the-legacy-querying-pipeline-querying)
- [Crawler intelligence & training-data provenance (Direction 6)](#crawler-intelligence--training-data-provenance-direction-6)
- [Adversarial self-play (Direction 2, `selfplay/`)](#adversarial-self-play-direction-2-selfplay)
- [Template generation (`template_generator/`)](#template-generation-template_generator)

## The core idea

The defensive mechanism is a **honeypot website seeded with canary tokens**:
each unique visitor (keyed by a browser-fingerprint device cookie when
available, else `User-Agent + ASN`) is served a page containing uniquely
generated fake facts (names, cities, institutions, years, …). If those
fabricated tokens later surface inside an LLM's output, that is evidence that a
specific scraper ingested the page. Because one physical device keeps **one**
canary set even across UA/IP/ASN rotation, a single canary set appearing under
several claimed identities is itself a **disguise** signal (surfaced on Crawler
Analytics). Every visit is also logged to Postgres for traffic analysis.

The system runs **many independent honeypot sites at once**, each a
self-contained Docker Compose stack, all sitting behind one nginx reverse proxy
that does host-based routing and centralized cross-site request logging.

## Multi-site deployment model

Sites are identified by a `site_id` (e.g. `site-001`). Each is its own isolated
Docker Compose stack (own `web` + `db` containers, volumes, network). The flow:

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

Because each site is a separate stack, **`website.port` and
`database.host_port` must be unique per site** — `ansible/site.yml` pre_tasks
actively validate this (they slurp every other `sites/*.yaml`, compute claimed
ports, and fail the run on a collision). **This is the single most common
source of deploy failures.**

### Config precedence (Ansible)

`ansible/group_vars/all.yml` holds global defaults: `website_dir`, `website`
(port, genmode), `database` (user, password, host_port), `scraper_version`,
`proxy` (enabled, base_domain, local_base_domain, container, conf_dir), and
`canary_tokens` (a list of ≥10 Python expressions). `configs/sites/<site_id>.yaml`
holds per-site overrides. `site.yml` merges the site file *over* the defaults
with `combine` (for `website`, `database`, `proxy`), coerces `genmode` to a real
bool, and asserts `canary_tokens | length >= 10`. A site may override
`proxy.server_name` to use a custom canonical address, and may carry a per-site
`canary_tokens` list (written automatically by the Site Configurator for
generator-authored flavors) that replaces the global default for that site.

## Reverse proxy + centralized logging (`proxy/`)

A single nginx (stack name `proxy`, container `proxy-nginx`) is the **only
locally exposed entry point** — it terminates both plain HTTP (`:80`) and HTTPS
(`:443`). Every per-site stack binds its host port to `127.0.0.1` only, so
sites are reachable from the network *only* through the proxy. Like a normal
website, a site is reached at `https://<hostname>/`: nginx selects the TLS cert
by **SNI** during the handshake, then routes the decrypted request by **Host**
header (name-based virtual hosting).

The proxy stack (`docker-compose.proxy.yml`) has these core services (plus the
passive Zeek TLS/TCP capture sidecar + shipper described under Direction 6a):

- **`certgen`** (`proxy/gen-cert.sh`, one-shot `alpine` init container) —
  writes a self-signed **wildcard** TLS cert into the shared `proxy/certs/`
  dir if one isn't there yet, then exits. Idempotent. nginx `depends_on` it
  with `condition: service_completed_successfully`, so the cert always exists
  before nginx starts. A single `*.<base_domain>` / `*.<local_base_domain>`
  cert covers **every** site because all site hostnames are subdomains of the
  base domains.
- **`nginx`** (`proxy-nginx`) — terminates TLS, routes, and logs. Config split
  across `proxy/nginx.conf` (base: global TLS, JSON `siteaccess` log format,
  `resolver 127.0.0.11`, the default catch-all server, rate-limit zones, and
  `include conf.d/*.conf` + `include admin.d/*.conf`), `proxy/snippets/mirror.conf`
  (the shared `/_mirror` target), Ansible-rendered `proxy/conf.d/<site_id>.conf`
  (one `server {}` per site), and `proxy/admin.d/admin.conf` (the only
  non-honeypot vhost — the public control center; see
  [DEPLOYMENT.md](DEPLOYMENT.md)).
- **`collector`** (`proxy/collector/app.py`, FastAPI + psycopg2) — receives
  nginx's request mirror and writes one row per request into the central
  `all_visits` table, then returns 204 as fast as possible. Fire-and-forget:
  any DB error is swallowed and the connection reset.
- **`fp-collector`** (`proxy/fp-collector/app.py`) — receives the Layer-1
  browser-fingerprint beacon that `website/static/js/fp.js` POSTs to
  `/__fpbeacon` and writes one row per beacon into `logdb.browser_fingerprints`.
  Same never-block/fire-and-forget contract as `collector`; caps body size.
- **`logdb`** (postgres:16, database `site_logs`, user/pass `logger`) — the
  cross-site aggregate log store.

Two logging paths run in parallel:

1. nginx `access_log` (JSON, `siteaccess` format, includes a `scheme` field
   recording http vs https) → `/var/log/nginx/dukecodeplus.access.log` inside
   the `nginx_logs` volume. Unmatched/scan traffic goes to
   `unmatched.access.log`; the admin vhost logs to `admin.access.log`.
2. nginx `mirror /_mirror` → `collector:8000` → `logdb` table `all_visits`
   (`site, client_ip, user_agent, method, uri, headers jsonb, ts`), tagged per
   site via the `X-Site` header. Only matched (real-site) requests are mirrored.

### Design decisions that must not silently change

- **Host-based routing (name-based virtual hosting).** One `server {}` per
  site, `server_name {{ site_id }}.{{ proxy.base_domain }}` (or a per-site
  `proxy.server_name` override) plus a browser-friendly
  `{{ site_id }}.{{ proxy.local_base_domain }}` alias, each rooted at `/`. The
  block also does `set $site_name <canonical hostname>;` and the mirror tags
  requests with `X-Site $site_name`, so even requests arriving via an alias are
  recorded under the canonical hostname in `all_visits.site`. No path-based
  routing — that would leak `/site-xxx/` and break Flask's root-relative
  links/static paths. Per-site blocks listen on **both** `listen 80;` and
  `listen 443 ssl;` (never `default_server`), so the same site answers over
  HTTP and HTTPS.
- **TLS termination via SNI.** nginx terminates TLS at the proxy and serves the
  honeypot over both `:80` and `:443`. One shared wildcard cert (self-signed by
  default; a trusted Let's Encrypt cert on the public deployment) is presented
  for any SNI; nginx then routes by Host header. The backend is still plain
  HTTP (`proxy_pass http://...:8080`); `X-Forwarded-Proto $scheme` carries the
  original scheme. **Both schemes serve the site on purpose** (not an
  HTTP→HTTPS redirect): the project rule that *all crawlers must reach the
  site* means a redirect would drop bots that don't follow redirects. To switch
  to redirect-to-HTTPS behavior, change the per-site block in `site.conf.j2`
  per the comment there.
- **Default catch-all server (in `proxy/nginx.conf`).** A `listen 80
  default_server; listen 443 ssl default_server;` block with `server_name _;`
  absorbs every request whose Host/SNI doesn't match a configured site —
  raw-IP scans, spoofed/junk Host values, no-Host requests. It `return 444`s
  (drops the connection) and **neither proxies nor mirrors**, so scan noise
  never reaches a real site's Flask backend (no canaries assigned to scanners)
  and never enters `all_visits`. Because of this block, any request that *does*
  reach a per-site block has a Host matching that site, so `all_visits.site` is
  never an arbitrary client value. Unmatched traffic is still logged —
  separately, to `unmatched.access.log`. **Do not remove this block or mark a
  per-site block `default_server`.**
- **Anti-spoof XFF.** nginx **overwrites** `X-Forwarded-For` with
  `$remote_addr` (never `$proxy_add_x_forwarded_for`). `server.py` trusts the
  first XFF entry for ASN lookup and canary keying, so appending would let a
  bot prepend a fake IP the app would believe.
- **Shared external network `proxy_net`.** nginx reaches each site at
  `http://{{ site_id }}-web:8080` via a network **alias** (the bare service
  name `web` is ambiguous across stacks on a shared network). Each site joins
  both its own `default` network and `proxy_net`.
- **Dynamic upstream resolution.** `resolver 127.0.0.11` (Docker embedded DNS)
  plus a `set $upstream ...; proxy_pass http://$upstream:8080$request_uri;`
  variable means `nginx -s reload` never fails just because a site container is
  momentarily down — names are resolved at request time, not config-load time.
- **Best-effort mirror.** The mirror uses `mirror_request_body off` (GET-only)
  and short timeouts (`proxy_connect_timeout 200ms`, `proxy_read_timeout
  500ms`, `proxy_next_upstream off`); the collector failing or being slow can
  never stall the real response.
- **No rate limiting on the honeypot path** — all traffic, including crawlers,
  must reach the sites. (The admin vhost *is* rate-limited; that surface is not
  research traffic.)

## The honeypot application (`website/`)

A small Flask app (`server.py`) with a single route, `GET /`, plus the static
fingerprinting beacon (`static/js/fp.js`) and a render-health helper
(`runtime_health.py`).

### The `scraper_version` indirection

`scraper_version` (an int, default 1) selects a whole "flavor" of the honeypot
in lockstep across three places:

- `website/varLists/scraper{N}.txt` — the 10 canary-token Python expressions.
- `website/templates/scraper{N}.html` — the HTML page rendered to visitors.
- the Postgres database name `scraper{N}-db`.

It must **not** be hardcoded. `server.py` reads it from the `SCRAPER_VERSION`
env var; the compose template passes it in; the Ansible `configure` role even
self-heals `server.py` with a `replace` task to guarantee the env-var form.
When `scraper_version != 1`, the configure role copies `scraper1.html` →
`scraper{N}.html` if one doesn't already exist, so a new version boots with a
working template you can then customize.

### Canary tokens (`var1`..`var10`)

`canary_tokens` in `all.yml` is the **global default**. The configure role
renders the first 10 entries into `website/varLists/scraper{N}.txt` via
`canary_vars.txt.j2`. A generator-authored flavor overrides this per site:
installing a generated template records its category-typed varList in
`configs/generated_templates.json`, `app/services/sites.py` embeds it as
`canary_tokens` in that site's `configs/sites/<id>.yaml`, and `site.yml`
prefers the per-site list over the global default — so a movies page deploys
with movie-shaped tokens while hand-made flavors keep following `all.yml`.

**Do not edit `website/varLists/*.txt` by hand — they are generated build
artifacts.** Each line is a Python expression `eval`'d server-side in
`gen_vars()` with the `fake` (Faker) object in scope. Available providers: base
Faker `en_US`, plus `faker_edu` (`institution_name()`) and `faker_food`
(`dish()`, `ingredient()`, `fruit()`). These 10 values become
`{{ var1 }}`..`{{ var10 }}` in the HTML template.

### Request handling in `server.py`

On each request `update_page()`:

1. Resolves the client IP via `get_client_ip()` — the **first**
   `X-Forwarded-For` entry if present, else `request.remote_addr`. Hashes it
   (SHA-256), derives the network address (IP minus last segment), and looks up
   the ASN via `ipwhois`. Behind the proxy, nginx sets XFF to the real client;
   standalone it falls back to `remote_addr`. **The proxy must overwrite, not
   append, XFF** or this IP is spoofable.
2. Parses the User-Agent (`user_agent_info.parse_user_agent`, backed by
   `user_agents`).
3. **Always** inserts a row into `new_visits` (the raw visit log).
4. Looks up `new_agents_vars` **by the device cookie `__abd_fp` (a `fp_id`)
   when the browser sent one, else by `(user_agent, asn)`** (the first time a
   cookie appears for an existing `(user_agent, asn)` row its null `fp_id` is
   backfilled, binding the device to its canary set):
   - **Seen before** → reuse the stored `var1..var10`, increment `view_count`,
     refresh `last_visited`/asn/ip. This makes canary tokens *stable per
     device* — one physical machine keeps **one** canary set even as it rotates
     its UA / exit IP / ASN, so a canary set surfacing under several claimed
     identities is the **disguise** signal (and a leaked set attributes to one
     device, not N fragments).
   - **New visitor + genmode on** → `set_vars()` generates a unique canary set
     (retrying to avoid duplicates) and stores a new row.
   - **New visitor + genmode off** → renders all vars as `"Null"` and stores
     nothing.
5. Renders `scraper{N}.html` with the vars.

`genmode` is controlled at runtime by the `nogen` CLI arg
(`python server.py nogen`); the compose template injects this command when
`website.genmode` is false.

### Databases

Two distinct Postgres stores:

- **Per-site `scraper{N}-db`** (inside each site stack's `db` container). Two
  tables, auto-created on boot via `Base.metadata.create_all`:
  - `new_visits` — append-only log of every request (UA breakdown, ASN, hashed
    IP, timestamp).
  - `new_agents_vars` — one row per unique visitor with its assigned canary
    tokens and `view_count` (keyed by `fp_id` when known, else
    `(user_agent, asn)`).
- **Central `site_logs`** (the proxy stack's `logdb`). Table `all_visits` — the
  cross-site aggregate the collector writes, tagged per site. The only place
  that joins traffic across every honeypot site, and what the Crawler Analytics
  request log reads. Additive columns (`client_port`) and additive tables
  (`browser_fingerprints`, `tls_handshakes`, `tcp_fingerprints`) support the
  fingerprinting layers below.

## Device fingerprinting (Layers 1/2/3)

Three additive fingerprint surfaces extend the TLS layer (all flow through the
same `logdb → crawler_graph → /logs` pipeline; all degrade gracefully when
their table is empty):

- **Layer 1 — browser fingerprints.** Honeypot pages embed
  `website/static/js/fp.js` (a one-line `<script src="/js/fp.js" defer>` in
  each `scraper{N}.html`). It reads the JS-visible surfaces (canvas,
  WebGL/WebGPU, AudioContext, fonts, screen/window geometry, navigator/UA-CH,
  automation tells) plus behavioral biometrics (mouse/scroll/keystroke +
  synthetic-humanization detection; idle gaps are excluded from the timing
  distributions so reading pauses don't corrupt the regularity stats) and POSTs
  JSON payloads to **`/__fpbeacon`**: a `load` beacon ~1.2s in (zero behavior)
  and re-armable cumulative `unload` beacons. All beacons of one page load
  share a random **`pv_id`** so the request log can attach the newest beacon of
  the right pageview. nginx routes that exact path to the `fp-collector`
  service → `logdb.browser_fingerprints`. The payload schema in `fp.js` is the
  contract shared with the collector and
  `crawler_graph.ingest.enrich.join_browser_fingerprints`. Canvas/WebGL/audio/
  font hashes + the composite `fp_id` become the strongest graph attribute hubs
  (cross-IP/proxy device stitching). A non-JS scraper never beacons — that
  *absence* is itself a signal. `fp.js` also writes the composite `fp_id` into
  an `__abd_fp` cookie so `server.py` can serve a returning device its stable
  canary set across UA/IP/ASN rotation.
- **Layer 2 — TCP/IP OS inference + JA4H.** The Zeek sidecar also logs each
  client SYN (`proxy/tls-capture/scripts/tcp-fingerprint.zeek`), including its
  **ordered TCP option kinds**; the multi-log `tls-shipper` computes a p0f-style
  OS guess and the **canonical FoxIO JA4T** (`{win}_{opt-kinds}_{mss}_{wscale}`,
  byte-identical to the FoxIO package's `conn.log`) into `logdb.tcp_fingerprints`
  (additive `opt_kinds` column), joined by 4-tuple. `infer_os` uses the option
  **order** to resolve the TTL-64 Linux/Apple ambiguity that otherwise reads as
  `unknown`; pre-upgrade rows keep the legacy signature (`opt_kinds IS NULL`).
  **JA4H** (an HTTP-header signature) is computed purely from the
  already-stored `all_visits.headers` (no new capture).
- **Layer 3 — cross-layer consistency.** `crawler_graph/analysis/consistency.py`
  scores each endpoint's *internal contradictions* (claimed UA/JS OS vs. the
  TCP/IP kernel, WebGL VM/software renderer cohorts, automation/behavioral
  tells). Automation uses strong/weak tell weighting, and the VM-renderer
  marker list is deliberately narrow — both to bound false positives on
  privacy-hardened / VM / WebView real users. Folded into campaign disguise
  detection and surfaced on Crawler Analytics both per-request and
  per-campaign. Validated by the offline selftest
  (`python -m crawler_graph selftest`).

The request↔beacon join is by `(client_ip, user_agent)` within a time window,
pageview-aware via `pv_id` and preferring the latest cumulative `unload` beacon
(**not** the `(client_ip, client_port)` 4-tuple, which is unreliable here since
the beacon rides a separate connection).

## The control-center web app (`app/`)

FastAPI + Jinja2 + Tailwind, branded **Duke WATCH** in the UI. It is the
operator console for the whole system, served on `http://localhost:8000` (and,
on the cloud deployment, on the HTTPS-only `admin.<base-domain>` vhost).

### Docker-out-of-Docker

`docker-compose.app.yml` runs the FastAPI container with the host Docker socket
mounted **and the project bind-mounted at the same absolute path**
(`${PWD}:${PWD}`, `PROJECT_ROOT=${PWD}`). This "path mirroring" is deliberate:
when the container runs `docker compose` / `ansible-playbook` against the host
daemon, build contexts resolve identically inside and out. The image
(`app/Dockerfile`, build context = repo root) bakes in the Docker CLI + compose
plugin, `ansible-core` + `community.general`, the template-generator ML stack
(torch + transformers/peft/accelerate), `torch_geometric` (so Crawler Analytics
can train the GraphSAGE GNN in-process), and the auto_query engine deps
(litellm, openai, rapidfuzz, openpyxl). The container joins `proxy_net` and
sets `PROXY_HTTP_ENTRY=http://proxy-nginx` so LLM Forensics can scrape honeypot
sites through the proxy by container name.

Because the project is bind-mounted, ordinary code edits need no image rebuild
— only Dockerfile/requirements changes do (`make app-build`).

**Starlette signature note:** call
`templates.TemplateResponse(request, "name.html", {context})` — request first
(the legacy `(name, context)` form silently treats the context dict as the
template name and 500s).

### Pages

Six top-nav pages (`base.html`), all account-protected (see
[AUTHENTICATION.md](AUTHENTICATION.md)):

- **Overview (`/`)** — hero + live statistics polled from `GET /api/stats`
  (`services/stats.py`), navigation cards, and a "how detection works"
  explainer.
- **Sites (`/sites`, `services/sites.py`)** — the Site Configurator. Edits the
  global `website_dir`; `scraper_version` is a dropdown of the flavors in
  `website/templates/` with a live iframe preview; collects per-site
  website/database settings; suggests non-colliding ports; `POST /sites/deploy`
  writes `configs/sites/<id>.yaml` and runs the playbook. Lists configured
  sites with live/deployed/stopped/config-only status and lifecycle actions
  (stop / start / delete), which run as background jobs under a cross-process
  publication lock. Load-bearing ordering in `sites._retire_site`: **route
  first, containers last** — withdrawing the nginx route first drops the
  hostname onto the catch-all (which is what "take it down" means) and stops
  the mirror immediately; monitoring artifacts are withdrawn next (the
  generated alert rules are `absent()`-based and would otherwise page forever);
  TLS is never reconciled by a retirement (shrinking the shared cert costs a
  rate-limited ACME issuance and buys nothing). A delete removes the site's
  YAML **only after** the stack is provably gone, so a partial failure stays
  listed and retryable. Every apply appends to `configs/history/applies.jsonl`.
- **Generator (`/generator`, `services/template_gen.py`)** — authors new
  honeypot page flavors with the fine-tuned Qwen3-1.7B + LoRA model, run as an
  in-container subprocess. Loading those weights costs 40-90s and peaks
  around 10-11 GiB *per process*, so runs go through a **warm worker**
  (`template_generator/generation_worker.py`) that keeps the model resident
  (~7 GiB) between templates: only the session's first template waits for the
  load. It is a child process spoken to over stdin/stdout — the same pipe the
  progress bar already streams — and a one-shot subprocess remains the automatic
  fallback. An unused worker releases the memory after `TEMPLATE_GEN_WARM_TTL`
  (default 30 min); `TEMPLATE_GEN_PRELOAD=1` loads at app startup instead, and
  `TEMPLATE_GEN_WARM=0` restores one process per template.
  The page offers one flavor per generator category (the `CATEGORIES`
  registry, read out of the script via AST — never imported), deduped through
  the template registry. Installing a generated page writes it into
  `website/templates/` as the next free `scraper<N>.html` (injecting the
  `/js/fp.js` beacon tag) and carries its category-typed varList into
  `website/varLists/scraper<N>.txt` + `configs/generated_templates.json`. The
  page also has an inline editor for existing flavors whose save validates
  Jinja syntax, re-injects `fp.js` if the edit dropped it, and writes
  atomically.
- **Crawler Analytics (`/logs`, `services/request_log.py` +
  `fingerprint_service.py` + `graph_intel.py`)** — the merged traffic view:
  1. *Request log* — read-only viewer of the central `all_visits` table
     (filter/paginate/search in SQL via the shared `services/logdb.py` fast
     path; CSV export; per-request header inspector). Each row is
     fingerprint-enriched: the beacon from the same IP and matching UA within a
     ±30-min window, pageview-aware via `pv_id`, preferring the richer `unload`
     beacon. Every row runs through the cross-layer consistency engine for a
     per-request verdict; rows are tinted green/orange/red by severity, and a
     browser-UA request that never ran JS surfaces the `browser_no_js` signal.
     Pagination swaps the table body in place (with prefetch) rather than
     reloading the page.
  2. *Device fingerprints* — KPI strip plus a disguised-devices panel: each row
     is one physical device (`fp_id`) flagged either for ≥2 claimed identities
     (red; identities counted version- and brand-insensitively so a browser
     auto-update or a second same-engine browser is ONE identity) or for one
     identity across ≥2 public netblocks (orange; counted per address family
     over public addresses only, so dual-stack, v6 privacy extensions, and
     Docker-internal hops never count).
  3. *Campaign intelligence* — insights band + full breakdown read from the
     persisted `crawler_graph/output/campaigns.json`; **Recompute**
     (`POST /intel/recompute`) re-runs the pipeline against the live `logdb`,
     optionally training + applying the GraphSAGE GNN in-process. The network
     graph renders as a static PNG and as a self-contained interactive HTML
     graph (no external libs).

  The old `/fingerprints` and `/intel` URLs 307-redirect here.
- **LLM Forensics (`/query`, `services/querying_service.py` +
  `auto_query_adapter.py` + `provenance_service.py`)** — the merged forensics
  view: provider API-key management (writes the git-ignored project-root
  `.env`; keys apply with no restart), detection runs on the auto_query engine
  (background worker + live progress page + downloadable artifacts), manual
  evaluation (paste/upload chatbot answers for providers without an API),
  membership inference (Min-K% demo), and the model-version timeline /
  RAG-vs-training provenance probes. The launcher has a querying-mode toggle —
  *Offline demo* (mock models only, no keys) vs *Use API keys* — enforced
  server-side by `querying_service.resolve_model_choice`. The old
  `/provenance` URL 307-redirects here.
- **Adversarial (`/selfplay`, `services/selfplay_service.py`)** — the
  adversarial self-play layer: training/coevolution/ingestion runs and the
  robust-detector second opinion (see Direction 2 below).

Plus the account pages (`/login`, `/signup`, `/account`, optional TOTP 2FA) and
the **Admin panel** (`/admin/approve` for access approval, `/admin/monitoring`
for the monitoring console) behind a separate admin-password session.

### Background jobs

Long-running actions (deploys, recomputes, generation, detection, provenance,
self-play) execute on server-side workers (`services/run_manager.py`,
`services/task_service.py`): the launch POST returns immediately and the
browser only polls status. Closing the tab never cancels a job; cancellation is
an explicit request from the progress UI. Jobs checkpoint under
`configs/history/jobs/` (or their own persisted run records), so completed
results survive navigation. The workers are in-process by design: an app
restart interrupts unfinished work, and persisted records report that
interruption as terminal instead of leaving a progress page spinning.

### Admin monitoring

The monitoring page renders every panel itself
(`services/monitoring_service.py` → `GET /admin/monitoring/status`, polled
client-side), reading Prometheus/Loki/Grafana over the private
`monitoring_bridge` network; Grafana is only ever a link (embedding a panel
would 404 over the documented loopback/SSH-tunnel path). Two panels are worth
understanding:

- **Capture integrity** — whether the honeypot is actually recording the
  research data it exists to record. The collector is fire-and-forget by
  design: it drops a visit rather than delay a response, and swallows the DB
  error — so a silent capture failure looks *exactly* like a healthy stack. The
  panel reads the central log for corpus size/growth (never the collector's
  process-local counters, which reset on restart) and the collector counters
  for loss (which the database cannot know). Loss that has stopped reads "Data
  lost earlier" — never "healthy".
- **What the proxy served (last 24h)** — a Loki aggregate of nginx statuses per
  site. nginx has no metrics exporter and `all_visits` never sees
  catch-all-dropped traffic, so this is the only view of what a real crawler
  received.

Every research-traffic reading excludes `admin.access.log` (the console's own
request stream — counting it made a traffic KPI observe itself). Scanner noise
(`unmatched.access.log`) is deliberately kept: it is research data.

## The auto_query detection engine (`auto_query/`)

The **current detection engine** — vendored from the team's
`auto-query-integrate` branch, designed to be embedded in a host application:
HTML, the faker template text, and ground-truth rows are supplied by the
caller, never loaded from its own disk layout. The app's
`app/services/auto_query_adapter.py` is that host-side caller. Four independent
pipelines (`auto_query/pipelines/`):

```
generate_prompt_pipeline(html, faker_template [, rendered_html])
    parser -> template_analyzer -> attribute_generator -> prompt_generator
    (one composed retrieval prompt)
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
    containment + fuzzy>=95) -> per-crawler attribution profiles
    -> cross-model ranking -> human-readable attribution summary
```

Two LLM roles, both offline-safe:

- **Target models** go through LiteLLM (`src/llm_client_litellm.py`): any
  provider = its standard API-key env var + one line in
  `auto_query/config/models.py`. `mock/scraper-sim` / `mock/honest-llm` are
  handled by a built-in simulator (never sent to LiteLLM), keeping the
  positive/negative demo working with no keys.
- **Internal processing** (attribute generation, schema generation, content
  extraction) runs on GPT-4.1 via `src/openai_client.py`
  (`OPENAI_API_KEY_INTERNAL`); with no key each step falls back to a
  deterministic heuristic, which is what the offline test suite exercises.

Real queries take many seconds per model, so detection runs execute on a
background worker thread; the POST returns at once and the run page polls a
status endpoint. Provider failures are classified
(`llm_client_litellm.classify_error`) into auth / quota / rate_limit /
model_not_found / network / provider_error, each with a human-readable hint
carried into the run record. `querying.store.save_run` writes atomically
(temp + `os.replace`) so the live poller never reads a half-written run.

The adapter maps the evaluation output onto a **legacy-superset run record**
persisted via `querying.store.save_run` — every key the UI/stats/testsuite
already read is preserved; `attribution_profile`, `summary.ranking`,
`summary.attribution_summary`, `kind` and `engine: "auto_query"` are added
alongside. A model counts as a **leak** at coverage ≥ `HIGH_RISK_THRESHOLD`
(0.3) or ≥2 canaries recovered from one crawler row.

## The legacy querying pipeline (`querying/`)

A Python package (run from the repo root: `python -m querying.main ...`, or
imported by the app). **No longer the engine behind the `/query` detection UI**
(that's `auto_query/` above), but still load-bearing: it hosts the Direction-6b
**training-data provenance layer** (`model_timeline.py`, `provenance.py`,
`membership.py`, `rag_disambiguation.py`), the **run store** (`store.py`, which
auto_query runs persist through) and the **ground-truth loaders**
(`ground_truth.py`) the adapter reuses. Also still runnable as a CLI. See
[`querying/README.md`](../querying/README.md) for the pipeline diagram,
provider routing, and the contracts to preserve.

**Provider routing note (load-bearing):** `querying/llm_client.py` routes any
non-mock `<provider>/<model>` id through LiteLLM, and a failure there raises
into a per-question error. It must **never** fall back to the offline mock for
a prefixed id — `mock/scraper-sim`'s answer deliberately fabricates a leak,
which would attribute false ingestion evidence to a real model.

## Crawler intelligence & training-data provenance (Direction 6)

Two additive research layers on top of the existing logging + querying.

### 6a — crawler graph (`crawler_graph/`, surfaced at `/logs`)

Clusters the central `all_visits` log into attributable *campaigns*. TLS
fingerprints (JA3/JA4) are captured **passively** by a Zeek sidecar that shares
nginx's network namespace (`proxy/tls-capture/`, `network_mode:
"service:nginx"`, `cap_add: NET_RAW`), so it reads the raw ClientHello *before*
nginx terminates TLS — a true fingerprint with no nginx rebuild. Zeek writes
JSON `ssl.log`; `proxy/tls-shipper/` streams it into `logdb.tls_handshakes`.
nginx forwards the client source port (`X-Client-Port` →
`all_visits.client_port`, an additive column) so each handshake joins to the
HTTP requests its connection carried by the `(client_ip, client_port)` 4-tuple.

The graph (IP nodes linked through shared JA4/UA/`/24`/ASN attribute hubs) is
partitioned by Louvain/Leiden; an optional **GraphSAGE GNN** (`ml/gnn.py`,
torch + torch_geometric, baked into the app image) attributes providers. It
requires ≥2 declared-provider classes to train (a single-class model is
degenerate and is deliberately skipped). Output:
`crawler_graph/output/campaigns.json` (+ `gnn_model.pt`,
`gnn_predictions.json`). The point is catching crawlers that **disguise**
themselves (undeclared infra on browser UAs; agentic browsers) — honest
declared crawlers need only UA + published IP ranges. See
[`crawler_graph/README.md`](../crawler_graph/README.md).

### 6b — provenance (`querying/{model_timeline,provenance,membership,rag_disambiguation}.py`, surfaced at `/query`)

Dates *when* a model ingested a site's canaries: derive each crawler's
mint/crawl time from `new_visits` (no schema change), probe successive model
versions against their knowledge cutoffs, and from which versions reproduce a
canary set bound the ingestion window + crawl-to-train latency. `membership.py`
adds Min-K%/Min-K%++ membership inference (served vs. never-served watermark
controls → a p-value) for guarded models that won't regurgitate;
`rag_disambiguation.py` separates training-memorization from live retrieval
(browsing off/on + `all_visits` live-fetch correlation).

## Adversarial self-play (Direction 2, `selfplay/`)

An **additive, read-only** RL layer that turns the `crawler_graph` detector
into the reward channel of a two-player game. It never edits the runtime layers
and writes only under `selfplay/output/` (never `crawler_graph/output/`, so a
training loop can't clobber the live `/logs` artifacts).

- **The oracle is the production detector.** `selfplay/defender.py` scores a
  synthetic attacker cohort by calling `crawler_graph.pipeline.run_intel(...)`
  — the *same* rule ensemble + cross-layer consistency the live page uses. An
  evasion the agent finds is a real adversarial example against the live
  pipeline.
- **Constrained MDP.** `selfplay/traffic_model.py` simulates a campaign
  operator in `all_visits`-shaped rows; the attacker's 4-factor action space
  (identity rotation, timing, fetch behavior, stack rung) walks a
  cost-to-evade ladder grounded in the consistency engine. PPO-Lagrangian
  (`ppo.py`, a GRU policy with reward + cost value heads and a learned dual λ)
  maximizes harvest subject to a detection budget.
- **Phase-0 calibration** (`calibration.py`) gates training: per-feature KS +
  an adversarial-AUC classifier confirm the simulator is indistinguishable from
  real `all_visits` on the exact feature vector the detector consumes.
- **The v1 deliverable** is a robust detector (`robust_detector.py`, an MLP —
  not a GNN, because the evader deliberately breaks graph edges) trained on the
  attacker's hard-negatives and run as a **second opinion** on `/logs`. It
  never silently replaces the live detector.
- **v2:** `coevolve.py` runs PSRO (best-response attacker ⇄ best-response
  robust detector) tracking exploitability; `ingestion.py` closes the loop with
  a Thompson-sampling content bandit rewarded by provable ingestion
  (`querying.membership`).

Dependency-light: torch + numpy + networkx + stdlib only. Training runs in the
dedicated `trainer` compose service (profile `trainer`, CPU-only) via
`make selfplay-*`, or as a background subprocess from the `/selfplay` page.
`python -m selfplay selftest` is the offline end-to-end check.

## Template generation (`template_generator/`)

An additive, self-contained sidecar that fine-tunes **Qwen3-1.7B** with
**LoRA** and uses it to author honeypot pages across 20 content categories. It
writes only inside `template_generator/` — it never modifies the website,
Ansible, or app layers. Pipeline:

```
scraper.py             -> data/text_generator_dataset/    (Wikipedia scrape into 20 category folders)
prepare_data.py        -> data/sft.jsonl                  (corpora masked to [[NAME]]/[[NUM]])
train.py               -> models/Qwen3-1.7B-lora/         (LoRA adapter only)
generate_templates.py  -> generated_templates/scraper_gen_<category>.{html,txt}
generation_worker.py   -> the same generator hosted in a process that keeps the
                          model loaded between runs (what the app drives)
```

Each generated template is a pair: the HTML page with `{{ var1 }}..{{ var10 }}`
slots and its category-typed varList (one base-Faker expression per slot).
Titles + content hashes + SimHash near-duplicates are deduped through a
registry — the local `template_registry.jsonl` by default, or the central
`registry_api/` FastAPI service (per-institution keys) so multiple institutions
never publish the same fake facts. Deploying a generated template is automatic
through the app's Generator page. See
[`template_generator/README.md`](../template_generator/README.md).
