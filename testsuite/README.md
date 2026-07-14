# AI Bot Defender — Test Suite

A runnable, configurable, **feature-organized** test suite that exercises every
user-visible feature of the project and reports what passed, failed, and skipped.

Every test runs **offline and deterministically** — no Docker daemon, no
Postgres, no model API keys, no network. External seams (the host Docker CLI, the
logdb/site `psql` calls, the Ansible playbook, model providers) are stubbed, and
traffic is synthesized in-process. The code under test is the project's own: the
canary generators, the User-Agent parser, the crawler-graph clustering pipeline
(including the real GraphSAGE GNN), the cross-layer consistency engine, the
querying/provenance logic, the proxy collectors, and the FastAPI routes.

## Install

From the repository root:

```bash
python -m venv .venv-tests && . .venv-tests/bin/activate
pip install -r testsuite/requirements.txt
```

The optional GraphSAGE GNN feature needs a heavier torch stack. Install it to run
that feature (otherwise it skips cleanly):

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu   # CPU-only
pip install -r testsuite/requirements-gnn.txt
```

## Run everything (one command)

```bash
python testsuite/run_tests.py        # or: make test-suite
```

You get a per-feature pass/fail/skip table and two reports:

- `testsuite/reports/latest.json`
- `testsuite/reports/latest.html`

## Run one feature at a time

List the features, then run any subset by name (positional or `-f`):

```bash
python testsuite/run_tests.py --list
python testsuite/run_tests.py fingerprinting
python testsuite/run_tests.py clustering fingerprinting
python testsuite/run_tests.py -f honeypot -f querying
```

Each feature is also a single test file you can run straight through pytest:

```bash
pytest testsuite/tests/test_fingerprinting.py -v
```

## Features covered

| Feature | What it verifies | Test file |
|---|---|---|
| `honeypot` | Canary token generation (real Faker varLists) + visitor identification (real UA parser) + stable/unique per-`(UA, ASN)` assignment | `test_honeypot_canary.py` |
| `fingerprinting` | Browser (Layer 1) folding, JA4H header signature, and the cross-layer consistency engine — incl. NAT-aware OS-spoof detection | `test_fingerprinting.py` |
| `clustering` | The crawler-graph pipeline clusters a large synthetic bot mix into the right campaigns and attributes/flags each population | `test_clustering.py` |
| `gnn` | GraphSAGE attributes disguised, UA-less cohorts to a provider via graph structure (optional torch) | `test_clustering_gnn.py` |
| `querying` | The LLM detection pipeline: scrape → probe → extract → match, leak vs. negative control | `test_querying_detection.py` |
| `provenance` | Ingestion-window inference, membership inference (Min-K%++), RAG-vs-training disambiguation | `test_provenance.py` |
| `logging` | The proxy request / fingerprint-beacon / TLS+TCP collectors and the rows they write | `test_proxy_logging.py` |
| `analytics` | The request-log + fingerprint viewer services: SQL escaping/pagination + graceful degradation | `test_analytics_service.py` |
| `sites` | Site Configurator config read/write/merge + the Ansible deploy shim | `test_sites_service.py` |
| `generator` | Honeypot template generator install logic (next-free-slot, no overwrite) | `test_template_generator.py` |
| `auth` | Reviewed approval, bcrypt account storage, login/logout sessions, and the protected-route guard | `test_auth.py` |
| `webapp` | Every FastAPI route/page/export/redirect after the analytics/forensics consolidation | `test_web_app.py` |
| `contracts` | Cross-component static contracts (honeypot/fp wiring, nginx/Ansible logging, app templates exist) | `test_static_contracts.py` |

### The clustering / fingerprinting example

`test_clustering.py` simulates a large, diverse bot population hitting the
honeypot — declared crawlers (GPTBot/ClaudeBot/Googlebot/…), ordinary humans, a
disguised stealth fleet, an agentic-browser population, a proxy-rotating device,
and a VM/headless cohort — then runs the real pipeline and asserts the system
both **logs who they are** (attributes declared crawlers to the right provider)
and **clusters them correctly** (groups the disguised fleet, stitches the
IP-rotating device into one campaign by its fingerprint, flags the VM cohort, and
does *not* raise serious flags on real humans). The population lives in
`tests/synthetic.py` and scales with `--bots`.

## Options

```bash
python testsuite/run_tests.py --bots 400         # scale the synthetic stress traffic
python testsuite/run_tests.py --gnn require       # fail (don't skip) if torch is absent
python testsuite/run_tests.py --gnn skip          # never run the GNN feature
python testsuite/run_tests.py -k canary           # forward a -k expression to pytest
python testsuite/run_tests.py -v                  # verbose pytest output
python testsuite/run_tests.py -- -x --lf          # forward raw args to pytest after --
```

`--gnn` defaults to `auto`: the GNN feature runs when `torch` + `torch_geometric`
are importable and is **skipped with a clear reason** otherwise (so the suite is
runnable on a minimal install). `--gnn require` turns that skip into a failure for
CI that must exercise the GNN.

## Live application tests (`run_app_tests.py`)

The offline suite above proves the *logic*. To run the **same features against the
actually-running application**, use the live harness — it mass-simulates a diverse
bot fleet hitting the real honeypot through the reverse proxy, then verifies the
real databases, the real fingerprint/clustering pipelines, the real
detection/provenance logic, and the real web app.

```bash
python testsuite/run_app_tests.py            # run everything that's up
python testsuite/run_app_tests.py --list
python testsuite/run_app_tests.py honeypot logging fingerprinting
python testsuite/run_app_tests.py --bots 200          # a bigger simulated burst
python testsuite/run_app_tests.py --proxy-url http://localhost --app-url http://localhost:8000
```

Prereqs (start whatever you want to test — anything not up just **skips** with a
clear reason, it never crashes the app):

```bash
make proxy                       # the reverse proxy + logdb
make playbook site_id=site-001   # at least one deployed honeypot site
make app                         # the web UI on :8000
```

It is **safe**: read-mostly, bounded in volume, and never destructive. The only
writes are honeypot page views (which mint canaries — the intended behavior),
fingerprint beacons, and mock detection runs. There are **no** deploys, DB resets,
or template generations. Features that would otherwise need an API key use the
offline **mock** models, so no key is required. Writes a separate
`reports/latest_app.{json,html}`.

The live features mirror the offline ones: `honeypot`, `logging`,
`fingerprinting`, `clustering`, `querying`, `provenance`, `webapp`, plus `graph`
(below). Because the anti-spoof proxy pins every request to the real client IP,
host-originated traffic shares one source IP — so the live `clustering` test
verifies real ingest + provider attribution, while the *multi-IP*
disguise/rotation scenarios stay the offline suite's job.

### Populating the campaigns graph (`graph` feature)

The campaign graph is an inherently *many-IP* feature, and a single host can't put
many distinct source IPs on the wire (the anti-spoof proxy overwrites a forged
`X-Forwarded-For`, and Docker's NAT rewrites the real source to the gateway — so
spoofing is impossible by design). To demonstrate it, the `graph` feature **seeds
the live logdb** with a realistic, clearly-marked (`AIBDSEED`) multi-IP crawler
population — declared crawlers, humans, a disguised stealth fleet, an agentic
cohort, a proxy-rotating device, a VM cohort — then runs the **real** recompute so
the app's `/logs` page fills with many clusters.

It also upgrades the in-app graph to an **interactive** view: each cluster gets a
distinct colour (a golden-angle hue sweep across the whole wheel, not blue shades),
and hovering a node shows that cluster's full rundown (label, flags, IPs, requests,
ASNs, providers, sample IPs); a legend isolates a cluster on hover. The same graph
is also written as a standalone `reports/campaigns_graph.html` you can open without
the app.

The seeded rows are removable at any time:

```bash
python testsuite/run_app_tests.py --clean-seed   # delete the AIBDSEED rows
```

## Notes

- A `stress`-marked clustering test scales the disguised fleet with `--bots`
  (default population if unset). An `integration` marker is reserved for opt-in
  tests against a live local stack (none ship by default — the suite is offline).
- The reports are regenerated on every run; `reports/`, `__pycache__/`, and
  `.pytest_cache/` are git-ignored.
