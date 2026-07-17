# AI Bot Defender

**Duke Code+ 2026 · Argus Lab** — a research platform for detecting AI scraper
bots and proving, with evidence, which LLMs ingested the pages they scraped.

LLM providers crawl the web at scale to build training corpora, often without
permission and increasingly in disguise. This project defends from the data
layer: it runs **honeypot websites seeded with canary tokens** — uniquely
generated fake facts served to each visitor — and then interrogates production
LLMs for those tokens. A canary surfacing in a model's output is direct
evidence that a specific scraper's harvest reached that model's training data
or retrieval index. Around that core loop sit traffic forensics (device
fingerprinting, TLS/TCP fingerprints, campaign clustering), training-data
provenance (dating *when* ingestion happened), and an adversarial self-play
layer that stress-tests the detector.

The operator console is branded **Duke WATCH** (Web Attribution Through Canary
Honeypots) in the UI.

## How it works

1. **Seed** — each honeypot site serves every unique visitor its own canary
   set (`var1`..`var10`), keyed by a browser-fingerprint device cookie when
   available, else `User-Agent + ASN`. One physical device keeps one canary set
   even across UA/IP/ASN rotation — so a canary set appearing under several
   claimed identities is itself a disguise signal.
2. **Log** — a single nginx reverse proxy fronts every site, routes by
   hostname, and mirrors every request into a central Postgres log
   (`all_visits`). A passive Zeek sidecar captures TLS/TCP fingerprints
   without touching the request path.
3. **Probe** — the detection engine scrapes a honeypot page, composes an
   adversarial retrieval prompt about its subject, and queries target LLMs
   (via LiteLLM, or by hand for chatbots without an API).
4. **Match** — extracted answers are fuzzy-matched against the stored canary
   sets, producing per-crawler attribution profiles and a cross-model ranking.

Three research layers build on the loop: **crawler-infrastructure
intelligence** (clustering the log into attributable campaigns and flagging
disguised crawlers and agentic browsers), **training-data provenance**
(model-version timeline probes, Min-K% membership inference, RAG-vs-training
disambiguation), and **adversarial self-play** (an RL crawler trained against
the production detector, whose evasions harden a robust second-opinion
detector).

## The control center

One account-protected web app (FastAPI, `http://localhost:8000`) drives
everything:

| Page | What it does |
|---|---|
| **Overview** (`/`) | Live statistics and navigation. |
| **Sites** (`/sites`) | Configure, deploy, stop, and delete honeypot sites (Ansible + Docker Compose under the hood). |
| **Generator** (`/generator`) | Author new honeypot page flavors with a LoRA-fine-tuned Qwen3 model, across 20 content categories. |
| **Crawler Analytics** (`/logs`) | The central request log with per-request fingerprint verdicts, disguised-device detection, and campaign intelligence (community detection + optional GraphSAGE GNN). |
| **LLM Forensics** (`/query`) | Detection runs against target LLMs, manual chatbot evaluation, membership inference, and provenance probes. |
| **Adversarial** (`/selfplay`) | Self-play training runs and the robust-detector second opinion. |

An **Admin panel** (separate admin password) handles access approval and the
monitoring console (Prometheus/Grafana/Loki).

## Quick start (local)

Prerequisites: Docker with the compose plugin, Node.js + npm (for the one-time
CSS build), Python 3 on the host (secret generation + the test suite).

```bash
cp .env.example .env
# Set SECRET_KEY and ADMIN_SECRET in .env — see docs/AUTHENTICATION.md
make proxy      # reverse proxy + central logging (generates a TLS cert)
make app        # control-center web app -> http://localhost:8000
```

Then create the first account (approve your email at `/admin/approve`, sign up
at `/signup` — the exact steps are in
[docs/AUTHENTICATION.md](docs/AUTHENTICATION.md)), and deploy your first
honeypot site from the **Sites** page. Long-running actions (deploys,
detection runs, training) execute server-side: closing the browser never
cancels them.

Everything runs offline by default — the detection demo uses built-in mock
models, so no API keys are required until you want to query real providers
(keys are managed from the LLM Forensics page, or in `.env`).

Other useful targets: `make up-all` (proxy + monitoring + app + every
configured site), `make playbook site_id=site-001` (deploy one site),
`make down-all`. The full command reference is in
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md); running on the public internet
(real hostnames, Let's Encrypt, hardening) is covered in
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Testing

```bash
pip install -r testsuite/requirements.txt
make test-suite                        # offline + deterministic: no Docker, DB, keys, or network
python testsuite/run_app_tests.py      # optional: the same features against the running stack
```

The offline suite covers every user-visible feature (269 tests at the time of
writing) and writes an HTML report to `testsuite/reports/`.

## Repository layout

| Path | What it is |
|---|---|
| `website/` | The Flask honeypot served to bots: canary generation, visit logging, the fingerprint beacon. |
| `proxy/` | The nginx reverse proxy + central logging stack: host-based routing, TLS, request mirror, fingerprint collectors, passive Zeek TLS/TCP capture. |
| `ansible/` | Renders and deploys each per-site Docker stack and its nginx config. |
| `app/` | The control-center web app (FastAPI + Jinja2 + Tailwind). |
| `auto_query/` | The detection engine: prompt generation → LLM querying → evaluation → attribution. |
| `querying/` | The legacy querying pipeline, still hosting the provenance/membership layer, the run store, and the ground-truth loaders (see its README for why both packages exist). |
| `crawler_graph/` | Campaign clustering + GNN attribution over the central log and fingerprint layers. |
| `selfplay/` | Adversarial self-play: RL crawler vs. the production detector, robust-detector training. |
| `template_generator/` | Offline LoRA fine-tuner that authors new honeypot page templates, deduped via a shared registry. |
| `testsuite/` | Offline and live pytest suites with per-feature reporting. |
| `monitoring/` | Prometheus / Grafana / Loki configuration for the self-hosted monitoring stack. |
| `frontend/` | The Tailwind CSS build for the web app (output is tracked; production needs no Node). |
| `scripts/` | Cloud-deployment helpers: public-host sync, Let's Encrypt setup, capture-namespace sync. |
| `docs/` | Architecture, development, deployment, and authentication guides + the research roadmap. |
| `configs/` | Machine-local deployment state written by the app (git-ignored except the template manifest). |

## Documentation

Start with [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — it explains each
layer and calls out the decisions that are load-bearing for the research
(anti-spoof headers, the catch-all server, canary keying). `AGENTS.md` carries
the ground rules for coding agents working in this repo.

> **Authorized testing only.** Use the querying tools against systems, models,
> pages, and datasets you are permitted to test.

## Stakeholders

| Name | Role |
|---|---|
| Emily Wenger | Department of Electrical and Computer Engineering |
| Steven Seiden | PhD student helper |
| Eric Hope, Alex Merck, Monther Yasin | Project leads |

## Team

Abigael Kipkorir · Nicole Li · Cole Burke · Paola Di Bono · Tristan Carter

## Resources

1. https://arguslab.pratt.duke.edu/research/
2. https://www.paladincapgroup.com/wp-content/uploads/2025/06/AI-Tech-Stack-Report.pdf
