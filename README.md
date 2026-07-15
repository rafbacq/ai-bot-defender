# AI Bot Defender 
### Code+ 2026 — Duke Office of Information Technology

---

## Overview

Ever wonder how ChatGPT or Claude.AI gather massive amounts of data they need to function? They deploy automated bots that crawl websites, extracting content at scale, sometimes without permission. This project puts you on the front lines of understanding & controlling this data collection process. Working with Duke's web logs & cutting-edge tools from the Argus Lab, you'll analyze how AI bots behave in the wild, identify patterns in their scraping activities & develop defensive strategies to protect institutional resources. You'll work at the foundational data layer of the Paladin AI Tech Stack, tackling one of the most pressing challenges in the AI era: who gets to control the data that powers AI?


This is your chance to shape how organizations defend their digital assets & gain hands-on experience with large-scale data analysis and cybersecurity principles while contributing to tools that could influence how Duke and other institutions manage their web presence. Whether you're interested in AI ethics, data privacy, cybersecurity or system design, this project offers practical skills & real-world impact.

---

## How it works

1. **Seed** — each honeypot website serves uniquely generated fake facts ("canary tokens") to every visitor, keyed by `User-Agent + ASN`.
2. **Log** — a single nginx reverse proxy fronts every site, routes by hostname, and mirrors every request into a central database so you can see exactly which crawlers visited.
3. **Probe** — the LLM Query Console scrapes a honeypot page and asks target LLMs about its subject using adversarial retrieval prompts.
4. **Match** — extracted answers are compared against the page's canary tokens. A high overlap is evidence that the model ingested the page.

**Going further (Direction 6).** Two research layers build on the core loop:
- **Crawler Intelligence (`/intel`)** clusters the central log into *campaigns* over IP / ASN / User-Agent and passively-captured **JA3/JA4 TLS fingerprints** (a Zeek sidecar that needs no nginx rebuild), using community detection plus an optional **GraphSAGE GNN** — and flags crawlers that *disguise* themselves (undeclared infrastructure, agentic browsers).
- **Training-Data Provenance (`/provenance`)** dates *when* a model ingested your canaries by probing successive model versions against their knowledge cutoffs, separates training-memorization from live retrieval, and proves membership statistically (Min-K%++) without needing the model to regurgitate.

## Quick start (local)

Everything runs locally and is driven from one web app at **http://localhost:8000**.
Run these commands in a WSL/Linux Bash terminal:

```bash
cd /mnt/c/Users/trist/ai-bot-defender
if [ ! -f .env ]; then
    cp .env.example .env
else
    echo ".env already exists; leaving it unchanged"
fi
# Edit /mnt/c/Users/trist/ai-bot-defender/.env and replace SECRET_KEY and ADMIN_SECRET.
make proxy      # reverse proxy + central logging stack (generates a self-signed TLS cert)
make app        # unified web app (landing page + sites + logs + query console)
```

The web app is account-protected. To create the first local account:

1. Open `http://localhost:8000/admin/approve`.
2. Unlock it with the value after `ADMIN_SECRET=` in the project-root `.env`.
3. Approve your email and institution.
4. Open `http://localhost:8000/signup` and use that same email and institution.
5. On later visits, use the chosen **username** at `http://localhost:8000/login`.

The external request form does not approve a user automatically. For local
testing, the administrator can approve an email directly without using the
form. Gmail SMTP is also optional; when it is blank, open `/signup` manually.
See [SIGNIN_README.md](SIGNIN_README.md) for exact file paths, secret-generation
commands, registration steps, troubleshooting, and deployment settings.

Other useful targets: `make up-all` (proxy + app + every configured site), `make playbook site_id=site-001` (deploy one site), `make down-all`. See `CLAUDE.md` for the full command reference and architecture.

## Background work and browser navigation

Long-running control-center actions execute on the server after their form has
been accepted. It is safe to switch tabs, visit another control-center page, or
close and reopen the browser while site deployment, campaign/GNN analysis,
template generation, detection/manual evaluation, prompt generation,
provenance/RAG, membership inference, self-play training/ingest, or robust live
scoring is running. A signed-in user sees an app-wide running-job indicator in
the header that links back to each dedicated progress view. Task-style feature
pages also rediscover that user's active job automatically, and completed task
results are restored from checkpoints where applicable.

Cancellation is an explicit server request from the progress UI. Merely hiding
or leaving a page never sends one. Once a launch has returned its progress page,
the browser is only a status viewer—not the owner of the computation.

This browser-lifetime guarantee is distinct from an application/container
restart. The current deployment uses in-process workers, so restarting the app
interrupts work that is still running. Persisted run/checkpoint records make the
interruption terminal and visible instead of leaving a progress page spinning;
already completed results and generated artifacts remain available.

To run the querying pipeline from the command line (offline demo, no API keys):

```bash
python -m querying.main --url https://example.com/ --models mock/scraper-sim mock/honest-llm
```

## Repository structure

| Path | What it is |
|---|---|
| `app/` | Unified web app (FastAPI + Jinja2 + Tailwind): landing page, Site Configurator, Request Log, LLM Query Console. |
| `querying/` | LLM querying pipeline: scrape → probe → extract → match against canary tokens. |
| `website/` | The Flask honeypot served to bots, plus its Postgres model. |
| `ansible/` | Renders & deploys each per-site Docker stack and its nginx config. |
| `proxy/` | The nginx reverse proxy + central request-logging stack. |
| `template_generator/` | Offline LoRA fine-tuner that generates new honeypot HTML templates across 20 content categories, deduped via a shared template registry. |
| `data/`, `cleaned_intros/`, `wikipedia_towns_text/` | Research corpora / datasets. |

> **Authorized testing only.** Use the querying tools against systems, models, pages, and datasets you are permitted to test.

## Stakeholders

| Name | Role |
|---|---|
| Emily Wenger | Department of Electrical and Computer Engineering |
| Steven Seiden | PhD student helper — TBD involvement |
| Eric Hope, Alex Merck, Monther Yasin | Project leads |

---

## Team

Abigael Kipkorir . Nicole Li . Cole Burke . Paola Di Bono . Tristan Carter

## Resources
1. https://arguslab.pratt.duke.edu/research/
2. https://www.paladincapgroup.com/wp-content/uploads/2025/06/AI-Tech-Stack-Report.pdf
