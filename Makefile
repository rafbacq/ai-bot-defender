.PHONY: frontend-css app app-build app-down app-logs app-dev playbook stack-up stack-down up-all down-all \
	ensure-net net-down proxy proxy-build proxy-down proxy-logs intel intel-selftest provenance \
	provenance-all test-suite selfplay-up selfplay-down selfplay-selftest \
	selfplay-calibrate selfplay-train selfplay-coevolve selfplay-ingest set-public-host letsencrypt

SITES := $(patsubst configs/sites/%.yaml,%,$(wildcard configs/sites/*.yaml))
APP_COMPOSE := docker compose -f docker-compose.app.yml
PROXY_COMPOSE := docker compose -f docker-compose.proxy.yml
TRAINER_COMPOSE := docker compose -f docker-compose.app.yml --profile trainer
ANSIBLE_PLAYBOOK := $(APP_COMPOSE) exec -T -w $(CURDIR)/ansible app ansible-playbook
FRONTEND_INPUTS := frontend/tailwind.input.css frontend/tailwind.config.js \
	frontend/package.json frontend/package-lock.json $(wildcard app/templates/*.html)

# Compile responsive utility classes once and serve them from the app itself.
# The generated file is tracked so production does not need Node at runtime;
# this target only runs npm when a template or frontend build input changed.
app/static/css/tailwind.css: $(FRONTEND_INPUTS)
	npm --prefix frontend ci
	npm --prefix frontend run build:css

frontend-css: app/static/css/tailwind.css

# --- Rebuild-only-when-needed bookkeeping ----------------------------------
# `make app` / `make proxy` used to `up -d --build` on EVERY run, forcing a full
# image build each time (the app image's ~11 GB torch/cu128 layer cache-thrashes,
# so a "warm" rebuild still cost minutes -- and `up-all` triggered it up to 3x
# via stack-up/intel/provenance). But the app image is bind-mounted at runtime
# (${PWD}:${PWD}), so the running code is always what's on disk -- an image
# rebuild is only needed when a BUILD INPUT (the Dockerfile or a requirements
# file / a proxy service's source) changes, never for ordinary code edits.
# So we build once, then reuse: a machine-local stamp records the last build and
# we rebuild only when the image is missing or an input is newer than the stamp.
# `make app-build` / `make proxy-build` force a rebuild on demand.
STAMP_DIR := .make
# Compose image name = <project>-<service>; project is pinned to
# `ai-bot-defender-app` in docker-compose.app.yml, service is `app`.
APP_IMAGE := ai-bot-defender-app-app
APP_STAMP := $(STAMP_DIR)/app-image.stamp
# Only these drive a pip install / apt layer; auto_query/ + the app/querying/...
# source are bind-mounted at runtime, so editing them needs no rebuild.
APP_BUILD_INPUTS := app/Dockerfile app/requirements.txt app/requirements-ml.txt \
	app/requirements-autoquery.txt app/requirements-auth.txt crawler_graph/requirements.txt
PROXY_IMAGES := proxy-collector proxy-fp-collector proxy-tls-capture proxy-tls-shipper
PROXY_STAMP := $(STAMP_DIR)/proxy-images.stamp
# The proxy service code is baked (not bind-mounted), so any file under these
# build contexts is a rebuild input.
PROXY_BUILD_INPUTS := proxy/collector proxy/fp-collector proxy/tls-capture proxy/tls-shipper

# Shared external network that the proxy and every site stack attach to.
# Idempotent: ignores "already exists".
ensure-net:
	docker network create proxy_net 2>/dev/null || true

# Remove the shared network (full teardown). Safe no-op if it's already gone or
# still in use -- nothing should be attached after the stacks are down.
net-down:
	docker network rm proxy_net 2>/dev/null || true

# --- Unified web app (landing page + sites + logs + query console) ---------
# Build the image only when it's missing or a build input changed; otherwise
# just (re)start the container (code is picked up from the runtime bind mount,
# so no rebuild is needed for code edits). Use `make app-build` to force a
# rebuild after changing a requirements file / the Dockerfile.
app: frontend-css ensure-net
	@if ! docker image inspect $(APP_IMAGE) >/dev/null 2>&1; then \
		echo "==> Building app image (first run -- the slow one; reused afterwards)"; \
		$(APP_COMPOSE) build app && mkdir -p $(STAMP_DIR) && touch $(APP_STAMP); \
	elif [ -f $(APP_STAMP) ] && [ -n "$$(find $(APP_BUILD_INPUTS) -newer $(APP_STAMP) 2>/dev/null)" ]; then \
		echo "==> App dependencies changed -- rebuilding image"; \
		$(APP_COMPOSE) build app && touch $(APP_STAMP); \
	else \
		mkdir -p $(STAMP_DIR); [ -f $(APP_STAMP) ] || touch $(APP_STAMP); \
		echo "==> App image up to date -- starting without rebuild ('make app-build' to force)"; \
	fi
	$(APP_COMPOSE) up -d
	@echo
	@echo "AI Bot Defender:  http://localhost:8000"

# Force a full rebuild of the app image, then start it. Run this after editing a
# requirements file or the Dockerfile (the only changes a rebuild is needed for).
app-build: frontend-css ensure-net
	$(APP_COMPOSE) build app
	@mkdir -p $(STAMP_DIR) && touch $(APP_STAMP)
	$(APP_COMPOSE) up -d
	@echo
	@echo "AI Bot Defender (rebuilt):  http://localhost:8000"

app-down:
	$(APP_COMPOSE) down

app-logs:
	$(APP_COMPOSE) logs -f app

# Run the app directly on the host (no container) for local development.
# Needs:  pip install -r app/requirements.txt
app-dev:
	PROJECT_ROOT=$(CURDIR) uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# --- Reverse proxy + central logging ---------------------------------------
# Same rebuild-only-when-needed logic as `app`: build the proxy's service images
# only when one is missing or a proxy source file changed, else just `up -d`.
# `make proxy-build` forces a rebuild (use after editing a collector/shipper).
proxy: ensure-net
	@missing=0; for img in $(PROXY_IMAGES); do docker image inspect $$img >/dev/null 2>&1 || missing=1; done; \
	if [ $$missing -eq 1 ]; then \
		echo "==> Building proxy images (first run or an image was removed)"; \
		$(PROXY_COMPOSE) build && mkdir -p $(STAMP_DIR) && touch $(PROXY_STAMP); \
	elif [ -f $(PROXY_STAMP) ] && [ -n "$$(find $(PROXY_BUILD_INPUTS) -newer $(PROXY_STAMP) 2>/dev/null)" ]; then \
		echo "==> Proxy sources changed -- rebuilding images"; \
		$(PROXY_COMPOSE) build && touch $(PROXY_STAMP); \
	else \
		mkdir -p $(STAMP_DIR); [ -f $(PROXY_STAMP) ] || touch $(PROXY_STAMP); \
		echo "==> Proxy images up to date -- starting without rebuild ('make proxy-build' to force)"; \
	fi
	$(PROXY_COMPOSE) up -d
	@bash scripts/sync-tls-capture-netns.sh
	@echo
	@echo "Reverse proxy:  http://localhost:80  +  https://localhost:443  (route sites by Host header / TLS SNI)"

# Force a full rebuild of the proxy service images, then start the stack.
proxy-build: ensure-net
	$(PROXY_COMPOSE) build
	@mkdir -p $(STAMP_DIR) && touch $(PROXY_STAMP)
	$(PROXY_COMPOSE) up -d
	@bash scripts/sync-tls-capture-netns.sh
	@echo
	@echo "Reverse proxy (rebuilt):  http://localhost:80  +  https://localhost:443"

proxy-down:
	$(PROXY_COMPOSE) down

proxy-logs:
	$(PROXY_COMPOSE) logs -f nginx

# --- Public identity (cloud deployment) -------------------------------------
# Sync every hostname-bearing config (all.yml, .env/certgen, TLS cert, each
# rendered nginx block) to this machine's public address in one command.
# HOST is optional: an IP (-> <ip>.sslip.io) or a real domain; when omitted the
# EC2 public IP is auto-detected. Run after every IP change (stop/start
# without an Elastic IP) or when a real domain is acquired.
set-public-host:
	@bash scripts/set-public-host.sh $(HOST)

# Issue/refresh the publicly-trusted Let's Encrypt cert for every public
# hostname (honeypot sites + admin control center) and wire nginx to it.
# LE_DRY_RUN=1 for a staging dry-run. Re-run after adding a site or changing
# the public host.
letsencrypt:
	@bash scripts/setup-letsencrypt.sh

# --- Site deployment -------------------------------------------------------
playbook: app
	@test -n "$(site_id)" || (echo "Usage: make playbook site_id=<id>"; exit 1)
	$(ANSIBLE_PLAYBOOK) site.yml -e site_id=$(site_id)

stack-up: app
	@for s in $(SITES); do \
		echo "==> Bringing up $$s"; \
		$(ANSIBLE_PLAYBOOK) site.yml -e site_id=$$s || exit 1; \
	done

stack-down:
	@for d in website/sites/*/; do \
		if [ -f $$d/docker-compose.yml ]; then \
			echo "==> Bringing down $$d"; \
			(cd $$d && docker compose down); \
		fi; \
	done

# --- Crawler intelligence + training-data provenance (Direction 6) ---------
# Run inside the app container (it has the analysis deps, the Docker CLI, and
# reaches logdb / per-site DBs). The GraphSAGE GNN (torch + torch_geometric) is
# now baked into the app image, so `--gnn` runs here too AND from the /intel page
# ("Recompute with GraphSAGE GNN") — no separate environment needed.
# Full attribution by default (ASN/RDAP enrichment — first run is slower over a
# large log, then cached in output/asn_cache.json). Override flags via INTEL_ARGS,
# e.g. `make intel INTEL_ARGS=--gnn` or `make intel INTEL_ARGS="--since-hours 168"`.
INTEL_ARGS ?=
intel: app
	$(APP_COMPOSE) exec -T -w $(CURDIR) app python -m crawler_graph build $(INTEL_ARGS)

intel-selftest: app
	$(APP_COMPOSE) exec -T -w $(CURDIR) app python -m crawler_graph selftest

# --- Adversarial self-play (Direction 2) -----------------------------------
# Runs in the DEDICATED `trainer` container (torch + torch_geometric baked into
# the same image) so long PPO/PSRO runs never compete with the FastAPI app.
# Override args via SP_ARGS, e.g. `make selfplay-train SP_ARGS="--iterations 60"`.
SP_ARGS ?=
selfplay-up: ensure-net
	$(TRAINER_COMPOSE) up -d --build trainer

selfplay-selftest: selfplay-up
	$(TRAINER_COMPOSE) exec -T -w $(CURDIR) trainer python -m selfplay selftest

selfplay-calibrate: selfplay-up
	$(TRAINER_COMPOSE) exec -T -w $(CURDIR) trainer python -m selfplay calibrate $(SP_ARGS)

selfplay-train: selfplay-up
	$(TRAINER_COMPOSE) exec -T -w $(CURDIR) trainer python -m selfplay train $(SP_ARGS)

selfplay-coevolve: selfplay-up
	$(TRAINER_COMPOSE) exec -T -w $(CURDIR) trainer python -m selfplay coevolve $(SP_ARGS)

selfplay-ingest: selfplay-up
	$(TRAINER_COMPOSE) exec -T -w $(CURDIR) trainer python -m selfplay ingest $(SP_ARGS)

selfplay-down:
	$(TRAINER_COMPOSE) rm -sf trainer

# Probe a deployed site's canaries across the model timeline to date ingestion.
#   make provenance site_id=site-001 db_name=scraper1-db [db_user=user]
provenance: app
	@test -n "$(site_id)" || (echo "Usage: make provenance site_id=<id> db_name=<scraperN-db> [db_user=user]"; exit 1)
	@test -n "$(db_name)" || (echo "Usage: make provenance site_id=<id> db_name=<scraperN-db> [db_user=user]"; exit 1)
	$(APP_COMPOSE) exec -T -w $(CURDIR) app python -m querying.provenance \
		--site $(site_id) --db-name $(db_name) --db-user $(if $(db_user),$(db_user),user)

# Best-effort provenance probe for EVERY configured site (offline mock models).
# Derives each site's DB name from its rendered compose; skips sites with no
# canaries yet and never fails the run — used by `up-all`.
provenance-all: app
	@for s in $(SITES); do \
		db=$$(grep -ohE 'scraper[0-9]+-db' website/sites/$$s/docker-compose.yml 2>/dev/null | head -1); \
		[ -n "$$db" ] || db=scraper1-db; \
		echo "==> provenance for $$s ($$db)"; \
		$(APP_COMPOSE) exec -T -w $(CURDIR) app python -m querying.provenance \
			--site $$s --db-name $$db --models mock/scraper-sim mock/honest-llm >/dev/null 2>&1 \
			&& echo "    ok" || echo "    skipped (no canaries yet or DB mismatch)"; \
	done

# Standalone project-wide test suite. Installs are intentionally not hidden here:
# create/activate a venv and `pip install -r testsuite/requirements.txt`, then run
# one command to execute every offline test, including GraphSAGE.
test-suite:
	python testsuite/run_tests.py

# Bring up the COMPLETE application, in dependency order, regardless of `make -j`:
#   1. proxy stack   (the only entry point + central logging; must be up first so
#                     each site's `nginx -s reload` succeeds)
#   2. web app + every configured site in configs/sites/*.yaml (`stack-up`
#                     starts the app because its container runs Ansible)
# Each step ensures proxy_net itself, so a bare `make up-all` works on a fresh
# machine. Sub-makes run sequentially so ordering holds even under parallel make.
up-all:
	$(MAKE) proxy
	$(MAKE) stack-up
	-$(MAKE) intel INTEL_ARGS="--no-asn --since-hours 168"
	-$(MAKE) provenance-all
	@echo
	@echo "==> AI Bot Defender is up (proxy + app + sites + intelligence + provenance):"
	@echo "    Web app:        http://localhost:8000"
	@echo "    Reverse proxy:  http://localhost:80  +  https://localhost:443"
	@echo "    Crawler intel:  http://localhost:8000/intel"
	@echo "    Provenance:     http://localhost:8000/provenance"
	@echo "    Sites deployed: $(if $(SITES),$(SITES),none yet — add one in the web app)"

# Tear down EVERYTHING the application created, in reverse order. The leading `-`
# on each step keeps the teardown going even if one stack is already gone, so a
# single `make down-all` always leaves a clean slate (no app, proxy, sites, or
# shared network).
down-all:
	-$(MAKE) app-down
	-$(MAKE) stack-down
	-$(MAKE) proxy-down
	-$(MAKE) net-down
	@echo
	@echo "==> AI Bot Defender is fully down (app, proxy, sites, and proxy_net removed)."
