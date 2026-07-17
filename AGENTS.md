# AGENTS.md

Ground rules for LLM coding agents (and a fast orientation for new
contributors) working in this repository.

## Read before changing anything

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — how the layers fit together
  and which decisions are load-bearing for the research. The sections on the
  reverse proxy and canary handling are the ones most often broken by
  well-meaning edits.
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) — every make target, the two test
  suites, the verification loop, dependency layout, coding conventions, the
  generated-artifacts table, and the full project-specific warning list.
- The README of the package you are changing (`querying/`, `crawler_graph/`,
  `selfplay/`, `template_generator/`, `testsuite/` each have one).

## Working rules

- **Inspect existing patterns before adding code.** This repo has strong,
  deliberate conventions (the `scraper_version` indirection, generated nginx
  config, per-site YAML overrides). Read the relevant template/role/module and
  mirror it rather than introducing a parallel approach.
- **Make minimal, focused changes.** Touch only what the task needs. Do not
  reformat or "clean up" unrelated files, and prefer extending an existing
  module over creating a duplicate system.
- **Do not change public surfaces unless explicitly asked**: the
  request/response contract of `website/server.py`, the `all_visits` /
  `new_visits` / `new_agents_vars` schemas, env-var names, the Ansible variable
  contract (`all.yml` keys, per-site yaml shape), Make targets, or the
  load-bearing nginx decisions (catch-all server, XFF overwrite, `X-Site`
  tagging, host-based routing).
- **Explain risky changes before making them** — anything that alters
  deployment behavior, database schemas, the proxy's security properties, or
  that could wipe data.
- **Respect the layering.** `template_generator/` and `selfplay/` are additive
  and must not modify the runtime layers; `selfplay/` writes only under
  `selfplay/output/`.
- **Don't edit generated artifacts** — change the source and re-render (the
  full table is in docs/DEVELOPMENT.md). In particular: `website/varLists/*.txt`,
  `proxy/conf.d/*.conf`, `website/sites/*/docker-compose.yml`.
- **The deployed server runs the working tree.** The app container bind-mounts
  the repository, so an edit on a deployed machine can affect the live app
  immediately. Test before you save when working on a live box.

## Things that will bite you

One line each — details and rationale in
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md#project-specific-warnings):

- `website.port` / `database.host_port` must be unique per site (the most
  common deploy failure).
- Postgres credentials are fixed at volume-creation time; changing them needs a
  volume reset, which wipes that site's data.
- The nginx catch-all server and the XFF overwrite are security-load-bearing.
- The TLS cert is shared across all sites; base-domain changes must reach the
  certgen service (or use `make set-public-host`).
- `app/services/sites.py`'s shared ruamel `YAML()` is not thread-safe — always
  go through `_yaml_load`/`_yaml_dump`.
- Keep `app/requirements.txt` byte-stable; new app deps go in a late-layer
  requirements file or the image rebuild re-downloads the multi-GB torch stack.
- `scraper_version` must come from the `SCRAPER_VERSION` env var — the playbook
  rewrites hardcoded values.
- `querying/llm_client.py` must never fall back to the mock models for a real
  provider id (the mock fabricates a leak).

## Testing

- `make test-suite` (offline, deterministic, no Docker/DB/keys/network) is the
  regression gate; `python testsuite/run_app_tests.py` exercises the live
  stack. There is no linter, type checker, or CI — do not invent other test
  commands.
- The offline suite can't catch routing/TLS/DB-write regressions; after
  touching `website/`, `ansible/`, or `proxy/`, run the live verification loop
  in docs/DEVELOPMENT.md.

## Key files by area

- **Canary logic:** `website/server.py`, `website/user_agent_info.py`,
  `website/varLists/scraper1.txt`.
- **Deployment automation:** `ansible/site.yml`, `ansible/group_vars/all.yml`,
  `ansible/roles/configure/` (templates + tasks), `ansible/roles/deploy/`.
- **Proxy & central logging:** `proxy/nginx.conf`, `proxy/snippets/mirror.conf`,
  `proxy/collector/app.py`, `docker-compose.proxy.yml`.
- **Web app:** `app/main.py` (routes), `app/services/` (business logic),
  `app/templates/` (Jinja2 + Tailwind).
- **Detection engine:** `auto_query/pipelines/`, `auto_query/src/`,
  `auto_query/config/models.py`, driven by
  `app/services/auto_query_adapter.py`.
- **Provenance:** `querying/{model_timeline,provenance,membership,rag_disambiguation}.py`.
- **Crawler intelligence:** the `crawler_graph/` package;
  `proxy/tls-capture/` + `proxy/tls-shipper/` for passive capture.
- **Orchestration:** the root `Makefile` — every workflow has a target.
