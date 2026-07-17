# `ansible/` — per-site deployment automation

Renders and deploys one Docker Compose stack + one nginx server block per
honeypot site. Local-only: the inventory targets `localhost` with a local
connection, and the playbook normally runs *inside the app container* (which
has ansible-core baked in) via `make playbook site_id=<id>` or the Site
Configurator page.

```
configs/sites/<site_id>.yaml   (per-site overrides, written by the web app)
   + group_vars/all.yml        (global defaults)
   -> site.yml                 merge, validate (unique ports, >=10 canary tokens)
   -> roles/configure          render docker-compose.yml, site.conf, varList,
                               per-site monitoring rules/targets
   -> roles/deploy             docker compose up -d --build, health checks
   -> roles/publish            publish the nginx route + monitoring artifacts
                               (a separate role so it runs only after the web
                               container is confirmed healthy, and can be
                               rolled back as a unit)
```

## Key facts

- **Variable contract:** `group_vars/all.yml` defines `website_dir`, `website`
  (port, genmode), `database` (user, password, host_port), `scraper_version`,
  `proxy` (base domains, container, conf dir, optional LE cert paths), and
  `canary_tokens`. Per-site YAML overrides merge *over* these; a per-site
  `canary_tokens` list (written by the Generator flow) replaces the global one.
- **Port uniqueness is validated** (`tasks/validate-site.yml`, run under the
  publication lock): a `website.port` or `database.host_port` collision aborts
  the run. This is the most common deploy failure.
- `-e reset_db=true` recreates the site's Postgres volume (**wipes that site's
  visits and canaries**) — required when changing DB credentials, which
  Postgres only applies at volume creation.
- The rendered outputs (`website/sites/<id>/docker-compose.yml`,
  `proxy/conf.d/<id>.conf`, `website/varLists/scraper{N}.txt`,
  `monitoring/{alerts.d,targets.d}/*`) are build artifacts — edit the
  templates in `roles/configure/templates/`, never the output.
- The proxy reload is `failed_when: false`: deploying before the proxy stack is
  up succeeds, but the route only goes live once the proxy runs.
