# `website/` — the honeypot application

The Flask app that bots actually hit. One route, `GET /`, which serves the
active page flavor with that visitor's canary tokens filled in and logs the
visit. Deployed as one Docker stack per site by the Ansible playbook (never run
publicly outside the reverse proxy — sites bind to `127.0.0.1` and the proxy is
the only entry point).

## Layout

| Path | Role |
|---|---|
| `server.py` | Request handling: client-IP/ASN resolution, canary assignment (stable per device — see below), visit logging. |
| `runtime_health.py` | Side-effect-free validation of the live render dependencies (used by the health probe so monitoring never mints real canaries). |
| `user_agent_info.py` | User-Agent parsing helpers. |
| `templates/scraper{N}.html` | The page flavors. New ones are scaffolded by the playbook or authored on the Generator page. |
| `varLists/scraper{N}.txt` | **Generated** canary-expression lists — never edit by hand (edit `canary_tokens` in the Ansible vars instead). |
| `static/js/fp.js` | The Layer-1 browser-fingerprint beacon; its payload schema is a contract shared with `proxy/fp-collector/` and `crawler_graph`. Also sets the `__abd_fp` device cookie. |
| `sites/` | **Rendered** per-site compose stacks (git-ignored build artifacts). |

## The two rules everything depends on

1. **Canary stability.** A visitor is keyed by the `__abd_fp` device cookie
   when present, else `(User-Agent, ASN)`. A returning visitor always gets the
   **same** `var1..var10` — that stability is what lets a leaked canary set
   attribute to one device, and what makes one set appearing under several
   identities a disguise signal.
2. **Trustable client IP.** `get_client_ip()` trusts the first
   `X-Forwarded-For` entry, which is safe only because the proxy *overwrites*
   XFF with the real client address. Never change the proxy to append.

`SCRAPER_VERSION` (env var — never hardcode it) selects the flavor:
`templates/scraper{N}.html` + `varLists/scraper{N}.txt` + database
`scraper{N}-db` in lockstep. `python server.py nogen` disables canary
generation (serves `"Null"` vars, stores nothing).
