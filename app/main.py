"""AI Bot Defender — unified FastAPI web application.

Routes:
    GET/POST /login             Sign in to an approved local account
    GET/POST /signup            Create an account from a one-time approval
    GET  /request-access        Link to the external access-request form
    GET/POST /admin/approve     Review-approved email administration
    POST /admin/decline         Revoke/notify a declined access request
    POST /logout                Clear the signed login session
    GET  /                      Landing page (stats + navigation)
    GET  /api/stats             Live stats (JSON, polled by the landing page)
    GET  /sites                 Site Configurator
    POST /sites/website-dir     Save the global website source path
    POST /sites/deploy          Deploy / re-apply a site via Ansible
    GET  /logs                  Crawler Analytics — requests + fingerprints + campaigns
    GET  /logs/fragment         Traffic-table rows for one page (AJAX Prev/Next paging)
    GET  /logs/export.csv       Download the current page of requests as CSV
    GET  /query                 LLM Forensics — detection + provenance + membership
    POST /query/run             Start a detection run (background) -> live run page
    GET  /query/runs/{id}/status Live run status (JSON, polled by the run page)
    GET  /query/runs/{id}/download/{artifact}  Final results (json/csv) + the
                                intermediate artifacts (prompt, raw responses,
                                extraction) kept out of the inline results view
    POST /query/keys            Save/clear a provider API key (writes .env)
    POST /query/prompt          Manual workflow: generate the retrieval prompt
    GET  /query/prompt.txt      Manual workflow: download the generated prompt
    POST /query/manual          Manual workflow: evaluate pasted/uploaded responses
    GET  /query/runs/{run_id}   Single run detail
    POST /provenance/run        Start a provenance/RAG probe (background) -> report page
    GET  /provenance/runs/{id}/status  Live probe status (JSON, polled by the report page)
    GET  /provenance/runs/{id}  Provenance/RAG report detail
    GET  /generator             Template Generator
    POST /generator/run         Start a background generation job; redirect to its progress view
    GET  /generator/status/{id} Live generation progress (JSON, polled by the page)
    POST /generator/edit        Save hand-edited text of a stored scraper<N>.html
"""

import math
import secrets
from datetime import datetime
from urllib.parse import urlencode, urlsplit

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import (
    FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import config
from .services import (
    auth_service, fingerprint_service, graph_intel, keys_service, provenance_service,
    querying_service, request_log, run_manager, selfplay_service, sites, stats,
    template_gen,
)

app = FastAPI(title="AI Bot Defender")
app.mount("/static", StaticFiles(directory=str(config.STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(config.TEMPLATE_DIR))


def _css_version():
    """mtime of app.css, used to cache-bust the stylesheet link. The CSS is served
    from the bind mount (it changes without a rebuild/restart), and browsers happily
    reuse a cached copy — a stale sheet is how the /logs severity tints once shipped
    invisibly. Evaluated per render so a fresh edit busts immediately."""
    try:
        return int((config.STATIC_DIR / "css" / "app.css").stat().st_mtime)
    except OSError:
        return 0


templates.env.globals["css_version"] = _css_version


# --- Authentication guard -------------------------------------------------
# SessionMiddleware is registered *after* the function middleware below so it
# wraps the guard and request.session is already populated when the guard runs.
_PUBLIC_PATHS = frozenset({
    "/login",
    "/signup",
    "/request-access",
    "/logout",
    "/admin/login",
    "/admin/approve",
    "/admin/decline",
})
_PUBLIC_PREFIXES = ("/static/",)


def _safe_next_url(value: str | None) -> str:
    """Return a same-origin redirect target, falling back to the overview."""
    value = value or "/"
    if not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or any(ch in value for ch in "\r\n"):
        return "/"
    return value


def _is_authenticated(request: Request) -> bool:
    return bool(request.session.get("username"))


def _is_admin(request: Request) -> bool:
    return bool(request.session.get("is_admin"))


def _admin_secret_matches(candidate: str) -> bool:
    return secrets.compare_digest(str(candidate or ""), config.ADMIN_SECRET)


@app.middleware("http")
async def auth_guard(request: Request, call_next):
    """Redirect unauthenticated traffic to login while leaving auth/static public."""
    path = request.url.path
    public = path in _PUBLIC_PATHS or any(
        path.startswith(prefix) for prefix in _PUBLIC_PREFIXES
    )
    if public or _is_authenticated(request):
        return await call_next(request)

    target = path
    if request.url.query:
        target = f"{target}?{request.url.query}"
    login_query = "" if target == "/" else f"?{urlencode({'next': target})}"
    return RedirectResponse(f"/login{login_query}", status_code=303)


app.add_middleware(
    SessionMiddleware,
    secret_key=config.SECRET_KEY,
    session_cookie="aibd_session",
    max_age=config.SESSION_MAX_AGE,
    same_site="lax",
    https_only=config.SESSION_HTTPS_ONLY,
)


def _pretty_timestamp(value):
    """Render an ISO 8601 timestamp as a readable string (e.g. "Jun 11, 2026,
    2:30 PM UTC"). Returns the value unchanged if it can't be parsed."""
    if not value:
        return value
    try:
        dt = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return value
    hour = dt.hour % 12 or 12
    meridiem = "AM" if dt.hour < 12 else "PM"
    pretty = f"{dt:%b} {dt.day}, {dt.year}, {hour}:{dt.minute:02d} {meridiem}"
    offset = dt.utcoffset() if dt.tzinfo is not None else None
    if offset is not None:
        pretty += " UTC" if offset.total_seconds() == 0 else f" {dt.tzname() or ''}".rstrip()
    return pretty


templates.env.filters["pretty_ts"] = _pretty_timestamp


# --- Landing ---------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html",
        {"active_page": "home", "stats": stats.landing_stats()},
    )


@app.get("/api/stats")
def api_stats():
    return JSONResponse(stats.landing_stats())


# --- Site Configurator -----------------------------------------------------
@app.get("/sites", response_class=HTMLResponse)
def sites_page(request: Request, deployed: str = "", ok: str = ""):
    versions = sites.available_scraper_versions() or [1]
    return templates.TemplateResponse(
        request,
        "sites.html",
        {
            "active_page": "sites",
            "sites": sites.list_sites(),
            "active_routes": sites.active_proxy_sites(),
            "versions": versions,
            "website_dir": sites.get_website_dir(),
            "suggested": sites.suggest_ports(),
            "deployed": deployed,
            "ok": ok,
            "deploy_output": _LAST_DEPLOY.get("output"),
            "deploy_site_id": _LAST_DEPLOY.get("site_id"),
        },
    )


@app.get("/sites/template/{version}", response_class=PlainTextResponse)
def site_template(version: int):
    source = sites.template_source(version)
    return source if source is not None else f"No template for scraper{version}.html"


@app.post("/sites/website-dir")
def save_website_dir(website_dir: str = Form(...)):
    if website_dir.strip():
        sites.set_website_dir(website_dir.strip())
    return RedirectResponse("/sites", status_code=303)


# Small module-level cache so the deploy output survives the post/redirect.
_LAST_DEPLOY = {}


@app.post("/sites/deploy")
def deploy(
    site_id: str = Form(...),
    scraper_version: str = Form("1"),
    port: str = Form(...),
    genmode: str = Form("true"),
    db_user: str = Form(""),
    db_password: str = Form(""),
    db_host_port: str = Form(...),
    reset_db: str = Form(""),
):
    site_id = site_id.strip()
    if not site_id or not port.strip() or not db_host_port.strip():
        _LAST_DEPLOY.update(site_id=site_id, output="site_id, port and db_host_port are required.")
        return RedirectResponse("/sites?ok=0", status_code=303)

    sites.write_site_config(
        site_id,
        scraper_version=scraper_version,
        port=port.strip(),
        genmode=(genmode == "true"),
        db_user=db_user.strip(),
        db_password=db_password.strip(),
        db_host_port=db_host_port.strip(),
    )
    ok, output = sites.deploy_site(site_id, reset_db=bool(reset_db))
    _LAST_DEPLOY.update(site_id=site_id, output=output)
    return RedirectResponse(f"/sites?deployed={site_id}&ok={1 if ok else 0}", status_code=303)


# --- Crawler Analytics (requests + fingerprints + campaigns, one page) -------
# Survives the post/redirect so a campaign-recompute error shows on the page.
_LAST_INTEL = {}


def _annotate_rows(data, disguise):
    """Fold the identity-rotation flags + a 3-tier severity onto each request row.

    The two flag bases carry different severities: a device wearing multiple
    claimed identities is ``disguised`` (red), while a single-identity device
    merely seen from several public networks is ``net_roaming`` (orange — that
    shape is also a phone hopping Wi-Fi/LTE or a privacy VPN). Shared by the full
    ``/logs`` page and the ``/logs/fragment`` AJAX paging endpoint so both render
    rows identically."""
    devices = [d for d in (disguise.get("devices") or []) if d.get("fp_id")]
    disguised_ids = {d["fp_id"] for d in devices if d.get("basis") == "identities"}
    roaming_ids = {d["fp_id"] for d in devices if d.get("basis") == "networks"}
    for row in data.get("rows") or []:
        if row.get("fp_id"):
            if row["fp_id"] in disguised_ids:
                row["disguised"] = True
            elif row["fp_id"] in roaming_ids:
                row["net_roaming"] = True
        row["severity"] = fingerprint_service.severity_of(row)
    return data


@app.get("/logs", response_class=HTMLResponse)
def logs_page(
    request: Request,
    site: str = "All sites",
    method: str = "All methods",
    search: str = "",
    page: int = 1,
    page_size: int = 100,
    ok: str = "",
):
    error = None
    data = {"total": 0, "last_24h": 0, "latest_ts": None, "rows": []}
    options = {"sites": [], "methods": []}
    active = []
    try:
        options = request_log.fetch_filter_options()
        data = request_log.fetch_requests(
            site=site, method=method, search=search, page=page, page_size=page_size
        )
        active = list(request_log.site_status_map())
    except request_log.RequestLogError as exc:
        error = str(exc)

    # Identity-rotation / disguise: devices (by fp_id) seen under multiple UAs/nets.
    # Fold a per-row `disguised` flag + a 3-tier severity, and pass the summary for the panel.
    disguise = fingerprint_service.disguise_summary(max_age=5)
    _annotate_rows(data, disguise)

    page_count = max(1, math.ceil((data["total"] or 0) / page_size))
    return templates.TemplateResponse(
        request,
        "analytics.html",
        {
            "active_page": "logs",
            "active_section": "traffic",
            "error": error,
            "data": data,
            "options": options,
            "active": active,
            "filters": {"site": site, "method": method, "search": search,
                        "page": page, "page_size": page_size},
            "page_count": page_count,
            # Fingerprint summary for the KPI strip (best-effort; None when absent).
            "fp": fingerprint_service.summary_counts(),
            # Devices caught wearing multiple identities (the disguise panel).
            "disguise": disguise,
            # Campaign intelligence: insights band + collapsible full breakdown.
            "available": graph_intel.available(),
            "gnn_available": graph_intel.gnn_available(),
            "gnn_status": graph_intel.gnn_status(),
            "report": graph_intel.load_report(),
            "has_viz": graph_intel.viz_path() is not None,
            "has_interactive": graph_intel.interactive_viz_path() is not None,
            "intel_error": _LAST_INTEL.get("error"),
            "ok": ok,
        },
    )


@app.get("/logs/fragment", response_class=HTMLResponse)
def logs_fragment(
    request: Request,
    site: str = "All sites",
    method: str = "All methods",
    search: str = "",
    page: int = 1,
    page_size: int = 100,
):
    """Just the traffic-table ``<tbody>`` rows for one page. The Prev/Next buttons fetch
    this and swap the table body in place, so paging is instant (no full-page reload,
    no scroll jump, and none of the campaign/stat work the full page does)."""
    try:
        data = request_log.fetch_requests(
            site=site, method=method, search=search, page=page, page_size=page_size
        )
    except request_log.RequestLogError as exc:
        return HTMLResponse(
            f'<tr><td colspan="7" class="muted" style="text-align:center;padding:24px">{exc}</td></tr>'
        )
    # The disguised-device set changes far slower than a human pages, so a briefly
    # cached copy keeps Prev/Next to a single psql round-trip.
    _annotate_rows(data, fingerprint_service.disguise_summary(max_age=30))
    return templates.TemplateResponse(request, "_traffic_rows.html", {"data": data})


@app.get("/logs/export.csv")
def logs_export(site: str = "All sites", method: str = "All methods",
                search: str = "", page: int = 1, page_size: int = 100):
    try:
        data = request_log.fetch_requests(
            site=site, method=method, search=search, page=page, page_size=page_size,
            enrich=False,
        )
        csv_text = request_log.requests_to_csv(data["rows"])
    except request_log.RequestLogError as exc:
        csv_text = f"error,{exc}\n"
    return PlainTextResponse(
        csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=all_visits_page_{page}.csv"},
    )


# --- Back-compat redirects (these views are now merged into /logs and /query) -
@app.get("/fingerprints")
def fingerprints_redirect():
    return RedirectResponse("/logs", status_code=307)


@app.get("/intel")
def intel_redirect():
    return RedirectResponse("/logs", status_code=307)


@app.post("/intel/recompute")
def intel_recompute(limit: str = Form(""), since_hours: str = Form(""), use_gnn: str = Form("")):
    lim = int(limit) if limit.strip().isdigit() else None
    since = int(since_hours) if since_hours.strip().isdigit() else None
    try:
        graph_intel.recompute(limit=lim, since_hours=since, use_gnn=bool(use_gnn))
        _LAST_INTEL.pop("error", None)
        ok = 1
    except graph_intel.IntelError as exc:
        _LAST_INTEL["error"] = str(exc)
        ok = 0
    # Refresh the self-play robust detector's second opinion over the same live
    # traffic (best-effort; no-op when self-play hasn't been trained yet).
    if selfplay_service.available() and selfplay_service.status().get("robust_detector_trained"):
        selfplay_service.score_live(since_hours=since)
    return RedirectResponse(f"/logs?ok={ok}", status_code=303)


@app.get("/intel/graph.png")
def intel_graph_png():
    path = graph_intel.viz_path()
    if not path:
        return PlainTextResponse("No visualization computed yet.", status_code=404)
    return FileResponse(str(path), media_type="image/png")


@app.get("/intel/graph.html")
def intel_graph_html():
    """The interactive campaign graph (distinct colour per cluster + hover rundown),
    embedded as an iframe on the analytics page."""
    path = graph_intel.interactive_viz_path()
    if not path:
        return PlainTextResponse("No interactive visualization computed yet.", status_code=404)
    return FileResponse(str(path), media_type="text/html")


# --- Adversarial self-play (Direction 2) ------------------------------------
_LAST_SELFPLAY = {}


@app.get("/selfplay", response_class=HTMLResponse)
def selfplay_page(request: Request):
    """Co-evolving crawler ⇄ honeypot self-play: the learned attacker, the
    cost-to-evade curve, and the robust detector's live second opinion."""
    report = selfplay_service.load_report()
    return templates.TemplateResponse(request, "selfplay.html", {
        "active_page": "selfplay",
        "status": selfplay_service.status(),
        "report": report,
        "strategies": selfplay_service.read_strategies(limit=40),
        "robust": selfplay_service.load_robust_predictions(),
        "runs": selfplay_service.list_runs(limit=10),
        "has_curve": selfplay_service.curve_path() is not None,
        "error": _LAST_SELFPLAY.pop("error", None),
    })


@app.post("/selfplay/run")
def selfplay_run(kind: str = Form("train"), iterations: str = Form(""),
                 cost_budget: str = Form(""), risk_mode: str = Form("")):
    overrides = {}
    if iterations.strip().isdigit():
        overrides["iterations"] = int(iterations)
    if cost_budget.strip():
        try:
            overrides["cost_budget"] = float(cost_budget)
        except ValueError:
            pass
    if risk_mode in ("expectation", "cvar"):
        overrides["risk_mode"] = risk_mode
    try:
        selfplay_service.launch_training(kind=kind, overrides=overrides)
        _LAST_SELFPLAY.pop("error", None)
    except selfplay_service.SelfPlayError as exc:
        _LAST_SELFPLAY["error"] = str(exc)
    return RedirectResponse("/selfplay", status_code=303)


@app.get("/selfplay/status")
def selfplay_status():
    """Live job status + log tail (polled by the page while a run is in flight)."""
    st = selfplay_service.status()
    st["log_tail"] = selfplay_service.job_log(tail=6000)
    return JSONResponse(st)


@app.post("/selfplay/score-live")
def selfplay_score_live():
    """Run the robust detector over current logdb traffic (the second opinion)."""
    res = selfplay_service.score_live()
    if not res.get("ok"):
        _LAST_SELFPLAY["error"] = f"Second-opinion scoring failed: {res.get('reason')}"
    return RedirectResponse("/selfplay", status_code=303)


@app.get("/selfplay/curve.png")
def selfplay_curve_png():
    path = selfplay_service.curve_path()
    if not path:
        return PlainTextResponse("No self-play curve computed yet.", status_code=404)
    return FileResponse(str(path), media_type="image/png")


# --- LLM Forensics (detection + provenance + membership, one page) ----------
# Survives the post/redirect so the membership result / run errors show on the page.
_LAST_PROV = {}


def _forensics_models():
    """The detection target models (the ``auto_query`` registry), annotated with
    provider/knowledge-cutoff from the provenance timeline, for the single
    shared model picker (mock entries pre-checked).

    The picker is exactly the registered models: the provenance timeline only
    *annotates* matching rows (provider + cutoff) — it never injects extra ids,
    so retired/unregistered timeline entries can't leak into the live picker.

    Each entry carries what the key-aware picker needs: a friendly ``label``,
    the ``mock``/live grouping, and ``ready`` — whether the model is queryable
    right now (mock ids always; live ids only with their provider key set)."""
    labels = querying_service.model_labels()

    def _entry(mid):
        return {"id": mid, "label": labels.get(mid), "provider": None,
                "cutoff": None, "mock": querying_service.is_mock(mid),
                "ready": querying_service.model_ready(mid),
                "checked": querying_service.is_mock(mid)}

    pool = {}
    for mid in querying_service.available_models():
        pool.setdefault(mid, _entry(mid))
    for entry in provenance_service.timeline():
        row = pool.get(entry["id"])
        if row is not None:
            row["provider"] = entry.get("provider")
            row["cutoff"] = entry.get("knowledge_cutoff")
    return list(pool.values())


def _recent_investigations(limit=14):
    """Merge detection runs + provenance/RAG reports into one time-sorted list."""
    items = []
    for r in querying_service.list_runs()[:20]:
        summary = r.get("summary") or {}
        manual = r.get("kind") == "manual"
        items.append({
            "kind": "Manual" if manual else "Detection",
            "kind_class": "badge--warn" if manual else "badge--navy",
            "label": r.get("subject") or r.get("site_id") or r.get("target_url") or r.get("run_id"),
            "status": r.get("status"), "leaked": bool(summary.get("matches_found")),
            "when": r.get("started_at"), "href": f"/query/runs/{r.get('run_id')}",
        })
    for r in provenance_service.list_reports()[:20]:
        kind = r.get("kind") or "provenance"
        items.append({
            "kind": "RAG" if "rag" in kind else "Provenance", "kind_class": "badge--clean",
            "label": r.get("site_id") or r.get("subject") or r.get("run_id"),
            "status": r.get("status"), "leaked": None,
            "when": r.get("started_at"), "href": f"/provenance/runs/{r.get('run_id')}",
        })
    items.sort(key=lambda x: x.get("when") or "", reverse=True)
    return items[:limit]


@app.get("/query", response_class=HTMLResponse)
def query_page(request: Request, demo: str = ""):
    return templates.TemplateResponse(
        request,
        "forensics.html",
        {
            "active_page": "query",
            "active_section": "forensics",
            "sites": sites.list_sites(),
            "models_pool": _forensics_models(),
            "providers": querying_service.provider_status(),
            "runs_summary": querying_service.runs_summary(),
            "timeline": provenance_service.timeline(),
            "prov_providers": provenance_service.provider_status(),
            "recent": _recent_investigations(),
            "membership": _LAST_PROV.get("membership"),
            "prov_error": _LAST_PROV.get("error"),
            "manual": _LAST_MANUAL,
            "provider_keys": keys_service.provider_rows(),
            "keys_msg": _LAST_KEYS.pop("msg", None),
            "keys_err": _LAST_KEYS.pop("err", None),
            "run_error": _LAST_RUN.pop("error", None),
            "demo": demo,
        },
    )


# Survives the post/redirect so a rejected model choice (e.g. "use API keys"
# with none configured) shows as a banner on the launcher instead of 500ing.
_LAST_RUN = {}


@app.post("/query/run")
def query_run(
    mode: str = Form("local"),
    site_id: str = Form(""),
    url: str = Form(""),
    models: list[str] = Form(default=[]),
    key_mode: str = Form("offline"),
    max_questions: int = Form(3),
    seed: str = Form(""),
):
    """Start a detection run in the background and redirect to its live page.

    ``key_mode`` is the launcher's querying-mode toggle: ``offline`` runs the
    mock simulators without touching any provider, ``api`` queries the models
    the user picked from the key-ready list. Real model queries take many
    seconds each, so the run executes on a worker thread; the run page then
    polls ``/query/runs/{id}/status`` and reveals the attribution results when
    it completes."""
    chosen, err = querying_service.resolve_model_choice(key_mode, models)
    if err:
        _LAST_RUN["error"] = err
        return RedirectResponse("/query#launch", status_code=303)
    if mode == "local" and site_id.strip():
        run_id = run_manager.start_detection(site_id=site_id.strip(), models=chosen)
    else:
        run_id = run_manager.start_detection(
            url=url.strip() or "http://127.0.0.1/", models=chosen
        )
    return RedirectResponse(f"/query/runs/{run_id}", status_code=303)


@app.get("/query/runs/{run_id}/status")
def query_run_status(run_id: str):
    """Live status for the run page's poller (JSON)."""
    return JSONResponse(run_manager.status(run_id))


@app.get("/query/runs/{run_id}/download/{artifact}")
def query_run_download(run_id: str, artifact: str):
    """Download one run artifact — the final results (``results`` json /
    ``results.csv``) or an intermediate pipeline stage (``prompt``,
    ``raw_responses``, ``extraction``) that the run page deliberately keeps
    out of the inline view. Works for detection and manual runs alike."""
    run = querying_service.load_run(run_id)
    if run is None:
        return PlainTextResponse("No run found with that id.", status_code=404)
    item = querying_service.run_artifact(run, artifact)
    if item is None:
        return PlainTextResponse(
            f"This run has no '{artifact}' artifact.", status_code=404
        )
    filename, media_type, content = item
    return PlainTextResponse(
        content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# --- Provider API keys ------------------------------------------------------
# Managed from the LLM Forensics page; written to the git-ignored project .env
# (which compose reads) and applied to the live process at once. Survives the
# post/redirect so the result banner shows on the page.
_LAST_KEYS = {}


@app.post("/query/keys")
def query_keys(action: str = Form("save"), env_var: str = Form(...), value: str = Form("")):
    try:
        if action == "clear":
            keys_service.clear_key(env_var)
            _LAST_KEYS["msg"] = f"Cleared {env_var}."
        else:
            masked = keys_service.set_key(env_var, value)
            _LAST_KEYS["msg"] = f"Saved {env_var} ({masked})."
    except keys_service.KeyError_ as exc:
        _LAST_KEYS["err"] = str(exc)
    return RedirectResponse("/query#keys", status_code=303)


# --- Manual-query workflow (auto_query engine) ------------------------------
# For providers without a suitable search-enabled API (ERNIE, Kimi, Meta AI...):
# generate the retrieval prompt here, run it in each chatbot by hand, then
# upload/paste the responses — they are evaluated identically to API runs.
# The generated prompt survives the post/redirect the same way _LAST_PROV does.
_LAST_MANUAL = {}


@app.post("/query/prompt")
def query_prompt(mode: str = Form("local"), site_id: str = Form(""), url: str = Form("")):
    _LAST_MANUAL.clear()
    try:
        if mode == "local" and site_id.strip():
            result = querying_service.generate_prompt(site_id=site_id.strip())
            _LAST_MANUAL["site_id"] = site_id.strip()
        else:
            result = querying_service.generate_prompt(url=url.strip() or "http://127.0.0.1/")
        _LAST_MANUAL.update(result)
    except Exception as exc:
        _LAST_MANUAL["error"] = f"{type(exc).__name__}: {exc}"
    return RedirectResponse("/query#manual", status_code=303)


@app.get("/query/prompt.txt")
def query_prompt_download():
    prompt = _LAST_MANUAL.get("prompt")
    if not prompt:
        return PlainTextResponse("No prompt generated yet.", status_code=404)
    return PlainTextResponse(
        prompt,
        headers={"Content-Disposition": "attachment; filename=generated_prompt.txt"},
    )


@app.post("/query/manual")
async def query_manual(
    site_id: str = Form(""),
    responses_file: UploadFile | None = File(None),
    manual_model: list[str] = Form(default=[]),
    manual_response: list[str] = Form(default=[]),
):
    from auto_query.manual_io import ManualResponsesError, load_manual_responses

    try:
        if responses_file is not None and responses_file.filename:
            data = await responses_file.read()
            records = load_manual_responses(data, responses_file.filename)
        else:
            records = [
                {"Model": model.strip(), "Responses": response.strip()}
                for model, response in zip(manual_model, manual_response)
                if model.strip() and response.strip()
            ]
        if not records:
            raise ManualResponsesError(
                "No responses given — upload a Model/Responses spreadsheet or "
                "fill in at least one model + response pair."
            )
        if not site_id.strip():
            raise ManualResponsesError("Pick the honeypot site the prompt came from.")
        run_id = run_manager.start_manual(records=records, site_id=site_id.strip())
    except ManualResponsesError as exc:
        _LAST_MANUAL["error"] = str(exc)
        return RedirectResponse("/query#manual", status_code=303)
    return RedirectResponse(f"/query/runs/{run_id}", status_code=303)


@app.get("/query/runs/{run_id}", response_class=HTMLResponse)
def query_run_detail(request: Request, run_id: str):
    run = querying_service.load_run(run_id)
    live = run_manager.status(run_id)
    # The page renders live (stepper + streaming model cards) while the run is
    # in flight, then swaps to the full results the moment it completes. If a
    # completed record is already on disk (a page reload after the fact), it
    # renders results straight away.
    return templates.TemplateResponse(
        request,
        "run_detail.html",
        {"active_page": "query", "active_section": "forensics",
         "run": run, "run_id": run_id, "live": live},
    )


# --- Training-Data Provenance (the view is now merged into /query) ----------
@app.get("/provenance")
def provenance_redirect():
    return RedirectResponse("/query", status_code=307)


@app.post("/provenance/run")
def provenance_run(
    kind: str = Form("provenance"),
    mode: str = Form("local"),
    site_id: str = Form(""),
    url: str = Form(""),
    models: list[str] = Form(default=[]),
    key_mode: str = Form("offline"),
    page_removed: str = Form(""),
    max_questions: int = Form(3),
    seed: str = Form(""),
):
    # Same querying-mode contract as /query/run — the provenance/RAG buttons
    # share the launcher form, so the toggle governs them too.
    chosen, choice_err = querying_service.resolve_model_choice(key_mode, models)
    if choice_err:
        _LAST_PROV["error"] = choice_err
        return RedirectResponse("/query#launch", status_code=303)
    seed_val = int(seed) if seed.strip().lstrip("-").isdigit() else None
    try:
        if kind == "rag":
            run = provenance_service.start_rag(
                mode, site_id.strip(), url.strip(), chosen,
                page_removed=bool(page_removed), max_questions=max_questions, seed=seed_val,
            )
        else:
            run = provenance_service.start_provenance(
                mode, site_id.strip(), url.strip(), chosen,
                max_questions=max_questions, seed=seed_val,
            )
        _LAST_PROV.pop("error", None)
        return RedirectResponse(f"/provenance/runs/{run['run_id']}", status_code=303)
    except Exception as exc:  # surface to the page
        _LAST_PROV["error"] = f"{type(exc).__name__}: {exc}"
        return RedirectResponse("/query", status_code=303)


@app.post("/provenance/membership-demo")
def provenance_membership(n: int = Form(24), seed: str = Form("")):
    seed_val = int(seed) if seed.strip().isdigit() else None
    try:
        _LAST_PROV["membership"] = provenance_service.membership_demo(n=n, seed=seed_val)
        _LAST_PROV.pop("error", None)
    except Exception as exc:
        _LAST_PROV["error"] = f"{type(exc).__name__}: {exc}"
    return RedirectResponse("/query?demo=1", status_code=303)


@app.get("/provenance/runs/{run_id}/status")
def provenance_run_status(run_id: str):
    """Live status for the provenance/RAG report page's poller (JSON)."""
    return JSONResponse(provenance_service.status(run_id))


@app.get("/provenance/runs/{run_id}", response_class=HTMLResponse)
def provenance_run_detail(request: Request, run_id: str):
    # Probes run in the background: while the report says `running` the page
    # polls the status endpoint and reloads itself when the worker finishes.
    report = provenance_service.load_report(run_id)
    return templates.TemplateResponse(
        request,
        "provenance_detail.html",
        {"active_page": "provenance", "active_section": "forensics",
         "report": report, "run_id": run_id,
         "live": provenance_service.status(run_id)},
    )


# --- Template Generator ----------------------------------------------------
# Survives the post/redirect so the result (installed flavors + model output) is
# shown on the page after generation, same pattern as _LAST_DEPLOY above.
_LAST_GEN = {}
# Result of the last inline template edit, shown on the page after a save (same
# post/redirect convention as _LAST_GEN — only rendered when ?saved= is present).
_LAST_EDIT = {}


@app.get("/generator", response_class=HTMLResponse)
def generator_page(request: Request, ok: str = "", saved: str = "", job: str = "",
                   version: str = ""):
    return templates.TemplateResponse(
        request,
        "generator.html",
        {
            "active_page": "generator",
            "types": template_gen.available_types(),
            "templates_list": template_gen.list_website_templates(),
            "interpreter": template_gen.current_interpreter(),
            "ok": ok,
            "job": job,
            "gen_output": _LAST_GEN.get("output"),
            "gen_installed": _LAST_GEN.get("installed"),
            "gen_type": _LAST_GEN.get("type"),
            "saved": saved,
            # Which scraper<N> the editor should reopen — the save redirect carries
            # it back so a save doesn't drop you onto the first template.
            "edit_version": version,
            "edit_ok": _LAST_EDIT.get("ok"),
            "edit_msg": _LAST_EDIT.get("message"),
            "edit_info": _LAST_EDIT.get("info"),
        },
    )


@app.post("/generator/run")
def generator_run(template_type: str = Form("towns")):
    # Generation runs the fine-tuned model and can take minutes, so it runs on a
    # background worker thread: we redirect immediately to the page, which polls
    # /generator/status/{job} to drive a live progress bar. (One template per
    # category per run — "all" = every category on one model load — deduped via
    # the registry, so there is no count/seed knob.)
    job_id = template_gen.start_generation(template_type)
    return RedirectResponse(f"/generator?job={job_id}", status_code=303)


@app.get("/generator/status/{job_id}")
def generator_status(job_id: str):
    """Live status for the generator progress bar (polled by the page).

    When the job finishes, its full result is copied into ``_LAST_GEN`` so the
    page can reload to ``/generator?ok=N`` and render the normal result notice
    (installed list + full model output) — the same view the blocking path used.
    """
    job = template_gen.generation_status(job_id)
    if job is None:
        return JSONResponse({
            "present": False, "done": True, "status": "missing", "ok": False,
            "percent": 0, "stage": "missing",
            "label": "No generation job with that id (it may have expired).",
        })
    if job["done"]:
        _LAST_GEN.update(type=job["type"], output=job["output"],
                         installed=job["installed"])
    log = job.get("output") or ""
    return JSONResponse({
        "present": True,
        "done": job["done"],
        "status": job["status"],
        "ok": job["status"] == "ok",
        "percent": job["percent"],
        "stage": job["stage"],
        "label": job["label"],
        "category": job.get("category"),
        "installed": len(job.get("installed") or []),
        "log": log[-4000:],  # live tail; the full output rides _LAST_GEN on done
    })


@app.post("/generator/edit")
def generator_edit(version: int = Form(...), html: str = Form(...)):
    # Save hand-edited text of an already-stored scraper<N>.html. The service
    # validates Jinja syntax (server.py renders the page live), keeps the
    # /js/fp.js beacon, and writes atomically — so an edit can't break the site.
    ok, message, info = template_gen.save_template(version, html)
    _LAST_EDIT.clear()
    _LAST_EDIT.update(ok=ok, message=message, info=info)
    return RedirectResponse(
        f"/generator?saved={1 if ok else 0}&version={version}#edit", status_code=303)


# --- Account access --------------------------------------------------------
@app.get("/request-access", response_class=HTMLResponse)
def request_access_page(request: Request):
    return templates.TemplateResponse(
        request,
        "request_access.html",
        {"form_url": config.GOOGLE_FORM_URL},
    )


@app.get("/admin/approve", response_class=HTMLResponse)
def admin_approve_page(request: Request):
    """Render the password form or the session-unlocked approval console."""
    if not _is_admin(request):
        return templates.TemplateResponse(
            request, "admin_login.html", {"error": ""}
        )

    flash = request.session.pop("admin_flash", {})
    return templates.TemplateResponse(
        request,
        "admin_approve.html",
        {
            "institutions": config.INSTITUTIONS,
            "message": flash.get("message", ""),
            "error": flash.get("error", ""),
            "signup_url": f"{config.APP_BASE_URL}/signup",
        },
    )


@app.post("/admin/login")
def admin_login(request: Request, admin_secret: str = Form(...)):
    if not _admin_secret_matches(admin_secret):
        return templates.TemplateResponse(
            request,
            "admin_login.html",
            {"error": "Invalid administrator password."},
            status_code=403,
        )
    request.session["is_admin"] = True
    return RedirectResponse("/admin/approve", status_code=303)


@app.post("/admin/approve")
def admin_approve_submit(
    request: Request,
    email: str = Form(...),
    institution: str = Form(...),
):
    if not _is_admin(request):
        return PlainTextResponse("Not authorized.", status_code=403)
    try:
        delivered = auth_service.approve_email(email, institution)
        if delivered:
            message = f"Approved {email.strip()} and sent the signup invitation."
        else:
            message = (
                f"Approved {email.strip()}. SMTP is not configured, so share "
                f"{config.APP_BASE_URL}/signup manually."
            )
        request.session["admin_flash"] = {"message": message}
    except auth_service.AuthError as exc:
        request.session["admin_flash"] = {"error": str(exc)}
    return RedirectResponse("/admin/approve", status_code=303)


@app.post("/admin/decline")
def admin_decline_submit(request: Request, email: str = Form(...)):
    if not _is_admin(request):
        return PlainTextResponse("Not authorized.", status_code=403)
    try:
        delivered = auth_service.decline_email(email)
        if delivered:
            message = f"Declined {email.strip()} and sent the notification."
        else:
            message = (
                f"Declined {email.strip()}. SMTP is not configured, so no email was sent."
            )
        request.session["admin_flash"] = {"message": message}
    except auth_service.AuthError as exc:
        request.session["admin_flash"] = {"error": str(exc)}
    return RedirectResponse("/admin/approve", status_code=303)


@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    if request.session.get("username"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        request,
        "signup.html",
        {"institutions": config.INSTITUTIONS, "error": "", "values": {}},
    )


@app.post("/signup")
def signup_submit(
    request: Request,
    email: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    institution: str = Form(...),
):
    ip = request.client.host if request.client else "unknown"
    try:
        canonical_username = auth_service.create_account(
            username, email, password, institution, ip
        )
    except auth_service.AuthError as exc:
        return templates.TemplateResponse(
            request,
            "signup.html",
            {
                "institutions": config.INSTITUTIONS,
                "error": str(exc),
                "values": {
                    "email": email,
                    "username": username,
                    "institution": institution,
                },
            },
            status_code=400,
        )
    request.session.clear()
    request.session["username"] = canonical_username
    return RedirectResponse("/", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/"):
    destination = _safe_next_url(next)
    if request.session.get("username"):
        return RedirectResponse(destination, status_code=303)
    return templates.TemplateResponse(
        request,
        "login.html",
        {"error": "", "next": destination, "username": ""},
    )


@app.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form("/"),
):
    destination = _safe_next_url(next)
    ip = request.client.host if request.client else "unknown"
    try:
        canonical_username = auth_service.verify_login(username, password, ip)
    except auth_service.AuthError as exc:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": str(exc), "next": destination, "username": username},
            status_code=400,
        )
    request.session.clear()
    request.session["username"] = canonical_username
    return RedirectResponse(destination, status_code=303)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)
