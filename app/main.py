"""AI Bot Defender — unified FastAPI web application.

Routes:
    GET/POST /login             Sign in by username or approved account email
    GET  /account               Manage the signed-in account's optional TOTP 2FA
    GET/POST /account/2fa/*     Set up, enable, or disable account TOTP
    GET/POST /signup            Create an account from a one-time approval
    GET  /request-access        Link to the external access-request form
    GET  /admin                 Redirect to the access-request admin tab
    GET/POST /admin/approve     Review-approved email administration
    GET  /admin/monitoring      Native monitoring overview + Grafana panels
    GET  /admin/monitoring/status  Monitoring health, KPIs, and alerts (JSON)
    GET  /admin/auth-check      Session-only nginx auth_request decision
    POST /admin/decline         Revoke/notify a declined access request
    POST /logout                Clear the signed login session
    GET  /                      Landing page (stats + navigation)
    GET  /api/stats             Live stats (JSON, polled by the landing page)
    GET  /sites                 Site Configurator
    POST /sites/website-dir     Save the global website source path
    POST /sites/deploy          Deploy / re-apply a site via Ansible
    POST /sites/start           Bring a taken-down site back up (existing config)
    POST /sites/stop            Take a site down: withdraw its route, stop its stack
    POST /sites/delete          Delete a site: withdraw, destroy the stack + data
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
from concurrent.futures import CancelledError
from datetime import datetime
from html import escape
from urllib.parse import urlencode, urlsplit

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import (
    FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import config
from .services import (
    auth_service, fingerprint_service, graph_intel, keys_service, provenance_service,
    job_catalog, monitoring_service, querying_service, request_log, run_manager,
    selfplay_service, sites, stats, task_service, template_gen, totp_service,
)

app = FastAPI(title="AI Bot Defender")
app.mount("/static", StaticFiles(directory=str(config.STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(config.TEMPLATE_DIR))


def _css_version(*_a, **_k):
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
    "/login/2fa",
    "/login/setup-2fa",
    "/signup",
    "/request-access",
    "/logout",
    "/admin",
    "/admin/login",
    "/admin/auth-check",
    "/admin/approve",
    "/admin/decline",
    "/admin/monitoring",
    "/admin/monitoring/status",
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


def _request_ip(request: Request) -> str:
    """The real client address, for rate-limit keying.

    Behind the admin nginx vhost every request arrives from the proxy
    container's address, which would collapse all public visitors into one
    rate-limit bucket (and let one attacker starve everyone). nginx sets
    X-Real-IP to the true client and only nginx (or a trusted SSH tunnel
    user hitting the loopback port directly) can reach this app, so the
    header is trustworthy here — honeypot visitors have no path to this vhost.
    """
    return request.headers.get("x-real-ip") or (
        request.client.host if request.client else "unknown"
    )


def _is_authenticated(request: Request) -> bool:
    return bool(request.session.get("username"))


def _is_admin(request: Request) -> bool:
    return bool(request.session.get("is_admin"))


def _job_identity(request):
    """Return ``(username, is_admin)`` for job ownership checks.

    ``None`` is accepted for direct route calls in the offline unit suite; real
    HTTP requests are always authenticated by ``auth_guard`` before reaching a
    job endpoint.
    """
    if request is None:
        return None, False
    try:
        session = request.session
    except (AttributeError, AssertionError):
        return None, False
    return session.get("username"), bool(session.get("is_admin"))


def _page_task(request, job_id="", *, kinds=None):
    """Resolve an explicit task id or rediscover this account's live page task."""
    owner, is_admin = _job_identity(request)
    if job_id:
        try:
            task = task_service.status(job_id, requester=owner, is_admin=is_admin)
        except task_service.TaskForbidden:
            return None
    else:
        task = task_service.latest(
            requester=owner,
            is_admin=is_admin,
            kinds=kinds,
            active_only=True,
        )
    if task:
        job_id = task["id"]
        task.pop("result", None)
        task.update(
            status_url=f"/jobs/{job_id}/status",
            cancel_url=f"/jobs/{job_id}/cancel",
        )
    return task


def _recent_task(request, *, kinds, max_age=7 * 24 * 60 * 60,
                 completed_only=False):
    """Newest owner-scoped task/result for restoring a page after returning."""
    owner, is_admin = _job_identity(request)
    jobs = task_service.list_jobs(
        requester=owner,
        is_admin=is_admin,
        kinds=kinds,
        max_age=max_age,
    )
    if completed_only:
        jobs = [job for job in jobs if job.get("done")]
    return jobs[0] if jobs else None


def _admin_secret_matches(candidate: str) -> bool:
    return secrets.compare_digest(str(candidate or ""), config.ADMIN_SECRET)


_ADMIN_DESTINATIONS = frozenset({"/admin/approve", "/admin/monitoring"})


def _admin_destination(value) -> str:
    """Allow only known admin tabs as post-unlock redirect destinations."""
    return value if isinstance(value, str) and value in _ADMIN_DESTINATIONS else "/admin/approve"


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


# --- Shared cancellable background operations ------------------------------
@app.get("/jobs/{job_id}/status")
def task_status(request: Request, job_id: str):
    owner, is_admin = _job_identity(request)
    try:
        state = task_service.status(job_id, requester=owner, is_admin=is_admin)
    except task_service.TaskForbidden as exc:
        return JSONResponse({"detail": str(exc)}, status_code=403)
    if state is None:
        return JSONResponse({
            "id": job_id, "status": "missing", "done": True, "ok": False,
            "label": "This job was not found (it may have expired).",
        }, status_code=404)
    return JSONResponse(state, headers={"Cache-Control": "no-store"})


@app.get("/jobs/active")
def active_jobs(request: Request):
    """Account-scoped catalog polled from every authenticated application page."""
    owner, is_admin = _job_identity(request)
    return JSONResponse(
        job_catalog.summary(owner=owner, is_admin=is_admin),
        headers={"Cache-Control": "no-store"},
    )


@app.post("/jobs/{job_id}/cancel")
def task_cancel(request: Request, job_id: str):
    owner, is_admin = _job_identity(request)
    try:
        state = task_service.cancel(job_id, requester=owner, is_admin=is_admin)
    except task_service.TaskForbidden as exc:
        return JSONResponse({"detail": str(exc)}, status_code=403)
    if state is None:
        return JSONResponse({"detail": "Job not found."}, status_code=404)
    return JSONResponse(state, headers={"Cache-Control": "no-store"})


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
    # This endpoint exists solely for the overview's live counters. Explicit
    # response headers prevent a browser, tunnel, or future reverse proxy from
    # serving a previous snapshot even if the caller forgets fetch(no-store).
    return JSONResponse(
        stats.landing_stats(),
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


# --- Site Configurator -----------------------------------------------------
# Every site lifecycle operation reports through the page's one job panel, so
# the panel has to rediscover any of them — not just a deploy.
_SITE_JOB_KINDS = frozenset({"site-deploy", "site-start", "site-stop", "site-delete"})


@app.get("/sites", response_class=HTMLResponse)
def sites_page(request: Request, deployed: str = "", ok: str = "", job: str = "",
               cancelled: str = "", action: str = ""):
    versions = sites.available_scraper_versions() or [1]
    background_job = _page_task(request, job, kinds=_SITE_JOB_KINDS)
    recent = _recent_task(
        request, kinds=_SITE_JOB_KINDS, completed_only=True,
    )
    recent_result = (recent or {}).get("result") or {}
    if not deployed and recent_result.get("site_id"):
        deployed = recent_result["site_id"]
        ok = "1" if recent_result.get("ok") else "0"
        # Restoring the banner by navigation rather than the redirect must not
        # relabel a take-down as a deploy.
        action = recent_result.get("action") or action
    deploy_output = recent_result.get("output") or _LAST_DEPLOY.get("output")
    deploy_site_id = recent_result.get("site_id") or _LAST_DEPLOY.get("site_id")
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
            "action": action or "deploy",
            "deploy_output": deploy_output,
            "deploy_site_id": deploy_site_id,
            "background_job": background_job,
            "cancelled": cancelled,
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
    request: Request = None,
):
    site_id = site_id.strip()
    if not site_id or not port.strip() or not db_host_port.strip():
        _LAST_DEPLOY.update(site_id=site_id, output="site_id, port and db_host_port are required.")
        return RedirectResponse("/sites?ok=0", status_code=303)

    def write_config():
        return sites.write_site_config(
            site_id,
            scraper_version=scraper_version,
            port=port.strip(),
            genmode=(genmode == "true"),
            db_user=db_user.strip(),
            db_password=db_password.strip(),
            db_host_port=db_host_port.strip(),
        )

    # Preserve direct-call behavior for the offline route unit tests. Real HTTP
    # requests always take the cancellable background path below.
    if request is None:
        write_config()
        ok, output = sites.deploy_site(site_id, reset_db=bool(reset_db))
        _LAST_DEPLOY.update(site_id=site_id, output=output)
        return RedirectResponse(
            f"/sites?deployed={site_id}&ok={1 if ok else 0}", status_code=303
        )

    owner, _ = _job_identity(request)

    def deploy_worker(task):
        task.update(label=f"Saving configuration for {site_id}…")
        write_config()
        task.check_cancelled()
        task.update(label=f"Starting deployment for {site_id}…")
        ok, output = sites.deploy_site(
            site_id, reset_db=bool(reset_db), task=task,
        )
        task.check_cancelled()
        _LAST_DEPLOY.update(site_id=site_id, output=output)
        return {
            "ok": ok,
            "label": f"{site_id} deployed." if ok else f"Deployment of {site_id} failed.",
            "error": None if ok else output[-1000:],
            "redirect": f"/sites?deployed={site_id}&ok={1 if ok else 0}",
            "site_id": site_id,
            "output": output,
            "reset_db": bool(reset_db),
        }

    try:
        job_id = task_service.start(
            "site-deploy", deploy_worker, owner=owner,
            label=f"Queueing deployment for {site_id}…",
            exclusive_key="site-deploy",
            redirect="/sites?ok=0",
        )
    except task_service.TaskBusy as exc:
        if exc.job_id:
            return RedirectResponse(f"/sites?job={exc.job_id}", status_code=303)
        _LAST_DEPLOY.update(site_id=site_id, output=str(exc))
        return RedirectResponse("/sites?ok=0", status_code=303)
    return RedirectResponse(f"/sites?job={job_id}", status_code=303)


# --- Site lifecycle (start / take down / delete) ---------------------------
# All three share the deploy job's exclusive key: each one takes the same
# cross-process publication lock, so letting the UI queue two at once would only
# produce a "publication busy" failure the operator has to interpret.
def _site_lifecycle(request, site_id, *, kind, action, label, run):
    """Start one background site-lifecycle operation and redirect to its job."""
    site_id = (site_id or "").strip()
    try:
        sites._validate_site_id(site_id)
    except ValueError as exc:
        _LAST_DEPLOY.update(site_id=site_id, output=str(exc))
        return RedirectResponse(f"/sites?ok=0&action={action}", status_code=303)

    def done(ok):
        return f"/sites?deployed={site_id}&ok={1 if ok else 0}&action={action}"

    if request is None:  # direct call from the offline route tests
        ok, output = run(site_id, None)
        _LAST_DEPLOY.update(site_id=site_id, output=output)
        return RedirectResponse(done(ok), status_code=303)

    owner, _ = _job_identity(request)

    def worker(task):
        ok, output = run(site_id, task)
        _LAST_DEPLOY.update(site_id=site_id, output=output)
        return {
            "ok": ok,
            "label": (
                f"{site_id} {label['done']}." if ok
                else f"{label['verb'].capitalize()} of {site_id} failed."
            ),
            "error": None if ok else output[-1000:],
            "redirect": done(ok),
            "site_id": site_id,
            "action": action,
            "output": output,
        }

    try:
        job_id = task_service.start(
            kind, worker, owner=owner,
            label=f"Queueing {label['verb']} of {site_id}…",
            exclusive_key="site-deploy",
            redirect=f"/sites?ok=0&action={action}",
        )
    except task_service.TaskBusy as exc:
        if exc.job_id:
            return RedirectResponse(f"/sites?job={exc.job_id}", status_code=303)
        _LAST_DEPLOY.update(site_id=site_id, output=str(exc))
        return RedirectResponse("/sites?ok=0", status_code=303)
    return RedirectResponse(f"/sites?job={job_id}", status_code=303)


@app.post("/sites/start")
def start_site(site_id: str = Form(...), request: Request = None):
    """Redeploy an already-configured site from its stored YAML.

    Deliberately runs the same playbook as a deploy rather than a bare
    ``compose start``: bringing a site back has to re-render its stack and
    re-publish its route, TLS, and monitoring rules, which is exactly what the
    playbook is for. No form values are written, so the site returns with the
    configuration (and stored canaries) it was taken down with.
    """
    return _site_lifecycle(
        request, site_id, kind="site-start", action="start",
        label={"verb": "start", "done": "is live again"},
        run=lambda sid, task: sites.deploy_site(sid, task=task),
    )


@app.post("/sites/stop")
def stop_site(site_id: str = Form(...), request: Request = None):
    return _site_lifecycle(
        request, site_id, kind="site-stop", action="stop",
        label={"verb": "take-down", "done": "is down"},
        run=lambda sid, task: sites.stop_site(sid, task=task),
    )


@app.post("/sites/delete")
def delete_site(site_id: str = Form(...), confirm: str = Form(""),
                request: Request = None):
    """Delete a site. ``confirm`` must echo the site id.

    The typed confirmation is a server-side gate, not decoration: this is the
    one site action that destroys the database volume, and the browser's
    dialog cannot be relied on (a stale tab, a replayed form, or a scripted
    POST all skip it).
    """
    site_id = (site_id or "").strip()
    if confirm.strip() != site_id or not site_id:
        _LAST_DEPLOY.update(
            site_id=site_id,
            output=(
                f"Deletion of {site_id or 'the site'} was not confirmed, so "
                "nothing was changed. Type the site id exactly to confirm."
            ),
        )
        return RedirectResponse(
            f"/sites?deployed={site_id}&ok=0&action=delete", status_code=303
        )
    return _site_lifecycle(
        request, site_id, kind="site-delete", action="delete",
        label={"verb": "deletion", "done": "is deleted"},
        run=lambda sid, task: sites.delete_site(sid, task=task),
    )


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
    bases = {str(d["fp_id"]): d.get("basis") for d in devices}
    # The summary card deliberately displays only its top N devices.  Resolve
    # every fp_id on this request page separately so device 51+ cannot lose its
    # disguise flag merely because it fell outside that presentation limit.
    page_ids = {
        str(row["fp_id"])
        for row in (data.get("rows") or [])
        if row.get("fp_id")
    }
    if page_ids:
        bases.update(fingerprint_service.disguise_bases(page_ids))
    for row in data.get("rows") or []:
        if row.get("fp_id"):
            basis = bases.get(str(row["fp_id"]))
            if basis == "identities":
                row["disguised"] = True
            elif basis == "networks":
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
    job: str = "",
    cancelled: str = "",
):
    # Keep the rendered page metadata in lockstep with fetch_requests(), which
    # applies these same safety bounds internally. Otherwise a hand-edited query
    # can serve one page size while displaying and dividing by another.
    page = max(1, page)
    page_size = min(500, max(25, page_size))
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

    background_job = _page_task(
        request, job, kinds={"campaign-intelligence"},
    )
    recent_intel = _recent_task(
        request, kinds={"campaign-intelligence"}, completed_only=True,
    )
    recent_intel_result = (recent_intel or {}).get("result") or {}

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
            "intel_error": recent_intel_result.get("error") or _LAST_INTEL.get("error"),
            "ok": ok,
            "background_job": background_job,
            "cancelled": cancelled,
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
            f'<tr><td colspan="8" class="muted" style="text-align:center;padding:24px">'
            f'{escape(str(exc))}</td></tr>'
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
def intel_recompute(limit: str = Form(""), since_hours: str = Form(""),
                    use_gnn: str = Form(""), request: Request = None):
    lim = int(limit) if limit.strip().isdigit() else None
    since = int(since_hours) if since_hours.strip().isdigit() else None
    def recompute(cancel_check=None, progress=None):
        try:
            if progress:
                progress("Loading traffic and building the campaign graph…")
            graph_intel.recompute(
                limit=lim, since_hours=since, use_gnn=bool(use_gnn),
                cancel_check=cancel_check,
            )
            _LAST_INTEL.pop("error", None)
            ok = 1
        except graph_intel.IntelError as exc:
            _LAST_INTEL["error"] = str(exc)
            ok = 0
        # Refresh the robust detector over the same traffic. It shares the
        # campaign job's cancellation token so Cancel stops the entire action.
        if ok and selfplay_service.available() and selfplay_service.status().get(
            "robust_detector_trained"
        ):
            if progress:
                progress("Refreshing the robust detector's second opinion…")
            selfplay_service.score_live(
                since_hours=since, cancel_check=cancel_check,
            )
        return ok

    if request is None:
        ok = recompute()
        return RedirectResponse(f"/logs?ok={ok}", status_code=303)

    owner, _ = _job_identity(request)

    def intel_worker(task):
        try:
            ok = recompute(
                cancel_check=task.check_cancelled,
                progress=lambda label: task.update(label=label),
            )
        except CancelledError:
            raise
        except Exception as exc:
            _LAST_INTEL["error"] = f"{type(exc).__name__}: {exc}"
            ok = 0
        return {
            "ok": bool(ok),
            "label": "Campaign analysis complete." if ok else "Campaign analysis failed.",
            "error": None if ok else _LAST_INTEL.get("error"),
            "redirect": f"/logs?ok={ok}",
            "limit": lim,
            "since_hours": since,
            "use_gnn": bool(use_gnn),
        }

    try:
        job_id = task_service.start(
            "campaign-intelligence", intel_worker, owner=owner,
            label="Queueing campaign analysis…", exclusive_key="campaign-intelligence",
            redirect="/logs?ok=0",
        )
    except task_service.TaskBusy as exc:
        if exc.job_id:
            return RedirectResponse(f"/logs?job={exc.job_id}", status_code=303)
        _LAST_INTEL["error"] = str(exc)
        return RedirectResponse("/logs?ok=0", status_code=303)
    return RedirectResponse(f"/logs?job={job_id}", status_code=303)


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
                 cost_budget: str = Form(""), risk_mode: str = Form(""),
                 request: Request = None):
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
        owner, _ = _job_identity(request)
        selfplay_service.launch_training(
            kind=kind, overrides=overrides, owner=owner,
        )
        _LAST_SELFPLAY.pop("error", None)
    except selfplay_service.SelfPlayError as exc:
        _LAST_SELFPLAY["error"] = str(exc)
    return RedirectResponse("/selfplay", status_code=303)


@app.get("/selfplay/status")
def selfplay_status():
    """Live job status + log tail (polled by the page while a run is in flight)."""
    st = selfplay_service.status()
    st["log_tail"] = selfplay_service.job_log(tail=6000)
    return JSONResponse(st, headers={"Cache-Control": "no-store"})


@app.post("/selfplay/cancel")
def selfplay_cancel(request: Request):
    owner, is_admin = _job_identity(request)
    try:
        job = selfplay_service.cancel_job(requester=owner, is_admin=is_admin)
    except selfplay_service.SelfPlayForbidden as exc:
        return JSONResponse({"detail": str(exc)}, status_code=403)
    return JSONResponse({"job": job}, headers={"Cache-Control": "no-store"})


@app.post("/selfplay/score-live")
def selfplay_score_live(request: Request = None):
    """Start cancellable robust-detector scoring in the background."""
    try:
        owner, _ = _job_identity(request)
        selfplay_service.launch_score(owner=owner)
        _LAST_SELFPLAY.pop("error", None)
    except selfplay_service.SelfPlayError as exc:
        _LAST_SELFPLAY["error"] = str(exc)
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
def query_page(request: Request, demo: str = "", job: str = "", cancelled: str = ""):
    background_job = _page_task(
        request, job, kinds={"manual-prompt", "membership-inference"},
    )
    prompt_task = _recent_task(
        request, kinds={"manual-prompt"}, completed_only=True,
    )
    membership_task = _recent_task(
        request, kinds={"membership-inference"}, completed_only=True,
    )
    prompt_result = (prompt_task or {}).get("result") or {}
    membership_result = (membership_task or {}).get("result") or {}
    # Keep the owner-scoped generated prompt while still surfacing a validation
    # error from the response POST. Previously, a saved prompt masked that error
    # entirely, making a rejected manual submission look like a no-op.
    manual = dict(prompt_result.get("manual") or _LAST_MANUAL)
    manual_error = _LAST_MANUAL.pop("error", None)
    if manual_error:
        manual["error"] = manual_error
    membership = membership_result.get("membership") or _LAST_PROV.get("membership")
    task_error = (
        membership_result.get("error")
        or prompt_result.get("error")
    )
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
            "membership": membership,
            "prov_error": task_error or _LAST_PROV.get("error"),
            "manual": manual,
            "provider_keys": keys_service.provider_rows(),
            "keys_msg": _LAST_KEYS.pop("msg", None),
            "keys_err": _LAST_KEYS.pop("err", None),
            "run_error": _LAST_RUN.pop("error", None),
            "demo": demo,
            "background_job": background_job,
            "cancelled": cancelled,
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
    request: Request = None,
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
    owner, _ = _job_identity(request)
    if mode == "local" and site_id.strip():
        run_id = run_manager.start_detection(
            site_id=site_id.strip(), models=chosen, owner=owner,
        )
    else:
        run_id = run_manager.start_detection(
            url=url.strip() or "http://127.0.0.1/", models=chosen, owner=owner,
        )
    return RedirectResponse(f"/query/runs/{run_id}", status_code=303)


@app.get("/query/runs/{run_id}/status")
def query_run_status(run_id: str):
    """Live status for the run page's poller (JSON)."""
    return JSONResponse(
        run_manager.status(run_id), headers={"Cache-Control": "no-store"},
    )


@app.post("/query/runs/{run_id}/cancel")
def query_run_cancel(request: Request, run_id: str):
    owner, is_admin = _job_identity(request)
    try:
        state = run_manager.cancel(run_id, requester=owner, is_admin=is_admin)
    except run_manager.RunForbidden as exc:
        return JSONResponse({"detail": str(exc)}, status_code=403)
    if state is None:
        return JSONResponse({"detail": "Run not found or no longer active."}, status_code=404)
    return JSONResponse(state, headers={"Cache-Control": "no-store"})


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
def query_prompt(mode: str = Form("local"), site_id: str = Form(""),
                 url: str = Form(""), request: Request = None):
    if request is None:
        _LAST_MANUAL.clear()

    def generate(cancel_check=None):
        if mode == "local" and site_id.strip():
            result = querying_service.generate_prompt(
                site_id=site_id.strip(), cancel_check=cancel_check,
            )
            selected_site = site_id.strip()
        else:
            result = querying_service.generate_prompt(
                url=url.strip() or "http://127.0.0.1/",
                cancel_check=cancel_check,
            )
            selected_site = None
        if cancel_check:
            cancel_check()
        manual = {}
        if selected_site:
            manual["site_id"] = selected_site
        manual.update(result)
        return manual

    if request is None:
        try:
            _LAST_MANUAL.update(generate())
        except Exception as exc:
            _LAST_MANUAL["error"] = f"{type(exc).__name__}: {exc}"
        return RedirectResponse("/query#manual", status_code=303)

    owner, _ = _job_identity(request)

    def prompt_worker(task):
        task.update(label="Scraping the page and composing the retrieval prompt…")
        try:
            manual = generate(cancel_check=task.check_cancelled)
            return {
                "ok": True, "label": "Manual retrieval prompt is ready.",
                "redirect": "/query#manual",
                "manual": manual,
            }
        except CancelledError:
            raise
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            return {
                "ok": False, "label": "Prompt generation failed.",
                "error": message, "redirect": "/query#manual",
                "manual": {"error": message},
            }

    try:
        job_id = task_service.start(
            "manual-prompt", prompt_worker, owner=owner,
            label="Queueing prompt generation…",
            exclusive_key=f"manual-prompt:{owner or 'anonymous'}",
            redirect="/query#manual",
        )
    except task_service.TaskBusy as exc:
        if exc.job_id:
            return RedirectResponse(f"/query?job={exc.job_id}#manual", status_code=303)
        _LAST_MANUAL["error"] = str(exc)
        return RedirectResponse("/query#manual", status_code=303)
    return RedirectResponse(f"/query?job={job_id}#manual", status_code=303)


@app.get("/query/prompt.txt")
def query_prompt_download(request: Request = None):
    prompt = None
    if request is not None:
        latest = _recent_task(
            request, kinds={"manual-prompt"}, completed_only=True,
        )
        prompt = (((latest or {}).get("result") or {}).get("manual") or {}).get("prompt")
    prompt = prompt or _LAST_MANUAL.get("prompt")
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
    request: Request = None,
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
                "No responses given — add at least one model and its complete response."
            )
        if not site_id.strip():
            raise ManualResponsesError("Pick the honeypot site the prompt came from.")
        owner, _ = _job_identity(request)
        run_id = run_manager.start_manual(
            records=records, site_id=site_id.strip(), owner=owner,
        )
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
    request: Request = None,
):
    # Same querying-mode contract as /query/run — the provenance/RAG buttons
    # share the launcher form, so the toggle governs them too.
    chosen, choice_err = querying_service.resolve_model_choice(key_mode, models)
    if choice_err:
        _LAST_PROV["error"] = choice_err
        return RedirectResponse("/query#launch", status_code=303)
    seed_val = int(seed) if seed.strip().lstrip("-").isdigit() else None
    owner, _ = _job_identity(request)
    try:
        if kind == "rag":
            run = provenance_service.start_rag(
                mode, site_id.strip(), url.strip(), chosen,
                page_removed=bool(page_removed), max_questions=max_questions, seed=seed_val,
                owner=owner,
            )
        else:
            run = provenance_service.start_provenance(
                mode, site_id.strip(), url.strip(), chosen,
                max_questions=max_questions, seed=seed_val,
                owner=owner,
            )
        _LAST_PROV.pop("error", None)
        return RedirectResponse(f"/provenance/runs/{run['run_id']}", status_code=303)
    except Exception as exc:  # surface to the page
        _LAST_PROV["error"] = f"{type(exc).__name__}: {exc}"
        return RedirectResponse("/query", status_code=303)


@app.post("/provenance/membership-demo")
def provenance_membership(n: int = Form(24), seed: str = Form(""),
                          request: Request = None):
    seed_val = int(seed) if seed.strip().isdigit() else None

    def run_demo(cancel_check=None):
        result = provenance_service.membership_demo(
            n=n, seed=seed_val, cancel_check=cancel_check,
        )
        if cancel_check:
            cancel_check()
        return result

    if request is None:
        try:
            _LAST_PROV["membership"] = run_demo()
            _LAST_PROV.pop("error", None)
        except Exception as exc:
            _LAST_PROV["error"] = f"{type(exc).__name__}: {exc}"
        return RedirectResponse("/query?demo=1", status_code=303)

    owner, _ = _job_identity(request)

    def membership_worker(task):
        task.update(label="Scoring served and control watermark documents…")
        try:
            membership = run_demo(cancel_check=task.check_cancelled)
            return {
                "ok": True, "label": "Membership inference complete.",
                "redirect": "/query?demo=1",
                "membership": membership,
            }
        except CancelledError:
            raise
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            return {
                "ok": False, "label": "Membership inference failed.",
                "error": message, "redirect": "/query#membership",
            }

    try:
        job_id = task_service.start(
            "membership-inference", membership_worker, owner=owner,
            label="Queueing membership inference…",
            exclusive_key=f"membership-inference:{owner or 'anonymous'}",
            redirect="/query#membership",
        )
    except task_service.TaskBusy as exc:
        if exc.job_id:
            return RedirectResponse(f"/query?job={exc.job_id}#membership", status_code=303)
        _LAST_PROV["error"] = str(exc)
        return RedirectResponse("/query#membership", status_code=303)
    return RedirectResponse(f"/query?job={job_id}#membership", status_code=303)


@app.get("/provenance/runs/{run_id}/status")
def provenance_run_status(run_id: str):
    """Live status for the provenance/RAG report page's poller (JSON)."""
    return JSONResponse(
        provenance_service.status(run_id), headers={"Cache-Control": "no-store"},
    )


@app.post("/provenance/runs/{run_id}/cancel")
def provenance_run_cancel(request: Request, run_id: str):
    owner, is_admin = _job_identity(request)
    try:
        state = provenance_service.cancel(
            run_id, requester=owner, is_admin=is_admin,
        )
    except provenance_service.ProbeForbidden as exc:
        return JSONResponse({"detail": str(exc)}, status_code=403)
    if not state.get("present"):
        return JSONResponse({"detail": "Probe not found."}, status_code=404)
    return JSONResponse(state, headers={"Cache-Control": "no-store"})


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
                   version: str = "", cancelled: str = ""):
    owner, is_admin = _job_identity(request)
    active_generation = None
    if job:
        try:
            active_generation = template_gen.generation_status(
                job, requester=owner, is_admin=is_admin,
            )
        except template_gen.GenerationForbidden:
            job = ""
    else:
        active_generation = template_gen.latest_generation(
            requester=owner, is_admin=is_admin, active_only=True,
        )
        if active_generation:
            job = active_generation["id"]

    latest_generation = template_gen.latest_generation(
        requester=owner,
        is_admin=is_admin,
        active_only=False,
        max_age=7 * 24 * 60 * 60,
    )
    completed_generation = (
        latest_generation
        if latest_generation and latest_generation.get("done")
        else None
    )
    if not ok and not job and completed_generation:
        ok = "1" if completed_generation.get("status") == "ok" else "0"
    generation_result = completed_generation or {}
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
            "gen_output": (generation_result.get("output")
                           if completed_generation else _LAST_GEN.get("output")),
            "gen_installed": (generation_result.get("installed")
                              if completed_generation else _LAST_GEN.get("installed")),
            "gen_type": (generation_result.get("type")
                         if completed_generation else _LAST_GEN.get("type")),
            "saved": saved,
            # Which scraper<N> the editor should reopen — the save redirect carries
            # it back so a save doesn't drop you onto the first template.
            "edit_version": version,
            "edit_ok": _LAST_EDIT.get("ok"),
            "edit_msg": _LAST_EDIT.get("message"),
            "edit_info": _LAST_EDIT.get("info"),
            "cancelled": cancelled,
        },
    )


@app.post("/generator/run")
def generator_run(template_type: str = Form("towns"), request: Request = None):
    # Generation runs the fine-tuned model and can take minutes, so it runs on a
    # background worker thread: we redirect immediately to the page, which polls
    # /generator/status/{job} to drive a live progress bar. (One template per
    # category per run — "all" = every category on one model load — deduped via
    # the registry, so there is no count/seed knob.)
    try:
        if request is None:
            job_id = template_gen.start_generation(template_type)
        else:
            owner, _ = _job_identity(request)
            job_id = template_gen.start_generation(template_type, owner=owner)
    except template_gen.GenerationBusy as exc:
        if exc.job_id:
            return RedirectResponse(f"/generator?job={exc.job_id}", status_code=303)
        _LAST_GEN.update(type=template_type, output=str(exc), installed=[])
        return RedirectResponse("/generator?ok=0", status_code=303)
    return RedirectResponse(f"/generator?job={job_id}", status_code=303)


@app.get("/generator/status/{job_id}")
def generator_status(job_id: str, request: Request = None):
    """Live status for the generator progress bar (polled by the page).

    When the job finishes, its full result is copied into ``_LAST_GEN`` so the
    page can reload to ``/generator?ok=N`` and render the normal result notice
    (installed list + full model output) — the same view the blocking path used.
    """
    try:
        if request is None:
            job = template_gen.generation_status(job_id)
        else:
            owner, is_admin = _job_identity(request)
            job = template_gen.generation_status(
                job_id, requester=owner, is_admin=is_admin,
            )
    except template_gen.GenerationForbidden as exc:
        return JSONResponse({"detail": str(exc)}, status_code=403)
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
    }, headers={"Cache-Control": "no-store"})


@app.post("/generator/cancel/{job_id}")
def generator_cancel(request: Request, job_id: str):
    owner, is_admin = _job_identity(request)
    try:
        job = template_gen.cancel_generation(
            job_id, requester=owner, is_admin=is_admin,
        )
    except template_gen.GenerationForbidden as exc:
        return JSONResponse({"detail": str(exc)}, status_code=403)
    if job is None:
        return JSONResponse({"detail": "Generation job not found."}, status_code=404)
    return JSONResponse(job, headers={"Cache-Control": "no-store"})


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


@app.get("/admin")
def admin_root():
    return RedirectResponse("/admin/approve", status_code=307)


@app.get("/admin/auth-check")
def admin_auth_check(request: Request):
    """Return a redirect-free decision for nginx ``auth_request`` subrequests."""
    return Response(status_code=204 if _is_admin(request) else 401)


@app.get("/admin/monitoring", response_class=HTMLResponse)
def admin_monitoring_page(request: Request):
    """Render immediately; the browser loads bounded monitoring data later."""
    if not _is_admin(request):
        return templates.TemplateResponse(
            request,
            "admin_login.html",
            {"error": "", "next": "/admin/monitoring"},
        )
    return templates.TemplateResponse(
        request,
        "admin_monitoring.html",
        {
            "active_admin_tab": "monitoring",
            "grafana_path": config.GRAFANA_PUBLIC_PATH,
        },
    )


@app.get("/admin/monitoring/status")
def admin_monitoring_status(request: Request):
    if not _is_admin(request):
        return JSONResponse({"detail": "Not authorized."}, status_code=403)
    return JSONResponse(
        monitoring_service.overview(),
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@app.get("/admin/approve", response_class=HTMLResponse)
def admin_approve_page(request: Request):
    """Render the password form or the session-unlocked approval console."""
    if not _is_admin(request):
        return templates.TemplateResponse(
            request,
            "admin_login.html",
            {"error": "", "next": "/admin/approve"},
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
            "active_admin_tab": "approve",
        },
    )


@app.post("/admin/login")
def admin_login(
    request: Request,
    admin_secret: str = Form(...),
    next: str = Form("", alias="next"),
):
    destination = _admin_destination(next)
    if not auth_service.admin_login_allowed(_request_ip(request)):
        return templates.TemplateResponse(
            request,
            "admin_login.html",
            {
                "error": "Too many attempts — try again in a few minutes.",
                "next": destination,
            },
            status_code=429,
        )
    if not _admin_secret_matches(admin_secret):
        return templates.TemplateResponse(
            request,
            "admin_login.html",
            {"error": "Invalid administrator password.", "next": destination},
            status_code=403,
        )
    request.session["is_admin"] = True
    return RedirectResponse(destination, status_code=303)


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
    ip = _request_ip(request)
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
    return _begin_second_factor(request, canonical_username, "/")


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
    ip = _request_ip(request)
    try:
        canonical_username = auth_service.verify_login(username, password, ip)
    except auth_service.AuthError as exc:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": str(exc), "next": destination, "username": username},
            status_code=400,
        )
    return _begin_second_factor(request, canonical_username, destination)


def _complete_login(request: Request, username: str, destination: str):
    request.session.clear()
    request.session["username"] = username
    return RedirectResponse(destination, status_code=303)


def _begin_second_factor(request: Request, username: str, destination: str):
    """Password (or a fresh signup) accepted — decide the second step.

    Enrolled users must present a TOTP code; un-enrolled users are walked
    through enrollment when REQUIRE_2FA is on. The pending_* session keys are
    NOT a login: the auth guard only honors session["username"], which is set
    exclusively by _complete_login after the second factor passes.
    """
    request.session.clear()
    if auth_service.get_totp_secret(username):
        request.session["pending_2fa_user"] = username
        request.session["pending_next"] = destination
        return RedirectResponse("/login/2fa", status_code=303)
    if config.REQUIRE_2FA:
        request.session["pending_setup_user"] = username
        request.session["pending_setup_secret"] = totp_service.generate_secret()
        request.session["pending_next"] = destination
        return RedirectResponse("/login/setup-2fa", status_code=303)
    return _complete_login(request, username, destination)


@app.get("/login/2fa", response_class=HTMLResponse)
def twofactor_page(request: Request):
    if not request.session.get("pending_2fa_user"):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "twofactor.html", {"error": ""})


@app.post("/login/2fa")
def twofactor_submit(request: Request, code: str = Form(...)):
    username = request.session.get("pending_2fa_user")
    if not username:
        return RedirectResponse("/login", status_code=303)
    destination = _safe_next_url(request.session.get("pending_next"))
    try:
        auth_service.verify_totp_login(username, code, _request_ip(request))
    except auth_service.AuthError as exc:
        return templates.TemplateResponse(
            request, "twofactor.html", {"error": str(exc)}, status_code=400
        )
    return _complete_login(request, username, destination)


@app.get("/login/setup-2fa", response_class=HTMLResponse)
def twofactor_setup_page(request: Request):
    username = request.session.get("pending_setup_user")
    secret = request.session.get("pending_setup_secret")
    if not (username and secret):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        request,
        "twofactor_setup.html",
        {
            "error": "",
            "secret": secret,
            "otpauth_uri": totp_service.provisioning_uri(secret, username),
        },
    )


@app.post("/login/setup-2fa")
def twofactor_setup_submit(request: Request, code: str = Form(...)):
    username = request.session.get("pending_setup_user")
    secret = request.session.get("pending_setup_secret")
    if not (username and secret):
        return RedirectResponse("/login", status_code=303)
    destination = _safe_next_url(request.session.get("pending_next"))
    if not totp_service.verify_code(secret, code):
        return templates.TemplateResponse(
            request,
            "twofactor_setup.html",
            {
                "error": "That code didn't match. Scan the QR code (or re-enter "
                "the secret) in your authenticator app and try the current code.",
                "secret": secret,
                "otpauth_uri": totp_service.provisioning_uri(secret, username),
            },
            status_code=400,
        )
    # Persist only after the user proves their authenticator produces valid
    # codes — a mis-scanned secret must never lock the account.
    auth_service.set_totp_secret(username, secret)
    return _complete_login(request, username, destination)


def _account_context(username: str, *, error: str = "", ok: str = ""):
    """Shared, freshly-read account state for the page and POST error paths."""
    return {
        "active_page": "account",
        "username": username,
        "twofactor_enabled": bool(auth_service.get_totp_secret(username)),
        "error": error,
        "ok": ok,
    }


def _account_setup_context(username: str, secret: str, *, error: str = ""):
    """Render context for voluntary setup, isolated from login-time enrollment."""
    return {
        "active_page": "account",
        "error": error,
        "secret": secret,
        "otpauth_uri": totp_service.provisioning_uri(secret, username),
        "setup_action": "/account/2fa/enable",
        "submit_label": "Enable two-factor",
        "cancel_url": "/account",
    }


@app.get("/account", response_class=HTMLResponse)
def account_page(request: Request, ok: str = ""):
    username = request.session.get("username")
    if not username:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        request, "account.html", _account_context(username, ok=ok)
    )


@app.get("/account/2fa/setup", response_class=HTMLResponse)
def account_twofactor_setup_page(request: Request):
    username = request.session.get("username")
    if not username:
        return RedirectResponse("/login", status_code=303)
    if auth_service.get_totp_secret(username):
        request.session.pop("account_setup_secret", None)
        return RedirectResponse("/account", status_code=303)

    # This key is deliberately distinct from pending_setup_secret: account
    # enrollment happens inside an authenticated session and must never be
    # mistaken for a login-time forced-enrollment session.
    secret = totp_service.generate_secret()
    request.session["account_setup_secret"] = secret
    return templates.TemplateResponse(
        request,
        "twofactor_setup.html",
        _account_setup_context(username, secret),
    )


@app.post("/account/2fa/enable")
def account_twofactor_enable(request: Request, code: str = Form(...)):
    username = request.session.get("username")
    if not username:
        return RedirectResponse("/login", status_code=303)
    if auth_service.get_totp_secret(username):
        request.session.pop("account_setup_secret", None)
        return RedirectResponse("/account", status_code=303)

    secret = request.session.get("account_setup_secret")
    if not secret:
        return RedirectResponse("/account/2fa/setup", status_code=303)
    if not totp_service.verify_code(secret, code):
        return templates.TemplateResponse(
            request,
            "twofactor_setup.html",
            _account_setup_context(
                username,
                secret,
                error=(
                    "That code didn't match. Scan the QR code (or re-enter "
                    "the secret) in your authenticator app and try the current code."
                ),
            ),
            status_code=400,
        )

    auth_service.set_totp_secret(username, secret)
    request.session.pop("account_setup_secret", None)
    return RedirectResponse("/account?ok=enabled", status_code=303)


@app.post("/account/2fa/disable")
def account_twofactor_disable(request: Request, code: str = Form(...)):
    username = request.session.get("username")
    if not username:
        return RedirectResponse("/login", status_code=303)
    if not auth_service.get_totp_secret(username):
        return RedirectResponse("/account", status_code=303)

    try:
        # Reuse the login verifier so disable attempts share the same strict
        # per-account/IP online-guess budget as the login challenge.
        auth_service.verify_totp_login(username, code, _request_ip(request))
    except auth_service.AuthError as exc:
        return templates.TemplateResponse(
            request,
            "account.html",
            _account_context(username, error=str(exc)),
            status_code=400,
        )

    auth_service.clear_totp_secret(username)
    request.session.pop("account_setup_secret", None)
    return RedirectResponse("/account?ok=disabled", status_code=303)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)
