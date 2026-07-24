"""Honeypot template generation service.

Drives ``template_generator/generate_templates.py`` from the web app and installs
its output into ``website/templates/`` as the next free ``scraper<N>.html`` flavor,
so a freshly generated page is immediately selectable in the Site Configurator's
template dropdown (which globs ``website/templates/scraper*.html``).

The generator authors one template per *category* (towns, movies, biography, ...:
the ``CATEGORIES`` registry inside ``generate_templates.py``) and emits, next to
each ``scraper_gen_<category>.html``, a matching ``.txt`` varList — 10 Faker
expressions typed to that category's slots (a movies page gets person/film-shaped
tokens, not town-shaped ones). It also dedups titles/content against a registry
(a local JSONL by default; a central registry API when TEMPLATE_GEN_REGISTRY_URL
is set) so two runs — or two institutions — never publish the same fake facts.

The model path (Qwen3-1.7B + LoRA) needs torch / transformers / peft. Those are
baked into the app image, so generation runs as an in-container subprocess under a
configurable interpreter (``TEMPLATE_GEN_PYTHON``, default ``python3``), mirroring
how ``sites.py`` shells out to ``ansible-playbook`` / ``docker compose``. When that
interpreter lacks the ML stack the run fails with an actionable message instead of
crashing the app.

Loading those weights costs 40-90s and peaks around 10-11 GiB, *per process* — so
a process per template made every template re-pay the whole load. Runs therefore go
through a **warm worker** that keeps the model resident between templates (see the
"Warm model worker" section below); a one-shot subprocess remains the fallback.

Install step: the ``.html`` goes to ``website/templates/scraper<N>.html`` and the
varList both to ``website/varLists/scraper<N>.txt`` (so a standalone ``server.py``
run works at once) and into ``configs/generated_templates.json`` — the manifest
``sites.py`` reads to embed the tokens as a per-site ``canary_tokens`` override in
``configs/sites/<id>.yaml``. At deploy time the Ansible ``configure`` role renders
the varList from those (per-site) tokens, so the deployed page keeps the
category-typed canaries instead of the global town-flavored defaults in ``all.yml``.
"""

import ast
import json
import os
import re
import signal
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from concurrent.futures import CancelledError
from datetime import datetime, timezone
from pathlib import Path

import jinja2

from .. import config

# Marker the generator subprocess prints (one JSON object per line) to report
# progress; must match ``_PROGRESS_PREFIX`` in template_generator/generate_templates.py.
_PROGRESS_PREFIX = "@@GENPROGRESS@@"

# Used when generate_templates.py is missing or can't be parsed for its
# CATEGORIES registry (the towns flavor always exists — it is what the model
# was originally trained on).
_FALLBACK_CATEGORIES = {"towns": "fictional U.S. town or small city"}

# Pseudo-type: run the generator with no --category, producing one template
# for every category it knows (20 model runs — slow, but one model load).
ALL_TYPE_ID = "all"

_SCRAPER_RE = re.compile(r"scraper(\d+)\.html")

# One category ~ minutes on a GPU (model load + a handful of sampled sections);
# the all-categories run does 20 of them on a single model load.
_TIMEOUT_ONE = 1800
_TIMEOUT_ALL = 4 * 3600


def _script_path():
    return config.TEMPLATE_GENERATOR_DIR / "generate_templates.py"


def _load_categories():
    """The generator's CATEGORIES registry, as ``{id: subject description}``.

    Read via ``ast`` (never imported/executed — the script's module scope is
    cheap but the app must not depend on the generator env). Falls back to the
    towns flavor when the script is absent or unparsable.
    """
    try:
        tree = ast.parse(_script_path().read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "CATEGORIES":
                    categories = ast.literal_eval(node.value)
                    return {
                        key: str((value or {}).get("subject") or key)
                        for key, value in categories.items()
                    }
    except Exception:
        pass
    return dict(_FALLBACK_CATEGORIES)


def available_types():
    """Template flavors the UI offers: one per generator category, plus 'all'."""
    types = [
        {
            "id": key,
            "label": key.replace("_", " ").title(),
            "description": f"A {subject} article seeded with 10 category-typed canary slots.",
        }
        for key, subject in sorted(_load_categories().items())
    ]
    types.append({
        "id": ALL_TYPE_ID,
        "label": "All categories",
        "description": (
            "One template for every category the generator knows "
            f"({len(types)} runs on a single model load — slow)."
        ),
    })
    return types


def get_type(type_id):
    for entry in available_types():
        if entry["id"] == type_id:
            return entry
    return None


def current_interpreter():
    """The Python used to run the generator (override with TEMPLATE_GEN_PYTHON)."""
    return os.environ.get("TEMPLATE_GEN_PYTHON", "python3")


# --- Existing website templates -------------------------------------------
def existing_versions():
    """The scraper flavors already stored as website/templates/scraper<N>.html."""
    versions = []
    for path in config.TEMPLATES_DIR.glob("scraper*.html"):
        match = _SCRAPER_RE.fullmatch(path.name)
        if match:
            versions.append(int(match.group(1)))
    return sorted(versions)


def list_website_templates():
    """Existing scraper flavors, newest first (for the editor dropdown + table)."""
    manifest = load_manifest()
    return [
        {
            "version": v,
            "filename": f"scraper{v}.html",
            # Generator-authored flavors record their category in the manifest;
            # hand-made flavors (scraper1.html and friends) have no entry and are
            # the base "towns" flavor the model was trained on, so default to that.
            "category": (manifest.get(str(v)) or {}).get("category") or "towns",
        }
        for v in sorted(existing_versions(), reverse=True)
    ]


def _next_version(taken):
    candidate = 1
    while candidate in taken:
        candidate += 1
    return candidate


# --- Generated-template manifest -------------------------------------------
# configs/generated_templates.json records, per installed scraper<N>, the
# category and the 10-line varList the generator authored for it. sites.py
# reads this to write a per-site canary_tokens override, so a deployed
# generated flavor renders with its own tokens (the Ansible configure role
# otherwise falls back to the global canary_tokens in all.yml).
def _manifest_path():
    return config.CONFIGS_DIR / "generated_templates.json"


def load_manifest():
    try:
        with open(_manifest_path()) as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_manifest(manifest):
    config.CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
    with open(_manifest_path(), "w") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")


def canary_tokens_for(version):
    """The generator-authored varList for scraper<version>, or None."""
    entry = load_manifest().get(str(version)) or {}
    tokens = entry.get("canary_tokens")
    if isinstance(tokens, list) and len(tokens) >= 10:
        return [str(t) for t in tokens]
    return None


# --- Editing a stored template ---------------------------------------------
# The client can rewrite the text of an already-installed scraper<N>.html
# "however they like". The page is rendered live by the honeypot's server.py
# (Flask's Jinja: render_template("scraper<N>.html", var1=..., ...)), so an edit
# that breaks Jinja syntax would 500 every visitor. save_template() guards that
# path: it validates syntax, keeps the /js/fp.js beacon, and writes atomically.

_CANARY_SLOT_RE = re.compile(r"{{\s*var(\d+)\s*}}")


def canary_slots_in(html):
    """The distinct ``{{ varN }}`` canary slots referenced in ``html`` (sorted).

    Editing is free-form, so a save can drop a canary. Surfacing which slots the
    page still renders lets the UI warn when an edit removed one (the varList /
    canary_tokens are unchanged — a dropped slot just never appears on the page).
    """
    return sorted({int(m.group(1)) for m in _CANARY_SLOT_RE.finditer(html or "")})


def validate_template_html(html):
    """Return ``None`` if ``html`` is safe to store as a scraper flavor, else a
    human-readable reason.

    The load-bearing check is Jinja **syntax**: ``website/server.py`` renders the
    stored page with Flask's Jinja, so an unbalanced ``{{ }}`` / ``{% %}`` would
    turn every honeypot request into a 500. Parsing with a vanilla jinja2
    ``Environment`` validates syntax with the same delimiters Flask uses, without
    requiring the ``varN`` values to be defined (parse != render).
    """
    if not html or not html.strip():
        return "Template is empty — nothing to save."
    try:
        jinja2.Environment().parse(html)
    except jinja2.TemplateSyntaxError as exc:
        where = f" (line {exc.lineno})" if getattr(exc, "lineno", None) else ""
        return f"Template has a Jinja syntax error{where}: {exc.message}"
    except Exception as exc:  # defensive: never let a parse quirk crash the save
        return f"Template could not be parsed: {exc}"
    return None


def _atomic_write_text(path, text):
    """Write ``text`` to ``path`` atomically (temp + os.replace) so the honeypot
    never renders a half-written template if it reads mid-save."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def save_template(version, html):
    """Overwrite an already-stored ``scraper<version>.html`` with edited ``html``.

    Returns ``(ok, message, info)`` where ``info`` (on success) carries
    ``{version, filename, canary_slots, beacon_present}``.

    Guardrails so an edit can never break the running honeypot:
      * only an **existing** flavor may be edited (never creates a new slot);
      * the HTML must pass Jinja **syntax** validation (server.py renders it live);
      * the ``/js/fp.js`` Layer-1 fingerprint beacon is re-injected if the edit
        dropped it (the contract every scraper<N>.html honors);
      * the file is written **atomically**.
    The category-typed varList / ``canary_tokens`` are left untouched — editing
    changes only the page text, not the canaries a deploy mints.
    """
    try:
        version = int(version)
    except (TypeError, ValueError):
        return False, f"Invalid template version: {version!r}.", {}

    if version not in existing_versions():
        return False, f"No stored template scraper{version}.html to edit.", {}

    reason = validate_template_html(html)
    if reason:
        return False, reason, {}

    # Normalize newlines and guarantee the fingerprint beacon survives the edit.
    html = html.replace("\r\n", "\n").replace("\r", "\n")
    html = _with_fingerprint_beacon(html)

    dest = config.TEMPLATES_DIR / f"scraper{version}.html"
    _atomic_write_text(dest, html)

    beacon_present = "fp.js" in html
    _append_edit_history(version, True)

    message = f"Saved scraper{version}.html."
    if not beacon_present:
        message += (
            " Warning: the /js/fp.js fingerprint beacon is missing and could not be "
            "auto-inserted (no </head> tag). Add "
            '<script src="/js/fp.js" defer></script> to keep device fingerprinting.'
        )
    return True, message, {
        "version": version,
        "filename": dest.name,
        "canary_slots": canary_slots_in(html),
        "beacon_present": beacon_present,
    }


def _append_edit_history(version, ok):
    """Best-effort audit line for a manual template edit (never breaks a save)."""
    try:
        config.HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        with open(config.HISTORY_DIR / "generations.jsonl", "a") as handle:
            handle.write(json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "type": "edit",
                "version": version,
                "status": "ok" if ok else "failed",
            }) + "\n")
    except Exception:
        pass


# --- Generation ------------------------------------------------------------
def generate(type_id, timeout=None):
    """Generate the ``type_id`` category (or every category for ``all``) and
    install each produced page into website/templates/ as the next free
    scraper<N>.html, with its varList recorded for deploy-time canary override.

    Returns ``(ok, output, installed)`` where ``installed`` is a list of
    ``{"version": N, "filename": "scraperN.html", "category": "..."}``.
    """
    tmpl_type = get_type(type_id)
    if tmpl_type is None:
        return False, f"Unknown template type: {type_id!r}.", []

    gen_dir = config.TEMPLATE_GENERATOR_DIR
    script = gen_dir / "generate_templates.py"
    if not script.exists():
        return False, f"generate_templates.py not found at {script}.", []

    if timeout is None:
        timeout = _TIMEOUT_ALL if type_id == ALL_TYPE_ID else _TIMEOUT_ONE

    out_dir = Path(tempfile.mkdtemp(prefix="tplgen_"))
    cmd = _build_cmd(type_id, out_dir)

    try:
        result = subprocess.run(
            cmd, cwd=str(gen_dir),
            capture_output=True, text=True, timeout=timeout,
        )
        output = (result.stdout or "") + (result.stderr or "")
        ok = result.returncode == 0
    except FileNotFoundError:
        shutil.rmtree(out_dir, ignore_errors=True)
        _append_history(type_id, False, 0)
        return False, (
            f"Python interpreter '{current_interpreter()}' not found. Template "
            "generation needs the template_generator environment (torch + "
            "transformers + peft). Set the TEMPLATE_GEN_PYTHON env var to a Python "
            "that has those installed — see template_generator/README.md."
        ), []
    except subprocess.TimeoutExpired as exc:
        shutil.rmtree(out_dir, ignore_errors=True)
        _append_history(type_id, False, 0)
        # Surface what the generator was doing (subprocess.run kills the child
        # and attaches its partial output) so a timeout is diagnosable from the UI.
        partial = ""
        for stream in (exc.stdout, exc.stderr):
            if stream:
                partial += stream.decode(errors="replace") if isinstance(stream, bytes) else stream
        message = f"Generation timed out after {timeout}s."
        if partial.strip():
            message += "\n\n[progress log before the timeout]\n" + partial[-3000:]
        return False, message, []

    installed = []
    if ok:
        installed = _install_generated(out_dir)
        if not installed:
            ok = False
            output += "\n\n[install] No scraper_gen_*.html was produced — nothing installed."

    if not ok:
        output = _ml_stack_hint(output)

    shutil.rmtree(out_dir, ignore_errors=True)
    _append_history(type_id, ok, len(installed))
    return ok, output, installed


def _build_argv(type_id, out_dir):
    """The generator arguments shared by every run path: category selection plus
    the dedup-registry flags read from the environment.

    Kept separate from the interpreter/script prefix because the warm worker is
    handed exactly this argv and parses it with ``generate_templates.py``'s own
    parser — so a warm run and a one-shot run take provably identical options.
    """
    argv = ["--out", str(out_dir)]
    if type_id != ALL_TYPE_ID:
        argv += ["--category", type_id]
    # Dedup registry: default is the generator's local JSONL
    # (template_generator/template_registry.jsonl). Point at the shared
    # cross-institution registry API by env, or skip checks entirely offline.
    if os.environ.get("TEMPLATE_GEN_REGISTRY_URL"):
        argv += ["--registry-url", os.environ["TEMPLATE_GEN_REGISTRY_URL"]]
        if os.environ.get("TEMPLATE_GEN_REGISTRY_API_KEY"):
            argv += ["--registry-api-key", os.environ["TEMPLATE_GEN_REGISTRY_API_KEY"]]
    if os.environ.get("TEMPLATE_GEN_INSTITUTION_ID"):
        argv += ["--institution-id", os.environ["TEMPLATE_GEN_INSTITUTION_ID"]]
    if os.environ.get("TEMPLATE_GEN_SKIP_REGISTRY") == "1":
        argv += ["--skip-registry-check"]
    return argv


def _build_cmd(type_id, out_dir):
    """The one-shot invocation: interpreter + script + the shared arguments.

    ``-u`` keeps the child's stdout unbuffered so a timed-out or streamed run
    yields its progress log line-by-line instead of in one final flush.
    """
    return [current_interpreter(), "-u", "generate_templates.py"] + _build_argv(
        type_id, out_dir)


# --- Warm model worker -----------------------------------------------------
# Loading Qwen3-1.7B + the LoRA adapter costs 40-90s on CPU and peaks around
# 10-11 GiB of allocation, per *process* — so running one process per
# template made every single template re-pay the whole load before writing a
# word. The worker (template_generator/generation_worker.py) is the same
# generator kept resident: it loads the weights on its first run and reuses them
# for every run after it, so only the first template of a session waits.
#
# It is a plain child process spoken to over stdin/stdout — the same pipe a
# one-shot run already streams — so the live progress bar, the log tail, the
# cancel path and the watchdog below work identically either way. When the
# worker cannot be used (no ML stack, missing script, a crash) the run silently
# falls back to the original one-shot subprocess: warming can never be the
# reason a generation fails.
#
# The weights are ~7 GiB resident, which is a lot to hold on a box that also
# runs the honeypot stack, so an unused worker releases them after
# TEMPLATE_GEN_WARM_TTL seconds (default 30 min; 0 = hold indefinitely).
# TEMPLATE_GEN_WARM=0 disables warming; TEMPLATE_GEN_PRELOAD=1 loads the model
# at app startup so even the session's first template skips the wait.
_DONE_PREFIX = "@@GENDONE@@"          # the worker's terminal line per request
_WORKER_SCRIPT = "generation_worker.py"
_WORKER_LOCK = threading.RLock()      # guards the handle below
_WORKER = {"proc": None, "idle_timer": None}
# One request at a time, held for a whole run: two writers on the worker's stdin
# would interleave, and each would read the other's terminal line as its own.
# It is also what keeps the idle timer from retiring a worker a run just took.
# Lock order everywhere: _WORKER_IO first, then _WORKER_LOCK.
_WORKER_IO = threading.Lock()
_HANDSHAKE_TIMEOUT = 120.0            # only bounds a wedged interpreter
# A preload gets a shorter budget than a generation on purpose: a run that
# starts during one *waits* for it (see _open_run_session), so this is also the
# longest a user-triggered generation can sit behind a background preload.
_PRELOAD_TIMEOUT = 600.0
_DEFAULT_WARM_TTL = 1800.0
_FALSEY = {"0", "false", "no", "off"}


def _env_flag(name, default):
    """Read a boolean knob. **Blank counts as unset**, not as false — the keys
    ship in `.env.example` with empty values, and a copied-but-unedited file
    must not silently turn warming off."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        raw = default
    return raw.strip().lower() not in _FALSEY


def warm_enabled():
    """Whether runs may reuse a resident model (``TEMPLATE_GEN_WARM``)."""
    return _env_flag("TEMPLATE_GEN_WARM", "1")


def preload_enabled():
    """Whether to load the model at app startup (``TEMPLATE_GEN_PRELOAD``).

    Off by default: the weights are ~7 GiB resident, which is a lot to hold on a
    machine that may never be asked to author a template. Turn it on when the
    first generation's wait matters more than the idle memory.
    """
    return warm_enabled() and _env_flag("TEMPLATE_GEN_PRELOAD", "0")


def warm_idle_ttl():
    """Seconds an unused worker holds the weights before releasing the memory
    (``TEMPLATE_GEN_WARM_TTL``; 0 or negative = hold them indefinitely)."""
    raw = os.environ.get("TEMPLATE_GEN_WARM_TTL")
    if raw is None or not raw.strip():
        return _DEFAULT_WARM_TTL
    try:
        return float(raw)
    except (TypeError, ValueError):
        return _DEFAULT_WARM_TTL


def _worker_script_path():
    return config.TEMPLATE_GENERATOR_DIR / _WORKER_SCRIPT


def _disarm_idle_timer():
    timer = _WORKER["idle_timer"]
    _WORKER["idle_timer"] = None
    if timer is not None:
        timer.cancel()


def _arm_idle_timer():
    ttl = warm_idle_ttl()
    if ttl <= 0:
        return
    timer = threading.Timer(ttl, _idle_expired)
    timer.daemon = True
    _WORKER["idle_timer"] = timer
    timer.start()


def _idle_expired():
    """The worker sat unused for a whole TTL — give the memory back.

    Claiming _WORKER_IO (never waiting for it) is what makes this safe: a run
    that starts while this timer is firing holds that lock, so the shutdown
    stands down and the run re-arms the timer when it finishes. Merely *testing*
    the lock would leave a window in which a run could claim the worker and then
    be killed mid-generation by a timer that had already decided it was idle.
    """
    with _WORKER_LOCK:
        _WORKER["idle_timer"] = None
    if not _WORKER_IO.acquire(blocking=False):
        return
    try:
        shutdown_worker()
    finally:
        _WORKER_IO.release()


def _read_until_done(proc, timeout, collect=None):
    """Read worker output up to its terminal ``@@GENDONE@@`` line.

    Returns the parsed payload, or None when the worker died or hung first (a
    worker that missed its deadline is killed — it can no longer be trusted to
    be idle). ``collect`` receives every ordinary output line.
    """
    killer = threading.Timer(timeout, lambda: _terminate_generation(proc))
    killer.daemon = True
    killer.start()
    try:
        for raw in proc.stdout:
            line = raw.rstrip("\n")
            if line.startswith(_DONE_PREFIX):
                try:
                    payload = json.loads(line[len(_DONE_PREFIX):])
                except ValueError:
                    return None
                return payload if isinstance(payload, dict) else None
            if collect is not None:
                collect(line)
        return None                       # EOF: the worker exited mid-request
    finally:
        killer.cancel()


def _worker_request(proc, request, timeout):
    """Send one short control request (ping / load) and wait for its result."""
    try:
        proc.stdin.write(json.dumps(request) + "\n")
        proc.stdin.flush()
    except (OSError, ValueError) as exc:
        return None, f"could not reach the worker: {exc}"
    log = []
    payload = _read_until_done(proc, timeout, collect=log.append)
    if payload is None:
        return None, "\n".join(log[-20:]).strip() or "the worker stopped without answering"
    return payload, str(payload.get("error") or "")


def _spawn_worker():
    """Start a worker and confirm it answers. Returns ``(proc, "")`` or
    ``(None, reason)`` — the reason is logged on the run that fell back."""
    script = _worker_script_path()
    if not script.exists():
        return None, f"{_WORKER_SCRIPT} not found at {script}"
    env = {**os.environ, "TEMPLATE_GEN_PROGRESS": "1", "PYTHONUNBUFFERED": "1"}
    try:
        proc = subprocess.Popen(
            [current_interpreter(), "-u", _WORKER_SCRIPT],
            cwd=str(config.TEMPLATE_GENERATOR_DIR), env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1,
            start_new_session=True,
        )
    except (OSError, ValueError) as exc:
        return None, f"could not start '{current_interpreter()}': {exc}"
    payload, detail = _worker_request(proc, {"cmd": "ping"}, _HANDSHAKE_TIMEOUT)
    if not (payload and payload.get("ok")):
        _terminate_generation(proc)
        return None, detail or "the worker did not answer its handshake"
    return proc, ""


def _ensure_worker():
    """The live worker, starting one if needed. ``(proc, "")`` or ``(None, why)``."""
    with _WORKER_LOCK:
        _disarm_idle_timer()
        proc = _WORKER["proc"]
        if proc is not None and proc.poll() is None:
            return proc, ""
        _WORKER["proc"] = None
        proc, why = _spawn_worker()
        _WORKER["proc"] = proc
        return proc, why


def _forget_worker(proc):
    """Drop a worker that can no longer be trusted (crashed, killed, wedged)."""
    with _WORKER_LOCK:
        if _WORKER["proc"] is proc:
            _disarm_idle_timer()
            _WORKER["proc"] = None
    _terminate_generation(proc)


def shutdown_worker():
    """Stop the warm worker and release the model's memory. True if one ran.

    This is unconditional — it stops the worker even if a generation is using
    it, which is what the app's shutdown hook wants. Callers that must not
    disturb a run (the idle timer) hold ``_WORKER_IO`` first.
    """
    with _WORKER_LOCK:
        _disarm_idle_timer()
        proc = _WORKER["proc"]
        _WORKER["proc"] = None
    if proc is None or proc.poll() is not None:
        return False
    try:
        proc.stdin.write(json.dumps({"cmd": "shutdown"}) + "\n")
        proc.stdin.flush()
    except (OSError, ValueError):
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        _terminate_generation(proc)
    return True


def preload_worker():
    """Load the model into the warm worker now, so even the first generation of
    the session skips the load.

    Called from the app's startup hook when ``TEMPLATE_GEN_PRELOAD`` is set.
    Never raises and never blocks a generation: if a run already holds the
    worker there is nothing to preload, and any failure just leaves generation
    on its normal (cold) path.
    """
    if not warm_enabled():
        return False, "warm model reuse is disabled (TEMPLATE_GEN_WARM=0)"
    if not _WORKER_IO.acquire(blocking=False):
        return False, "the generator is already running"
    try:
        proc, why = _ensure_worker()
        if proc is None:
            return False, why
        # argv=[] is the parser's defaults — the same model/adapter/dtype every
        # generation asks for, so the run that follows finds the bundle warm.
        payload, detail = _worker_request(
            proc, {"cmd": "load", "argv": []}, _PRELOAD_TIMEOUT)
        if not (payload and payload.get("ok")):
            _forget_worker(proc)
            return False, detail or "the model could not be loaded"
        with _WORKER_LOCK:
            if _WORKER["proc"] is proc:
                _arm_idle_timer()
        return True, "model loaded and resident"
    except Exception as exc:              # a preload must never break startup
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        _WORKER_IO.release()


def warm_status():
    """Whether a model is currently held in memory (for status/diagnostics)."""
    with _WORKER_LOCK:
        proc = _WORKER["proc"]
        alive = proc is not None and proc.poll() is None
        return {
            "enabled": warm_enabled(),
            "loaded": alive,
            "pid": proc.pid if alive else None,
            "busy": _WORKER_IO.locked(),
            "idle_ttl": warm_idle_ttl(),
        }


def _ml_stack_hint(output):
    """Append an actionable hint when a failed run's output shows the usual
    cause — the interpreter is missing the template-generator ML stack."""
    if "ModuleNotFoundError" in output and any(
        pkg in output for pkg in ("torch", "transformers", "peft")
    ):
        output += (
            "\n\n[hint] The interpreter is missing the ML stack. Run the app on a host "
            "with template_generator/requirements.txt installed, or point "
            "TEMPLATE_GEN_PYTHON at that environment's python."
        )
    return output


# --- Background generation jobs (live progress bar) ------------------------
# ``generate()`` above is the blocking path (CLI + testsuite, which stubs
# subprocess.run). The web app instead starts a *job* that streams the generator
# subprocess so the page can render a live, animated progress bar:
#   start_generation()    -> spawns a worker thread, returns a job id at once
#   _run_generation_job() -> streams the child, parsing the @@GENPROGRESS@@
#                            milestone lines the generator prints, installs on
#                            success, and finalizes the job
#   generation_status()   -> polled by the browser until the job is done
# Live process handles stay in memory, while public progress/result state is
# atomically checkpointed under configs/history/jobs.  The browser can leave or
# close and later rediscover the same job; its poller never owns execution.
_JOBS = {}
_JOBS_LOCK = threading.Lock()
_MAX_JOBS = 50
_MAX_LOG_LINES = 400  # live log tail cap (bounds the status payload + memory)
_ACCESS_UNSET = object()


class GenerationForbidden(RuntimeError):
    pass


class GenerationBusy(RuntimeError):
    def __init__(self, message, job_id=None):
        super().__init__(message)
        self.job_id = job_id


def _generation_jobs_dir():
    path = config.HISTORY_DIR / "jobs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _generation_job_path(job_id):
    safe_id = "".join(ch for ch in str(job_id) if ch.isalnum() or ch in "_-")
    if safe_id != str(job_id) or not safe_id:
        return None
    return _generation_jobs_dir() / f"generation-{safe_id}.json"


def _generation_record(job):
    return {key: value for key, value in job.items() if not key.startswith("_")}


def _write_generation_record(record):
    path = _generation_job_path(record.get("id", ""))
    if path is None:
        return
    tmp = path.with_name(f".{path.name}.{threading.get_ident()}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2, default=str)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _read_generation_record(job_id):
    path = _generation_job_path(job_id)
    if path is None or not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            record = json.load(handle)
    except (OSError, ValueError):
        return None
    return record if isinstance(record, dict) and record.get("id") == job_id else None


def _persist_generation_locked(job):
    _write_generation_record(_generation_record(job))


def _same_generation_owner(job, requester, is_admin=False):
    owner = job.get("owner")
    return bool(is_admin or owner is None or (requester and requester == owner))


def _interrupted_generation(record):
    if record.get("done") or record.get("status") not in {"running", "cancelling"}:
        return record
    record = dict(record)
    record.update(
        done=True,
        status="interrupted",
        stage="error",
        label="Generation was interrupted when the application service restarted.",
        output=(record.get("output") or "")
        + "\n\n[interrupted] The application service restarted before generation finished.",
        updated=time.time(),
    )
    _write_generation_record(record)
    return record


def _persisted_generations():
    records = []
    try:
        paths = list(_generation_jobs_dir().glob("generation-*.json"))
    except OSError:
        return records
    for path in paths:
        try:
            with open(path, encoding="utf-8") as handle:
                record = json.load(handle)
            if isinstance(record, dict) and record.get("id"):
                records.append(record)
        except (OSError, ValueError):
            continue
    return records


def _new_job(type_id, owner=None):
    cancel_event = threading.Event()
    job_id = uuid.uuid4().hex[:12]
    job = {
        "id": job_id,
        "type": type_id,
        "status": "running",   # running | cancelling | cancelled | ok | failed
        "done": False,
        "percent": 0.0,
        "stage": "queued",     # queued | loading | generating | finalizing | done | error
        "label": "Starting…",
        "category": None,
        "output": "",
        "installed": [],
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "updated": time.time(),
        "owner": owner,
        "_cancel_event": cancel_event,
        "_process": None,
        "_committed": False,
    }
    with _JOBS_LOCK:
        active = next((j for j in _JOBS.values() if not j.get("done")), None)
        if active is not None:
            # Re-submitting after navigating back must attach to the existing
            # GPU job rather than starting a duplicate model process.
            if _same_generation_owner(active, owner):
                raise GenerationBusy("Template generation is already running.", active["id"])
            raise GenerationBusy("Another template generation is already running.")
        _JOBS[job_id] = job
        if len(_JOBS) > _MAX_JOBS:
            finished = sorted(
                (jid for jid, j in _JOBS.items() if j["done"]),
                key=lambda jid: _JOBS[jid]["updated"],
            )
            for jid in finished[: len(_JOBS) - _MAX_JOBS]:
                _JOBS.pop(jid, None)
        _persist_generation_locked(job)
    return job


def _update_job(job_id, **fields):
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if job is None:
            return
        if job.get("status") == "cancelling" and not fields.get("done"):
            for key in ("status", "stage", "label", "percent", "category"):
                fields.pop(key, None)
        # Progress only ever moves forward: clamp percent monotonic so a
        # per-category retry (which re-walks the same band) never rewinds the bar.
        if "percent" in fields:
            fields["percent"] = max(job["percent"], float(fields["percent"]))
        job.update(fields)
        job["updated"] = time.time()
        _persist_generation_locked(job)


def generation_status(job_id, *, requester=_ACCESS_UNSET, is_admin=False):
    """A copy of live/persisted state for the page poller, or None if unknown."""
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if job:
            if requester is not _ACCESS_UNSET and not _same_generation_owner(
                job, requester, is_admin
            ):
                raise GenerationForbidden("This generation belongs to a different account.")
            return {
                key: value for key, value in job.items()
                if not key.startswith("_") and key != "owner"
            }
    record = _read_generation_record(job_id)
    if record is None:
        return None
    record = _interrupted_generation(record)
    if requester is not _ACCESS_UNSET and not _same_generation_owner(
        record, requester, is_admin
    ):
        raise GenerationForbidden("This generation belongs to a different account.")
    return {key: value for key, value in record.items() if key != "owner"}


def list_generations(*, requester=None, is_admin=False, active_only=False,
                     max_age=None):
    """Visible generation jobs newest-first, for page/job-center recovery."""
    with _JOBS_LOCK:
        live = {job_id: _generation_record(job) for job_id, job in _JOBS.items()}
    merged = {
        record["id"]: record
        for record in _persisted_generations()
        if record.get("id")
    }
    with _JOBS_LOCK:
        live.update({
            job_id: _generation_record(job)
            for job_id, job in _JOBS.items()
        })
    merged.update(live)
    now = time.time()
    visible = []
    for job_id, record in merged.items():
        if job_id not in live:
            record = _interrupted_generation(record)
        if not _same_generation_owner(record, requester, is_admin):
            continue
        if active_only and record.get("done"):
            continue
        if max_age is not None and now - float(record.get("updated") or 0) > max_age:
            continue
        visible.append({key: value for key, value in record.items() if key != "owner"})
    visible.sort(key=lambda item: item.get("updated", 0), reverse=True)
    return visible


def latest_generation(*, requester=None, is_admin=False, active_only=False,
                      max_age=None):
    jobs = list_generations(
        requester=requester,
        is_admin=is_admin,
        active_only=active_only,
        max_age=max_age,
    )
    return jobs[0] if jobs else None


def _terminate_generation(proc):
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, OSError):
        try:
            proc.terminate()
        except (ProcessLookupError, OSError):
            pass

    def escalate():
        if proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, OSError):
                try:
                    proc.kill()
                except (ProcessLookupError, OSError):
                    pass

    timer = threading.Timer(4.0, escalate)
    timer.daemon = True
    timer.start()


def cancel_generation(job_id, *, requester=None, is_admin=False):
    """Stop one live generation process; safe to call more than once."""
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if job is None:
            return None
        owner = job.get("owner")
        if not (is_admin or owner is None or (requester and requester == owner)):
            raise GenerationForbidden("This generation belongs to a different account.")
        if not job.get("done") and not job.get("_committed"):
            job["_cancel_event"].set()
            job.update(status="cancelling", label="Stopping the generator…", updated=time.time())
            _persist_generation_locked(job)
            proc = job.get("_process")
        else:
            proc = None
    _terminate_generation(proc)
    return generation_status(job_id)


def _parse_progress_line(line):
    """Parse one ``@@GENPROGRESS@@{...}`` line into job-update fields, or None."""
    try:
        data = json.loads(line[len(_PROGRESS_PREFIX):])
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    fields = {}
    if isinstance(data.get("percent"), (int, float)):
        fields["percent"] = data["percent"]
    if data.get("stage"):
        fields["stage"] = str(data["stage"])
    if data.get("label"):
        fields["label"] = str(data["label"])
    if "category" in data:
        fields["category"] = data.get("category")
    return fields


def _finish_job(job_id, ok, output, installed, cancelled=False):
    """Mark a job terminal (success or failure) and record it in history."""
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        type_id = job["type"] if job else None
    n = len(installed)
    fields = {
        "done": True,
        "status": "cancelled" if cancelled else "ok" if ok else "failed",
        "stage": "cancelled" if cancelled else "done" if ok else "error",
        "output": output,
        "installed": installed,
        "label": ("Cancelled — no generated template was installed." if cancelled else
                  f"Installed {n} template{'' if n == 1 else 's'}." if ok else
                  "Generation did not complete."),
    }
    if ok:
        fields["percent"] = 100
    _update_job(job_id, **fields)
    if type_id is not None:
        _append_history(type_id, ok, n, status="cancelled" if cancelled else None)


def start_generation(type_id, owner=None):
    """Start a generation run in the background; return its job id immediately.

    Validation failures (unknown category, missing generator script) produce a
    job that is already ``done``/``failed`` with the reason, so the page's poller
    surfaces them the same way as a runtime failure.
    """
    job_id = _new_job(type_id, owner=owner)["id"]

    if get_type(type_id) is None:
        _finish_job(job_id, False, f"Unknown template type: {type_id!r}.", [])
        return job_id

    gen_dir = config.TEMPLATE_GENERATOR_DIR
    script = gen_dir / "generate_templates.py"
    if not script.exists():
        _finish_job(job_id, False, f"generate_templates.py not found at {script}.", [])
        return job_id

    timeout = _TIMEOUT_ALL if type_id == ALL_TYPE_ID else _TIMEOUT_ONE
    threading.Thread(
        target=_run_generation_job, args=(job_id, type_id, gen_dir, timeout),
        name=f"tplgen-{job_id}", daemon=True,
    ).start()
    return job_id


def _run_generation_job(job_id, type_id, gen_dir, timeout):
    """Worker entry point: run the streaming job, finalizing as failed on any
    unexpected error so the job is never left ``running`` (which would spin the
    page's poller forever)."""
    try:
        _stream_generation_job(job_id, type_id, gen_dir, timeout)
    except Exception as exc:  # belt & braces around the whole streaming body
        import traceback
        _finish_job(job_id, False,
                    f"Generation crashed: {type(exc).__name__}: {exc}\n\n"
                    + traceback.format_exc(), [])


class _RunSession:
    """One generator run, seen as a stream of the generator's stdout lines.

    Either a request to the warm worker (``warm``) or a one-shot subprocess —
    the streaming loop, progress parser, watchdog and cancel path below are
    identical for both, because both are just that pipe.
    """

    def __init__(self, proc, warm, notes=(), holds_io=False):
        self.proc = proc
        self.warm = warm
        self.notes = list(notes)      # shown at the top of this run's log
        self.holds_io = holds_io      # this session owns _WORKER_IO
        self.done = None              # the warm worker's terminal payload

    def lines(self):
        """Yield the run's output lines, ending when the run does."""
        for raw in self.proc.stdout:
            line = raw.rstrip("\n")
            if self.warm and line.startswith(_DONE_PREFIX):
                try:
                    self.done = json.loads(line[len(_DONE_PREFIX):])
                except ValueError:
                    self.done = {"ok": False, "error": "unreadable worker result"}
                return
            yield line
        if not self.warm:
            self.proc.wait()

    def succeeded(self):
        if self.warm:
            return bool(self.done and self.done.get("ok"))
        return self.proc.returncode == 0

    def failure_note(self):
        """Why a warm run failed, when the reason isn't already in the log."""
        if not self.warm:
            return ""
        if self.done is None:
            return ("[warm] the resident model worker stopped before this run "
                    "finished; the next run starts a fresh one.")
        error = str(self.done.get("error") or "").strip()
        return f"[warm] {error}" if error else ""


def _open_run_session(type_id, gen_dir, out_dir):
    """Start this run on the warm worker, falling back to a one-shot process.

    Returns ``(session, None)``, or ``(None, message)`` when neither path could
    be started (the message is what the failed job shows).
    """
    argv = _build_argv(type_id, out_dir)
    notes = []

    if warm_enabled():
        handed_off = False
        # Waiting here is deliberate. The only other holder is a startup preload
        # (bounded by _PRELOAD_TIMEOUT), and waiting for it means this run finds
        # the model already loaded. Falling back instead would start a *second*
        # ~11 GiB load beside the one in flight — enough to OOM the box.
        _WORKER_IO.acquire()
        try:
            proc, why = _ensure_worker()
            if proc is not None:
                try:
                    proc.stdin.write(json.dumps({"cmd": "generate", "argv": argv}) + "\n")
                    proc.stdin.flush()
                    handed_off = True
                    return _RunSession(proc, True, holds_io=True), None
                except (OSError, ValueError) as exc:
                    _forget_worker(proc)
                    why = f"could not send the run to the worker: {exc}"
            notes.append(f"[warm] resident model unavailable ({why}); running a "
                         "one-shot generator for this template instead.")
        finally:
            if not handed_off:
                _WORKER_IO.release()

    # Ask the generator to emit @@GENPROGRESS@@ milestone lines and keep its
    # stdout unbuffered so they arrive live rather than in one final flush.
    env = {**os.environ, "TEMPLATE_GEN_PROGRESS": "1", "PYTHONUNBUFFERED": "1"}
    try:
        proc = subprocess.Popen(
            _build_cmd(type_id, out_dir), cwd=str(gen_dir), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, start_new_session=True,
        )
    except FileNotFoundError:
        return None, (
            f"Python interpreter '{current_interpreter()}' not found. Template "
            "generation needs the template_generator environment (torch + "
            "transformers + peft). Set the TEMPLATE_GEN_PYTHON env var to a Python "
            "that has those installed — see template_generator/README.md."
        )
    return _RunSession(proc, False, notes), None


def _release_session(session):
    """Hand the run's process back.

    A one-shot child has already exited. The warm worker keeps its weights and
    starts the idle countdown — unless this run ended it (cancel, timeout, or a
    crash), in which case it is dropped and the next run starts a fresh one.
    """
    try:
        if session.warm:
            if session.done is None or session.proc.poll() is not None:
                _forget_worker(session.proc)
            else:
                with _WORKER_LOCK:
                    if _WORKER["proc"] is session.proc:
                        _arm_idle_timer()
    finally:
        if session.holds_io:
            session.holds_io = False
            _WORKER_IO.release()


def _stream_generation_job(job_id, type_id, gen_dir, timeout):
    """Stream the generator run, drive live progress, and install its output."""
    out_dir = Path(tempfile.mkdtemp(prefix="tplgen_"))
    _update_job(job_id, stage="loading", label="Launching the generator…", percent=1)

    session, failure = _open_run_session(type_id, gen_dir, out_dir)
    if session is None:
        shutil.rmtree(out_dir, ignore_errors=True)
        _finish_job(job_id, False, failure, [])
        return
    try:
        _drive_generation_job(job_id, session, out_dir, timeout)
    finally:
        _release_session(session)


def _drive_generation_job(job_id, session, out_dir, timeout):
    """Consume one open run: live progress, cancellation, install, finalize."""
    proc = session.proc

    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if job is not None:
            job["_process"] = proc
            cancel_now = job["_cancel_event"].is_set()
        else:
            cancel_now = True
    if cancel_now:
        _terminate_generation(proc)

    # The readline loop below blocks, so a child that hangs without printing
    # would never be reaped — a watchdog timer enforces the hard timeout.
    timed_out = {"hit": False}

    def _kill():
        timed_out["hit"] = True
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    watchdog = threading.Timer(timeout, _kill)
    watchdog.start()

    lines = list(session.notes)
    last_push = 0.0
    try:
        for line in session.lines():
            now = time.time()
            if line.startswith(_PROGRESS_PREFIX):
                fields = _parse_progress_line(line)
                if fields:
                    fields["output"] = "\n".join(lines[-_MAX_LOG_LINES:])
                    _update_job(job_id, **fields)
                    last_push = now
                continue
            lines.append(line)
            # Throttle output snapshots so a long run doesn't rebuild the whole
            # log string on every line (progress lines refresh it too).
            if now - last_push > 0.4:
                _update_job(job_id, output="\n".join(lines[-_MAX_LOG_LINES:]))
                last_push = now
    finally:
        watchdog.cancel()

    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        cancelled = bool(job and job["_cancel_event"].is_set())
        if job is not None:
            job["_process"] = None

    ok = session.succeeded() and not timed_out["hit"]
    # A cancel or a timeout killed the worker on purpose; only explain a warm
    # run that failed on its own (the two branches below say the rest).
    if not ok and not cancelled and not timed_out["hit"]:
        note = session.failure_note()
        if note:
            lines.append(note)
    output = "\n".join(lines)

    if cancelled:
        shutil.rmtree(out_dir, ignore_errors=True)
        _finish_job(job_id, False, output + "\n\n[cancelled] Stopped by user.", [],
                    cancelled=True)
        return

    if timed_out["hit"]:
        shutil.rmtree(out_dir, ignore_errors=True)
        _finish_job(job_id, False,
                    output + f"\n\n[timeout] Generation exceeded {timeout}s and was stopped.", [])
        return

    installed = []
    if ok:
        prior_manifest = load_manifest()
        manifest_existed = _manifest_path().exists()

        def cancel_check():
            with _JOBS_LOCK:
                current = _JOBS.get(job_id)
                if current and current["_cancel_event"].is_set():
                    raise CancelledError()

        try:
            installed = _install_generated(out_dir, cancel_check=cancel_check)
            # Linearization point: either cancellation won the lock (rollback),
            # or the fully installed artifact set commits and a later click is
            # simply racing a job that has already completed.
            with _JOBS_LOCK:
                current = _JOBS.get(job_id)
                rollback = bool(current and current["_cancel_event"].is_set())
                if current and not rollback:
                    current["_committed"] = True
            if rollback:
                _rollback_installed(installed, prior_manifest, manifest_existed)
                raise CancelledError()
        except CancelledError:
            shutil.rmtree(out_dir, ignore_errors=True)
            _finish_job(
                job_id, False, output + "\n\n[cancelled] Stopped by user.", [],
                cancelled=True,
            )
            return
        if not installed:
            ok = False
            output += "\n\n[install] No scraper_gen_*.html was produced — nothing installed."

    if not ok:
        output = _ml_stack_hint(output)

    shutil.rmtree(out_dir, ignore_errors=True)
    _finish_job(job_id, ok, output, installed)


_HEAD_OPEN_RE = re.compile(r"(<head\b[^>]*>)", re.IGNORECASE)
_HEAD_CLOSE_RE = re.compile(r"</head>", re.IGNORECASE)


def _with_fingerprint_beacon(html):
    """Keep every installed page fingerprinted and usable on mobile browsers.

    The generator predates both the Layer-1 beacon and the public site's shared
    responsive stylesheet.  Add the same-origin head assets when a generated or
    edited template omits them.  Malformed fragments without a real ``<head>``
    are left alone so ``save_template`` can retain its existing warning path.
    """
    if not _HEAD_OPEN_RE.search(html) or not _HEAD_CLOSE_RE.search(html):
        return html

    lower = html.lower()
    head_assets = []
    if not re.search(r"<meta\b[^>]*\bcharset\s*=", html, re.IGNORECASE):
        head_assets.append('<meta charset="utf-8">')
    if not re.search(
            r"<meta\b[^>]*\bname\s*=\s*(['\"])viewport\1", html,
            re.IGNORECASE):
        head_assets.append(
            '<meta name="viewport" content="width=device-width, initial-scale=1, '
            'viewport-fit=cover">')
    if "/css/site.css" not in lower:
        head_assets.append('<link rel="stylesheet" href="/css/site.css?v=1">')

    if head_assets:
        html = _HEAD_OPEN_RE.sub(
            lambda match: match.group(1) + "\n" + "\n".join(head_assets),
            html,
            count=1,
        )
    if "fp.js" not in lower:
        html = _HEAD_CLOSE_RE.sub(
            '<script src="/js/fp.js" defer></script>\n</head>', html, count=1)
    return html


def _read_varlist(path):
    """The 10 Faker expressions of a scraper_gen_<category>.txt, or None."""
    try:
        lines = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()]
    except OSError:
        return None
    lines = [ln for ln in lines if ln]
    return lines if len(lines) >= 10 else None


def _rollback_installed(installed, prior_manifest, manifest_existed):
    for item in installed:
        version = item["version"]
        for path in (
            config.TEMPLATES_DIR / f"scraper{version}.html",
            config.WEBSITE_DIR / "varLists" / f"scraper{version}.txt",
        ):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
    if manifest_existed:
        _save_manifest(prior_manifest)
    else:
        try:
            _manifest_path().unlink()
        except FileNotFoundError:
            pass


def _install_generated(out_dir, cancel_check=None):
    """Install each scraper_gen_<category>.html from ``out_dir`` into
    website/templates/ as the next free scraper<N>.html (never overwriting an
    existing flavor), carrying its varList into website/varLists/ + the manifest."""
    config.TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    generated = sorted(out_dir.glob("scraper_gen_*.html"))
    installed = []
    taken = set(existing_versions())
    manifest = load_manifest()
    prior_manifest = dict(manifest)
    manifest_existed = _manifest_path().exists()
    try:
        for src in generated:
            if cancel_check:
                cancel_check()
            category = src.stem[len("scraper_gen_"):]
            version = _next_version(taken)
            taken.add(version)
            dest = config.TEMPLATES_DIR / f"scraper{version}.html"
            dest.write_text(
                _with_fingerprint_beacon(src.read_text(encoding="utf-8")),
                encoding="utf-8")

            varlist = _read_varlist(src.with_suffix(".txt"))
            if varlist:
                varlists_dir = config.WEBSITE_DIR / "varLists"
                varlists_dir.mkdir(parents=True, exist_ok=True)
                (varlists_dir / f"scraper{version}.txt").write_text(
                    "\n".join(varlist) + "\n", encoding="utf-8")
                manifest[str(version)] = {
                    "category": category,
                    "canary_tokens": varlist,
                    "installed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                }
            installed.append({"version": version, "filename": dest.name, "category": category})
            if cancel_check:
                cancel_check()
        if installed:
            _save_manifest(manifest)
        if cancel_check:
            cancel_check()
        return installed
    except CancelledError:
        _rollback_installed(installed, prior_manifest, manifest_existed)
        raise


def _append_history(type_id, ok, installed_count, status=None):
    try:
        config.HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        with open(config.HISTORY_DIR / "generations.jsonl", "a") as handle:
            handle.write(json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "type": type_id,
                "installed": installed_count,
                "status": status or ("ok" if ok else "failed"),
            }) + "\n")
    except Exception:
        # History is best-effort; never let logging break a generation run.
        pass
