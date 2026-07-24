#!/usr/bin/env python3
"""Warm-model generation worker — the generator kept resident between runs.

Loading Qwen3-1.7B + the LoRA adapter costs 40-90s on CPU (it is CPU-bound,
so it depends on what else the box is doing) and peaks around 10-11 GiB before
settling at ~7 GiB, and that cost is per *process*. ``generate_templates.py``
pays it once and exits, so the web app's original design (one subprocess per
template) re-paid the whole load for every single template it authored.

This is the same generator, hosted in a process that stays alive: it loads the
weights on the first request and reuses them for every request after it, so only
the first template of a session waits for the model.

Protocol — deliberately the same shape as the ``@@GENPROGRESS@@`` protocol the
app already parses, so the app's streaming, progress-bar, log-tail, cancel and
watchdog paths are unchanged:

  * one JSON request per line on **stdin**::

        {"cmd": "ping"}                     liveness handshake (loads nothing)
        {"cmd": "load",     "argv": [...]}  load the weights now (preload)
        {"cmd": "generate", "argv": [...]}  argv is exactly what would follow
                                            `generate_templates.py` on the CLI
        {"cmd": "shutdown"}                 release the weights and exit

  * everything the generator prints — ordinary log lines and ``@@GENPROGRESS@@``
    milestones alike — streams straight to **stdout**, untouched;

  * every request ends with exactly one terminal line::

        @@GENDONE@@{"ok": true|false, "warm": bool, "error": "..."}

The worker handles one request at a time (the app already serializes generation
jobs) and never exits because a request failed — only on ``shutdown``, on EOF,
or when it is killed. Cancelling a run kills this process, which is why the app
treats a dead worker as "cold again" and simply starts a new one next time.

Run it by hand to try the protocol out::

    printf '%s\\n' '{"cmd":"ping"}' \\
                   '{"cmd":"generate","argv":["--category","towns","--out","/tmp/x"]}' \\
      | python3 generation_worker.py
"""

import json
import os
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    # The app launches this with cwd=template_generator/, but keep the import
    # working regardless of where it was started from.
    sys.path.insert(0, str(HERE))

import generate_templates as generator  # noqa: E402  (needs the path above)

DONE_PREFIX = "@@GENDONE@@"

# The resident weights. Held at module scope so it survives between requests —
# that single fact is the entire point of this process existing.
_BUNDLE = None


def _respond(**payload):
    """Terminate the current request with the one line the app waits for."""
    print(DONE_PREFIX + json.dumps(payload), flush=True)


def _ensure_bundle(args):
    """The resident model, loading it when this is the first request.

    Returns ``(bundle, warm)`` where ``warm`` is True when the weights were
    already in memory. A request asking for a different model/adapter/dtype
    drops the old bundle first, so the two never sit in RAM at once.
    """
    global _BUNDLE
    key = generator.bundle_key(args)
    if _BUNDLE is not None and _BUNDLE.key == key:
        return _BUNDLE, True
    if _BUNDLE is not None:
        _BUNDLE = None
        import gc
        gc.collect()
    _BUNDLE = generator.load_model_bundle(args)
    return _BUNDLE, False


def _handle(request):
    """Serve one request. Returns False only when asked to shut down."""
    cmd = str(request.get("cmd") or "generate").strip()

    if cmd == "ping":
        _respond(ok=True, warm=_BUNDLE is not None, pid=os.getpid())
        return True

    if cmd == "shutdown":
        _respond(ok=True, shutdown=True)
        return False

    if cmd in ("load", "generate"):
        args = generator.build_parser().parse_args(list(request.get("argv") or []))
        if cmd == "load":
            _, warm = _ensure_bundle(args)
            _respond(ok=True, warm=warm, loaded=True)
            return True
        bundle, warm = _ensure_bundle(args)
        generator.dispatch(args, bundle=bundle)
        _respond(ok=True, warm=warm)
        return True

    _respond(ok=False, error=f"unknown command {cmd!r}")
    return True


def main():
    while True:
        # readline() makes the request/response loop explicit: "" is EOF (the
        # app closed the pipe or exited), which is one of the two ways this
        # process is meant to end.
        line = sys.stdin.readline()
        if not line:          # the app closed the pipe (or exited)
            return 0
        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError("request must be a JSON object")
        except ValueError as exc:
            _respond(ok=False, error=f"malformed request: {exc}")
            continue

        try:
            if not _handle(request):
                return 0
        except SystemExit as exc:
            # argparse exits the process on a bad argv; here that must only fail
            # the request. (Its diagnostics have already gone to stderr.)
            _respond(ok=False, error=f"invalid arguments (exit code {exc.code})")
        except Exception as exc:
            # One bad run must never cost the session its loaded weights.
            traceback.print_exc()
            sys.stderr.flush()
            _respond(ok=False, error=f"{type(exc).__name__}: {exc}")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
