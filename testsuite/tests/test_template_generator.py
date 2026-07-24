"""Honeypot template generator service (app.services.template_gen).

The generator shells out to ``template_generator/generate_templates.py`` (the ML
model) and installs each produced ``scraper_gen_<category>.html`` into
``website/templates/`` as the next free ``scraper<N>.html``, carrying the
category-typed varList into ``website/varLists/scraper<N>.txt`` and the
``configs/generated_templates.json`` manifest (which sites.py embeds as a
per-site canary_tokens override at deploy time). With the model subprocess
stubbed, these tests assert the CLI contract (--category / --out, no
--num/--seed), the install logic (never overwriting an existing flavor, filling
the lowest free slots, fp.js beacon injection), varList/manifest recording, and
history — plus clean handling of bad input.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time

import pytest

STUB_HTML = "<html><head><title>T</title></head><body>{{ var1 }}</body></html>"
STUB_VARLIST = "\n".join(["fake.city()"] * 10) + "\n"

# A torch-free stand-in for generate_templates.py that prints @@GENPROGRESS@@
# milestone lines (the contract the app parses) and writes one page + varList —
# so the streaming/background-job path can be exercised without the ML stack.
STUB_STREAMING_GENERATOR = '''\
import json, sys
from pathlib import Path
argv = sys.argv
out = Path(argv[argv.index("--out") + 1])
category = argv[argv.index("--category") + 1] if "--category" in argv else "towns"
def emit(p, stage, label):
    print("@@GENPROGRESS@@" + json.dumps({"percent": p, "stage": stage, "label": label,
          "category": category}), flush=True)
emit(6, "loading", "Loading the model...")
print("device=cpu dtype=stub (non-progress log line)", flush=True)
emit(55, "generating", "[%s] drafting sections" % category)
out.joinpath("scraper_gen_%s.html" % category).write_text(
    "<html><head><title>T</title></head><body>{{ var1 }}</body></html>", encoding="utf-8")
out.joinpath("scraper_gen_%s.txt" % category).write_text(
    "\\n".join(["fake.city()"] * 10) + "\\n", encoding="utf-8")
emit(100, "done", "Wrote 1 template.")
'''


# A torch-free stand-in for generate_templates.py that implements the contract
# the warm worker drives (build_parser / bundle_key / load_model_bundle /
# run_generate(bundle=) / dispatch) and records every real "model load" to
# loads.txt — so a test can prove the weights are loaded once and then reused.
STUB_WARM_GENERATOR = '''\
import argparse, json
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOADS = HERE / "loads.txt"
CATEGORIES = {"towns": {"subject": "town"}, "animals": {"subject": "animal"}}


class ModelBundle:
    def __init__(self, key):
        self.key = key
        self.runs = 0


def bundle_key(args):
    return (str(args.model), str(args.adapter), bool(args.base_only), str(args.dtype))


def load_model_bundle(args):
    with LOADS.open("a", encoding="utf-8") as fh:
        fh.write("load\\n")
    print("@@GENPROGRESS@@" + json.dumps(
        {"percent": 6, "stage": "loading", "label": "Loading the model..."}), flush=True)
    return ModelBundle(bundle_key(args))


def build_parser():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Qwen/Qwen3-1.7B")
    ap.add_argument("--adapter", type=Path, default=HERE / "adapter")
    ap.add_argument("--base-only", action="store_true")
    ap.add_argument("--reprocess", action="store_true")
    ap.add_argument("--register-only", action="store_true")
    ap.add_argument("--dtype", default="auto")
    ap.add_argument("--out", type=Path, default=HERE / "generated_templates")
    ap.add_argument("--category", default=None)
    ap.add_argument("--institution-id", default="local")
    ap.add_argument("--registry", type=Path, default=HERE / "registry.jsonl")
    ap.add_argument("--registry-url", default=None)
    ap.add_argument("--registry-api-key", default=None)
    ap.add_argument("--skip-registry-check", action="store_true")
    return ap


def run_generate(args, bundle=None):
    if bundle is None:
        bundle = load_model_bundle(args)
    elif bundle.runs:
        print("device=cpu | model already resident (no reload)", flush=True)
    bundle.runs += 1
    category = args.category or "towns"
    args.out.mkdir(parents=True, exist_ok=True)
    print("device=cpu (non-progress log line)", flush=True)
    (args.out / ("scraper_gen_%s.html" % category)).write_text(
        "<html><head><title>T</title></head><body>{{ var1 }}</body></html>",
        encoding="utf-8")
    (args.out / ("scraper_gen_%s.txt" % category)).write_text(
        "\\n".join(["fake.city()"] * 10) + "\\n", encoding="utf-8")
    print("@@GENPROGRESS@@" + json.dumps(
        {"percent": 100, "stage": "done", "label": "Wrote 1 template."}), flush=True)


def dispatch(args, bundle=None):
    run_generate(args, bundle=bundle)


def main():
    dispatch(build_parser().parse_args())


if __name__ == "__main__":
    main()
'''


def _install_warm_worker(paths, monkeypatch, generator_source=STUB_WARM_GENERATOR):
    """Put the REAL generation_worker.py next to a stub generator, and point the
    service's interpreter at this Python."""
    import shutil
    from pathlib import Path as _Path

    real_worker = (_Path(__file__).resolve().parents[2]
                   / "template_generator" / "generation_worker.py")
    shutil.copyfile(real_worker, paths["generator"] / "generation_worker.py")
    (paths["generator"] / "generate_templates.py").write_text(
        generator_source, encoding="utf-8")
    monkeypatch.setenv("TEMPLATE_GEN_PYTHON", sys.executable)
    monkeypatch.setenv("TEMPLATE_GEN_WARM", "1")
    monkeypatch.setenv("TEMPLATE_GEN_WARM_TTL", "30")


def _run_to_completion(template_gen, type_id, timeout=60):
    job_id = template_gen.start_generation(type_id)
    deadline = time.time() + timeout
    job = template_gen.generation_status(job_id)
    while not job["done"] and time.time() < deadline:
        time.sleep(0.05)
        job = template_gen.generation_status(job_id)
    assert job["done"] is True, f"job {job_id} never completed: {job}"
    return job


def test_warm_worker_loads_the_model_once_for_many_generations(
    isolated_app_config, monkeypatch,
):
    """The model is loaded on the first generation and REUSED by later ones.

    This is the whole point of the warm worker: loading Qwen3-1.7B + LoRA costs
    40-90s and peaks around 10-11 GiB per process, so a process per template
    re-paid it every time. Two back-to-back generations must produce two
    templates from exactly one model load.
    """
    from app.services import template_gen

    paths = isolated_app_config
    _install_warm_worker(paths, monkeypatch)
    loads = paths["generator"] / "loads.txt"

    try:
        first = _run_to_completion(template_gen, "towns")
        assert first["status"] == "ok"
        assert [i["filename"] for i in first["installed"]] == ["scraper1.html"]
        assert loads.read_text(encoding="utf-8").count("load") == 1
        # The first run is the one that pays for the load, and must not claim
        # otherwise in its own log.
        assert "model already resident" not in first["output"]
        # The weights stay resident between runs — that is what makes the next
        # generation skip the load.
        assert template_gen.warm_status()["loaded"] is True

        second = _run_to_completion(template_gen, "animals")
        assert second["status"] == "ok"
        assert [i["filename"] for i in second["installed"]] == ["scraper2.html"]
        assert loads.read_text(encoding="utf-8").count("load") == 1, (
            "the second generation reloaded the model instead of reusing it")
        assert "model already resident" in second["output"]

        # Everything the one-shot path guarantees still holds on the warm path.
        stored = (paths["templates"] / "scraper2.html").read_text(encoding="utf-8")
        assert '<script src="/js/fp.js" defer></script>' in stored
        assert template_gen.canary_tokens_for(2) == ["fake.city()"] * 10
        assert "non-progress log line" in second["output"]
        assert "@@GENPROGRESS@@" not in second["output"]
        assert "@@GENDONE@@" not in second["output"]
        assert second["percent"] == 100 and second["stage"] == "done"
    finally:
        template_gen.shutdown_worker()

    assert template_gen.warm_status()["loaded"] is False


def test_idle_expiry_never_retires_a_worker_a_run_just_claimed(
    isolated_app_config, monkeypatch,
):
    """The idle timer must stand down against a run, not race it.

    The TTL exists to give ~7 GiB back when nobody is generating. If expiry
    only *tested* whether a run was in flight, a run that claimed the worker
    immediately after that test would be killed mid-generation by a timer that
    had already decided the worker was idle — a rare, baffling failure. Expiry
    therefore has to claim the same lock a run holds.
    """
    from app.services import template_gen

    paths = isolated_app_config
    _install_warm_worker(paths, monkeypatch)

    try:
        # Warm a worker, then stand in for a run that owns it.
        ok, detail = template_gen.preload_worker()
        assert ok is True, detail
        assert template_gen.warm_status()["loaded"] is True

        assert template_gen._WORKER_IO.acquire(blocking=False)
        try:
            template_gen._idle_expired()          # fires while the "run" holds it
            assert template_gen.warm_status()["loaded"] is True, (
                "idle expiry killed the worker out from under a running job")
        finally:
            template_gen._WORKER_IO.release()

        # With no run in flight the same call does release the memory — and it
        # holds the run lock while doing so, which is what closes the window: a
        # run cannot slip in between "it is idle" and the kill.
        held = {}
        real_shutdown = template_gen.shutdown_worker

        def recording_shutdown():
            held["io_locked"] = template_gen._WORKER_IO.locked()
            return real_shutdown()

        monkeypatch.setattr(template_gen, "shutdown_worker", recording_shutdown)
        template_gen._idle_expired()
        assert held.get("io_locked") is True, (
            "idle expiry retired the worker without holding the lock a run takes")
        assert template_gen.warm_status()["loaded"] is False
    finally:
        template_gen.shutdown_worker()


def test_preload_loads_the_model_before_the_first_generation(
    isolated_app_config, monkeypatch,
):
    """TEMPLATE_GEN_PRELOAD warms the model up front, so even the session's
    first template generates without waiting for a load."""
    from app.services import template_gen

    paths = isolated_app_config
    _install_warm_worker(paths, monkeypatch)
    loads = paths["generator"] / "loads.txt"

    monkeypatch.setenv("TEMPLATE_GEN_PRELOAD", "1")
    assert template_gen.preload_enabled() is True
    try:
        ok, detail = template_gen.preload_worker()
        assert ok is True, detail
        assert loads.read_text(encoding="utf-8").count("load") == 1
        assert template_gen.warm_status()["loaded"] is True

        job = _run_to_completion(template_gen, "towns")
        assert job["status"] == "ok" and job["installed"]
        assert loads.read_text(encoding="utf-8").count("load") == 1, (
            "the preloaded model was not reused by the generation")
    finally:
        template_gen.shutdown_worker()


def test_app_lifespan_preloads_and_always_releases_the_model(monkeypatch):
    """The app's lifespan hook is what makes preload opt-in and, more
    importantly, what stops a host-mode restart stranding ~7 GiB of weights in
    memory: the worker must be shut down on the way out, every time."""
    pytest.importorskip("fastapi")
    import asyncio
    import threading

    from app import main

    calls = []
    preloaded = threading.Event()

    def fake_preload():
        calls.append("preload")
        preloaded.set()
        return True, "ok"

    monkeypatch.setattr(main.template_gen, "preload_enabled", lambda: True)
    monkeypatch.setattr(main.template_gen, "preload_worker", fake_preload)
    monkeypatch.setattr(main.template_gen, "shutdown_worker",
                        lambda: calls.append("shutdown"))

    async def drive():
        async with main._lifespan(main.app):
            assert preloaded.wait(5), "the startup preload never ran"
            assert "shutdown" not in calls, "released the model while serving"

    asyncio.run(drive())
    assert calls == ["preload", "shutdown"]

    # With preload off, nothing is loaded at boot — but shutdown still runs, so
    # a worker warmed by an earlier generation is never left behind.
    calls.clear()
    monkeypatch.setattr(main.template_gen, "preload_enabled", lambda: False)

    async def drive_without_preload():
        async with main._lifespan(main.app):
            pass

    asyncio.run(drive_without_preload())
    assert calls == ["shutdown"]


def test_generation_falls_back_to_a_one_shot_run_without_the_worker(
    isolated_app_config, monkeypatch,
):
    """A missing/broken worker must never be the reason a generation fails: the
    run falls back to the original one-shot subprocess and says why."""
    from app.services import template_gen

    paths = isolated_app_config
    # Only the generator script — no generation_worker.py to warm anything with.
    (paths["generator"] / "generate_templates.py").write_text(
        STUB_STREAMING_GENERATOR, encoding="utf-8")
    monkeypatch.setenv("TEMPLATE_GEN_PYTHON", sys.executable)
    monkeypatch.setenv("TEMPLATE_GEN_WARM", "1")

    job = _run_to_completion(template_gen, "towns")

    assert job["status"] == "ok"
    assert [i["filename"] for i in job["installed"]] == ["scraper1.html"]
    assert "[warm] resident model unavailable" in job["output"]
    assert "generation_worker.py not found" in job["output"]
    assert template_gen.warm_status()["loaded"] is False


def test_warm_reuse_can_be_switched_off(isolated_app_config, monkeypatch):
    """TEMPLATE_GEN_WARM=0 restores the original one-process-per-template
    behaviour outright — no worker is started and nothing stays resident."""
    from app.services import template_gen

    paths = isolated_app_config
    _install_warm_worker(paths, monkeypatch)
    monkeypatch.setenv("TEMPLATE_GEN_WARM", "0")
    loads = paths["generator"] / "loads.txt"

    assert template_gen.warm_enabled() is False
    assert template_gen.preload_enabled() is False
    job = _run_to_completion(template_gen, "towns")

    assert job["status"] == "ok" and job["installed"]
    assert loads.read_text(encoding="utf-8").count("load") == 1
    assert template_gen.warm_status()["loaded"] is False


@pytest.mark.parametrize("env,warm,preload", [
    ({}, True, False),                                          # defaults
    ({"TEMPLATE_GEN_WARM": ""}, True, False),                   # blank = unset
    ({"TEMPLATE_GEN_PRELOAD": ""}, True, False),
    ({"TEMPLATE_GEN_WARM": "0"}, False, False),
    ({"TEMPLATE_GEN_WARM": "off"}, False, False),
    ({"TEMPLATE_GEN_PRELOAD": "1"}, True, True),
    ({"TEMPLATE_GEN_PRELOAD": "true"}, True, True),
    # Preload is meaningless without warming, and must not force it back on.
    ({"TEMPLATE_GEN_WARM": "0", "TEMPLATE_GEN_PRELOAD": "1"}, False, False),
])
def test_warm_env_knobs_treat_blank_as_unset(monkeypatch, env, warm, preload):
    """The knobs ship in .env.example with empty values, so a copied-but-unedited
    file must keep the defaults rather than silently disabling model reuse."""
    from app.services import template_gen

    for name in ("TEMPLATE_GEN_WARM", "TEMPLATE_GEN_PRELOAD"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    assert template_gen.warm_enabled() is warm
    assert template_gen.preload_enabled() is preload


@pytest.mark.parametrize("raw,ttl", [
    (None, 1800.0), ("", 1800.0), ("junk", 1800.0), ("0", 0.0), ("60", 60.0),
])
def test_warm_idle_ttl_falls_back_on_blank_or_junk(monkeypatch, raw, ttl):
    """A bad TTL must not crash a generation or pin the weights by accident."""
    from app.services import template_gen

    monkeypatch.delenv("TEMPLATE_GEN_WARM_TTL", raising=False)
    if raw is not None:
        monkeypatch.setenv("TEMPLATE_GEN_WARM_TTL", raw)
    assert template_gen.warm_idle_ttl() == ttl


def test_generator_script_exposes_the_warm_load_contract():
    """generate_templates.py keeps the seam the warm worker drives: the model
    load is separable from generation, and both paths share one argv parser."""
    import importlib.util
    import inspect
    from pathlib import Path as _Path

    script = (_Path(__file__).resolve().parents[2]
              / "template_generator" / "generate_templates.py")
    spec = importlib.util.spec_from_file_location("generate_templates_under_test", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # run_generate can be handed an already-loaded bundle instead of loading one.
    assert "bundle" in inspect.signature(module.run_generate).parameters
    assert inspect.signature(module.run_generate).parameters["bundle"].default is None

    # A freshly loaded bundle has served nothing yet, so the first run using it
    # cannot report itself as a reuse.
    assert module.ModelBundle(None, None, "cpu", "", ("k",)).runs == 0

    # The worker parses a request's argv with the CLI's own parser, so a warm
    # run and a one-shot run take identical options.
    args = module.build_parser().parse_args(["--category", "towns", "--out", "/tmp/out"])
    assert args.category == "towns" and str(args.out) == "/tmp/out"

    # Only model/adapter/base-only/dtype force a reload; category and output
    # (what actually varies between runs) reuse the resident weights.
    other = module.build_parser().parse_args(["--category", "animals", "--out", "/tmp/x"])
    assert module.bundle_key(args) == module.bundle_key(other)
    assert module.bundle_key(
        module.build_parser().parse_args(["--base-only"])) != module.bundle_key(args)

    # dispatch() routes exactly like the CLI's main() always did.
    seen = []
    module.run_generate = lambda a, bundle=None: seen.append(("generate", bundle))
    module.run_reprocess = lambda a: seen.append(("reprocess", None))
    module.run_register_only = lambda a: seen.append(("register", None))
    module.dispatch(module.build_parser().parse_args(["--reprocess"]))
    module.dispatch(module.build_parser().parse_args(["--register-only"]))
    module.dispatch(module.build_parser().parse_args([]), bundle="warm")
    assert seen == [("reprocess", None), ("register", None), ("generate", "warm")]


def test_single_category_run_installs_next_free_slot(isolated_app_config, monkeypatch):
    """A --category run installs into the lowest free scraper<N> slot with its varList."""
    from app.services import template_gen

    paths = isolated_app_config
    (paths["templates"] / "scraper1.html").write_text("existing 1", encoding="utf-8")
    (paths["templates"] / "scraper3.html").write_text("existing 3", encoding="utf-8")
    (paths["generator"] / "generate_templates.py").write_text("# stub generator", encoding="utf-8")

    seen = {}

    def fake_run(cmd, cwd, capture_output, text, timeout):
        seen["cmd"] = cmd
        out_dir = template_gen.Path(cmd[cmd.index("--out") + 1])
        (out_dir / "scraper_gen_towns.html").write_text(STUB_HTML, encoding="utf-8")
        (out_dir / "scraper_gen_towns.txt").write_text(STUB_VARLIST, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="generated", stderr="")

    monkeypatch.setattr(template_gen.subprocess, "run", fake_run)
    ok, output, installed = template_gen.generate("towns", timeout=5)

    assert ok is True and output == "generated"
    # New CLI: category selection, no --num/--seed.
    assert seen["cmd"][seen["cmd"].index("--category") + 1] == "towns"
    assert "--num" not in seen["cmd"] and "--seed" not in seen["cmd"]
    # Installed into the lowest free slot (2) — existing flavors untouched.
    assert [item["filename"] for item in installed] == ["scraper2.html"]
    assert installed[0]["category"] == "towns"
    assert (paths["templates"] / "scraper1.html").read_text(encoding="utf-8") == "existing 1"
    assert (paths["templates"] / "scraper3.html").read_text(encoding="utf-8") == "existing 3"
    # The stored page gained the Layer-1 fingerprint beacon tag.
    stored = (paths["templates"] / "scraper2.html").read_text(encoding="utf-8")
    assert '<script src="/js/fp.js" defer></script>' in stored
    # varList lands beside the website templates and in the manifest.
    varlist = (paths["website"] / "varLists" / "scraper2.txt").read_text(encoding="utf-8")
    assert varlist.strip().splitlines() == ["fake.city()"] * 10
    manifest = json.loads((paths["root"] / "configs" / "generated_templates.json").read_text())
    assert manifest["2"]["category"] == "towns"
    assert manifest["2"]["canary_tokens"] == ["fake.city()"] * 10
    assert template_gen.canary_tokens_for(2) == ["fake.city()"] * 10
    assert "installed" in (paths["history"] / "generations.jsonl").read_text(encoding="utf-8")


def test_all_categories_run_fills_slots_in_category_order(isolated_app_config, monkeypatch):
    """An 'all' run omits --category and installs every produced page; a page
    without a varList still installs but is not recorded in the manifest."""
    from app.services import template_gen

    paths = isolated_app_config
    (paths["templates"] / "scraper1.html").write_text("existing 1", encoding="utf-8")
    (paths["templates"] / "scraper3.html").write_text("existing 3", encoding="utf-8")
    (paths["generator"] / "generate_templates.py").write_text("# stub generator", encoding="utf-8")

    seen = {}

    def fake_run(cmd, cwd, capture_output, text, timeout):
        seen["cmd"] = cmd
        out_dir = template_gen.Path(cmd[cmd.index("--out") + 1])
        for category in ("animals", "books", "towns"):
            (out_dir / f"scraper_gen_{category}.html").write_text(STUB_HTML, encoding="utf-8")
            if category != "books":  # books "forgot" its varList
                (out_dir / f"scraper_gen_{category}.txt").write_text(STUB_VARLIST, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="generated", stderr="")

    monkeypatch.setattr(template_gen.subprocess, "run", fake_run)
    ok, _, installed = template_gen.generate("all", timeout=5)

    assert ok is True
    assert "--category" not in seen["cmd"]
    # Lowest free slots (2, 4, 5) in category-name order — never 1 or 3.
    assert [(i["filename"], i["category"]) for i in installed] == [
        ("scraper2.html", "animals"), ("scraper4.html", "books"), ("scraper5.html", "towns")]
    manifest = json.loads((paths["root"] / "configs" / "generated_templates.json").read_text())
    assert set(manifest) == {"2", "5"}, "the varList-less page must not enter the manifest"
    assert template_gen.canary_tokens_for(4) is None


def test_unknown_template_type_is_rejected(isolated_app_config):
    """An unknown category id fails cleanly with a message and installs nothing."""
    from app.services import template_gen

    ok, output, installed = template_gen.generate("does-not-exist")
    assert ok is False
    assert "Unknown template type" in output
    assert installed == []


def test_missing_generator_script_is_reported(isolated_app_config):
    """When the generator script is absent the service explains it instead of crashing."""
    from app.services import template_gen

    # No generate_templates.py is written into the throwaway template_generator dir.
    ok, output, installed = template_gen.generate("towns")
    assert ok is False
    assert "generate_templates.py not found" in output
    assert installed == []


def test_edit_saves_text_and_preserves_canaries_and_beacon(isolated_app_config):
    """Editing the text of a stored flavor rewrites scraper<N>.html, keeps the
    fp.js beacon, records the used canary slots, and appends an edit history line."""
    from app.services import template_gen

    paths = isolated_app_config
    original = (
        "<html><head><title>Old</title>"
        '<script src="/js/fp.js" defer></script></head>'
        "<body>{{ var1 }} {{ var2 }}</body></html>"
    )
    (paths["templates"] / "scraper1.html").write_text(original, encoding="utf-8")

    edited = (
        "<html><head><title>New Story</title></head>"
        "<body>A tale of {{ var2 }} and {{ var5 }}.</body></html>"
    )
    ok, message, info = template_gen.save_template(1, edited)

    assert ok is True and "Saved scraper1.html" in message
    stored = (paths["templates"] / "scraper1.html").read_text(encoding="utf-8")
    assert "A tale of {{ var2 }} and {{ var5 }}." in stored
    # The fingerprint beacon dropped by the edit is re-injected on save.
    assert '<script src="/js/fp.js" defer></script>' in stored
    assert '<meta name="viewport"' in stored
    assert '<link rel="stylesheet" href="/css/site.css?v=1">' in stored
    assert info["canary_slots"] == [2, 5] and info["beacon_present"] is True
    assert '"type": "edit"' in (paths["history"] / "generations.jsonl").read_text(encoding="utf-8")


def test_edit_rejects_broken_jinja_and_leaves_file_intact(isolated_app_config):
    """A syntactically invalid edit is refused (so the live honeypot can't 500),
    and the on-disk template is left exactly as it was."""
    from app.services import template_gen

    paths = isolated_app_config
    good = "<html><head></head><body>{{ var1 }}</body></html>"
    (paths["templates"] / "scraper1.html").write_text(good, encoding="utf-8")

    ok, message, info = template_gen.save_template(1, "<body>{{ var1 </body>")
    assert ok is False and "syntax error" in message.lower() and info == {}
    assert (paths["templates"] / "scraper1.html").read_text(encoding="utf-8") == good

    # Empty content is refused too.
    empty_ok, empty_msg, _ = template_gen.save_template(1, "   ")
    assert empty_ok is False and "empty" in empty_msg.lower()
    assert (paths["templates"] / "scraper1.html").read_text(encoding="utf-8") == good


def test_edit_rejects_unknown_version(isolated_app_config):
    """Editing may only touch an already-stored flavor — never create a new slot."""
    from app.services import template_gen

    ok, message, info = template_gen.save_template(42, "<html><head></head><body>ok</body></html>")
    assert ok is False and "no stored template" in message.lower() and info == {}
    assert not (isolated_app_config["templates"] / "scraper42.html").exists()


def test_edit_warns_when_beacon_cannot_be_injected(isolated_app_config):
    """If an edit drops fp.js and there's no </head> to re-inject it, the save
    still succeeds but flags the missing beacon."""
    from app.services import template_gen

    paths = isolated_app_config
    (paths["templates"] / "scraper1.html").write_text(
        "<html><head></head><body>{{ var1 }}</body></html>", encoding="utf-8")

    ok, message, info = template_gen.save_template(1, "<body>just text {{ var3 }}</body>")
    assert ok is True and info["beacon_present"] is False
    assert "fp.js" in message and info["canary_slots"] == [3]


def test_categories_parse_from_the_real_generator_script(isolated_app_config):
    """available_types() reads the CATEGORIES registry out of the real
    generate_templates.py via AST (plus the 'all' pseudo-type)."""
    import shutil
    from pathlib import Path

    from app.services import template_gen

    real = Path(__file__).resolve().parents[2] / "template_generator" / "generate_templates.py"
    paths = isolated_app_config
    shutil.copyfile(real, paths["generator"] / "generate_templates.py")

    ids = [t["id"] for t in template_gen.available_types()]
    assert "towns" in ids and "all" in ids
    assert len(ids) > 10, f"expected the full category registry, got {ids}"


def test_streaming_generation_job_installs_and_reaches_100(isolated_app_config, monkeypatch):
    """The background-job path (behind the live progress bar) streams the
    generator subprocess, parses its @@GENPROGRESS@@ milestones into live status,
    installs the produced page, and finishes at 100% — all without the ML stack."""
    from app.services import template_gen

    paths = isolated_app_config
    (paths["generator"] / "generate_templates.py").write_text(
        STUB_STREAMING_GENERATOR, encoding="utf-8")
    # Run the stub with this interpreter (robust across environments).
    monkeypatch.setenv("TEMPLATE_GEN_PYTHON", sys.executable)

    job_id = template_gen.start_generation("towns")
    assert isinstance(job_id, str) and job_id

    # Poll until the worker thread finishes (bounded so a hang fails the test).
    deadline = time.time() + 30
    job = template_gen.generation_status(job_id)
    while not job["done"] and time.time() < deadline:
        time.sleep(0.05)
        job = template_gen.generation_status(job_id)

    assert job["done"] is True, "job never completed"
    assert job["status"] == "ok"
    assert job["percent"] == 100 and job["stage"] == "done"
    # Installed into the lowest free slot (templates dir starts empty -> 1).
    assert [i["filename"] for i in job["installed"]] == ["scraper1.html"]
    assert job["installed"][0]["category"] == "towns"
    stored = (paths["templates"] / "scraper1.html").read_text(encoding="utf-8")
    assert "{{ var1 }}" in stored
    assert '<script src="/js/fp.js" defer></script>' in stored  # beacon injected on install
    # varList + manifest recorded, exactly like the blocking path.
    assert template_gen.canary_tokens_for(1) == ["fake.city()"] * 10
    # Non-progress stdout is captured in the live log; progress lines are stripped.
    assert "non-progress log line" in job["output"]
    assert "@@GENPROGRESS@@" not in job["output"]
    assert "installed" in (paths["history"] / "generations.jsonl").read_text(encoding="utf-8")


def test_generation_is_rediscovered_deduplicated_and_checkpointed(
    isolated_app_config, monkeypatch,
):
    """Leaving the generator page cannot orphan or duplicate its model process."""
    from app.services import template_gen

    paths = isolated_app_config
    script = STUB_STREAMING_GENERATOR.replace(
        "import json, sys", "import json, sys, time",
    ).replace(
        'emit(6, "loading", "Loading the model...")',
        'emit(6, "loading", "Loading the model...")\ntime.sleep(0.35)',
    )
    (paths["generator"] / "generate_templates.py").write_text(
        script, encoding="utf-8",
    )
    monkeypatch.setenv("TEMPLATE_GEN_PYTHON", sys.executable)

    job_id = template_gen.start_generation("towns", owner="alice")
    discovered = template_gen.latest_generation(
        requester="alice", active_only=True,
    )
    assert discovered["id"] == job_id and discovered["done"] is False

    with pytest.raises(template_gen.GenerationBusy) as busy:
        template_gen.start_generation("books", owner="alice")
    assert busy.value.job_id == job_id

    deadline = time.time() + 30
    state = template_gen.generation_status(job_id, requester="alice")
    while not state["done"] and time.time() < deadline:
        time.sleep(0.03)
        state = template_gen.generation_status(job_id, requester="alice")
    assert state["status"] == "ok" and state["installed"]

    with template_gen._JOBS_LOCK:
        template_gen._JOBS.pop(job_id, None)
    restored = template_gen.generation_status(job_id, requester="alice")
    assert restored["status"] == "ok" and restored["installed"] == state["installed"]
    with pytest.raises(template_gen.GenerationForbidden):
        template_gen.generation_status(job_id, requester="bob")


def test_streaming_generation_job_reports_unknown_category(isolated_app_config):
    """An unknown category fails the job at once (before any worker spawns), with
    the reason carried on the job for the poller to surface."""
    from app.services import template_gen

    (isolated_app_config["generator"] / "generate_templates.py").write_text(
        "# stub", encoding="utf-8")
    job_id = template_gen.start_generation("does-not-exist")
    job = template_gen.generation_status(job_id)
    assert job["done"] is True and job["status"] == "failed"
    assert "Unknown template type" in job["output"] and job["installed"] == []
