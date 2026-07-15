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
