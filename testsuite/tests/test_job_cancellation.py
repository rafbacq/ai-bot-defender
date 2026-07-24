"""Cancellation lifecycle coverage for every background execution model."""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from concurrent.futures import CancelledError
from urllib.parse import parse_qs, urlsplit

import pytest


def _wait_status(read, terminal=("cancelled",), timeout=10):
    deadline = time.time() + timeout
    state = read()
    while state.get("status") not in terminal and time.time() < deadline:
        time.sleep(0.02)
        state = read()
    return state


def test_shared_task_cancels_registered_process_and_enforces_owner():
    pytest.importorskip("fastapi")
    from app.services import task_service

    started = threading.Event()
    holder = {}

    def worker(task):
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            start_new_session=True,
        )
        holder["proc"] = proc
        task.attach_process(proc)
        started.set()
        try:
            proc.wait()
            task.check_cancelled()
        finally:
            task.detach_process(proc)

    job_id = task_service.start("test-process", worker, owner="alice")
    assert started.wait(5), "test child process did not start"

    with pytest.raises(task_service.TaskForbidden):
        task_service.cancel(job_id, requester="bob")
    assert holder["proc"].poll() is None, "another user must not stop this process"

    requested = task_service.cancel(job_id, requester="alice")
    assert requested["status"] == "cancelling"
    final = _wait_status(lambda: task_service.status(job_id, requester="alice"))
    assert final["done"] is True and final["status"] == "cancelled"
    assert holder["proc"].poll() is not None
    # Repeated cancellation is deliberately harmless.
    assert task_service.cancel(job_id, requester="alice")["status"] == "cancelled"


def test_shared_task_is_rediscoverable_and_result_survives_registry_eviction(
    isolated_app_config,
):
    """A page poller/client is not the owner of execution or result state."""
    pytest.importorskip("fastapi")
    from app.services import task_service

    started = threading.Event()
    release = threading.Event()

    def worker(task):
        started.set()
        while not release.wait(0.01):
            task.check_cancelled()
        return {
            "ok": True,
            "label": "Finished while the browser was away.",
            "payload": {"value": 42},
            "redirect": "/sites",
        }

    job_id = task_service.start(
        "persistence-test", worker, owner="alice",
        label="Running independently…",
    )
    assert started.wait(5)
    discovered = task_service.latest(
        requester="alice", kinds={"persistence-test"}, active_only=True,
    )
    assert discovered["id"] == job_id and discovered["status"] == "running"

    release.set()
    final = _wait_status(
        lambda: task_service.status(job_id, requester="alice"),
        terminal=("completed",),
    )
    assert final["done"] is True and final["ok"] is True
    assert task_service.result(job_id, requester="alice")["payload"] == {"value": 42}

    # Simulate a later app view after the bounded in-memory cache evicted the
    # completed entry. The ignored on-disk checkpoint remains authoritative.
    with task_service._LOCK:
        task_service._JOBS.pop(job_id, None)
    restored = task_service.status(job_id, requester="alice")
    assert restored["status"] == "completed" and restored["label"].startswith("Finished")
    assert task_service.result(job_id, requester="alice")["payload"]["value"] == 42
    with pytest.raises(task_service.TaskForbidden):
        task_service.status(job_id, requester="bob")


def test_template_generation_cancel_stops_child_and_installs_nothing(
    isolated_app_config, monkeypatch,
):
    from app.services import template_gen

    paths = isolated_app_config
    (paths["generator"] / "generate_templates.py").write_text(
        """\
CATEGORIES = {"towns": {"subject": "town"}}
import json, time
print("@@GENPROGRESS@@" + json.dumps({"percent": 5, "stage": "loading", "label": "started"}), flush=True)
time.sleep(60)
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("TEMPLATE_GEN_PYTHON", sys.executable)

    job_id = template_gen.start_generation("towns", owner="alice")
    deadline = time.time() + 5
    while time.time() < deadline:
        job = template_gen.generation_status(job_id)
        if job["stage"] == "loading" and job["percent"] >= 1:
            break
        time.sleep(0.02)

    with pytest.raises(template_gen.GenerationForbidden):
        template_gen.cancel_generation(job_id, requester="bob")
    template_gen.cancel_generation(job_id, requester="alice")
    final = _wait_status(lambda: template_gen.generation_status(job_id))
    assert final["done"] is True and final["status"] == "cancelled"
    assert final["installed"] == []
    assert not list(paths["templates"].glob("scraper*.html"))


# A torch-free generator whose "generation" blocks, exposing the warm worker to
# a cancel mid-run. Usable both as the worker's module and as a one-shot script.
SLOW_WARM_GENERATOR = '''\
import argparse, json, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
# "quick" returns immediately; every other category blocks, so a run can be
# caught mid-generation and cancelled.
CATEGORIES = {"towns": {"subject": "town"}, "quick": {"subject": "quick page"}}


class ModelBundle:
    def __init__(self, key):
        self.key = key


def bundle_key(args):
    return (str(args.model), str(args.adapter), bool(args.base_only), str(args.dtype))


def load_model_bundle(args):
    return ModelBundle(bundle_key(args))


def build_parser():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="m")
    ap.add_argument("--adapter", type=Path, default=HERE / "adapter")
    ap.add_argument("--base-only", action="store_true")
    ap.add_argument("--reprocess", action="store_true")
    ap.add_argument("--register-only", action="store_true")
    ap.add_argument("--dtype", default="auto")
    ap.add_argument("--out", type=Path, default=HERE / "out")
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
    print("@@GENPROGRESS@@" + json.dumps(
        {"percent": 20, "stage": "generating", "label": "drafting"}), flush=True)
    if (args.category or "") == "quick":
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "scraper_gen_quick.html").write_text(
            "<html><head></head><body>{{ var1 }}</body></html>", encoding="utf-8")
        (args.out / "scraper_gen_quick.txt").write_text(
            "\\n".join(["fake.city()"] * 10) + "\\n", encoding="utf-8")
        return
    time.sleep(60)


def dispatch(args, bundle=None):
    run_generate(args, bundle=bundle)


def main():
    dispatch(build_parser().parse_args())


if __name__ == "__main__":
    main()
'''


def test_template_generation_cancel_stops_the_warm_worker_and_recovers(
    isolated_app_config, monkeypatch,
):
    """Cancelling a run served by the resident model must stop it exactly like a
    one-shot run — and the next generation must still work.

    Cancel kills the worker (the only way to interrupt a model mid-generation),
    so the weights go with it; the service must notice the dead worker and start
    a fresh one rather than wedging every later run.
    """
    import shutil
    from pathlib import Path

    from app.services import template_gen

    paths = isolated_app_config
    shutil.copyfile(
        Path(__file__).resolve().parents[2] / "template_generator" / "generation_worker.py",
        paths["generator"] / "generation_worker.py",
    )
    (paths["generator"] / "generate_templates.py").write_text(
        SLOW_WARM_GENERATOR, encoding="utf-8")
    monkeypatch.setenv("TEMPLATE_GEN_PYTHON", sys.executable)
    monkeypatch.setenv("TEMPLATE_GEN_WARM", "1")
    monkeypatch.setenv("TEMPLATE_GEN_WARM_TTL", "30")

    try:
        job_id = template_gen.start_generation("towns", owner="alice")
        deadline = time.time() + 15
        while time.time() < deadline:
            if template_gen.generation_status(job_id)["percent"] >= 20:
                break
            time.sleep(0.02)
        assert template_gen.warm_status()["loaded"] is True

        with pytest.raises(template_gen.GenerationForbidden):
            template_gen.cancel_generation(job_id, requester="bob")
        template_gen.cancel_generation(job_id, requester="alice")

        final = _wait_status(lambda: template_gen.generation_status(job_id))
        assert final["done"] is True and final["status"] == "cancelled"
        assert final["installed"] == []
        assert not list(paths["templates"].glob("scraper*.html"))
        # The killed worker is dropped, not left behind as a wedged handle.
        assert template_gen.warm_status()["loaded"] is False
        assert template_gen.warm_status()["busy"] is False

        # A cancel must not poison the generator: the next run starts a fresh
        # worker and completes normally.
        next_id = template_gen.start_generation("quick", owner="alice")
        after = _wait_status(
            lambda: template_gen.generation_status(next_id), terminal=("ok", "failed"),
        )
        assert after["status"] == "ok", after["output"]
        assert [i["filename"] for i in after["installed"]] == ["scraper1.html"]
    finally:
        template_gen.shutdown_worker()


def test_detection_run_cooperatively_cancels_and_rejects_other_owner(monkeypatch):
    pytest.importorskip("fastapi")
    from app.services import auto_query_adapter, run_manager

    started = threading.Event()

    def slow_run(*, run_id, progress, cancel_check, **kwargs):
        started.set()
        while True:
            cancel_check()
            time.sleep(0.01)

    monkeypatch.setattr(auto_query_adapter, "run_detection", slow_run)
    run_id = run_manager.start_detection(
        url="https://example.test", models=["mock/honest-llm"], owner="alice",
    )
    assert started.wait(5)
    with pytest.raises(run_manager.RunForbidden):
        run_manager.cancel(run_id, requester="bob")
    run_manager.cancel(run_id, requester="alice")
    final = _wait_status(lambda: run_manager.status(run_id))
    assert final["done"] is True and final["status"] == "cancelled"


def test_provenance_probe_cancels_and_persists_terminal_status(
    tmp_path, monkeypatch,
):
    pytest.importorskip("fastapi")
    from app.services import provenance_service
    from querying import config as q_config
    from querying import provenance

    monkeypatch.setattr(q_config, "PROVENANCE_DIR", tmp_path / "provenance")
    started = threading.Event()

    def slow_probe(*, run_id, cancel_check, **kwargs):
        started.set()
        while True:
            cancel_check()
            time.sleep(0.01)

    monkeypatch.setattr(provenance, "run_provenance", slow_probe)
    run = provenance_service.start_provenance(
        "custom", "", "https://example.test", ["mock/honest-llm"],
        owner="alice",
    )
    assert started.wait(5)
    with pytest.raises(provenance_service.ProbeForbidden):
        provenance_service.cancel(run["run_id"], requester="bob")
    provenance_service.cancel(run["run_id"], requester="alice")
    final = _wait_status(lambda: provenance_service.status(run["run_id"]))
    assert final["done"] is True and final["status"] == "cancelled"
    assert provenance_service.load_report(run["run_id"])["status"] == "cancelled"


def test_selfplay_cancel_terminates_exact_active_job(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from app.services import selfplay_service

    started = threading.Event()
    stopped = threading.Event()
    calls = []

    class FakeProcess:
        returncode = None
        pid = 987654

        def wait(self):
            started.set()
            assert stopped.wait(5), "cancel did not terminate the fake trainer"
            return self.returncode

        def poll(self):
            return self.returncode

    fake = FakeProcess()

    def fake_popen(*args, **kwargs):
        calls.append(kwargs)
        return fake

    def fake_terminate(proc):
        assert proc is fake
        proc.returncode = -15
        stopped.set()

    monkeypatch.setattr(selfplay_service, "available", lambda: True)
    monkeypatch.setattr(selfplay_service, "torch_available", lambda: True)
    monkeypatch.setattr(selfplay_service, "_log_path", lambda: tmp_path / "job.log")
    monkeypatch.setattr(selfplay_service.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(selfplay_service, "_terminate_process", fake_terminate)
    with selfplay_service._LOCK:
        selfplay_service._JOB.update(status="idle", owner=None)

    selfplay_service.launch_training("coevolve", owner="alice")
    assert started.wait(5)
    with pytest.raises(selfplay_service.SelfPlayForbidden):
        selfplay_service.cancel_job(requester="bob")
    selfplay_service.cancel_job(requester="alice")
    final = _wait_status(lambda: selfplay_service.status()["job"])
    assert final["status"] == "cancelled" and final["returncode"] == -15
    assert calls[0]["start_new_session"] is True


def test_selfplay_live_scoring_uses_the_same_cancellable_lifecycle(
    tmp_path, monkeypatch,
):
    pytest.importorskip("fastapi")
    from app.services import selfplay_service

    detector = tmp_path / "robust_detector.pt"
    detector.write_bytes(b"stub")
    monkeypatch.setattr(selfplay_service.sp_config, "ROBUST_DETECTOR", detector)
    monkeypatch.setattr(selfplay_service, "available", lambda: True)
    monkeypatch.setattr(selfplay_service, "_log_path", lambda: tmp_path / "score.log")
    started = threading.Event()

    def slow_score(*, threshold=0.5, since_hours=None, cancel_check=None):
        started.set()
        while True:
            cancel_check()
            time.sleep(0.01)

    monkeypatch.setattr(selfplay_service, "score_live", slow_score)
    with selfplay_service._LOCK:
        selfplay_service._JOB.update(status="idle", owner=None)

    selfplay_service.launch_score(owner="alice")
    assert started.wait(5)
    selfplay_service.cancel_job(requester="alice")
    final = _wait_status(lambda: selfplay_service.status()["job"])
    assert final["status"] == "cancelled" and final["kind"] == "score-live"


def test_authenticated_http_job_can_be_cancelled_only_by_its_launcher(monkeypatch):
    """Exercise Request injection, redirect/job id, JSON status, and POST cancel."""
    pytest.importorskip("fastapi")
    import json
    from starlette.requests import Request

    from app import main

    started = threading.Event()

    def slow_membership(*, n, seed, cancel_check):
        started.set()
        while True:
            cancel_check()
            time.sleep(0.01)

    monkeypatch.setattr(main.provenance_service, "membership_demo", slow_membership)

    def request_for(username, path="/"):
        return Request({
            "type": "http", "http_version": "1.1", "method": "POST",
            "scheme": "http", "path": path, "raw_path": path.encode(),
            "query_string": b"", "headers": [], "client": ("test", 50000),
            "server": ("testserver", 80), "session": {"username": username},
        })

    # Keep a direct assertion on FastAPI's dependency graph: this is what
    # proves a real HTTP request injects Request instead of taking the legacy
    # ``request is None`` direct-call branch. The route functions themselves
    # are invoked below because AnyIO's worker-thread adapter is not compatible
    # with this suite's Python 3.14 runner; production uses Python 3.11.
    route = next(
        route for route in main.app.routes
        if getattr(route, "path", None) == "/provenance/membership-demo"
    )
    assert route.dependant.request_param_name == "request"

    alice = request_for("alice", "/provenance/membership-demo")
    response = main.provenance_membership(n=24, seed="4", request=alice)
    assert response.status_code == 303
    job_id = parse_qs(urlsplit(response.headers["location"]).query)["job"][0]
    assert started.wait(5)
    status = json.loads(main.task_status(alice, job_id).body)
    assert status["status"] == "running"

    bob = request_for("bob", f"/jobs/{job_id}/cancel")
    assert main.task_cancel(bob, job_id).status_code == 403

    requested = main.task_cancel(alice, job_id)
    assert requested.status_code == 200
    assert json.loads(requested.body)["status"] == "cancelling"
    final = _wait_status(
        lambda: json.loads(main.task_status(alice, job_id).body),
    )
    assert final["done"] is True and final["status"] == "cancelled"


def test_http_job_keeps_running_after_launching_client_closes(monkeypatch):
    """Closing a browser client does not cancel work; a new client rediscovers it."""
    pytest.importorskip("fastapi")
    import json
    from starlette.requests import Request

    from app import main

    started = threading.Event()
    release = threading.Event()

    def slow_membership(*, n, seed, cancel_check):
        started.set()
        while not release.wait(0.01):
            cancel_check()
        return {
            "served_mean": -2.0, "control_mean": -4.0, "auc": 1.0,
            "p_value": 0.001, "is_member": True, "backend": "mock",
        }

    monkeypatch.setattr(main.provenance_service, "membership_demo", slow_membership)

    def request_for(path):
        return Request({
            "type": "http", "http_version": "1.1", "method": "POST",
            "scheme": "http", "path": path, "raw_path": path.encode(),
            "query_string": b"", "headers": [], "client": ("test", 50000),
            "server": ("testserver", 80), "session": {"username": "alice"},
        })

    first = request_for("/provenance/membership-demo")
    response = main.provenance_membership(n=24, seed="8", request=first)
    assert response.status_code == 303
    job_id = parse_qs(urlsplit(response.headers["location"]).query)["job"][0]
    assert started.wait(5)
    del first  # the launching request/browser is gone; no cancellation was sent

    reopened = request_for("/jobs/active")
    active = main.active_jobs(reopened)
    assert active.status_code == 200
    listed = json.loads(active.body)["jobs"]
    assert any(job["id"] == job_id and job["status"] == "running" for job in listed)

    release.set()
    final = _wait_status(
        lambda: json.loads(main.task_status(reopened, job_id).body),
        terminal=("completed",),
    )
    assert final["done"] is True and final["ok"] is True
    result = main.task_service.result(job_id, requester="alice")
    assert result["membership"]["is_member"] is True


def test_cancelled_campaign_render_keeps_last_complete_artifact_set(
    tmp_path, monkeypatch,
):
    """Cancellation between render phases must not publish a mixed report/graph."""
    from crawler_graph import config, pipeline, reporting

    output = tmp_path / "intel"
    output.mkdir()
    monkeypatch.setattr(config, "OUTPUT_DIR", output)
    monkeypatch.setattr(config, "CAMPAIGNS_JSON", output / "campaigns.json")
    monkeypatch.setattr(config, "GRAPH_VIZ", output / "campaigns_graph.png")
    monkeypatch.setattr(config, "GRAPH_VIZ_HTML", output / "campaigns_graph.html")
    config.CAMPAIGNS_JSON.write_text("old-report", encoding="utf-8")
    config.GRAPH_VIZ.write_bytes(b"old-png")
    config.GRAPH_VIZ_HTML.write_text("old-html", encoding="utf-8")

    cancelled = threading.Event()

    def fake_graph(graph, membership, path=None, **kwargs):
        path.write_bytes(b"new-png")
        cancelled.set()  # cancellation lands after the first staged render
        return path

    monkeypatch.setattr(reporting, "render_graph", fake_graph)

    def cancel_check():
        if cancelled.is_set():
            raise CancelledError()

    visits = [{
        "id": 1,
        "ts": "2026-07-15T00:00:00+00:00",
        "site": "site-001",
        "client_ip": "203.0.113.10",
        "client_port": 32100,
        "user_agent": "Mozilla/5.0",
        "method": "GET",
        "uri": "/",
        "asn": "AS64500",
    }]
    with pytest.raises(CancelledError):
        pipeline.run_intel(
            visits=visits, handshakes=[], browser_fps=[], tcp_fps=[],
            resolve_asn=False, write=True, render=True,
            cancel_check=cancel_check,
        )

    assert config.CAMPAIGNS_JSON.read_text(encoding="utf-8") == "old-report"
    assert config.GRAPH_VIZ.read_bytes() == b"old-png"
    assert config.GRAPH_VIZ_HTML.read_text(encoding="utf-8") == "old-html"
