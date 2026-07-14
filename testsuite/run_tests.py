#!/usr/bin/env python3
"""Runnable, configurable test runner for the AI Bot Defender test suite.

One command runs every feature's tests and prints a pass/fail/skip table grouped
by feature, plus machine- and human-readable reports:

    python testsuite/run_tests.py                 # run everything
    python testsuite/run_tests.py --list          # list the features + their tests
    python testsuite/run_tests.py fingerprinting clustering   # run only these features
    python testsuite/run_tests.py -f honeypot     # same, via --feature
    python testsuite/run_tests.py --bots 400      # scale the synthetic stress traffic
    python testsuite/run_tests.py --gnn require    # fail (don't skip) if torch is absent
    python testsuite/run_tests.py -k canary        # forward a -k expression to pytest
    python testsuite/run_tests.py -- -x -vv        # forward raw args to pytest after --

Each feature is also runnable on its own straight through pytest, e.g.::

    pytest testsuite/tests/test_fingerprinting.py -v

Writes ``testsuite/reports/latest.json`` and ``testsuite/reports/latest.html``.
"""

from __future__ import annotations

import argparse
import html
import inspect
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Repo root = the parent of testsuite/. Kept as a plain abspath (not symlink
# resolved) so it matches the path conftest puts on sys.path in this bind-mount.
ROOT = Path(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
TESTS_DIR = "testsuite/tests"
REPORT_DIR = ROOT / "testsuite" / "reports"


# Feature registry: name -> (test file, pytest marker | None, description).
# The map is the single source of truth for ``--feature`` selection, ``--list``,
# and the grouped report. Add a feature by adding a row + its test file.
FEATURES: dict[str, tuple[str, str | None, str]] = {
    "honeypot":       ("test_honeypot_canary.py", None,
                       "Canary token generation + per-visitor identification & assignment"),
    "fingerprinting": ("test_fingerprinting.py", None,
                       "Device fingerprinting: browser/TCP layers + cross-layer consistency"),
    "clustering":     ("test_clustering.py", None,
                       "Crawler-graph campaign clustering, attribution & disguise detection"),
    "gnn":            ("test_clustering_gnn.py", "gnn",
                       "GraphSAGE GNN provider attribution (optional torch dependency)"),
    "querying":       ("test_querying_detection.py", None,
                       "Legacy querying pipeline: scrape -> probe -> extract -> match"),
    "auto_query":     ("test_auto_query_detection.py", None,
                       "auto_query detection engine: attribution matcher, offline fallbacks & adapter"),
    "auto_query_live": ("test_auto_query_live.py", None,
                       "Live API querying: key management, error classification, background runs"),
    "provenance":     ("test_provenance.py", None,
                       "Training-data provenance, membership inference & RAG disambiguation"),
    "logging":        ("test_proxy_logging.py", None,
                       "Reverse-proxy request/fingerprint/TLS logging collectors"),
    "analytics":      ("test_analytics_service.py", None,
                       "Request-log + fingerprint viewer services (SQL build, degradation)"),
    "sites":          ("test_sites_service.py", None,
                       "Site Configurator config read/write/merge + Ansible deploy shim"),
    "generator":      ("test_template_generator.py", None,
                       "Honeypot template generator install logic"),
    "auth":           ("test_auth.py", None,
                       "Reviewed access, signup/login sessions, redirects & password storage"),
    "webapp":         ("test_web_app.py", None,
                       "FastAPI web application routes, pages, exports & redirects"),
    "contracts":      ("test_static_contracts.py", None,
                       "Cross-component static contracts (templates, nginx/Ansible wiring)"),
}

FILE_TO_FEATURE = {meta[0]: name for name, meta in FEATURES.items()}


class ResultCollector:
    """A pytest plugin that captures per-test outcomes for the reports."""

    def __init__(self) -> None:
        self.descriptions: dict[str, str] = {}
        self.results: dict[str, dict] = {}
        self.started_at = datetime.now(timezone.utc)
        self.exitstatus: int | None = None

    def pytest_collection_modifyitems(self, session, config, items):  # pragma: no cover - pytest hook
        for item in items:
            doc = inspect.getdoc(getattr(item, "obj", None)) or ""
            self.descriptions[item.nodeid] = doc.splitlines()[0] if doc else ""

    def pytest_runtest_logreport(self, report):  # pragma: no cover - pytest hook
        if report.when == "call" or (report.when == "setup" and (report.failed or report.skipped)):
            reason = ""
            if report.skipped and isinstance(getattr(report, "longrepr", None), tuple):
                reason = report.longrepr[2]
            self.results[report.nodeid] = {
                "nodeid": report.nodeid,
                "feature": _feature_of(report.nodeid),
                "description": self.descriptions.get(report.nodeid, ""),
                "outcome": report.outcome,
                "duration": round(float(getattr(report, "duration", 0.0) or 0.0), 4),
                "reason": reason,
                "failure": str(report.longrepr) if report.failed else "",
            }

    def pytest_sessionfinish(self, session, exitstatus):  # pragma: no cover - pytest hook
        self.exitstatus = int(exitstatus)

    def payload(self) -> dict:
        finished = datetime.now(timezone.utc)
        results = [self.results[k] for k in sorted(self.results)]
        counts = _counts(results)
        return {
            "suite": "AI Bot Defender test suite",
            "started_at": self.started_at.isoformat(timespec="seconds"),
            "finished_at": finished.isoformat(timespec="seconds"),
            "duration_s": round((finished - self.started_at).total_seconds(), 3),
            "exitstatus": self.exitstatus,
            "counts": counts,
            "by_feature": _by_feature(results),
            "results": results,
        }


def _feature_of(nodeid: str) -> str:
    filename = nodeid.split("::", 1)[0].rsplit("/", 1)[-1]
    return FILE_TO_FEATURE.get(filename, filename)


def _counts(results) -> dict:
    return {
        "passed": sum(1 for r in results if r["outcome"] == "passed"),
        "failed": sum(1 for r in results if r["outcome"] == "failed"),
        "skipped": sum(1 for r in results if r["outcome"] == "skipped"),
        "total": len(results),
    }


def _by_feature(results) -> dict:
    out: dict[str, dict] = {}
    for feature in FEATURES:
        group = [r for r in results if r["feature"] == feature]
        if group:
            out[feature] = _counts(group)
    # Any unmapped files (shouldn't happen) still show up.
    for r in results:
        if r["feature"] not in FEATURES:
            out.setdefault(r["feature"], {"passed": 0, "failed": 0, "skipped": 0, "total": 0})
    return out


# --- Reporting -------------------------------------------------------------
def write_reports(payload: dict, json_path: Path, html_path: Path) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    rows = []
    for result in payload["results"]:
        outcome = result["outcome"]
        color = {"passed": "#16794c", "failed": "#b42318", "skipped": "#8a5a00"}.get(outcome, "#334155")
        extra = ""
        if result["failure"]:
            extra = f"<pre>{html.escape(result['failure'])}</pre>"
        elif result["reason"]:
            extra = f"<em>{html.escape(result['reason'])}</em>"
        rows.append(
            "<tr>"
            f"<td><span style='background:{color}'></span> <strong>{html.escape(outcome.upper())}</strong></td>"
            f"<td>{html.escape(result['feature'])}</td>"
            f"<td>{html.escape(result['nodeid'])}<br><small>{html.escape(result['description'])}</small>{extra}</td>"
            f"<td>{result['duration']:.3f}s</td>"
            "</tr>"
        )

    feat_rows = "".join(
        f"<tr><td>{html.escape(name)}</td><td>{c['passed']}</td><td>{c['failed']}</td>"
        f"<td>{c['skipped']}</td><td>{c['total']}</td></tr>"
        for name, c in payload["by_feature"].items()
    )
    c = payload["counts"]
    html_doc = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>AI Bot Defender Test Report</title>
<style>
 body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 32px; color: #172033; }}
 h1 {{ margin-bottom: 4px; }} h2 {{ margin-top: 28px; font-size: 15px; color: #334; }}
 .summary {{ display: flex; gap: 12px; margin: 16px 0; flex-wrap: wrap; }}
 .pill {{ border: 1px solid #d8dee8; border-radius: 6px; padding: 8px 12px; background: #f8fafc; }}
 table {{ border-collapse: collapse; width: 100%; margin-top: 8px; }}
 th, td {{ border-bottom: 1px solid #e5e7eb; padding: 8px 10px; text-align: left; vertical-align: top; }}
 th {{ font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: #526070; }}
 small, em {{ color: #526070; }}
 span {{ display: inline-block; width: 10px; height: 10px; border-radius: 999px; }}
 pre {{ white-space: pre-wrap; background: #fff4f3; border: 1px solid #ffd6d2; padding: 10px; border-radius: 6px; }}
</style></head><body>
 <h1>AI Bot Defender Test Report</h1>
 <div>{html.escape(payload['finished_at'])} · {payload['duration_s']}s</div>
 <div class="summary">
  <div class="pill"><strong>{c['total']}</strong> total</div>
  <div class="pill"><strong>{c['passed']}</strong> passed</div>
  <div class="pill"><strong>{c['failed']}</strong> failed</div>
  <div class="pill"><strong>{c['skipped']}</strong> skipped</div>
 </div>
 <h2>By feature</h2>
 <table><thead><tr><th>Feature</th><th>Passed</th><th>Failed</th><th>Skipped</th><th>Total</th></tr></thead>
 <tbody>{feat_rows}</tbody></table>
 <h2>All tests</h2>
 <table><thead><tr><th>Result</th><th>Feature</th><th>Test</th><th>Time</th></tr></thead>
 <tbody>{''.join(rows)}</tbody></table>
</body></html>
"""
    html_path.write_text(html_doc, encoding="utf-8")


def print_summary(payload: dict, json_path: Path, html_path: Path) -> None:
    c = payload["counts"]
    print("\n" + "=" * 70)
    print("AI Bot Defender — test summary")
    print("=" * 70)
    for feature, counts in payload["by_feature"].items():
        flag = "OK " if counts["failed"] == 0 else "FAIL"
        skip = f" ({counts['skipped']} skipped)" if counts["skipped"] else ""
        print(f"  [{flag}] {feature:<15} {counts['passed']}/{counts['total']} passed{skip}")
    # Surface failures + skip reasons explicitly.
    for r in payload["results"]:
        if r["outcome"] == "failed":
            print(f"    FAILED  {r['nodeid']}")
        elif r["outcome"] == "skipped" and r["reason"]:
            print(f"    skipped {r['nodeid']} — {r['reason']}")
    print("-" * 70)
    print(f"  TOTAL: {c['passed']} passed, {c['failed']} failed, {c['skipped']} skipped "
          f"({c['total']} tests in {payload['duration_s']}s)")
    print(f"  Reports: {json_path}  |  {html_path}")
    print("=" * 70)


# --- CLI -------------------------------------------------------------------
def _select_features(names: list[str]) -> tuple[list[str], list[str]]:
    """Split requested names into (valid features, unknown names)."""
    valid, unknown = [], []
    for raw in names:
        for name in str(raw).split(","):
            name = name.strip()
            if not name:
                continue
            (valid if name in FEATURES else unknown).append(name)
    # De-dupe while preserving order.
    return list(dict.fromkeys(valid)), unknown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("features", nargs="*", help="Feature names to run (default: all). See --list.")
    parser.add_argument("-f", "--feature", action="append", default=[],
                        help="Feature to run (repeatable; comma-separated allowed).")
    parser.add_argument("--list", action="store_true", help="List features (and collected tests) and exit.")
    parser.add_argument("--bots", type=int, default=None,
                        help="Synthetic stress-traffic size (sets BOT_DEFENDER_BOTS).")
    parser.add_argument("--gnn", choices=["auto", "require", "skip"], default="auto",
                        help="GNN tests: auto (skip if torch absent), require (fail if absent), skip.")
    parser.add_argument("-k", dest="keyword", default=None, help="Forward a -k expression to pytest.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose pytest output.")
    parser.add_argument("--json", type=Path, default=REPORT_DIR / "latest.json")
    parser.add_argument("--html", type=Path, default=REPORT_DIR / "latest.html")
    parser.epilog = "Anything after a literal `--` is passed straight to pytest."

    # Split on the first `--` ourselves: argparse.REMAINDER mixed with a `nargs=*`
    # positional mis-routes flags that follow a feature name, so we keep raw
    # pytest passthrough out of argparse entirely.
    raw = list(sys.argv[1:] if argv is None else argv)
    extra_pytest_args: list[str] = []
    if "--" in raw:
        cut = raw.index("--")
        raw, extra_pytest_args = raw[:cut], raw[cut + 1:]
    args = parser.parse_args(raw)

    try:
        import pytest
    except ImportError:
        print("pytest is not installed. Install the suite dependencies first:", file=sys.stderr)
        print("  pip install -r testsuite/requirements.txt", file=sys.stderr)
        return 2

    requested, unknown = _select_features(list(args.features) + list(args.feature))
    if unknown:
        print(f"Unknown feature(s): {', '.join(unknown)}", file=sys.stderr)
        print(f"Available: {', '.join(FEATURES)}", file=sys.stderr)
        return 2

    if args.list:
        print("Available features:\n")
        for name, (filename, marker, desc) in FEATURES.items():
            tag = " [needs torch]" if marker == "gnn" else ""
            print(f"  {name:<15} {desc}{tag}")
            print(f"  {'':<15} -> {TESTS_DIR}/{filename}")
        print("\nRun all:   python testsuite/run_tests.py")
        print("Run some:  python testsuite/run_tests.py clustering fingerprinting")
        print("Direct:    pytest testsuite/tests/test_clustering.py -v")
        return 0

    # Environment knobs read by the synthetic-traffic + GNN tests.
    os.environ["PROJECT_ROOT"] = str(ROOT)
    if args.bots is not None:
        os.environ["BOT_DEFENDER_BOTS"] = str(max(1, args.bots))
    if args.gnn == "require":
        os.environ["BOT_DEFENDER_REQUIRE_GNN"] = "1"
    else:
        os.environ.pop("BOT_DEFENDER_REQUIRE_GNN", None)

    # Which test files to run.
    selected = requested or list(FEATURES)
    targets = [f"{TESTS_DIR}/{FEATURES[name][0]}" for name in selected]

    pytest_args = list(targets)
    pytest_args.append("-vv" if args.verbose else "-q")
    pytest_args += ["-o", "addopts="]   # ignore any inherited addopts for a clean run
    if args.gnn == "skip":
        pytest_args += ["-m", "not gnn"]
    if args.keyword:
        pytest_args += ["-k", args.keyword]
    pytest_args += extra_pytest_args

    collector = ResultCollector()
    code = pytest.main(pytest_args, plugins=[collector])
    payload = collector.payload()
    write_reports(payload, args.json, args.html)
    print_summary(payload, args.json, args.html)
    return int(code)


if __name__ == "__main__":
    raise SystemExit(main())
