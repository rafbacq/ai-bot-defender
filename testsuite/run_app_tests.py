#!/usr/bin/env python3
"""Runner for the LIVE application test suite — the same features as
``run_tests.py``, but exercised against the actually-running stack.

It mass-simulates a diverse bot fleet hitting the real honeypot through the
reverse proxy, then verifies the real databases, the real fingerprint/clustering
pipelines, the real detection/provenance logic, and the real web app. Features
that would need an API key use the offline **mock** models, so no key is required.

It is safe: read-mostly (the only writes are honeypot page views, fingerprint
beacons, and mock detection runs), bounded in volume, and **never destructive**
(no deploys, DB resets, or template generation). Any part of the stack that is
not up causes its tests to **skip** with a clear reason — it never crashes the app.

    python testsuite/run_app_tests.py                 # run everything that's up
    python testsuite/run_app_tests.py --list
    python testsuite/run_app_tests.py honeypot logging
    python testsuite/run_app_tests.py --bots 200      # bigger simulated burst
    python testsuite/run_app_tests.py --proxy-url http://localhost --app-url http://localhost:8000

Prereqs (start what you want to test): `make proxy` (logdb), a deployed site
(`make playbook site_id=site-001`), and `make app` (the web UI). Writes
``testsuite/reports/latest_app.{json,html}``.
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

ROOT = Path(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
TESTS_DIR = "testsuite/app_tests"
REPORT_DIR = ROOT / "testsuite" / "reports"

# Live-feature registry: name -> (test file, description). Mirrors run_tests.py.
FEATURES: dict[str, tuple[str, str]] = {
    "honeypot":       ("test_app_honeypot.py", "Real per-visitor canary assignment + identity logging (site DB)"),
    "logging":        ("test_app_logging.py", "Central all_visits logging via the nginx mirror -> collector"),
    "fingerprinting": ("test_app_fingerprinting.py", "fp.js -> fp-collector beacons + cross-layer verdicts"),
    "clustering":     ("test_app_clustering.py", "crawler_graph pipeline over the live log + provider attribution"),
    "querying":       ("test_app_querying.py", "LLM detection pipeline vs. the real site (mock models)"),
    "provenance":     ("test_app_provenance.py", "Membership demo + provenance run vs. the real site (mock)"),
    "webapp":         ("test_app_webapp.py", "The running FastAPI app: pages, stats, redirects, safe POSTs"),
    "graph":          ("test_app_graph.py", "Seed a multi-IP population -> populate + render the interactive campaigns graph"),
}
FILE_TO_FEATURE = {meta[0]: name for name, meta in FEATURES.items()}


class ResultCollector:
    def __init__(self) -> None:
        self.descriptions: dict[str, str] = {}
        self.results: dict[str, dict] = {}
        self.started_at = datetime.now(timezone.utc)
        self.exitstatus: int | None = None

    def pytest_collection_modifyitems(self, session, config, items):  # pragma: no cover
        for item in items:
            doc = inspect.getdoc(getattr(item, "obj", None)) or ""
            self.descriptions[item.nodeid] = doc.splitlines()[0] if doc else ""

    def pytest_runtest_logreport(self, report):  # pragma: no cover
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

    def pytest_sessionfinish(self, session, exitstatus):  # pragma: no cover
        self.exitstatus = int(exitstatus)

    def payload(self) -> dict:
        finished = datetime.now(timezone.utc)
        results = [self.results[k] for k in sorted(self.results)]
        return {
            "suite": "AI Bot Defender LIVE application test suite",
            "started_at": self.started_at.isoformat(timespec="seconds"),
            "finished_at": finished.isoformat(timespec="seconds"),
            "duration_s": round((finished - self.started_at).total_seconds(), 3),
            "exitstatus": self.exitstatus,
            "counts": _counts(results),
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
    return out


def write_reports(payload: dict, json_path: Path, html_path: Path) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    rows = []
    for r in payload["results"]:
        color = {"passed": "#16794c", "failed": "#b42318", "skipped": "#8a5a00"}.get(r["outcome"], "#334155")
        extra = f"<pre>{html.escape(r['failure'])}</pre>" if r["failure"] else (
            f"<em>{html.escape(r['reason'])}</em>" if r["reason"] else "")
        rows.append(
            "<tr>"
            f"<td><span style='background:{color}'></span> <strong>{html.escape(r['outcome'].upper())}</strong></td>"
            f"<td>{html.escape(r['feature'])}</td>"
            f"<td>{html.escape(r['nodeid'])}<br><small>{html.escape(r['description'])}</small>{extra}</td>"
            f"<td>{r['duration']:.3f}s</td></tr>")
    feat_rows = "".join(
        f"<tr><td>{html.escape(n)}</td><td>{c['passed']}</td><td>{c['failed']}</td>"
        f"<td>{c['skipped']}</td><td>{c['total']}</td></tr>"
        for n, c in payload["by_feature"].items())
    c = payload["counts"]
    html_path.write_text(f"""<!doctype html><html><head><meta charset="utf-8">
<title>AI Bot Defender LIVE Test Report</title><style>
 body {{ font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; margin:32px; color:#172033; }}
 h1 {{ margin-bottom:4px; }} h2 {{ margin-top:28px; font-size:15px; color:#334; }}
 .summary {{ display:flex; gap:12px; margin:16px 0; flex-wrap:wrap; }}
 .pill {{ border:1px solid #d8dee8; border-radius:6px; padding:8px 12px; background:#f8fafc; }}
 table {{ border-collapse:collapse; width:100%; margin-top:8px; }}
 th,td {{ border-bottom:1px solid #e5e7eb; padding:8px 10px; text-align:left; vertical-align:top; }}
 th {{ font-size:12px; text-transform:uppercase; letter-spacing:.04em; color:#526070; }}
 small,em {{ color:#526070; }} span {{ display:inline-block; width:10px; height:10px; border-radius:999px; }}
 pre {{ white-space:pre-wrap; background:#fff4f3; border:1px solid #ffd6d2; padding:10px; border-radius:6px; }}
</style></head><body>
 <h1>AI Bot Defender — LIVE application test report</h1>
 <div>{html.escape(payload['finished_at'])} · {payload['duration_s']}s</div>
 <div class="summary"><div class="pill"><strong>{c['total']}</strong> total</div>
 <div class="pill"><strong>{c['passed']}</strong> passed</div>
 <div class="pill"><strong>{c['failed']}</strong> failed</div>
 <div class="pill"><strong>{c['skipped']}</strong> skipped</div></div>
 <h2>By feature</h2><table><thead><tr><th>Feature</th><th>Passed</th><th>Failed</th><th>Skipped</th><th>Total</th></tr></thead>
 <tbody>{feat_rows}</tbody></table>
 <h2>All tests</h2><table><thead><tr><th>Result</th><th>Feature</th><th>Test</th><th>Time</th></tr></thead>
 <tbody>{''.join(rows)}</tbody></table></body></html>""", encoding="utf-8")


def print_summary(payload: dict, json_path: Path, html_path: Path) -> None:
    c = payload["counts"]
    print("\n" + "=" * 70)
    print("AI Bot Defender — LIVE application test summary")
    print("=" * 70)
    if not payload["by_feature"]:
        print("  (no tests ran)")
    for feature, counts in payload["by_feature"].items():
        flag = "FAIL" if counts["failed"] else ("SKIP" if counts["passed"] == 0 and counts["skipped"] else "OK ")
        skip = f" ({counts['skipped']} skipped)" if counts["skipped"] else ""
        print(f"  [{flag}] {feature:<15} {counts['passed']}/{counts['total']} passed{skip}")
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


def _cleanup_test_rows(ran_graph: bool) -> None:
    """Default post-run hygiene. The live tests tag every fabricated row they
    write into logdb (the AIBDSEED fleet, AIBDLive/pvtest beacons); leaving those
    behind made the real /logs page report phantom devices, disguised crawlers,
    and campaigns long after a test run. Remove them, and when the graph feature
    recomputed the persisted campaigns report over the seeded population,
    re-point that report at the real traffic too."""
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from testsuite.app_tests import seed
    try:
        seed.clean_logdb()
        seed.clean_asn_cache()
        print("Cleaned the fabricated test rows out of logdb (--keep-seed to keep them).")
    except Exception as exc:
        print(f"warning: could not clean test rows from logdb: {exc}", file=sys.stderr)
        return
    if not ran_graph:
        return
    try:
        seed.recompute_live()
        print("Recomputed the campaigns report over the real traffic.")
    except Exception as exc:
        print("warning: the campaigns report still reflects the seeded population "
              f"(recompute failed: {exc}). Use the Recompute button on /logs.", file=sys.stderr)


def _select_features(names):
    valid, unknown = [], []
    for raw in names:
        for name in str(raw).split(","):
            name = name.strip()
            if not name:
                continue
            (valid if name in FEATURES else unknown).append(name)
    return list(dict.fromkeys(valid)), unknown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("features", nargs="*", help="Feature names to run (default: all). See --list.")
    parser.add_argument("-f", "--feature", action="append", default=[],
                        help="Feature to run (repeatable; comma-separated allowed).")
    parser.add_argument("--list", action="store_true", help="List features and exit.")
    parser.add_argument("--clean-seed", action="store_true",
                        help="Remove every fabricated test row (AIBDSEED/AIBDLive/pvtest markers) "
                             "from logdb and exit.")
    parser.add_argument("--keep-seed", action="store_true",
                        help="Leave the fabricated test rows in logdb after the run (e.g. to "
                             "browse the seeded campaign demo); by default they are cleaned up.")
    parser.add_argument("--bots", type=int, default=None,
                        help="Simulated traffic size (sets BOT_DEFENDER_APP_BOTS; default 40).")
    parser.add_argument("--proxy-url", default=None, help="Reverse-proxy entry (sets PROXY_HTTP).")
    parser.add_argument("--app-url", default=None, help="Web app base URL (sets APP_BASE_URL).")
    parser.add_argument("-k", dest="keyword", default=None, help="Forward a -k expression to pytest.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose pytest output.")
    parser.add_argument("--json", type=Path, default=REPORT_DIR / "latest_app.json")
    parser.add_argument("--html", type=Path, default=REPORT_DIR / "latest_app.html")
    parser.epilog = "Anything after a literal `--` is passed straight to pytest."

    raw = list(sys.argv[1:] if argv is None else argv)
    extra: list[str] = []
    if "--" in raw:
        cut = raw.index("--")
        raw, extra = raw[:cut], raw[cut + 1:]
    args = parser.parse_args(raw)

    try:
        import pytest
    except ImportError:
        print("pytest is not installed. Install: pip install -r testsuite/requirements.txt", file=sys.stderr)
        return 2

    requested, unknown = _select_features(list(args.features) + list(args.feature))
    if unknown:
        print(f"Unknown feature(s): {', '.join(unknown)}", file=sys.stderr)
        print(f"Available: {', '.join(FEATURES)}", file=sys.stderr)
        return 2

    if args.clean_seed:
        os.environ["PROJECT_ROOT"] = str(ROOT)
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from testsuite.app_tests import seed
        try:
            seed.clean_logdb()
            seed.clean_asn_cache()
            print("Removed every fabricated test row from the central log. "
                  "Re-run a recompute (or the 'graph' feature) to refresh the campaigns view.")
            return 0
        except Exception as exc:
            print(f"Could not clean seed rows: {exc}", file=sys.stderr)
            return 1

    if args.list:
        print("Available live features:\n")
        for name, (filename, desc) in FEATURES.items():
            print(f"  {name:<15} {desc}")
            print(f"  {'':<15} -> {TESTS_DIR}/{filename}")
        print("\nRun all:   python testsuite/run_app_tests.py")
        print("Run some:  python testsuite/run_app_tests.py honeypot fingerprinting")
        print("Direct:    pytest testsuite/app_tests/test_app_honeypot.py -v")
        return 0

    os.environ["PROJECT_ROOT"] = str(ROOT)
    if args.bots is not None:
        os.environ["BOT_DEFENDER_APP_BOTS"] = str(max(1, args.bots))
    if args.proxy_url:
        os.environ["PROXY_HTTP"] = args.proxy_url
    if args.app_url:
        os.environ["APP_BASE_URL"] = args.app_url

    selected = requested or list(FEATURES)
    targets = [f"{TESTS_DIR}/{FEATURES[name][0]}" for name in selected]
    pytest_args = list(targets) + ["-vv" if args.verbose else "-q", "-o", "addopts="]
    if args.keyword:
        pytest_args += ["-k", args.keyword]
    pytest_args += extra

    collector = ResultCollector()
    code = pytest.main(pytest_args, plugins=[collector])
    payload = collector.payload()
    write_reports(payload, args.json, args.html)
    print_summary(payload, args.json, args.html)
    if not args.keep_seed:
        _cleanup_test_rows(ran_graph="graph" in selected)
    return int(code)


if __name__ == "__main__":
    raise SystemExit(main())
