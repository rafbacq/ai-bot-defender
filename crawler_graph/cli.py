"""CLI for the crawler-graph intelligence package.

    python -m crawler_graph build         # load logdb -> graph -> communities -> report
    python -m crawler_graph build --gnn    # also train + apply the GraphSAGE attribution
    python -m crawler_graph gnn-train       # train the GraphSAGE model from logdb data
    python -m crawler_graph report          # print the last persisted campaigns
    python -m crawler_graph selftest        # offline synthetic end-to-end check

Run from the repository root.
"""

import argparse
import json

from . import config


def _print_summary(result):
    meta = result["meta"]
    f = result["findings"]
    print(json.dumps({"meta": meta, "findings_summary": {
        "n_campaigns": f["n_campaigns"], "n_disguised": f["n_disguised"],
        "n_agentic": f["n_agentic"]}}, indent=2, default=str))
    print("\nTop campaigns:")
    for c in result["campaigns"][:15]:
        flags = []
        if c["disguise_suspected"]:
            flags.append("DISGUISE")
        if c["agentic_suspected"]:
            flags.append("AGENTIC")
        print(f"  [{c['campaign_id']}] {c['label']}  "
              f"ips={c['n_ips']} reqs={c['n_requests']} asns={c['n_asns']} "
              f"{'/'.join(flags)}")


def cmd_build(args):
    from . import pipeline

    result = pipeline.run_intel(
        limit=args.limit, since_hours=args.since_hours,
        resolve_asn=not args.no_asn, use_gnn=args.gnn,
        method=args.method, write=not args.no_write, render=not args.no_viz,
    )
    _print_summary(result)
    if not args.no_write:
        print(f"\nWrote {config.CAMPAIGNS_JSON}")
    return 0


def cmd_gnn_train(args):
    from .ingest import db, enrich
    from .graphing import builder as graph
    from .ml import features, gnn as gnn_mod

    if not gnn_mod.torch_available():
        print("torch / torch_geometric are not installed. Install the GNN extra:\n"
              "  pip install -r crawler_graph/requirements-gnn.txt")
        return 1
    visits = db.fetch_visits(limit=args.limit, since_hours=args.since_hours)
    handshakes = db.fetch_handshakes(since_hours=args.since_hours)
    enrich.join_fingerprints(visits, handshakes)
    enrich.enrich_visits(visits, resolve_asn=not args.no_asn)
    endpoints = enrich.aggregate_endpoints(visits)
    full = graph.build_graph(endpoints)
    ip_graph = graph.project_to_ip_graph(full)
    arrays = features.build_arrays(ip_graph, endpoints)
    print(f"Training GraphSAGE on {len(arrays['nodes'])} IP nodes, "
          f"{len(arrays['labels'])} provider classes, "
          f"{sum(arrays['train_mask'])} labeled...")
    result = gnn_mod.train_classifier(arrays, epochs=args.epochs, verbose=True)
    if not result.get("predictions"):
        print(f"GNN training skipped: {result.get('reason')}")
        return 1
    gnn_mod.save_predictions(result)
    model_path = gnn_mod.save_model(result)
    print(f"final_loss={result.get('final_loss')} "
          f"train_acc={result.get('train_acc')} val_acc={result.get('val_acc')}")
    print(f"  predictions -> {config.GNN_PREDS}")
    print(f"  model       -> {model_path}")
    return 0


def cmd_report(args):
    from . import reporting as report

    payload = report.read_campaigns()
    if not payload:
        print("No persisted campaigns. Run `python -m crawler_graph build` first.")
        return 1
    print(json.dumps(payload, indent=2, default=str)[:8000])
    return 0


def cmd_selftest(args):
    from .tests import test_pipeline as selftest

    return selftest.run(gnn=args.gnn)


def main():
    ap = argparse.ArgumentParser(prog="crawler_graph", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    b = sub.add_parser("build", help="run the full pipeline from logdb")
    b.add_argument("--limit", type=int, default=None)
    b.add_argument("--since-hours", type=int, default=None)
    b.add_argument("--gnn", action="store_true", help="train + apply GraphSAGE attribution")
    b.add_argument("--method", default="auto", choices=["auto", "louvain", "leiden", "greedy"])
    b.add_argument("--no-asn", action="store_true", help="skip ipwhois ASN lookups")
    b.add_argument("--no-write", action="store_true")
    b.add_argument("--no-viz", action="store_true")
    b.set_defaults(func=cmd_build)

    g = sub.add_parser("gnn-train", help="train the GraphSAGE attribution model")
    g.add_argument("--limit", type=int, default=None)
    g.add_argument("--since-hours", type=int, default=None)
    g.add_argument("--epochs", type=int, default=200)
    g.add_argument("--no-asn", action="store_true")
    g.set_defaults(func=cmd_gnn_train)

    r = sub.add_parser("report", help="print the last persisted campaigns")
    r.set_defaults(func=cmd_report)

    s = sub.add_parser("selftest", help="offline synthetic end-to-end check")
    s.add_argument("--gnn", action="store_true", help="also train + check the GraphSAGE GNN")
    s.set_defaults(func=cmd_selftest)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
