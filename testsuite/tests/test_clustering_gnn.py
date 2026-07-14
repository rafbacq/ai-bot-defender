"""GraphSAGE GNN provider attribution (crawler_graph.ml.gnn).

Verifies the GNN's *purpose*: attributing a provider to **disguised, UA-less**
nodes through graph structure alone. Two declared providers (labeled by their bot
UA) each have a covert cohort that wears a plain browser UA but shares the
provider's ASN — so the only thing tying a covert cohort to a provider is the
graph. A correct GraphSAGE propagates the label across that structure.

torch + torch_geometric are an OPTIONAL, heavier dependency
(``testsuite/requirements-gnn.txt``). By default this module SKIPS cleanly when
they are absent (clearly reported as skipped, with the reason). Set
``BOT_DEFENDER_REQUIRE_GNN=1`` (the runner's ``--gnn require``) to turn the skip
into a hard failure so CI can insist the GNN path was exercised.
"""

from __future__ import annotations

import importlib
import os
import random
from datetime import datetime, timedelta, timezone

import pytest

pytestmark = pytest.mark.gnn

BROWSER_A = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"
BROWSER_B = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
GPTBOT = "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"
CLAUDEBOT = "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"


def _gnn_modules():
    """Import torch/torch_geometric — skip (or fail under --gnn require) if absent."""
    require = bool(os.environ.get("BOT_DEFENDER_REQUIRE_GNN"))
    for mod in ("torch", "torch_geometric"):
        if require:
            importlib.import_module(mod)  # raises ImportError -> a hard failure
        else:
            pytest.importorskip(mod, reason=f"{mod} not installed (optional GNN dep)")
    from crawler_graph.ml import gnn as gnn_mod
    assert gnn_mod.torch_available(), "torch/torch_geometric import succeeded but GNN reports unavailable"
    return gnn_mod


def _covert_cohort_scenario(seed=11):
    """Two labeled providers + two covert cohorts sharing each provider's ASN.

    Returns ``(visits, handshakes, {'oai': [...], 'ant': [...]})``.
    """
    rng = random.Random(seed)
    base = datetime(2026, 6, 1, tzinfo=timezone.utc)
    visits, handshakes = [], []
    port = [40000]

    def add(ip, ua, ja4, n, asn):
        for _ in range(n):
            port[0] += 1
            ts = base + timedelta(seconds=rng.randint(0, 86400))
            visits.append({"id": len(visits) + 1, "ts": ts.isoformat(), "site": "site-001",
                           "client_ip": ip, "client_port": port[0], "user_agent": ua,
                           "method": "GET", "uri": rng.choice(["/", "/a", "/b", "/c"]), "asn": asn})
            if ja4:
                handshakes.append({"ts": ts.isoformat(), "src_ip": ip, "src_port": port[0],
                                   "ja3": None, "ja4": ja4, "sni": "s"})

    for i in range(8):  # labeled OpenAI (GPTBot), ASN 20473
        add(f"45.10.5.{i}", GPTBOT, "OAI_STACK", rng.randint(20, 50), "20473")
    covert_oai = [f"45.10.9.{i}" for i in range(6)]
    for ip in covert_oai:  # covert OpenAI: browser UA, SAME ASN 20473
        add(ip, BROWSER_A, "COVERT_OAI", rng.randint(10, 30), "20473")

    for i in range(6):  # labeled Anthropic (ClaudeBot), ASN 399358
        add(f"160.79.10.{i}", CLAUDEBOT, "ANT_STACK", rng.randint(20, 50), "399358")
    covert_ant = [f"160.79.20.{i}" for i in range(5)]
    for ip in covert_ant:  # covert Anthropic: browser UA, SAME ASN 399358
        add(ip, BROWSER_B, "COVERT_ANT", rng.randint(10, 30), "399358")

    for i in range(8):  # unrelated noise browsers (unique UA + ASN + fingerprint)
        add(f"73.55.{rng.randint(1, 250)}.{i}",
            f"Mozilla/5.0 (X11; Linux x86_64) Firefox/12{i}.0", f"uniq{i}",
            rng.randint(2, 5), f"70{i}")

    return visits, handshakes, {"oai": covert_oai, "ant": covert_ant}


def _build_arrays(visits, handshakes):
    from crawler_graph.analysis import consistency
    from crawler_graph.graphing import builder as graph
    from crawler_graph.ingest import enrich
    from crawler_graph.ml import features

    enrich.join_fingerprints(visits, handshakes)
    enrich.enrich_visits(visits, resolve_asn=False)
    endpoints = enrich.aggregate_endpoints(visits)
    enrich.attach_browser_fingerprints(endpoints, [])
    consistency.annotate(endpoints)
    ip_graph = graph.project_to_ip_graph(graph.build_graph(endpoints))
    return features.build_arrays(ip_graph, endpoints)


def test_graphsage_attributes_disguised_cohorts_via_structure():
    """The trained classifier generalizes and labels covert cohorts by their
    provider purely from shared-ASN graph structure (no declared UA)."""
    from collections import Counter

    gnn_mod = _gnn_modules()
    visits, handshakes, covert = _covert_cohort_scenario()
    arrays = _build_arrays(visits, handshakes)

    assert len(arrays["labels"]) >= 2, "scenario must give the GNN >=2 provider classes"
    result = gnn_mod.train_classifier(arrays, epochs=250)
    assert result.get("predictions"), f"GNN produced no predictions: {result.get('reason')}"

    preds = result["predictions"]
    if result.get("val_acc") is not None:
        assert result["val_acc"] >= 0.5, f"poor generalization (val_acc={result['val_acc']})"

    def majority(ips):
        votes = Counter(preds[ip]["provider"] for ip in ips if ip in preds)
        return votes.most_common(1)[0][0] if votes else None

    assert majority(covert["oai"]) == "OpenAI", "covert OpenAI cohort misattributed"
    assert majority(covert["ant"]) == "Anthropic", "covert Anthropic cohort misattributed"
    # The covert cohorts carry no declared UA — they were unlabeled training-wise.
    assert all(not preds[ip]["labeled"] for ip in covert["oai"] + covert["ant"])


def test_trained_gnn_model_persists_and_round_trips(tmp_path, monkeypatch):
    """Saving + reloading the classifier reproduces identical predictions."""
    gnn_mod = _gnn_modules()
    from crawler_graph import config as cg_config

    monkeypatch.setattr(cg_config, "OUTPUT_DIR", tmp_path)
    monkeypatch.setattr(cg_config, "GNN_MODEL", tmp_path / "gnn_model.pt")
    monkeypatch.setattr(cg_config, "GNN_PREDS", tmp_path / "gnn_predictions.json")

    visits, handshakes, _ = _covert_cohort_scenario()
    arrays = _build_arrays(visits, handshakes)
    result = gnn_mod.train_classifier(arrays, epochs=120)
    assert result.get("predictions")

    saved = gnn_mod.save_model(result)
    assert saved == tmp_path / "gnn_model.pt"
    reloaded = gnn_mod.load_and_predict(arrays, saved)
    mism = sum(1 for ip in arrays["nodes"]
               if reloaded[ip]["provider"] != result["predictions"][ip]["provider"])
    assert mism == 0, f"reloaded model disagrees on {mism} nodes"


def test_gnn_is_skipped_for_a_single_class_graph():
    """With only one declared-provider class the classifier is degenerate and is
    deliberately skipped (returns a reason, not bogus attributions)."""
    gnn_mod = _gnn_modules()
    visits, handshakes, _ = _covert_cohort_scenario()
    # Drop every Anthropic-labeled node so only OpenAI remains as a class.
    visits = [v for v in visits if "ClaudeBot" not in v["user_agent"]]
    arrays = _build_arrays(visits, handshakes)
    result = gnn_mod.train_classifier(arrays, epochs=50)
    assert not result.get("predictions")
    assert "one declared-provider class" in (result.get("reason") or "")
