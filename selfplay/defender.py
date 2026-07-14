"""The detector oracle — the reward channel of the game.

This wraps the **production** crawler-graph detector and returns a scalar
disguise/detection score ``D`` in ``[0, 1]`` for the attacker's cohort. It uses
the real detector code at every step:

* enrichment + aggregation (``ingest.enrich``), the cross-layer consistency engine
  (``analysis.consistency``), the identity graph + community detection
  (``graphing.builder`` / ``graphing.community``), and the campaign / disguise
  ensemble (``graphing.campaigns``) — exactly the stage order of
  ``pipeline.run_intel`` (verified pipeline.py:93-122), inlined here only so we can
  read ``endpoints`` + ``membership`` and attribute the verdict **precisely to the
  attacker's own IPs** instead of whatever campaign community-detection lumped them
  into.
* optionally the frozen GraphSAGE classifier (``ml.gnn.load_and_predict`` against
  the live ``crawler_graph`` model) — the sixth production disguise signal — as an
  inductive scoring pass with no retraining. Skipped gracefully when torch or the
  saved model is absent.

``D`` composes: attacker-endpoint contradiction rate + cohort-level disguise/agentic
verdict + (optional) confident GNN attribution of the attacker's browser/automation
IPs. Higher = more detectable. This is the constraint signal of the CMDP.
"""


class FrozenDetector:
    def __init__(self, cfg=None, use_frozen_gnn=True, background_bundle=None,
                 robust_scorer=None, robust_weight=1.0):
        self.cfg = cfg
        self.use_frozen_gnn = use_frozen_gnn
        self._gnn_ready = None
        self._background = background_bundle
        # v2 co-evolution: an optional *learned* defender (robust MLP) folded in as
        # defense-in-depth. ``robust_scorer(endpoints_dict) -> {ip: prob}``; the
        # attacker is detected if EITHER the rule ensemble OR the learned detector
        # flags it (max), which is what makes the arms race bite.
        self.robust_scorer = robust_scorer
        self.robust_weight = robust_weight

    # -- availability --------------------------------------------------------
    def gnn_ready(self):
        if self._gnn_ready is not None:
            return self._gnn_ready
        ok = False
        try:
            from crawler_graph.ml import gnn as gnn_mod
            from crawler_graph import config as cg_config
            ok = bool(self.use_frozen_gnn and gnn_mod.torch_available()
                      and cg_config.GNN_MODEL.exists())
        except Exception:
            ok = False
        self._gnn_ready = ok
        return ok

    # -- the oracle ----------------------------------------------------------
    def score(self, cohort_bundle, background_bundle=None, attacker_ips=None):
        """Return a dict with ``D`` in [0,1] + a breakdown, for the attacker cohort."""
        from crawler_graph.analysis import consistency
        from crawler_graph.graphing import builder as graph
        from crawler_graph.graphing import campaigns as campaigns_mod
        from crawler_graph.graphing import community
        from crawler_graph.ingest import enrich

        bg = background_bundle if background_bundle is not None else self._background
        cv, ch, cb, ct = cohort_bundle.as_tuple()
        if bg is not None:
            bv, bh, bb, bt = bg.as_tuple()
        else:
            bv = bh = bb = bt = []
        visits = list(cv) + list(bv)
        handshakes = list(ch) + list(bh)
        browser_fps = list(cb) + list(bb)
        tcp_fps = list(ct) + list(bt)
        attacker_ips = set(attacker_ips or {v["client_ip"] for v in cv})

        # --- real pipeline stages (mirror pipeline.run_intel order) ----------
        enrich.join_fingerprints(visits, handshakes)
        enrich.join_tcp_fingerprints(visits, tcp_fps)
        enrich.enrich_visits(visits, resolve_asn=False)
        endpoints = enrich.aggregate_endpoints(visits)
        enrich.attach_browser_fingerprints(endpoints, browser_fps)
        consistency.annotate(endpoints)

        full_graph = graph.build_graph(endpoints)
        membership, _ = community.detect_communities(full_graph)

        # Optional frozen-GNN provider predictions (inductive, no retrain).
        gnn_preds = self._frozen_gnn_preds(full_graph, endpoints) if self.gnn_ready() else {}
        # Supply the providers' published IP ranges so a declared-UA cohort arriving
        # from off-range IPs is caught as impersonation (range_violation) — the
        # defender is assumed to know published crawler CIDRs.
        camps = campaigns_mod.build_campaigns(full_graph, membership, endpoints,
                                              gnn_preds=gnn_preds, ranges=self._ranges())

        # --- attribute the verdict to the attacker's own IPs -----------------
        atk = [endpoints[ip] for ip in attacker_ips if ip in endpoints]
        n = len(atk) or 1
        contradiction_rate = sum(1 for r in atk if (r.get("consistency") or {}).get("inconsistent")) / n
        cons_score = sum((r.get("consistency") or {}).get("score", 0) for r in atk) / n

        # The campaign that holds the plurality of attacker IPs.
        best_camp, best_overlap = None, 0
        for c in camps:
            overlap = len(attacker_ips & set(c.get("sample_ips") or []))
            if overlap > best_overlap:
                best_camp, best_overlap = c, overlap
        cohort_flag = 0.0
        gnn_flag = 0.0
        if best_camp is not None:
            purity = best_overlap / max(1, best_camp.get("n_ips", 1))
            if best_camp.get("disguise_suspected"):
                cohort_flag = min(1.0, 0.5 + 0.5 * purity)
            elif best_camp.get("agentic_suspected"):
                cohort_flag = min(1.0, 0.35 + 0.4 * purity)
            if best_camp.get("gnn_provider") and not best_camp.get("declared_providers"):
                gnn_flag = 0.3 * purity

        # --- compose the rule/GNN-based score in [0,1] ----------------------
        D_rule = min(1.0, 0.5 * cohort_flag + 0.35 * contradiction_rate
                     + 0.15 * min(1.0, cons_score / 4.0) + gnn_flag)

        # --- v2: fold in the learned robust detector (defense-in-depth) -----
        robust_prob = 0.0
        if self.robust_scorer is not None and atk:
            try:
                atk_eps = {r["client_ip"]: r for r in atk}
                probs = self.robust_scorer(atk_eps)
                if probs:
                    robust_prob = float(sum(probs.values()) / len(probs))
            except Exception:
                robust_prob = 0.0
        D = max(D_rule, self.robust_weight * robust_prob)

        return {
            "D": float(D),
            "D_rule": float(D_rule),
            "robust_prob": float(robust_prob),
            "contradiction_rate": float(contradiction_rate),
            "cons_score": float(cons_score),
            "cohort_flag": float(cohort_flag),
            "gnn_flag": float(gnn_flag),
            "disguised": bool(best_camp and best_camp.get("disguise_suspected")),
            "agentic": bool(best_camp and best_camp.get("agentic_suspected")),
            "label": best_camp.get("label") if best_camp else "Unattributed",
            "n_attacker_endpoints": len(atk),
        }

    def _ranges(self):
        if getattr(self, "_ranges_cache", None) is None:
            from . import personas
            self._ranges_cache = personas.provider_ranges()
        return self._ranges_cache

    def _frozen_gnn_preds(self, full_graph, endpoints):
        try:
            from crawler_graph.graphing import builder as graph
            from crawler_graph.ml import features, gnn as gnn_mod
            ip_graph = graph.project_to_ip_graph(full_graph)
            arrays = features.build_arrays(ip_graph, endpoints)
            return gnn_mod.load_and_predict(arrays)
        except Exception:
            return {}
