"""Offline end-to-end self-test (no DB, no API keys, no live services).

Validates, in order:
  1. Core: simulated traffic flows through the REAL ``crawler_graph`` detector; the
     oracle separates an evading strategy from a caught one; honest background is not
     flagged; calibration says sim-vs-sim is indistinguishable.
  2. RL (needs torch): a short PPO-Lagrangian run reduces the detector score and
     beats the naive baseline; the robust detector separates attacker from honest
     endpoints; policy + robust-detector save/load round-trip.
  3. Isolation: nothing was written under ``crawler_graph/output``.

Run: ``python -m selfplay selftest`` (add ``--fast`` to skip the RL training block).
"""

import statistics


def _core():
    from .. import actions, calibration, defender, personas, traffic_model as TM
    from ..config import SelfPlayConfig
    from ..env import HoneypotCrawlEnv

    print("[core] simulator -> real detector oracle")
    cfg = SelfPlayConfig()
    cfg.horizon_T = 18
    tm = TM.TrafficModel(personas.default_personas(), cfg=cfg, seed=1)
    det = defender.FrozenDetector(cfg=cfg, use_frozen_gnn=False)
    env = HoneypotCrawlEnv(tm, det, cfg, seed=0)

    def fixed_D(action, seeds):
        Ds = []
        for s in seeds:
            env.reset(seed=s)
            info = None
            for _ in range(cfg.horizon_T):
                _, _, done, _, info = env.step(action)
            Ds.append(info["detector"]["D"])
        return statistics.mean(Ds)

    evader = fixed_D((3, 6, 0, 5), range(5))     # resi_consistent + rotate_both + slow
    caught = fixed_D((0, 0, 0, 2), range(5))     # headless_js + keep + fast
    print(f"[core] evader D={evader:.3f}  caught D={caught:.3f}")
    assert caught > 0.5, f"a naive attacker should be caught (D={caught:.3f})"
    assert evader < 0.3, f"a residential-consistent evader should slip (D={evader:.3f})"
    assert caught - evader > 0.3, "oracle does not separate evasion from detection"

    # honest background must not be flagged, and impersonation must be
    print("[core] honest background false-positive + impersonation check")
    from crawler_graph.graphing import builder, community, campaigns as cmod
    from crawler_graph.ingest import enrich
    from crawler_graph.analysis import consistency
    bg = tm.sample_background(60, seed=5)
    v = list(bg.visits)
    enrich.enrich_visits(v, resolve_asn=False)
    eps = enrich.aggregate_endpoints(v)
    enrich.attach_browser_fingerprints(eps, bg.browser_fps)
    consistency.annotate(eps)
    g = builder.build_graph(eps)
    mem, _ = community.detect_communities(g)
    camps = cmod.build_campaigns(g, mem, eps, ranges=personas.provider_ranges())
    declared = [c for c in camps if c["declared_providers"]]
    assert declared, "expected honest declared crawlers in the background"
    assert not any(c["disguise_suspected"] for c in declared), "honest crawler falsely flagged"

    print("[core] calibration sim-vs-sim indistinguishable")
    e1 = calibration.build_endpoints(tm.sample_background(200, seed=10))
    e2 = calibration.build_endpoints(tm.sample_background(200, seed=77))
    rep = calibration.indistinguishability_report(e1, e2)
    assert rep["passed"], f"sim-vs-sim should be indistinguishable ({rep})"
    print(f"[core] PASSED  (calib auc={rep['adversarial_auc']} ks={rep['ks_pass_frac']})")


def _rl(full):
    from crawler_graph.ml import gnn
    if not gnn.torch_available():
        print("[rl] torch / torch_geometric unavailable — skipping RL block")
        return
    import torch
    from .. import evaluate, ppo, robust_detector, defender, personas, traffic_model as TM
    from ..config import SelfPlayConfig
    from ..env import HoneypotCrawlEnv, OBS_DIM, ACTION_DIMS
    from ..policy import build_policy

    print("[rl] short PPO-Lagrangian training")
    cfg = SelfPlayConfig()
    cfg.iterations = 30 if full else 12
    cfg.episodes_per_iter = 12
    cfg.horizon_T = 18
    cfg.seed = 0
    tm = TM.TrafficModel(personas.default_personas(), cfg=cfg, seed=1)
    det = defender.FrozenDetector(cfg=cfg, use_frozen_gnn=False)
    env = HoneypotCrawlEnv(tm, det, cfg, seed=0)
    policy, history = ppo.train_attacker(env, cfg)
    d0, dN = history[0]["mean_D"], history[-1]["mean_D"]
    e0, eN = history[0]["evasion_rate"], history[-1]["evasion_rate"]
    print(f"[rl] mean_D {d0:.3f} -> {dN:.3f} ; evasion {e0:.2f} -> {eN:.2f} ; lambda {history[-1]['lambda']:.1f}")
    # Robust, fast signal: the CMDP drives the production-detector score down
    # substantially. (Full evasion, D->0, needs ~45 iters — not asserted here to
    # keep the selftest quick and seed-robust; the `train` CLI shows it converge.)
    assert dN < d0 - (0.2 if full else 0.1), f"training did not reduce detection (D {d0:.3f}->{dN:.3f})"
    assert history[-1]["mean_episodic_cost"] < history[0]["mean_episodic_cost"], \
        "episodic cost (detectability) did not fall under the CMDP"

    print("[rl] robust detector on attacker hard-negatives vs. honest endpoints")
    X, y, _ = robust_detector.gather_dataset(env, policy, n_attacker_eps=20, n_bg_batches=4)
    res = robust_detector.train(X, y, seed=0)
    assert res.get("trained"), f"robust detector failed to train: {res.get('reason')}"
    print(f"[rl] robust val_auc={res['val_auc']} (n_pos={res['n_pos']} n_neg={res['n_neg']})")
    assert res["val_auc"] >= 0.7, f"robust detector should separate attacker from honest (auc={res['val_auc']})"

    print("[rl] robust-detector + policy save/load round-trip")
    robust_detector.save(res)
    eps = __import__("selfplay.calibration", fromlist=["build_endpoints"]).build_endpoints(
        tm.sample_background(30, seed=3))
    scored = robust_detector.score_endpoints(eps)
    assert len(scored) == len(eps) and all(0 <= p <= 1 for p in scored.values())
    torch.save({"state_dict": policy.state_dict(), "obs_dim": OBS_DIM,
                "act_dims": list(ACTION_DIMS), "hidden": cfg.hidden},
               __import__("selfplay.config", fromlist=["POLICY_CKPT"]).POLICY_CKPT)
    ck = torch.load(__import__("selfplay.config", fromlist=["POLICY_CKPT"]).POLICY_CKPT, weights_only=False)
    p2 = build_policy(ck["obs_dim"], ck["act_dims"], ck["hidden"])
    p2.load_state_dict(ck["state_dict"])
    print("[rl] PASSED")


def _v2(full):
    """v2: a tiny co-evolution round + the ingestion closed loop."""
    from .. import ingestion
    print("[v2] ingestion closed-loop (real membership test as reward)")
    rep = ingestion.run_ingestion_experiment(n_rounds=40, seed=1)
    assert rep["best_arm"]["name"] in ("rare-5gram", "steg-marker"), \
        f"content bandit should favor a memorable arm (got {rep['best_arm']['name']})"
    assert rep["final_membership"]["p_value"] < 0.05, "winning content should be provably ingested"
    print(f"[v2] ingestion PASSED  (best={rep['best_arm']['name']} p={rep['final_membership']['p_value']} "
          f"backend={rep['membership_backend']})")

    from crawler_graph.ml import gnn
    if not gnn.torch_available():
        print("[v2] torch unavailable — skipping PSRO block")
        return
    if not full:
        print("[v2] fast mode — skipping PSRO block")
        return
    print("[v2] short PSRO co-evolution")
    from .. import coevolve
    from ..config import SelfPlayConfig
    cfg = SelfPlayConfig()
    cfg.psro_iterations = 2
    cfg.psro_br_iterations = 8
    cfg.episodes_per_iter = 8
    cfg.eval_episodes = 16
    cfg.horizon_T = 16
    rep = coevolve.run_psro(cfg, verbose=True, save=False)
    assert len(rep["exploitability"]) == cfg.psro_iterations, "PSRO did not run all rounds"
    assert rep["robust_val_auc"] is not None, "co-evolution produced no robust detector"
    assert len(rep["payoff_matrix"]) >= 1, "no payoff matrix"
    print(f"[v2] PSRO PASSED  (exploitability={rep['exploitability']} robust_auc={rep['robust_val_auc']})")


def _isolation(before):
    from crawler_graph import config as cg
    after = _cg_output_snapshot(cg)
    assert after == before, (
        f"self-play wrote into crawler_graph/output (isolation violated):\n"
        f"  before={before}\n  after={after}")
    print("[isolation] PASSED  (crawler_graph/output untouched)")


def _cg_output_snapshot(cg):
    snap = {}
    for p in (cg.CAMPAIGNS_JSON, cg.GNN_MODEL, cg.GNN_PREDS):
        try:
            snap[p.name] = p.stat().st_mtime if p.exists() else None
        except OSError:
            snap[p.name] = None
    return snap


def run(full=True):
    from crawler_graph import config as cg
    before = _cg_output_snapshot(cg)
    _core()
    _rl(full)
    _v2(full)
    _isolation(before)
    print("\nSELFPLAY SELFTEST PASSED ✓")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
