# `selfplay/` — adversarial self-play (Direction 2)

A co-evolving crawler ⇄ honeypot RL layer: a learned crawler is trained in a
calibrated traffic simulator to harvest content while evading the **production
`crawler_graph` detector**, and the evasions it discovers are used to train a
**robust detector** that runs as a second opinion on the Crawler Analytics
page. Additive and read-only over the runtime layers: it writes only under
`selfplay/output/` (never `crawler_graph/output/`).

## How it fits together

- **The oracle is the production detector** (`defender.py`): synthetic attacker
  cohorts are scored by `crawler_graph.pipeline.run_intel(...)` — the same rule
  ensemble and cross-layer consistency engine the live `/logs` page uses — so
  an evasion found here is a real adversarial example.
- **Constrained MDP** (`traffic_model.py`, `actions.py`, `env.py`): the
  attacker controls identity rotation, timing, fetch behavior, and a **stack
  rung** on a cost-to-evade ladder grounded in the consistency engine — each
  cheaper rung trips a specific contradiction; only a residential-consistent
  stack at full infra cost evades.
- **PPO-Lagrangian** (`ppo.py`, `policy.py`): a GRU policy with reward + cost
  value heads and a learned dual λ maximizes harvest subject to a detection
  budget (CVaR mode available in `config.py`).
- **Calibration gate** (`calibration.py`): per-feature KS + an adversarial-AUC
  classifier confirm the simulator matches real `all_visits` traffic on the
  exact feature vector the detector consumes, before any training counts.
- **v1 deliverable** (`robust_detector.py`): an MLP over the node feature
  vector (an MLP, not a GNN — the evader deliberately breaks graph edges),
  trained on the attacker's hard-negatives, saved to
  `output/robust_detector.pt`, and scored against live traffic from `/logs`.
- **v2** (`coevolve.py`, `ingestion.py`): PSRO co-evolution tracking
  exploitability, plus a Thompson-sampling content bandit rewarded by provable
  ingestion (`querying.membership`).

## Running it

```bash
make selfplay-selftest    # offline end-to-end check (core + short PPO + v2)
make selfplay-calibrate
make selfplay-train       # args via SP_ARGS="--iterations 60"
make selfplay-coevolve
make selfplay-ingest
```

Training runs in the dedicated `trainer` compose service (profile `trainer`,
CPU-only) so long runs never compete with the web app — or as a background job
from the `/selfplay` page. Dependency-light by design: torch + numpy +
networkx + stdlib only (all already in the app image).
