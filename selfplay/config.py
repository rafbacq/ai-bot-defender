"""Paths + hyperparameters for the self-play package.

Everything is env-overridable (like ``crawler_graph/config.py``) so the same code
runs as a host CLI, inside the app container, or in a one-off training container.

The most important invariant here: ``OUTPUT_DIR`` is **our own** directory. We
never write into ``crawler_graph``'s output, so a training loop can never clobber
the artifacts the live ``/logs`` page reads.
"""

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = Path(os.environ.get("PROJECT_ROOT", PACKAGE_DIR.parent))

# --- our own artifact dir (never crawler_graph/output) ----------------------
OUTPUT_DIR = Path(os.environ.get("SELFPLAY_OUTPUT_DIR", str(PACKAGE_DIR / "output")))
RUNS_DIR = OUTPUT_DIR / "runs"
ROBUST_DETECTOR = OUTPUT_DIR / "robust_detector.pt"
ROBUST_PREDS = OUTPUT_DIR / "robust_predictions.json"
EVAL_REPORT = OUTPUT_DIR / "eval_report.json"
STRATEGIES_LOG = OUTPUT_DIR / "strategies.jsonl"
CALIB_REPORT = OUTPUT_DIR / "calib_report.json"
CURVE_PNG = OUTPUT_DIR / "curve.png"
POLICY_CKPT = OUTPUT_DIR / "attacker_policy.pt"


def ensure_output_dir():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    return OUTPUT_DIR


def _f(name, default):
    return float(os.environ.get(name, default))


def _i(name, default):
    return int(os.environ.get(name, default))


@dataclass
class SelfPlayConfig:
    """The full knob set for a self-play run. Constructed from env defaults; any
    field can be overridden per call (CLI / service)."""

    # --- episode / campaign structure --------------------------------------
    horizon_T: int = field(default_factory=lambda: _i("SP_HORIZON_T", 24))
    cohort_size: int = field(default_factory=lambda: _i("SP_COHORT_SIZE", 10))
    background_size: int = field(default_factory=lambda: _i("SP_BACKGROUND_SIZE", 60))

    # --- constrained-MDP (PPO-Lagrangian) ----------------------------------
    # detection_budget_delta: the *diagnostic* evasion threshold on the terminal
    # production-detector score D (an episode "evades" when D < delta).
    # cost_budget: the constraint the dual actually enforces — a bound on the mean
    # *episodic* cost (dense per-step detectability + terminal D). Kept separate so
    # the reported evasion metric is the real detector's verdict, not the shaped cost.
    detection_budget_delta: float = field(default_factory=lambda: _f("SP_DELTA", 0.25))
    cost_budget: float = field(default_factory=lambda: _f("SP_COST_BUDGET", 0.30))
    risk_mode: str = field(default_factory=lambda: os.environ.get("SP_RISK_MODE", "expectation"))  # or "cvar"
    cvar_alpha: float = field(default_factory=lambda: _f("SP_CVAR_ALPHA", 0.1))
    lagrange_lr: float = field(default_factory=lambda: _f("SP_LAGRANGE_LR", 0.5))
    lagrange_init: float = field(default_factory=lambda: _f("SP_LAGRANGE_INIT", 0.5))
    lagrange_max: float = field(default_factory=lambda: _f("SP_LAGRANGE_MAX", 50.0))

    # --- reward shaping ----------------------------------------------------
    harvest_weight: float = field(default_factory=lambda: _f("SP_HARVEST_W", 1.0))
    rotation_cost: float = field(default_factory=lambda: _f("SP_ROT_COST", 0.02))
    slow_cost: float = field(default_factory=lambda: _f("SP_SLOW_COST", 0.015))
    intrinsic_bonus: float = field(default_factory=lambda: _f("SP_INTRINSIC", 0.0))
    dense_consistency_weight: float = field(default_factory=lambda: _f("SP_DENSE_W", 0.15))

    # --- PPO ---------------------------------------------------------------
    gamma: float = field(default_factory=lambda: _f("SP_GAMMA", 0.99))
    gae_lambda: float = field(default_factory=lambda: _f("SP_GAE_LAMBDA", 0.95))
    clip_eps: float = field(default_factory=lambda: _f("SP_CLIP", 0.2))
    ppo_epochs: int = field(default_factory=lambda: _i("SP_PPO_EPOCHS", 4))
    lr: float = field(default_factory=lambda: _f("SP_LR", 3e-4))
    entropy_coef: float = field(default_factory=lambda: _f("SP_ENT", 0.01))
    value_coef: float = field(default_factory=lambda: _f("SP_VF", 0.5))
    hidden: int = field(default_factory=lambda: _i("SP_HIDDEN", 64))
    max_grad_norm: float = field(default_factory=lambda: _f("SP_GRAD_CLIP", 0.5))

    # --- training budget ---------------------------------------------------
    iterations: int = field(default_factory=lambda: _i("SP_ITERS", 50))
    episodes_per_iter: int = field(default_factory=lambda: _i("SP_EPS_PER_ITER", 16))
    eval_episodes: int = field(default_factory=lambda: _i("SP_EVAL_EPS", 64))
    seed: int = field(default_factory=lambda: _i("SP_SEED", 0))

    # --- oracle ------------------------------------------------------------
    detector_backend: str = field(default_factory=lambda: os.environ.get("SP_DETECTOR", "auto"))  # auto|gnn|rule_only
    # OFF by default: the production GraphSAGE model in crawler_graph/output is
    # trained on the REAL traffic distribution and does not transfer to the
    # synthetic simulator (it spuriously attributes synthetic IPs, inflating D).
    # The rule ensemble is the faithful oracle for synthetic self-play. Enable only
    # when the simulator is calibrated to the same distribution the GNN was trained
    # on (a real-data deployment). SP_USE_GNN=1 to override.
    use_frozen_gnn: bool = field(default_factory=lambda: bool(_i("SP_USE_GNN", 0)))

    # --- co-evolution (v2) -------------------------------------------------
    psro_iterations: int = field(default_factory=lambda: _i("SP_PSRO_ITERS", 4))
    psro_br_iterations: int = field(default_factory=lambda: _i("SP_PSRO_BR_ITERS", 30))
    population_cap: int = field(default_factory=lambda: _i("SP_POP_CAP", 8))

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_overrides(cls, **kw):
        cfg = cls()
        for k, v in (kw or {}).items():
            if v is not None and hasattr(cfg, k):
                setattr(cfg, k, type(getattr(cfg, k))(v))
        return cfg
