"""The self-play environment (single-agent view: attacker vs. a frozen detector).

A minimal, dependency-light Gymnasium-style env (``reset`` / ``step``) — we do NOT
import gymnasium (it is not in the app image); the interface is duck-typed and the
PPO trainer only needs ``reset``/``step`` + the observation/action dims exported
here.

One **episode = operating one crawl campaign** against the honeypot fleet over
``horizon_T`` waves. Each wave the attacker picks a factored action; the traffic
model realizes it into synthetic rows; a small negative *dense* reward comes from
the real cross-layer consistency scorer applied to the wave; at the terminal step
the whole cohort (embedded in a fixed honest/declared background) is scored by the
production detector oracle, yielding ``D_terminal`` — the CMDP constraint signal.

The observation is deliberately **partial** (the agent never sees ``D``): it sees
its own action echoes plus the environment's responses (served-trap, throttled,
harvest). A recurrent policy integrates these into a belief about how "hot" it is.
"""

import numpy as np

from . import actions as A
from .reward import CMDPReward

OBS_DIM = 11
ACTION_DIMS = A.ACTION_DIMS


class HoneypotCrawlEnv:
    def __init__(self, traffic_model, detector, cfg, seed=0):
        self.tm = traffic_model
        self.detector = detector
        self.cfg = cfg
        self.reward_fn = CMDPReward(cfg)
        self._rng = np.random.default_rng(seed)
        self._ep = 0
        self.state = None
        self.background = None
        self.t = 0
        self.cum_harvest = 0.0
        self.prev_dec = None
        self._last = {}

    # ------------------------------------------------------------------ API
    def reset(self, seed=None):
        if seed is None:
            seed = int(self._rng.integers(0, 2**31))
        self._ep += 1
        self.state = self.tm.new_cohort(seed=seed)
        self.background = self.tm.sample_background(self.cfg.background_size, seed=seed + 1)
        self.t = 0
        self.cum_harvest = 0.0
        self.prev_dec = None
        self._last = {"served_trap": 0.0, "throttled": 0.0, "infra": 0.0,
                      "rotated": 0.0, "speed": 0.0, "rung": 0.0}
        return self._obs(), {}

    def step(self, action):
        from crawler_graph.analysis import consistency
        dec = A.decode(action)
        info_step = self.tm.realize_step(self.state, dec, cohort_cap=self.cfg.cohort_size)
        # Dense signal: the REAL consistency scorer on this wave's endpoint.
        info_step["consistency"] = consistency.score_endpoint(info_step["endpoint"])

        r = self.reward_fn.step_reward(info_step, dec, self.prev_dec)
        step_cost = self.reward_fn.step_cost(info_step)   # dense detectability proxy
        self.cum_harvest += float(info_step.get("content_value", 0.0))
        self.prev_dec = dec
        self._last = {
            "served_trap": 1.0 if info_step.get("served_trap") else 0.0,
            "throttled": 1.0 if info_step.get("throttled") else 0.0,
            "infra": float(info_step.get("infra_cost", 0.0)),
            "rotated": 1.0 if (dec.get("rotate_ua") or dec.get("rotate_asn")) else 0.0,
            "speed": {"fast": 0.0, "human": 0.5, "slow": 1.0}[dec["speed_name"]],
            "rung": dec["stack"].rung / max(1, len(A.STACK_PRESETS) - 1),
        }
        self.t += 1
        terminated = self.t >= self.cfg.horizon_T
        cost = step_cost
        info = {"harvest_step": info_step.get("content_value", 0.0)}

        if terminated:
            det = self.detector.score(self.state.bundle, self.background,
                                      attacker_ips=set(self.state.ips.keys()))
            # Terminal cost = dense step cost + the REAL production-detector verdict.
            cost = step_cost + self.reward_fn.terminal_cost(det)
            info["detector"] = det
            info["evaded"] = bool(det["D"] < self.cfg.detection_budget_delta)
            info["cum_harvest"] = self.cum_harvest
            info["n_ips"] = self.state.n_ips()
            info["n_asns"] = self.state.n_asns()
            info["mean_req_per_ip"] = self.state.mean_req_per_ip()
        info["cost"] = cost
        return self._obs(), r, terminated, False, info

    # -------------------------------------------------------------- helpers
    def _obs(self):
        st = self.state
        return np.array([
            self.t / max(1, self.cfg.horizon_T),
            (st.n_ips() / max(1, self.cfg.cohort_size)) if st else 0.0,
            (st.n_asns() / max(1, self.cfg.cohort_size)) if st else 0.0,
            np.log1p(st.mean_req_per_ip()) / 5.0 if st else 0.0,
            np.tanh(self.cum_harvest / 20.0),
            self._last["served_trap"],
            self._last["throttled"],
            self._last["infra"],
            self._last["rotated"],
            self._last["speed"],
            self._last["rung"],
        ], dtype=np.float32)
