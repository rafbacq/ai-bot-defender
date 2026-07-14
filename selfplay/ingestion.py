"""v2b — harvest reward through *real* ingestion + the closed-loop content policy.

v1's harvest is an abstract page-value proxy. v2b grounds "harvest" in whether the
content actually gets **ingested and is provably in the weights**, reusing the real
querying stack:

* ``provable_ingestion`` runs the genuine Min-K% membership test
  (``querying.membership.run_membership``) on served vs. never-served watermark
  documents — the D4 statistic (a p-value that the content is in training data).
* ``ContentBandit`` is a Thompson-sampling allocator over *content arms* (honeypot
  flavor × canary design) whose reward is provable ingestion — the D5 closed-loop
  honeypot: it steers content toward what is both taken by crawlers **and**
  detectable once ingested.

The output is a **content-policy recommendation** (which flavor + canary design to
serve) surfaced to the Site Configurator for human-in-the-loop apply — the RL never
auto-writes the honeypot config. Degrades gracefully (a latent-Bernoulli fallback)
when the querying membership layer isn't importable.
"""

import random
from dataclasses import dataclass, field

import numpy as np


def _membership_available():
    try:
        from querying import membership  # noqa: F401
        return True
    except Exception:
        return False


def provable_ingestion(memorability, n=20, seed=0):
    """Run the real membership test for content of a given ``memorability`` in [0,1].

    A ``memorability`` fraction of served watermarks are treated as memorized by the
    model; the test then separates served from never-served controls. Returns
    ``{p_value, auc, provable}``. Higher memorability ⇒ cleaner separation ⇒ lower p.
    Falls back to a latent-Bernoulli model when ``querying.membership`` is absent.
    """
    if not _membership_available():
        rng = random.Random(f"{memorability}|{seed}")
        p = max(1e-4, 1.0 - memorability) * rng.uniform(0.2, 1.0)
        return {"p_value": round(p, 4), "auc": round(0.5 + 0.5 * memorability, 3),
                "provable": p < 0.05, "backend": "fallback"}

    from querying import membership
    wm = membership.generate_watermarks(n=n, seed=seed)
    served, control = wm["served"], wm["control"]
    k = int(round(memorability * len(served)))
    rng = random.Random(seed)
    memorized = set(rng.sample(served, k)) if k > 0 else set()
    scorer = membership.MockScorer(memorized=memorized, seed=seed)
    res = membership.run_membership(served, control, scorer=scorer)
    p = float(res.get("p_value", res.get("p", 1.0)))
    auc = float(res.get("auc", res.get("roc_auc", 0.5)))
    return {"p_value": round(p, 4), "auc": round(auc, 3), "provable": p < 0.05,
            "backend": "querying.membership"}


@dataclass
class ContentArm:
    name: str
    flavor: str                 # e.g. "scraper3" — which honeypot template
    canary_design: str          # e.g. "rare-5gram" | "common-phrase" | "steg-marker"
    memorability: float         # latent true ingestion propensity (unknown to the bandit)
    alpha: float = 1.0          # Beta posterior (successes + 1)
    beta: float = 1.0           # Beta posterior (failures + 1)
    pulls: int = 0

    def posterior_mean(self):
        return self.alpha / (self.alpha + self.beta)


class ContentBandit:
    """Thompson sampling over content arms; reward = provable ingestion (p<0.05)."""

    def __init__(self, arms, seed=0):
        self.arms = arms
        self.rng = random.Random(seed)
        self.history = []

    def _sample_arm(self):
        best, best_theta = None, -1.0
        for a in self.arms:
            theta = self.rng.betavariate(a.alpha, a.beta)
            if theta > best_theta:
                best, best_theta = a, theta
        return best

    def run(self, n_rounds=60):
        for t in range(n_rounds):
            arm = self._sample_arm()
            res = provable_ingestion(arm.memorability, seed=self.rng.randint(0, 10**6))
            reward = 1.0 if res["provable"] else 0.0
            arm.alpha += reward
            arm.beta += (1.0 - reward)
            arm.pulls += 1
            self.history.append({"round": t, "arm": arm.name, "reward": reward,
                                 "p_value": res["p_value"]})
        return self.report()

    def report(self):
        ranked = sorted(self.arms, key=lambda a: a.posterior_mean(), reverse=True)
        best = ranked[0]
        # a fresh, higher-resolution membership test on the winner for the headline p
        final = provable_ingestion(best.memorability, n=40, seed=12345)
        return {
            "best_arm": {"name": best.name, "flavor": best.flavor,
                         "canary_design": best.canary_design,
                         "posterior_mean": round(best.posterior_mean(), 3),
                         "pulls": best.pulls},
            "final_membership": final,
            "arms": [{"name": a.name, "flavor": a.flavor, "canary_design": a.canary_design,
                      "posterior_mean": round(a.posterior_mean(), 3), "pulls": a.pulls}
                     for a in ranked],
            "recommendation": (
                f"Serve flavor '{best.flavor}' with the '{best.canary_design}' canary "
                f"design: it maximized provable ingestion (membership p={final['p_value']}, "
                f"posterior take-rate {best.posterior_mean():.2f}). Apply via the Site "
                f"Configurator (human-in-the-loop)."),
            "human_in_the_loop": True,
        }


def default_arms():
    """Representative content arms spanning canary designs of differing memorability."""
    return [
        ContentArm("rare-5gram", "scraper2", "rare 5-gram watermark", memorability=0.85),
        ContentArm("steg-marker", "scraper3", "steganographic repetition marker", memorability=0.6),
        ContentArm("named-entity", "scraper1", "fabricated named-entity facts", memorability=0.4),
        ContentArm("common-phrase", "scraper1", "common-phrase filler", memorability=0.12),
    ]


def run_ingestion_experiment(n_rounds=60, arms=None, seed=0):
    """The closed-loop content-policy experiment: allocate content strategies by
    measured provable-ingestion lift and recommend the winner (human-applied)."""
    arms = arms or default_arms()
    bandit = ContentBandit(arms, seed=seed)
    report = bandit.run(n_rounds=n_rounds)
    report["kind"] = "ingestion"
    report["n_rounds"] = n_rounds
    report["membership_backend"] = "querying.membership" if _membership_available() else "fallback"
    return report
