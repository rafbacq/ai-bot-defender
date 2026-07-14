"""Membership inference for training-data provenance (AI Bot Defender — 6b).

Detects whether a piece of content was in a model's training data **without
needing the model to regurgitate it**, using the per-token log-probability
signal (Min-K% / Min-K%++) and a controlled null: watermark documents you served
vs. a matched set you generated but never served. If the served set scores as
"member" and the control set does not — with a significant gap — that is
calibrated evidence of ingestion, not a coincidence.

References: Shi et al. "Detecting Pretraining Data from LLMs" (Min-K% Prob, 2023);
Zhang et al. "Min-K%++" (2024); Maini et al. "LLM Dataset Inference" (2024).

Backends (chosen by ``QUERY_MEMBERSHIP_BACKEND``):
  * ``mock``  — deterministic offline simulator (a constructed "memorized" set
    scores high). Lets the whole statistic + hypothesis test run with no model.
  * ``hf``    — a local HuggingFace causal LM (full logits -> true Min-K%++).
  * ``openai``— an OpenAI-compatible Completions endpoint with logprobs+echo
    (chosen-token logprobs -> Min-K%; Min-K%++ needs full distributions, so it
    falls back to Min-K% here).

Only the statistics + test are required to import this module; torch/transformers
are imported lazily inside the HF backend.
"""

import math
import random
import string

from . import config

# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


def min_k_percent(token_logprobs, k=0.2):
    """Min-K% Prob: mean of the lowest-k% token log-probs (higher => more member-like)."""
    lps = [lp for lp in token_logprobs if lp is not None]
    if not lps:
        return None
    n = max(1, int(len(lps) * k))
    lowest = sorted(lps)[:n]
    return sum(lowest) / len(lowest)


def min_k_percent_pp(token_logprobs, token_mu, token_sigma, k=0.2):
    """Min-K%++: z-normalize each token log-prob by the position's vocab mean/std,
    then average the lowest k%. Needs full next-token distributions (HF backend)."""
    z = []
    for lp, mu, sigma in zip(token_logprobs, token_mu, token_sigma):
        if lp is None or mu is None or not sigma:
            continue
        z.append((lp - mu) / sigma)
    if not z:
        return None
    n = max(1, int(len(z) * k))
    lowest = sorted(z)[:n]
    return sum(lowest) / len(lowest)


def score_from_stats(stats, k=0.2):
    """Pick the strongest available statistic for one text's per-token stats."""
    lps = stats.get("logprobs") or []
    mu = stats.get("mu")
    sigma = stats.get("sigma")
    if mu and sigma:
        val = min_k_percent_pp(lps, mu, sigma, k=k)
        if val is not None:
            return val, "min_k++"
    val = min_k_percent(lps, k=k)
    return val, "min_k"


def _auc(served, control):
    """AUC of served-vs-control (= P(served > control)); 0.5 = no separation."""
    if not served or not control:
        return None
    wins = ties = 0
    for s in served:
        for c in control:
            if s > c:
                wins += 1
            elif s == c:
                ties += 1
    return (wins + 0.5 * ties) / (len(served) * len(control))


def mann_whitney_p(served, control):
    """One-sided p-value that served > control (H1). scipy if present, else normal approx."""
    if not served or not control:
        return None
    try:
        from scipy.stats import mannwhitneyu

        return float(mannwhitneyu(served, control, alternative="greater").pvalue)
    except Exception:
        pass
    # Normal approximation with tie/continuity handling.
    n1, n2 = len(served), len(control)
    auc = _auc(served, control)
    u = auc * n1 * n2
    mu = n1 * n2 / 2.0
    sigma = math.sqrt(n1 * n2 * (n1 + n2 + 1) / 12.0)
    if sigma == 0:
        return 1.0
    z = (u - mu - 0.5) / sigma
    return 0.5 * math.erfc(z / math.sqrt(2))  # one-sided upper tail


def membership_test(served_scores, control_scores):
    """Return the hypothesis-test result for served-vs-control membership scores."""
    served = [s for s in served_scores if s is not None]
    control = [c for c in control_scores if c is not None]
    auc = _auc(served, control)
    p = mann_whitney_p(served, control)
    return {
        "n_served": len(served),
        "n_control": len(control),
        "served_mean": round(sum(served) / len(served), 4) if served else None,
        "control_mean": round(sum(control) / len(control), 4) if control else None,
        "auc": round(auc, 4) if auc is not None else None,
        "p_value": p,
        "is_member": bool(p is not None and p < config.MEMBERSHIP_ALPHA and (auc or 0) > 0.5),
        "alpha": config.MEMBERSHIP_ALPHA,
    }


# ---------------------------------------------------------------------------
# Watermark / control document generation
# ---------------------------------------------------------------------------
_ADJ = ["municipal", "regional", "provincial", "historical", "agricultural", "coastal"]
_ROLE = ["postmaster", "archivist", "surveyor", "magistrate", "almoner", "cartwright"]


def generate_watermarks(n=24, seed=None):
    """Return ``{"served": [...], "control": [...]}`` watermark documents.

    Served docs are meant to be embedded in honeypot pages; control docs are
    generated the same way but never served — the statistical null. Each carries
    a unique high-entropy nonce so it cannot occur naturally on the web.
    """
    rng = random.Random(seed)

    def make(tag):
        nonce = "".join(rng.choices(string.ascii_uppercase + string.digits, k=12))
        adj = rng.choice(_ADJ)
        role = rng.choice(_ROLE)
        year = rng.randint(1850, 1979)
        return (f"In the {adj} register {tag}-{nonce}, the {role} recorded that the "
                f"settlement was chartered in {year} under ordinance {nonce[:6]}.")

    return {
        "served": [make("WM") for _ in range(n)],
        "control": [make("CT") for _ in range(n)],
    }


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------
class MockScorer:
    """Deterministic offline scorer simulating a model that memorized ``memorized``.

    Texts in the memorized set get high (less-negative) token log-probs; others
    get low ones — so served watermarks separate from controls and the whole
    statistic + test plumbing is verifiable with no model or network.
    """

    def __init__(self, memorized=None, seed=0):
        self.memorized = set(memorized or [])
        self.seed = seed

    def token_stats(self, text):
        rng = random.Random(f"{self.seed}|{text}")
        member = text in self.memorized
        n_tok = max(8, len(text.split()))
        center = -0.6 if member else -4.0
        logprobs = [center + rng.gauss(0, 0.4) for _ in range(n_tok)]
        mu = [-6.0 for _ in range(n_tok)]       # simulated vocab mean log-prob
        sigma = [2.0 for _ in range(n_tok)]
        return {"logprobs": logprobs, "mu": mu, "sigma": sigma}


class LocalHFScorer:
    """Score with a local HuggingFace causal LM (true Min-K%++ from full logits)."""

    def __init__(self, model_name=None, device=None):
        self.model_name = model_name or config.MEMBERSHIP_MODEL
        self.device = device
        self._model = None
        self._tok = None

    def _ensure(self):
        if self._model is not None:
            return
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self._tok = AutoTokenizer.from_pretrained(self.model_name)
        self._model = AutoModelForCausalLM.from_pretrained(self.model_name)
        if self.device is None:
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self._model.to(self.device).eval()

    def token_stats(self, text):
        import torch

        self._ensure()
        ids = self._tok(text, return_tensors="pt").input_ids.to(self.device)
        if ids.size(1) < 2:
            return {"logprobs": [], "mu": [], "sigma": []}
        with torch.no_grad():
            logits = self._model(ids).logits  # [1, seq, vocab]
        logprobs, mu, sigma = [], [], []
        logsm = torch.log_softmax(logits[0], dim=-1)        # [seq, vocab]
        for i in range(1, ids.size(1)):
            dist = logsm[i - 1]
            target = ids[0, i]
            logprobs.append(float(dist[target]))
            mu.append(float(dist.mean()))
            sigma.append(float(dist.std()) or 1.0)
        return {"logprobs": logprobs, "mu": mu, "sigma": sigma}


class OpenAILogprobScorer:
    """Score via an OpenAI-compatible Completions endpoint (logprobs + echo).

    Yields chosen-token log-probs -> Min-K% (full distributions aren't returned,
    so Min-K%++ degrades to Min-K%). Requires a Completions-style endpoint that
    honors ``echo`` + ``logprobs``; many chat-only endpoints do not.
    """

    def __init__(self, model=None):
        self.model = model or config.MEMBERSHIP_MODEL

    def token_stats(self, text):
        import httpx

        if not config.OPENAI_API_KEY:
            raise RuntimeError("OPENAI_API_KEY is not set for the openai membership backend.")
        resp = httpx.post(
            f"{config.OPENAI_API_BASE}/completions",
            headers={"Authorization": f"Bearer {config.OPENAI_API_KEY}"},
            json={"model": self.model, "prompt": text, "max_tokens": 0,
                  "echo": True, "logprobs": 1, "temperature": 0},
            timeout=60,
        )
        resp.raise_for_status()
        lp = resp.json()["choices"][0]["logprobs"]["token_logprobs"]
        return {"logprobs": [v for v in lp if v is not None], "mu": None, "sigma": None}


def get_scorer(backend=None, **kwargs):
    backend = backend or config.MEMBERSHIP_BACKEND
    if backend == "hf":
        return LocalHFScorer(**kwargs)
    if backend == "openai":
        return OpenAILogprobScorer(**kwargs)
    return MockScorer(**kwargs)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def run_membership(served_texts, control_texts, scorer=None, k=None):
    """Score served vs. control texts and run the membership hypothesis test."""
    scorer = scorer or get_scorer()
    k = k if k is not None else config.MEMBERSHIP_K
    methods = set()

    def score_all(texts):
        out = []
        for text in texts:
            try:
                stats = scorer.token_stats(text)
                val, method = score_from_stats(stats, k=k)
                methods.add(method)
                out.append(val)
            except Exception as exc:  # pragma: no cover - keep going
                print(f"membership: scoring failed: {exc}")
                out.append(None)
        return out

    served_scores = score_all(served_texts)
    control_scores = score_all(control_texts)
    result = membership_test(served_scores, control_scores)
    result["served_scores"] = [round(s, 4) for s in served_scores if s is not None]
    result["control_scores"] = [round(c, 4) for c in control_scores if c is not None]
    result["k"] = k
    # The strongest statistic actually computed: Min-K%++ when full next-token
    # distributions were available (hf backend / mock), else plain Min-K%.
    result["statistic"] = "min_k++" if "min_k++" in methods else "min_k"
    return result
