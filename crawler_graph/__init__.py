"""Crawler-infrastructure graph intelligence (AI Bot Defender — Direction 6a).

Reads the reverse proxy's central request log (``all_visits``) and the passively
captured TLS fingerprints (``tls_handshakes``, written by the Zeek capture
sidecar), builds an identity graph over (client IP, ASN, /24, User-Agent, JA3/JA4)
and clusters it into *campaigns* — coherent pieces of crawler infrastructure —
with Louvain community detection and an optional GraphSAGE GNN.

The point of the fingerprint layer is to attribute and, crucially, to catch
crawlers that **disguise** themselves (undeclared provider infrastructure on
browser-like User-Agents, or agentic browsers) — the cases where the User-Agent
alone is worthless. Honest, self-declaring crawlers (GPTBot, ClaudeBot, …) are
attributed from their User-Agent + published IP ranges without needing any of
the fingerprint machinery.

Run it::

    python -m crawler_graph build          # load -> graph -> communities -> report
    python -m crawler_graph gnn-train       # train the GraphSAGE model (needs torch/PyG)
    python -m crawler_graph selftest        # offline synthetic end-to-end check

Authorized research use only — operate on your own honeypot traffic.
"""

__all__ = ["pipeline", "config"]
