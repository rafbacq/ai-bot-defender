"""AI Bot Defender — Direction 2: co-evolving crawler ⇄ honeypot self-play (RL).

An *additive* research layer that turns the existing crawler-graph detector
(``crawler_graph/``, surfaced on ``/logs``) into the reward channel of an
adversarial game. A learned crawler agent tries to harvest honeypot content while
evading detection; the evasions it discovers are replayed to **harden** the
detector, and the infrastructure cost it must pay to defeat each fingerprint layer
becomes a measurable *cost-to-evade* curve.

Design invariants (do not break):

* ``selfplay/`` only **reads** ``crawler_graph`` / ``querying`` / ``auto_query`` —
  it never edits the runtime layers (``website/``, ``proxy/``, ``ansible/``).
* The reward oracle is the *production* detector: ``crawler_graph.pipeline.run_intel``
  called on synthetic traffic (``resolve_asn=False, write=False``), so an evasion
  found here is a real adversarial example against the live pipeline.
* Everything writes only under ``selfplay/output/`` (see ``config.OUTPUT_DIR``);
  it never touches ``crawler_graph/output/`` (the live detector's artifacts).
* Heavy deps (torch) are imported lazily inside functions, exactly like
  ``crawler_graph.ml.gnn``, so importing the package never requires them.

Entry points: ``python -m selfplay {calibrate,train,evaluate,coevolve,selftest}``.
"""

__version__ = "0.1.0"
