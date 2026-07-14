# `crawler_graph/` — crawler-infrastructure graph intelligence (Direction 6a)

Clusters the reverse proxy's cross-site request log into **campaigns** — coherent
pieces of crawler infrastructure — and flags the ones that **disguise** themselves.

Honest, self-declaring crawlers (GPTBot, ClaudeBot, …) are attributed from their
User-Agent + published IP ranges, no fingerprinting required. The fingerprint
layer exists for the cases where the UA is worthless: **undeclared provider
infrastructure** (browser-like UAs on rotating residential ASNs) and **agentic
browsers** (real Chrome engines, no bot UA).

## Pipeline

```
all_visits (+ client_port, headers)   tls_handshakes (JA3/JA4)   tcp_fingerprints (SYN: TTL/window -> OS)   browser_fingerprints (fp.js: canvas/WebGL/audio/font/automation/behavior)
        \                                  |                            |                                          /
         join TLS + TCP by (client_ip, client_port, ts)  <- enrich.join_fingerprints / join_tcp_fingerprints
                         |
        enrich: ASN · /24 · UA flags · JA4H (header sig)  <- enrich.enrich_visits (+ compute_ja4h)
                         |
        aggregate to one record per client IP            <- enrich.aggregate_endpoints
                         |
        attach browser fingerprints (by client_ip)       <- enrich.attach_browser_fingerprints
                         |
        cross-layer consistency: contradictions/VM/auto  <- analysis/consistency.annotate
                         |
        identity graph: IP nodes linked through shared    <- graphing/builder.build_graph
        attribute hubs (fpid/canvas/webgl/audio > JA4 > UA/ja4h > /24 > ASN)
                         |
   community detection (Louvain / Leiden / greedy)        <- graphing/community.detect_communities
                         |
   (optional) GraphSAGE provider attribution             <- ml/gnn.train_classifier
                         |
   campaigns + disguise/agentic/VM-cohort/contradiction   <- graphing/campaigns.build_campaigns
                         |
   output/campaigns.json (+ campaigns.png)                <- reporting.write_campaigns
```

### Device-fingerprint, TCP/OS, HTTP-header and consistency layers

Beyond the TLS layer, three more fingerprint surfaces feed the same graph:

* **Layer 1 — browser device fingerprints.** Honeypot pages embed `website/static/js/fp.js`,
  which collects canvas/WebGL/WebGPU/audio/font hashes, screen/navigator/UA-CH, automation
  tells and behavioral biometrics, and POSTs them to `/__fpbeacon` → the proxy stack's
  `fp-collector` → `logdb.browser_fingerprints`. The canvas/WebGL/audio/font hashes and the
  composite `fp_id` become the **strongest attribute hubs** (a shared device key stitches one
  physical machine across IP changes and proxy rotation — the doc's cross-session stitching).
* **Layer 2 — TCP/IP OS inference (JA4T-ish).** The Zeek sidecar also logs each client SYN
  (`proxy/tls-capture/scripts/tcp-fingerprint.zeek`); the shipper computes a p0f-style OS guess
  (initial-TTL + window/scale) into `logdb.tcp_fingerprints`, joined by the 4-tuple. *Host
  caveat:* the captured SYN is the real client's only when the proxy receives connections
  directly / via source-preserving DNAT — behind a userland docker-proxy it may be the
  forwarder's (same caveat as the TLS-IP match). The OS-inference logic itself is covered by the
  offline selftest. Because of this, the consistency engine **does not let the SYN-derived OS
  drive a spoof verdict when the client address is local/NAT** (loopback, RFC1918, link-local) —
  otherwise the local build, which NATs every visitor through the Docker userland proxy, reads
  each client's kernel as the proxy's (typically `Linux`) and falsely flags the operator's own
  Windows/macOS browser as an OS spoof. Real crawlers arrive from routable public IPs, where the
  TCP layer stays trustworthy. Set `INTEL_TRUST_PRIVATE_TCP=1` to re-enable trust for a genuine
  same-LAN / source-preserving-DNAT deployment.
* **HTTP header signature (JA4H).** Computed from the already-stored `all_visits.headers`
  (no new capture) — a header-set/ordering signature that separates browsers from automation
  libraries.
* **Cross-layer consistency (`analysis/consistency.py`).** The doc's core thesis — hunt
  *internal contradiction*. Per endpoint it cross-checks claimed UA/JS OS vs. the TCP/IP
  kernel, the WebGL renderer (VM/software cohort), and automation/behavioral tells, emitting a
  weighted contradiction score that boosts disguise detection and surfaces on `/intel` +
  `/fingerprints`.

## Package layout

```
crawler_graph/
  config.py          tunables, logdb access details, artifact paths
  pipeline.py        run_intel() — the orchestrator (CLI + app entry)
  cli.py             argparse CLI;  __main__.py delegates here
  reporting.py       persist campaigns.json + render the network PNG
  ingest/            db.py · enrich.py · known_crawlers.py   (logdb -> enriched endpoints;
                       fetch_browser_fingerprints / fetch_tcp_fingerprints + JA4H + joins)
  analysis/          consistency.py                          (cross-layer contradiction scoring)
  graphing/          builder.py · community.py · campaigns.py (graph -> communities -> campaigns)
  ml/                features.py · gnn.py                     (feature matrix + GraphSAGE)
  tests/             test_pipeline.py                         (offline synthetic self-test)
  output/            machine-local artifacts (git-ignored)
```

## The fingerprint capture path (passive, no nginx rebuild)

TLS fingerprints come from a **Zeek sidecar that shares nginx's network
namespace** (`proxy/tls-capture/`), so it sees the raw ClientHello *before* nginx
terminates TLS — a true JA3/JA4 without modifying the load-bearing proxy. Zeek
writes JSON `ssl.log`; `proxy/tls-shipper/` streams it into `logdb.tls_handshakes`.
nginx forwards the client source port (`X-Client-Port` → `all_visits.client_port`)
so each handshake joins to the HTTP requests its connection carried, by 4-tuple.

Two things to verify once on a new host (see `proxy/tls-capture/scripts/entrypoint.sh`):
1. the IP Zeek records (`id.orig_h`) matches nginx's `$remote_addr` — true on
   Docker bridge with iptables DNAT, not always with the userland docker-proxy; and
2. the capture interface carries `:443` (auto-detected; override with `CAPTURE_IFACE`).

Without the capture sidecar the campaign analysis still works on UA/ASN/timing —
you just lose spoof-resistant disguise detection.

## Run it

```bash
# Offline synthetic end-to-end check (no DB, no keys); add --gnn to also train it:
python -m crawler_graph selftest [--gnn]

# Build campaigns from the live logdb -> output/campaigns.json (+ campaigns.png):
python -m crawler_graph build [--since-hours 168] [--gnn]

# Train the GraphSAGE attribution model (needs the GNN extra):
python -m crawler_graph gnn-train

# From the repo via the app container (has the deps + Docker access):
make intel            # build
make intel-selftest   # selftest
```

The web app's **/intel** page reads `output/campaigns.json` and offers a
"Recompute" button. Tick **GraphSAGE GNN** there to train + apply the attribution
model *in the app* (torch_geometric is in the app image) — no terminal needed.
The CLI (`make`/`python` above) does the same headlessly.

## Dependencies

* Core (`requirements.txt`, baked into the app image): `networkx`,
  `python-louvain` (imported as `community`), `ipwhois`, `matplotlib`.
  `leidenalg`+`python-igraph` are used for Leiden if present.
* GNN: `torch` + `torch_geometric` — **baked into the app image** (torch ships
  for the template generator; `torch_geometric` is added in a late Docker layer),
  so the GNN runs from `/intel` and `make intel INTEL_ARGS=--gnn` with no extra
  setup. CPU is fine. `requirements-gnn.txt` (adds `scikit-learn` for the optional
  KMeans-over-embeddings path) is only for running the package outside that image.

## How disguise vs. agentic is decided (campaigns.py)

* **disguise** — a published-range violation (declared crawler UA from outside
  that provider's CIDRs), **or** one TLS fingerprint shared across multiple ASNs
  at crawl volume on browser/automation UAs with no declared bot UA, **or** the
  GNN attributing a no-declared-UA cohort to a provider.
* **agentic** — a coherent shared browser fingerprint on browser UAs at *casual*
  volume (not a systematic crawl); disguise takes precedence.
* Honest declared crawlers get neither flag.

## Optional: published IP ranges

Drop a merged `crawler_graph/crawler_ranges.json` of `{provider: [CIDR, ...]}`
(from providers' published crawler-IP files) to enable IP-range verification.
It is intentionally not vendored because the ranges change.

> Authorized research use only — operate on your own honeypot traffic.
