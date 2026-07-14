"""Offline end-to-end self-test for the crawler graph (no DB, no API keys).

Synthesizes traffic across populations that exercise every fingerprint layer:
  * an honest declared crawler (GPTBot/ClaudeBot) from one ASN across many IPs,
  * ordinary human browsers (varied UAs, UNIQUE device fingerprints, consistent
    across all layers — they must NOT be flagged),
  * a DISGUISED stealth fleet — browser UAs across many ASNs sharing ONE JA4 AND
    whose TCP/IP stack (Linux) contradicts the claimed Windows UA/platform,
  * an AGENTIC-browser population (shared JA4, casual volume, self-consistent),
  * a PROXY-ROTATOR — one physical machine (ONE canvas hash + fp_id) hopping
    across several ASNs (Layer-1 device-graph stitching), and
  * a VM/headless cohort (WebGL renderer = SwiftShader).

Then it runs the pipeline and asserts: honest crawler attributed & unflagged;
stealth fleet -> disguise + cross-layer contradiction; agentic -> agentic;
proxy-rotator stitched into ONE campaign via its device fingerprint; VM cohort
flagged. Run: ``python -m crawler_graph selftest``.
"""

import random
from datetime import datetime, timedelta, timezone


def _synth_visits(seed=7):
    rng = random.Random(seed)
    base = datetime(2026, 6, 1, tzinfo=timezone.utc)
    visits = []
    handshakes = []
    browser_fps = []
    tcp_fps = []
    port = [20000]
    fp_seen = set()

    def add(ip, ua, ja4, n, asn, site="site-001", tcp_os=None, canvas=None,
            webgl=None, fp_id=None, webgl_renderer=None, font=None, platform=None,
            automation_score=0, behavior_synthetic=False):
        for _ in range(n):
            port[0] += 1
            ts = base + timedelta(seconds=rng.randint(0, 86400))
            visits.append({
                "id": len(visits) + 1,
                "ts": ts.isoformat(),
                "site": site,
                "client_ip": ip,
                "client_port": port[0],
                "user_agent": ua,
                "method": "GET",
                "uri": rng.choice(["/", "/about", "/history", "/contact"]),
                # pre-attached asn so the test doesn't need network RDAP lookups
                "asn": asn,
            })
            if ja4:
                handshakes.append({
                    "ts": ts.isoformat(), "src_ip": ip, "src_port": port[0],
                    "ja3": None, "ja4": ja4, "sni": f"{site}.dukecodeplus.example",
                })
            if tcp_os:  # Layer-2 TCP/IP SYN fingerprint, joined by 4-tuple
                tcp_fps.append({
                    "ts": ts.isoformat(), "src_ip": ip, "src_port": port[0],
                    "ttl": None, "win_size": None, "win_scale": None, "mss": None,
                    "os_guess": tcp_os, "ja4t": "synthetic",
                })
        # One Layer-1 browser fingerprint per IP (the JS beacon), if applicable.
        if (canvas or webgl or fp_id or webgl_renderer or font) and ip not in fp_seen:
            fp_seen.add(ip)
            browser_fps.append({
                "ts": (base + timedelta(seconds=rng.randint(0, 86400))).isoformat(),
                "site": site, "client_ip": ip, "client_port": port[0] + 1,
                "user_agent": ua, "phase": "load", "fp_id": fp_id,
                "canvas_hash": canvas, "webgl_hash": webgl, "webgl_vendor": None,
                "webgl_renderer": webgl_renderer, "audio_hash": None, "font_hash": font,
                "navigator": {"platform": platform} if platform else {},
                "automation": {"score": automation_score} if automation_score else {},
                "behavior": {"synthetic": behavior_synthetic,
                             "interacted": not behavior_synthetic},
            })

    # 1) Honest GPTBot: ONE ASN, declared UA, systematic crawl -> attributed, no flag.
    for i in range(8):
        add(f"45.10.5.{i}", "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
            "t13d1516h2_GPTBOTSTACK_aaa", rng.randint(20, 60), asn="20473", tcp_os="Linux")

    # 1b) Honest ClaudeBot: a second declared provider (gives the GNN >=2 classes).
    for i in range(6):
        add(f"160.79.10.{i}", "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
            "t13d1516h2_CLAUDESTACK_bbb", rng.randint(15, 40), asn="399358", tcp_os="Linux")

    # 2) Human browsers: varied UAs, UNIQUE device fingerprints, fully consistent
    #    across UA/JS/TCP layers, scattered ASNs, low volume -> never flagged.
    humans = [
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0 Safari/537.36", "Windows", "Win32"),
        ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15", "Apple", "MacIntel"),
        ("Mozilla/5.0 (X11; Linux x86_64) Firefox/127.0", "Linux", "Linux x86_64"),
    ]
    for i in range(15):
        ua, tcp_os, platform = humans[i % 3]
        add(f"73.55.{rng.randint(1, 250)}.{rng.randint(1, 250)}", ua, f"t13d_unique_{i}",
            rng.randint(1, 4), asn=f"70{rng.randint(10, 99)}", tcp_os=tcp_os,
            canvas=f"canvas_human_{i}", fp_id=f"fp_human_{i}", platform=platform)

    # 3) DISGUISED stealth fleet: Windows browser UA + Win32 platform, MANY ASNs,
    #    ONE shared JA4, SYSTEMATIC volume -> disguise; AND the SYN says Linux, so
    #    the claimed OS contradicts the kernel (cross-layer contradiction).
    stealth_ja4 = "t13d1517h2_STEALTHSTACK_zzz"
    for i in range(12):
        add(f"104.{rng.randint(20, 60)}.{rng.randint(1, 250)}.{rng.randint(1, 250)}",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0 Safari/537.36",
            stealth_ja4, rng.randint(12, 30), asn=f"AS-PROXY-{i % 5}", tcp_os="Linux",
            canvas=f"canvas_stealth_{i}", fp_id=f"fp_stealth_{i}", platform="Win32")

    # 4) AGENTIC browser population: browser UA, ONE shared JA4, many ASNs, CASUAL
    #    volume, fully self-consistent (Apple UA + MacIntel + Apple SYN, unique
    #    device fp) -> agentic_suspected, NOT disguise.
    agentic_ja4 = "t13d1518h2_AGENTBROWSER_yyy"
    for i in range(10):
        add(f"98.{rng.randint(20, 90)}.{rng.randint(1, 250)}.{rng.randint(1, 250)}",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605 Chrome/124.0 Safari/537.36",
            agentic_ja4, rng.randint(1, 3), asn=f"AS-RES-{10 + i}", tcp_os="Apple",
            canvas=f"canvas_agentic_{i}", fp_id=f"fp_agentic_{i}", platform="MacIntel")

    # 5) PROXY-ROTATOR: ONE physical machine (same canvas hash + fp_id) hopping
    #    across 4 different ASNs. The ONLY thing tying the IPs together is the
    #    Layer-1 device fingerprint -> they must stitch into a SINGLE campaign.
    rotator_ips = [f"5.5.{i}.{i}" for i in range(4)]
    for i, ip in enumerate(rotator_ips):
        add(ip, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/127.7 Safari/537.36",
            None, rng.randint(2, 5), asn=f"AS-VPN-{i}", tcp_os="Windows",
            canvas="canvas_SHARED_DEVICE", fp_id="fp_SHARED_DEVICE", platform="Win32")

    # 6) VM / headless cohort: SwiftShader WebGL renderer, shared font set (so they
    #    cluster), same ASN, unique canvas -> vm_cohort_suspected.
    vm_ips = [f"6.6.6.{i}" for i in range(3)]
    for i, ip in enumerate(vm_ips):
        add(ip, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HeadlessChrome/123.0 Safari/537.36",
            None, rng.randint(3, 7), asn="AS-CLOUD-1", tcp_os="Linux",
            canvas=f"canvas_vm_{i}", fp_id=f"fp_vm_{i}", font="font_VM_SHARED",
            webgl_renderer="Google SwiftShader", platform="Win32", automation_score=2)

    return visits, handshakes, browser_fps, tcp_fps, {"rotator": rotator_ips, "vm": vm_ips}


def run(gnn=False):
    from .. import pipeline

    visits, handshakes, browser_fps, tcp_fps, markers = _synth_visits()
    result = pipeline.run_intel(
        visits=visits, handshakes=handshakes, browser_fps=browser_fps, tcp_fps=tcp_fps,
        resolve_asn=False, use_gnn=False, write=False, render=False,
    )

    meta = result["meta"]
    findings = result["findings"]
    camps = result["campaigns"]

    print(f"visits={meta['n_visits']} handshakes={meta['n_handshakes']} "
          f"browser_fps={meta['n_browser_fps']} tcp_fps={meta['n_tcp_fps']} "
          f"endpoints={meta['n_endpoints']} method={meta['community_method']} "
          f"modularity={meta['modularity']}")
    print(f"campaigns={findings['n_campaigns']} disguised={findings['n_disguised']} "
          f"agentic={findings['n_agentic']} vm_cohort={findings['n_vm_cohort']} "
          f"contradiction={findings['n_contradiction']}")
    print(f"inconsistent_endpoints={meta['n_inconsistent_endpoints']} "
          f"vm_cohort_endpoints={meta['n_vm_cohort_endpoints']} "
          f"browser_fps_present={meta['browser_fingerprints_present']} "
          f"tcp_present={meta['tcp_fingerprints_present']}")
    for c in camps:
        print(f"  [{c['campaign_id']}] {c['label']!r} ips={c['n_ips']} "
              f"reqs={c['n_requests']} req/ip={c['mean_req_per_ip']} asns={c['n_asns']} "
              f"ja4={len(c['ja4'])} dev_fp_ips={c['browser_fingerprinted_ips']} "
              f"disguise={c['disguise_suspected']} agentic={c['agentic_suspected']} "
              f"vm={c['vm_cohort_suspected']} contradiction={c['contradiction_suspected']} "
              f"stitched={c['shared_device_fingerprint']}")

    # --- Assertions: existing campaign behavior -----------------------------
    assert findings["n_campaigns"] >= 3, "expected several campaigns"
    assert any("OpenAI" in c["label"] for c in camps), "honest GPTBot not attributed"
    assert any("Anthropic" in c["label"] for c in camps), "honest ClaudeBot not attributed"
    openai = next(c for c in camps if "OpenAI" in c["label"])
    assert not openai["disguise_suspected"] and not openai["agentic_suspected"], \
        "honest declared crawler should not be flagged"
    assert not openai["contradiction_suspected"], "honest crawler wrongly flagged inconsistent"

    disguised = [c for c in camps if c["disguise_suspected"]]
    assert disguised, "disguised stealth fleet was NOT flagged"
    stealth = max(disguised, key=lambda c: c["n_ips"])
    assert stealth["n_asns"] >= 2, "stealth fleet should span multiple ASNs"
    assert stealth["shared_fingerprint"] and stealth["systematic"], \
        "stealth fleet should share a fingerprint at crawl volume"

    agentic = [c for c in camps if c["agentic_suspected"]]
    assert agentic, "agentic-browser population was NOT flagged"
    assert not any(a["systematic"] for a in agentic), \
        "agentic cohorts should be casual-volume, not systematic"

    # --- Assertions: NEW fingerprint layers ---------------------------------
    assert meta["browser_fingerprints_present"], "browser fingerprints not joined"
    assert meta["tcp_fingerprints_present"], "TCP fingerprints not joined"

    # Cross-layer contradiction: the stealth fleet's Windows UA vs Linux SYN.
    assert findings["n_contradiction"] >= 1, "no cross-layer contradiction detected"
    assert stealth["contradiction_suspected"], \
        "stealth fleet's claimed-OS vs TCP-OS contradiction was missed"

    # Device-graph stitching: the proxy-rotator's 4 IPs (one shared canvas/fp_id
    # across 4 ASNs) must collapse into a SINGLE campaign flagged shared-device.
    rotator = set(markers["rotator"])
    stitched = [c for c in camps if rotator & set(c["sample_ips"])]
    assert len(stitched) == 1, \
        f"proxy-rotator split across {len(stitched)} campaigns (device stitching failed)"
    rot = stitched[0]
    assert rotator <= set(rot["sample_ips"]), "not all rotator IPs landed in one campaign"
    assert rot["shared_device_fingerprint"], "shared device fingerprint not flagged"
    assert rot["n_asns"] >= 2 and rot["disguise_suspected"], \
        "proxy-rotator across ASNs should read as disguise via device stitching"

    # VM/headless cohort flagged.
    assert findings["n_vm_cohort"] >= 1, "VM/software-renderer cohort not flagged"

    print("\nSELFTEST PASSED ✓  (GPTBot attributed & unflagged; stealth fleet -> "
          "disguise+contradiction; agentic -> agentic; proxy-rotator stitched by "
          "device fingerprint; VM cohort flagged)")

    if gnn:
        _run_gnn_check()
    return 0


def _gnn_scenario(seed=11):
    """Synthesize a graph that exercises the GNN's *purpose*: attributing a
    provider to disguised, UA-less nodes via graph structure.

    Two declared providers (labeled) plus two **covert** cohorts that wear a
    browser UA (unlabeled) but share each declared provider's ASN — so the only
    thing tying them to a provider is the graph. A correct GNN propagates the
    provider label across that structure. Returns (visits, handshakes, covert
    IP sets).
    """
    rng = random.Random(seed)
    base = datetime(2026, 6, 1, tzinfo=timezone.utc)
    visits, handshakes, port = [], [], [40000]
    # Distinct browser UAs per cohort: a *shared* exact UA is itself a strong
    # linking signal, so giving every cohort the same one would merge them into
    # one hub. Here the intended provider signal is the shared ASN.
    BROWSER_A = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0 Safari/537.36"
    BROWSER_B = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/124.0 Safari/537.36"

    def add(ip, ua, ja4, n, asn):
        for _ in range(n):
            port[0] += 1
            ts = base + timedelta(seconds=rng.randint(0, 86400))
            visits.append({"id": len(visits) + 1, "ts": ts.isoformat(), "site": "site-001",
                           "client_ip": ip, "client_port": port[0], "user_agent": ua,
                           "method": "GET", "uri": rng.choice(["/", "/a", "/b", "/c"]), "asn": asn})
            if ja4:
                handshakes.append({"ts": ts.isoformat(), "src_ip": ip, "src_port": port[0],
                                   "ja3": None, "ja4": ja4, "sni": "s"})

    for i in range(8):  # labeled OpenAI (GPTBot), ASN 20473
        add(f"45.10.5.{i}", "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
            "OAI_STACK", rng.randint(20, 50), "20473")
    covert_oai = [f"45.10.9.{i}" for i in range(6)]
    for ip in covert_oai:  # covert OpenAI: browser UA, SAME ASN 20473
        add(ip, BROWSER_A, "COVERT_OAI", rng.randint(10, 30), "20473")

    for i in range(6):  # labeled Anthropic (ClaudeBot), ASN 399358
        add(f"160.79.10.{i}", "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
            "ANT_STACK", rng.randint(20, 50), "399358")
    covert_ant = [f"160.79.20.{i}" for i in range(5)]
    for ip in covert_ant:  # covert Anthropic: browser UA, SAME ASN 399358
        add(ip, BROWSER_B, "COVERT_ANT", rng.randint(10, 30), "399358")

    for i in range(8):  # unrelated noise browsers (unique UA + ASN + fingerprint)
        add(f"73.55.{rng.randint(1, 250)}.{i}",
            f"Mozilla/5.0 (X11; Linux x86_64) Firefox/12{i}.0", f"uniq{i}",
            rng.randint(2, 5), f"70{i}")

    return visits, handshakes, {"oai": covert_oai, "ant": covert_ant}


def _run_gnn_check():
    """Train + verify the GraphSAGE classifier: generalization (val), disguise
    attribution via structure, and a save/load round-trip."""
    from collections import Counter

    from ..analysis import consistency
    from ..ingest import enrich
    from ..graphing import builder as graph
    from ..ml import features, gnn as gnn_mod

    print("\n[gnn] GraphSAGE attribution check")
    if not gnn_mod.torch_available():
        print("[gnn] torch / torch_geometric not installed — skipping "
              "(install crawler_graph/requirements-gnn.txt to enable)")
        return

    visits, handshakes, covert = _gnn_scenario()
    enrich.join_fingerprints(visits, handshakes)
    enrich.enrich_visits(visits, resolve_asn=False)
    endpoints = enrich.aggregate_endpoints(visits)
    # Fold in the (empty) browser layer + consistency so the GNN feature vector
    # includes the new fingerprint/consistency columns, matching the live path.
    enrich.attach_browser_fingerprints(endpoints, [])
    consistency.annotate(endpoints)
    ip_graph = graph.project_to_ip_graph(graph.build_graph(endpoints))
    arrays = features.build_arrays(ip_graph, endpoints)

    print(f"[gnn] nodes={len(arrays['nodes'])} classes={arrays['labels']} "
          f"labeled={sum(arrays['train_mask'])}")
    res = gnn_mod.train_classifier(arrays, epochs=250)
    assert res.get("predictions"), f"GNN produced no predictions: {res.get('reason')}"
    preds = res["predictions"]
    print(f"[gnn] final_loss={res.get('final_loss')} train_acc={res.get('train_acc')} "
          f"val_acc={res.get('val_acc')} (held-out labeled={res.get('n_val')})")

    # 1) Generalization: held-out labeled nodes are classified correctly.
    if res.get("val_acc") is not None:
        assert res["val_acc"] >= 0.5, f"poor generalization (val_acc={res['val_acc']})"

    # 2) Purpose: covert cohorts (browser UA, no declared provider) are attributed
    #    to the right provider purely via shared-ASN graph structure.
    def majority(ips):
        votes = Counter(preds[ip]["provider"] for ip in ips if ip in preds)
        return votes.most_common(1)[0][0] if votes else None

    oai_pred, ant_pred = majority(covert["oai"]), majority(covert["ant"])
    print(f"[gnn] covert OpenAI cohort -> {oai_pred} ; covert Anthropic cohort -> {ant_pred}")
    assert oai_pred == "OpenAI", f"covert OpenAI cohort misattributed ({oai_pred})"
    assert ant_pred == "Anthropic", f"covert Anthropic cohort misattributed ({ant_pred})"

    # 3) The trained model persists and reloads with identical predictions.
    path = gnn_mod.save_model(res)
    reloaded = gnn_mod.load_and_predict(arrays, path)
    mism = sum(1 for ip in arrays["nodes"] if reloaded[ip]["provider"] != preds[ip]["provider"])
    assert mism == 0, f"reloaded model disagrees on {mism} nodes"
    print(f"[gnn] model saved -> {path}; reload round-trips ({len(reloaded)} nodes, 0 mismatch)")
    print("[gnn] GNN PASSED ✓  (generalizes, attributes disguised cohorts via structure, persists)")


if __name__ == "__main__":
    raise SystemExit(run())
