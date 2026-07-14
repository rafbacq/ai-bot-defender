"""Persist crawler-graph results and (optionally) render a network visualization.

Writes ``output/campaigns.json`` (the artifact the app's /intel page reads) and,
when matplotlib is installed, a spring-layout PNG of the IP graph colored by
campaign. matplotlib is imported lazily so the package works without it.
"""

import json
from datetime import datetime, timezone

from . import config

# Minimum projected IP–IP edge weight for a *cross-cluster* edge to be drawn as a
# bridge. Projected weights are sums of shared-attribute weights (config.EDGE_WEIGHTS:
# a generic shared UA or ASN is ~1–3; a shared JA4/audio/device fingerprint is 5–7).
# Cross-cluster links at/below a single weak attribute are noise the community
# detector already discounted — drawing them is what turns the graph into a
# hairball — so only fingerprint-strength cross links (≥ this) render as bridges.
_BRIDGE_MIN_WEIGHT = 5.0


def write_campaigns(campaigns, meta, path=None):
    """Write the campaigns + run metadata to JSON; return the path."""
    path = path or config.CAMPAIGNS_JSON
    config.ensure_output_dir()
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "meta": meta,
        "findings": _findings_summary(campaigns),
        "campaigns": campaigns,
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, default=str)
    return path


def read_campaigns(path=None):
    """Read the persisted campaigns payload, or ``None`` if absent/invalid."""
    path = path or config.CAMPAIGNS_JSON
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None


def _findings_summary(campaigns):
    return {
        "n_campaigns": len(campaigns),
        "n_disguised": sum(1 for c in campaigns if c.get("disguise_suspected")),
        "n_agentic": sum(1 for c in campaigns if c.get("agentic_suspected")),
        "n_vm_cohort": sum(1 for c in campaigns if c.get("vm_cohort_suspected")),
        "n_contradiction": sum(1 for c in campaigns if c.get("contradiction_suspected")),
        "n_declared": sum(1 for c in campaigns if c.get("declared_providers")),
        "n_browser_fingerprinted": sum(c.get("browser_fingerprinted_ips", 0) for c in campaigns),
    }


def _grouped_layout(graph, membership, seed=42):
    """Community-aware layout that draws each campaign as its own compact, clearly
    separated cluster. Returns ``{node: (x, y)}`` normalized to roughly ``[-1, 1]^2``.

    A single global spring layout is the wrong tool for this graph: the campaigns
    are cross-linked through shared /24 / ASN / UA hubs, so a global layout
    collapses them into one indistinct central blob, while any *disconnected*
    component (an unrelated cohort that shares no attribute) gets flung off to the
    side — the classic spring-layout-on-a-disconnected-graph failure, and exactly
    the awkward picture this replaces. Instead we:

      1. lay out each community's induced subgraph on its own and scale it to a
         radius ``~ sqrt(size)`` (so node density is uniform across clusters, big
         and small alike);
      2. pack the cluster *centres* with a short circle-seeded force relaxation —
         mutual repulsion when two disks would overlap + gentle gravity toward the
         centroid — so the clusters spread into their own regions yet stay a
         compact cloud (never overlapping, never one flung away);
      3. drop each node at its cluster centre + local offset.

    Deterministic (seeded), and fast at this graph's size."""
    import math

    import networkx as nx

    groups = {}
    for node in graph.nodes():
        groups.setdefault(membership.get(node, -1), []).append(node)

    # 1) Local layout + radius per cluster.
    local, radius = {}, {}
    for cid, members in groups.items():
        n = len(members)
        r = 0.6 + 0.9 * math.sqrt(n)
        if n == 1:
            pos = {members[0]: (0.0, 0.0)}
        elif n == 2:
            pos = {members[0]: (-0.5, 0.0), members[1]: (0.5, 0.0)}
        else:
            sub = graph.subgraph(members)
            try:
                pos = nx.spring_layout(sub, seed=seed, k=1.3 / math.sqrt(n), weight="weight")
            except Exception:
                pos = nx.circular_layout(sub)
        cx = sum(p[0] for p in pos.values()) / n
        cy = sum(p[1] for p in pos.values()) / n
        maxd = max((math.hypot(p[0] - cx, p[1] - cy) for p in pos.values()), default=1.0) or 1.0
        local[cid] = {nd: ((p[0] - cx) / maxd * r, (p[1] - cy) / maxd * r) for nd, p in pos.items()}
        radius[cid] = r

    # 2) Pack the cluster centres (largest first), seeded on a circle big enough to
    #    hold every disk, then relaxed so none overlap.
    cids = sorted(groups, key=lambda c: -len(groups[c]))
    m = len(cids)
    # Clear gap between clusters, scaled to the typical cluster size so big and
    # small clusters alike get visible whitespace around them.
    margin = 1.0 + 0.5 * (sum(radius.values()) / m)
    centers = {}
    if m == 1:
        centers[cids[0]] = (0.0, 0.0)
    else:
        circ = sum(2 * radius[c] + margin for c in cids)
        rseed = max(circ / (2 * math.pi), max(radius.values()))
        for i, cid in enumerate(cids):
            ang = 2 * math.pi * i / m
            centers[cid] = (rseed * math.cos(ang), rseed * math.sin(ang))
        for it in range(360):
            grav = 0.009 if it < 300 else 0.0  # last passes are pure de-overlap
            gx = sum(c[0] for c in centers.values()) / m
            gy = sum(c[1] for c in centers.values()) / m
            moved = 0.0
            for i in range(m):
                a = cids[i]
                ax, ay = centers[a]
                ax += (gx - ax) * grav
                ay += (gy - ay) * grav
                for j in range(m):
                    if i == j:
                        continue
                    bx, by = centers[cids[j]]
                    dx, dy = ax - bx, ay - by
                    d = math.hypot(dx, dy) or 1e-6
                    need = radius[a] + radius[cids[j]] + margin
                    if d < need:
                        push = (need - d) / 2.0
                        ax += dx / d * push
                        ay += dy / d * push
                        moved += push
                centers[a] = (ax, ay)
            if grav == 0.0 and moved < 1e-3:
                break

    # 3) Place nodes, then normalize to [-1, 1]^2.
    out = {}
    for cid, members in groups.items():
        cx, cy = centers[cid]
        for nd in members:
            lx, ly = local[cid][nd]
            out[nd] = (cx + lx, cy + ly)
    xs = [p[0] for p in out.values()] or [0.0]
    ys = [p[1] for p in out.values()] or [0.0]
    minx, miny = min(xs), min(ys)
    span = max(max(xs) - minx, max(ys) - miny) or 1.0
    return {nd: (2 * (x - minx) / span - 1.0, 2 * (y - miny) / span - 1.0)
            for nd, (x, y) in out.items()}


def render_graph(ip_graph, membership, path=None, max_nodes=400):
    """Render the IP graph colored by community to a PNG. Returns path or None."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import networkx as nx
    except Exception:
        return None
    if ip_graph.number_of_nodes() == 0:
        return None

    path = path or config.GRAPH_VIZ
    config.ensure_output_dir()

    graph = ip_graph
    if graph.number_of_nodes() > max_nodes:
        # Keep the highest-degree nodes so the picture stays legible.
        keep = sorted(graph.degree, key=lambda kv: kv[1], reverse=True)[:max_nodes]
        graph = graph.subgraph([n for n, _ in keep]).copy()

    colors = [membership.get(n, -1) for n in graph.nodes()]
    # Community-aware grouped layout (each cluster its own separated region) — a
    # plain global spring layout collapses the cross-linked clusters into one blob.
    pos = _grouped_layout(graph, membership)

    # Split edges: intra-cluster (cohesion, drawn faint) vs. genuinely *strong*
    # cross-cluster bridges (drawn boldly). Weak single-attribute cross-links — a
    # shared generic UA or ASN, which is almost every cross-cluster edge — are NOT
    # drawn: community detection already discounted them, and rendering thousands
    # of them is exactly what buries the clusters in an indistinct hairball.
    intra, bridges = [], []
    for u, v, d in graph.edges(data=True):
        if membership.get(u) == membership.get(v):
            intra.append((u, v))
        elif float(d.get("weight", 1.0)) >= _BRIDGE_MIN_WEIGHT:
            bridges.append((u, v))

    plt.figure(figsize=(12, 9))
    nx.draw_networkx_edges(graph, pos, edgelist=intra, alpha=0.13, width=0.5,
                           edge_color="#9aa4b2")
    if bridges:
        nx.draw_networkx_edges(graph, pos, edgelist=bridges, alpha=0.6, width=1.4,
                               edge_color="#C84E00")
    nx.draw_networkx_nodes(graph, pos, node_color=colors, cmap="tab20",
                           node_size=70, linewidths=0.4, edgecolors="#222")
    plt.title("Crawler campaigns (IPs grouped & colored by community)")
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(path, dpi=130)
    plt.close()
    return path


# --- Interactive (hover + per-campaign colour) renderer --------------------
def _campaign_color(i):
    """A distinct, well-spread colour per campaign (golden-angle hue sweep).

    Deliberately NOT a blue ramp: consecutive campaigns land far apart on the hue
    wheel, so every cluster is an obviously different colour."""
    hue = (i * 137.508) % 360
    light = 47 + (i % 3) * 5  # small lightness wobble so neighbours differ more
    return f"hsl({hue:.0f}, 68%, {light}%)"


def _flag_chips(camp):
    chips = []
    if camp.get("disguise_suspected"):
        chips.append(("DISGUISE", "#C84E00"))
    if camp.get("contradiction_suspected"):
        chips.append(("CONTRADICTION", "#993399"))
    if camp.get("vm_cohort_suspected"):
        chips.append(("VM", "#0577B1"))
    if camp.get("shared_device_fingerprint"):
        chips.append(("STITCHED", "#012169"))
    if camp.get("agentic_suspected"):
        chips.append(("AGENTIC", "#E89923"))
    if not chips and camp.get("systematic"):
        chips.append(("SYSTEMATIC", "#666"))
    if not chips:
        chips.append(("BENIGN", "#16794c"))
    return chips


def _rundown_html(camp, color):
    """The per-cluster summary shown on hover — the 'important rundown'."""
    import html as _html

    def esc(v):
        return _html.escape(str(v))

    chips = "".join(
        f'<span style="background:{c};color:#fff;border-radius:999px;'
        f'padding:1px 7px;font-size:10px;font-weight:700;margin-right:4px">{t}</span>'
        for t, c in _flag_chips(camp))
    asns = ", ".join(f"{esc(a['asn'])} ({a['ips']})" for a in (camp.get("asns") or [])[:4]) or "—"
    providers = ", ".join(esc(p) for p in (camp.get("declared_providers") or [])) or "none declared"
    uas = (camp.get("top_user_agents") or ["—"])[0]
    ips = ", ".join(esc(ip) for ip in (camp.get("sample_ips") or [])[:6])
    ja4 = (camp.get("ja4") or [])
    rows = [
        f'<div style="font-weight:800;font-size:13px;margin-bottom:2px">'
        f'<span style="display:inline-block;width:10px;height:10px;border-radius:999px;'
        f'background:{color};margin-right:6px"></span>#{camp.get("campaign_id")} {esc(camp.get("label"))}'
        f' <span style="color:#888;font-weight:500">({esc(camp.get("confidence"))})</span></div>',
        f'<div style="margin:4px 0">{chips}</div>',
        f'<table style="font-size:11px;border-collapse:collapse">'
        f'<tr><td style="color:#888;padding-right:8px">IPs</td><td><b>{camp.get("n_ips")}</b></td>'
        f'<td style="color:#888;padding:0 8px">Requests</td><td><b>{camp.get("n_requests")}</b></td></tr>'
        f'<tr><td style="color:#888;padding-right:8px">Req / IP</td><td>{camp.get("mean_req_per_ip")}</td>'
        f'<td style="color:#888;padding:0 8px">ASNs</td><td>{camp.get("n_asns")}</td></tr>'
        f'<tr><td style="color:#888;padding-right:8px">JA4</td><td>{len(ja4)}</td>'
        f'<td style="color:#888;padding:0 8px">Browser FP</td><td>{camp.get("browser_fingerprinted_ips", 0)}</td></tr>'
        f'</table>',
        f'<div style="font-size:11px;margin-top:4px"><span style="color:#888">Providers:</span> {providers}</div>',
        f'<div style="font-size:11px"><span style="color:#888">ASNs:</span> {asns}</div>',
        f'<div style="font-size:11px;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'
        f'<span style="color:#888">Top UA:</span> {esc(uas)}</div>',
        f'<div style="font-size:11px"><span style="color:#888">IPs:</span> <span style="font-family:monospace">{ips}</span></div>',
    ]
    reasons = camp.get("inconsistency_reasons") or camp.get("disguise_reasons") or []
    if reasons:
        rows.append(f'<div style="font-size:11px;margin-top:3px;color:#b42318">⚠ {esc(reasons[0])}</div>')
    return "".join(rows)


def render_interactive(ip_graph, membership, campaigns, path=None, max_nodes=600):
    """Render an interactive, self-contained HTML graph (no external libs/CDNs).

    Each IP is a node positioned by a spring layout, coloured by its campaign with
    a distinct hue, and shows the full campaign rundown on hover. Returns the path,
    or ``None`` if it can't be built (so the pipeline never fails on rendering)."""
    try:
        import html as _html
        import json as _json

        if ip_graph.number_of_nodes() == 0 or not campaigns:
            return None
        path = path or config.GRAPH_VIZ_HTML
        config.ensure_output_dir()

        graph = ip_graph
        if graph.number_of_nodes() > max_nodes:
            keep = sorted(graph.degree, key=lambda kv: kv[1], reverse=True)[:max_nodes]
            graph = graph.subgraph([n for n, _ in keep]).copy()

        by_comm = {c.get("community_id"): c for c in campaigns}
        colors = {c.get("campaign_id"): _campaign_color(c.get("campaign_id", i))
                  for i, c in enumerate(campaigns)}
        rundowns = {c.get("campaign_id"): _rundown_html(c, colors[c.get("campaign_id")])
                    for c in campaigns}

        # Community-aware grouped layout: each campaign is its own compact, clearly
        # separated cluster (a plain global spring layout collapses the cross-linked
        # clusters into one central blob and flings disconnected ones off-screen).
        pos = _grouped_layout(graph, membership)

        xs = [p[0] for p in pos.values()] or [0]
        ys = [p[1] for p in pos.values()] or [0]
        minx, maxx, miny, maxy = min(xs), max(xs), min(ys), max(ys)
        W, H, pad = 1000.0, 680.0, 36.0

        def sx(x):
            return pad + (x - minx) / (maxx - minx or 1) * (W - 2 * pad)

        def sy(y):
            return pad + (y - miny) / (maxy - miny or 1) * (H - 2 * pad)

        # Edges first (under the nodes). Intra-cluster edges are drawn faint — they
        # fill in a cluster's interior and show its cohesion. Cross-cluster edges are
        # only drawn when they're a *strong* bridge (shared fingerprint-strength
        # attribute, ``>= _BRIDGE_MIN_WEIGHT``) — the genuinely interesting "this
        # fleet spans clusters" signal — and then boldly, in the alert colour. Weak
        # single-attribute cross-links (a shared generic UA / ASN, i.e. nearly every
        # cross-cluster edge) are skipped: they're the clutter that buried the
        # clusters before, and the community detector already treated them as noise.
        edge_svg = []
        for u, v, d in graph.edges(data=True):
            if u not in pos or v not in pos:
                continue
            w = float(d.get("weight", 1.0))
            if membership.get(u) == membership.get(v):
                col, op, sw = "#c4cbd6", min(0.18, 0.05 + w / 70.0), min(1.2, 0.4 + w / 20.0)
            elif w >= _BRIDGE_MIN_WEIGHT:
                col, op, sw = "#C84E00", min(0.7, 0.32 + w / 24.0), min(2.6, 1.0 + w / 10.0)
            else:
                continue
            edge_svg.append(
                f'<line x1="{sx(pos[u][0]):.1f}" y1="{sy(pos[u][1]):.1f}" '
                f'x2="{sx(pos[v][0]):.1f}" y2="{sy(pos[v][1]):.1f}" '
                f'stroke="{col}" stroke-opacity="{op:.2f}" stroke-width="{sw:.2f}"/>')

        node_svg = []
        for n, p in pos.items():
            cid = membership.get(n)
            camp = by_comm.get(cid)
            campaign_id = camp.get("campaign_id") if camp else -1
            color = colors.get(campaign_id, "#9aa4b2")
            nreq = graph.nodes.get(n, {}).get("n_requests", 1) or 1
            r = max(3.5, min(12.0, 2.8 + (float(nreq) ** 0.5)))
            node_svg.append(
                f'<circle class="nd" cx="{sx(p[0]):.1f}" cy="{sy(p[1]):.1f}" r="{r:.1f}" '
                f'fill="{color}" stroke="#fff" stroke-width="1" data-c="{campaign_id}" '
                f'data-ip="{_html.escape(str(n))}"><title>{_html.escape(str(n))}</title></circle>')

        # Legend (one row per campaign, click to highlight).
        legend = []
        for c in campaigns:
            cid = c.get("campaign_id")
            chips = "".join(f'<i style="color:{col}">{t}</i> ' for t, col in _flag_chips(c))
            legend.append(
                f'<div class="lg" data-c="{cid}">'
                f'<span class="sw" style="background:{colors[cid]}"></span>'
                f'<b>#{cid}</b> {_html.escape(str(c.get("label")))} '
                f'<span class="mut">· {c.get("n_ips")} IP / {c.get("n_requests")} req</span> {chips}</div>')

        data_json = _json.dumps(rundowns)
        doc = _TEMPLATE.format(
            edges="\n".join(edge_svg), nodes="\n".join(node_svg),
            legend="\n".join(legend), W=W, H=H, data=data_json,
            n_campaigns=len(campaigns), n_nodes=graph.number_of_nodes())
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(doc)
        return path
    except Exception:
        return None


_TEMPLATE = """<!doctype html><html><head><meta charset="utf-8">
<style>
 html,body{{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#172033;background:#fff}}
 .wrap{{display:flex;gap:0;height:100vh}}
 .graph{{flex:1;position:relative;min-width:0}}
 svg{{width:100%;height:100%;display:block}}
 .nd{{cursor:pointer;transition:r .08s}} .nd:hover{{stroke:#172033;stroke-width:2}}
 .side{{width:280px;border-left:1px solid #e5e7eb;overflow:auto;padding:10px 12px;font-size:12px}}
 .side h3{{margin:.2rem 0 .5rem;font-size:13px}}
 .lg{{padding:4px 6px;border-radius:6px;cursor:pointer;line-height:1.35}}
 .lg:hover,.lg.on{{background:#f1f5f9}}
 .sw{{display:inline-block;width:11px;height:11px;border-radius:999px;vertical-align:middle;margin-right:5px}}
 .mut{{color:#8a93a3}} .lg i{{font-style:normal;font-weight:700;font-size:10px;margin-right:3px}}
 #tip{{position:absolute;pointer-events:none;background:#fff;border:1px solid #d8dee8;border-radius:8px;
   box-shadow:0 6px 24px rgba(0,0,0,.14);padding:9px 11px;max-width:360px;display:none;z-index:9}}
 .hd{{padding:6px 12px;border-bottom:1px solid #e5e7eb;font-size:12px;color:#526070}}
</style></head><body>
<div class="wrap">
 <div class="graph">
  <div class="hd">{n_campaigns} campaigns · {n_nodes} IP nodes — hover a node for its cluster rundown</div>
  <svg viewBox="0 0 {W:.0f} {H:.0f}" preserveAspectRatio="xMidYMid meet">
   <g>{edges}</g><g>{nodes}</g>
  </svg>
  <div id="tip"></div>
 </div>
 <div class="side"><h3>Campaigns</h3>{legend}</div>
</div>
<script>
 var RUN = {data};
 var tip = document.getElementById('tip');
 var graph = document.querySelector('.graph');
 function show(cid, ev){{
   var html = RUN[cid]; if(!html){{return;}}
   tip.innerHTML = html; tip.style.display='block';
   var r = graph.getBoundingClientRect();
   var x = ev.clientX - r.left + 14, y = ev.clientY - r.top + 14;
   if(x + 370 > r.width) x = ev.clientX - r.left - 374;
   tip.style.left = Math.max(4,x)+'px'; tip.style.top = Math.max(4,y)+'px';
 }}
 function clearHi(){{ document.querySelectorAll('.nd').forEach(function(n){{n.style.opacity=1;}});
   document.querySelectorAll('.lg').forEach(function(l){{l.classList.remove('on');}}); }}
 document.querySelectorAll('.nd').forEach(function(n){{
   n.addEventListener('mousemove', function(e){{ show(n.getAttribute('data-c'), e); }});
   n.addEventListener('mouseleave', function(){{ tip.style.display='none'; }});
 }});
 document.querySelectorAll('.lg').forEach(function(l){{
   var cid = l.getAttribute('data-c');
   l.addEventListener('mouseenter', function(){{
     clearHi(); l.classList.add('on');
     document.querySelectorAll('.nd').forEach(function(n){{ n.style.opacity = n.getAttribute('data-c')===cid?1:0.12; }});
   }});
   l.addEventListener('mouseleave', clearHi);
 }});
</script></body></html>"""
