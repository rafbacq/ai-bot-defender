"""Build the crawler identity graph from per-endpoint records.

Model: a bipartite-ish graph with two node kinds —

  * ``ip`` nodes (one per client IP — the actors), and
  * ``attr`` nodes (one per shared attribute value: a JA4 hash, an exact
    User-Agent, a /24 netblock, an ASN).

Each IP connects to its attribute nodes with an edge weighted by how strongly
that attribute implies "same actor" (JA strongest, ASN weakest — see
``config.EDGE_WEIGHTS``). Community detection over this graph groups IPs that
share discriminative attributes into campaigns. The attribute-hub design keeps
edge construction linear instead of O(IPs^2), and naturally ties together a
disguised fleet that rotates IPs/ASNs but reuses one TLS stack (a shared JA4
hub holds them together even when nothing else does).

``project_to_ip_graph`` collapses the bipartite graph to a weighted IP–IP graph
(shared-attribute weight summed over hubs) for the homogeneous GraphSAGE GNN.
"""

from .. import config


def _require_networkx():
    try:
        import networkx as nx
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "networkx is required for the crawler graph. "
            "Install it: pip install -r crawler_graph/requirements.txt"
        ) from exc
    return nx


def build_graph(endpoints, edge_weights=None, attr_hub_cap=None):
    """Return a ``networkx.Graph`` of ip + attr nodes with weighted edges.

    ``endpoints`` is the dict from ``enrich.aggregate_endpoints``. Attribute hubs
    that touch more than ``attr_hub_cap`` IPs are dropped (a huge shared ASN is
    noise, not a campaign); set the cap to 0 to keep everything.
    """
    nx = _require_networkx()
    weights = edge_weights or config.EDGE_WEIGHTS
    cap = config.ATTR_HUB_CAP if attr_hub_cap is None else attr_hub_cap

    graph = nx.Graph()

    # Pass 1: add IP nodes and collect attribute -> [ips] memberships.
    members = {}  # attr_node_id -> set(ip)

    def _attr(kind, value):
        return f"{kind}::{value}"

    for ip, rec in endpoints.items():
        graph.add_node(ip, kind="ip", **{k: rec[k] for k in (
            "asn", "asn_descr", "netblock", "n_requests", "ua_top", "n_user_agents",
            "n_sites", "n_paths", "path_entropy", "ua_entropy", "hour_entropy",
            "has_fingerprint", "has_browser_fingerprint", "n_device_keys",
            "automation_score", "providers_ua", "is_declared_crawler", "is_browser",
            "is_automated", "mean_gap", "std_gap", "burstiness", "span_s",
        ) if k in rec})

        for ja in rec.get("ja4") or []:
            members.setdefault(_attr("ja", ja), set()).add(ip)
        # If no JA4, fall back to JA3 so the fingerprint signal still links.
        if not rec.get("ja4"):
            for ja in rec.get("ja3") or []:
                members.setdefault(_attr("ja", ja), set()).add(ip)
        for ua in rec.get("user_agents") or {}:
            if ua:
                members.setdefault(_attr("ua", ua), set()).add(ip)
        if rec.get("netblock"):
            members.setdefault(_attr("net", rec["netblock"]), set()).add(ip)
        if rec.get("asn"):
            members.setdefault(_attr("asn", rec["asn"]), set()).add(ip)

        # Layer-1 device-correlation keys (canvas/WebGL/audio/font + composite
        # fp_id) and the HTTP-header signature (ja4h). A shared device key ties
        # together the SAME physical machine even when it rotates IPs/ASNs and
        # clears cookies — the cross-session stitching the reference doc describes.
        for kind, field in (("canvas", "canvas"), ("webglfp", "webgl_fp"),
                            ("audio", "audio"), ("font", "font"), ("fpid", "fpid"),
                            ("ja4h", "ja4h")):
            for val in rec.get(field) or []:
                if val:
                    members.setdefault(_attr(kind, val), set()).add(ip)

    # Pass 2: add attribute hubs (skipping singletons and oversized hubs) and
    # connect each member IP to the hub with the attribute's weight.
    for attr_id, ips in members.items():
        if len(ips) < 2:
            continue  # a singleton attribute links nothing
        if cap and len(ips) > cap:
            continue  # giant hub (e.g. a shared ASN) — too noisy to be a campaign
        kind = attr_id.split("::", 1)[0]
        weight = weights.get(kind, 1.0)
        graph.add_node(attr_id, kind="attr", attr_kind=kind, degree=len(ips))
        for ip in ips:
            graph.add_edge(ip, attr_id, weight=weight, kind=kind)
    return graph


def project_to_ip_graph(graph):
    """Collapse the bipartite graph to a weighted IP–IP graph.

    Two IPs are linked with weight = sum over shared attribute hubs of that
    hub's edge weight (so two IPs sharing a JA4 *and* a /24 are strongly tied).
    """
    nx = _require_networkx()
    ip_graph = nx.Graph()
    for node, data in graph.nodes(data=True):
        if data.get("kind") == "ip":
            ip_graph.add_node(node, **data)

    for attr_node, data in graph.nodes(data=True):
        if data.get("kind") != "attr":
            continue
        ips = list(graph.neighbors(attr_node))
        w = config.EDGE_WEIGHTS.get(data.get("attr_kind"), 1.0)
        for i in range(len(ips)):
            for j in range(i + 1, len(ips)):
                a, b = ips[i], ips[j]
                if ip_graph.has_edge(a, b):
                    ip_graph[a][b]["weight"] += w
                else:
                    ip_graph.add_edge(a, b, weight=w)
    return ip_graph


def graph_summary(graph):
    nx = _require_networkx()
    ip_nodes = [n for n, d in graph.nodes(data=True) if d.get("kind") == "ip"]
    attr_nodes = [n for n, d in graph.nodes(data=True) if d.get("kind") == "attr"]
    return {
        "ip_nodes": len(ip_nodes),
        "attr_nodes": len(attr_nodes),
        "edges": graph.number_of_edges(),
        "components": nx.number_connected_components(graph) if graph.number_of_nodes() else 0,
    }
