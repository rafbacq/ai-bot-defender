"""Community detection over the identity graph.

Prefers Louvain (``python-louvain``) on the weighted bipartite graph; will use
Leiden (``leidenalg`` + ``igraph``) if installed; falls back to networkx's
greedy modularity so the package still produces campaigns with zero optional
deps. Returns a mapping of **IP node -> community id** (attribute hubs are
assigned too but filtered out by the caller).
"""

import itertools


def detect_communities(graph, method="auto"):
    """Return ``{node: community_id}`` for all nodes, plus the method used.

    ``method`` in {"auto", "louvain", "leiden", "greedy"}.
    """
    if graph.number_of_nodes() == 0:
        return {}, "none"

    order = (
        [method] if method != "auto"
        else ["louvain", "leiden", "greedy"]
    )
    for name in order:
        try:
            if name == "louvain":
                return _louvain(graph), "louvain"
            if name == "leiden":
                return _leiden(graph), "leiden"
            if name == "greedy":
                return _greedy(graph), "greedy"
        except Exception:
            if method != "auto":
                raise
            continue
    return _greedy(graph), "greedy"


def _louvain(graph):
    import community as community_louvain  # python-louvain

    return community_louvain.best_partition(graph, weight="weight", random_state=42)


def _leiden(graph):
    import igraph as ig
    import leidenalg

    nodes = list(graph.nodes())
    index = {n: i for i, n in enumerate(nodes)}
    edges = [(index[u], index[v]) for u, v in graph.edges()]
    weights = [graph[u][v].get("weight", 1.0) for u, v in graph.edges()]
    g = ig.Graph(n=len(nodes), edges=edges)
    g.es["weight"] = weights
    part = leidenalg.find_partition(
        g, leidenalg.ModularityVertexPartition, weights="weight", seed=42
    )
    membership = {}
    for cid, members in enumerate(part):
        for vid in members:
            membership[nodes[vid]] = cid
    return membership


def _greedy(graph):
    import networkx as nx

    communities = nx.algorithms.community.greedy_modularity_communities(
        graph, weight="weight"
    )
    membership = {}
    for cid, members in enumerate(communities):
        for node in members:
            membership[node] = cid
    return membership


def modularity(graph, membership):
    """Modularity of the partition (quality score), or ``None`` if unavailable."""
    try:
        import networkx as nx

        groups = {}
        for node, cid in membership.items():
            if node in graph:
                groups.setdefault(cid, set()).add(node)
        return round(
            nx.algorithms.community.modularity(
                graph, groups.values(), weight="weight"
            ),
            4,
        )
    except Exception:
        return None


def community_sizes(membership, graph):
    """Count IP nodes per community (ignores attribute hubs)."""
    sizes = {}
    for node, cid in membership.items():
        if graph.nodes.get(node, {}).get("kind") == "ip":
            sizes[cid] = sizes.get(cid, 0) + 1
    return dict(sorted(sizes.items(), key=lambda kv: kv[1], reverse=True))


def _next_id(membership):
    return (max(membership.values()) + 1) if membership else 0
