from collections import defaultdict

import graphviz

from network_lab.config import LabConfig
from network_lab.engine import (
    _load_lab_config, _container_kind, _parse_gobgp_peers,
    _parse_bird_peers, _parse_frr_peers, _build_peer_name_map,
    LABEL_KEY,
)
from network_lab.podman import Podman


def _get_down_peers(config: LabConfig, podman: Podman) -> set[tuple[str, str]]:
    """Return set of (router_a, router_b) tuples where the BGP session is down."""
    containers = podman.container_list(label=f"{LABEL_KEY}={config.name}")
    running = [c for c in containers if c.get("State") == "running"]
    name_map = _build_peer_name_map(config)

    down_pairs: set[tuple[str, str]] = set()

    for c in running:
        container_name = c["Names"][0]
        display_name = container_name.removeprefix(f"nl-{config.name}-")
        image = c.get("Image", "")
        kind = _container_kind(image)

        peers = []
        if kind == "gobgp":
            result = podman.container_exec(container_name, ["gobgp", "-j", "neighbor"])
            if result.returncode == 0 and result.stdout.strip():
                peers = _parse_gobgp_peers(result.stdout)
        elif kind == "bird":
            result = podman.container_exec(container_name, ["birdc", "show", "protocols", "all"])
            if result.returncode == 0 and result.stdout.strip():
                peers = _parse_bird_peers(result.stdout)
        elif kind == "frr":
            result = podman.container_exec(container_name, ["vtysh", "-c", "show bgp summary json"])
            if result.returncode == 0 and result.stdout.strip():
                peers = _parse_frr_peers(result.stdout)

        for peer in peers:
            if peer["state"] != "established":
                raw = peer["neighbor"]
                peer_name = name_map.get(raw, raw)
                pair = tuple(sorted([display_name, peer_name]))
                down_pairs.add(pair)

    return down_pairs


def _build_dot(config: LabConfig, down_peers: set[tuple[str, str]] | None = None,
               forward_path: list[str] | None = None,
               backward_path: list[str] | None = None) -> graphviz.Digraph:
    """Build a graphviz Digraph object from the lab config."""
    if down_peers is None:
        down_peers = set()

    g = graphviz.Digraph("topology", engine="neato", format="svg")
    g.attr(bgcolor="white", pad="0.5", overlap="false", splines="true")
    g.attr("node", shape="box", style="rounded,filled", fillcolor="#d4e6f1",
           fontname="Helvetica", fontsize="10", width="1.8", height="0.6",
           margin="0.2,0.15")
    g.attr("edge", fontname="Helvetica", fontsize="8")

    # Group routers by ASN for subgraph clusters
    asn_groups: dict[int, list] = defaultdict(list)
    for router in config.routers:
        if router.asn is not None:
            asn_groups[router.asn].append(router)

    cluster_colors = ["#d4e6f1", "#f9e0e0", "#d5f5d5", "#fdf3d7", "#e8d5f5", "#d5f5f0"]
    cluster_borders = ["#2980b9", "#c0392b", "#27ae60", "#f39c12", "#8e44ad", "#1abc9c"]

    # Track which routers are in multi-member ASN clusters
    clustered_routers: set[str] = set()

    for idx, (asn, members) in enumerate(sorted(asn_groups.items())):
        if len(members) < 2:
            continue
        color = cluster_colors[idx % len(cluster_colors)]
        border = cluster_borders[idx % len(cluster_borders)]
        with g.subgraph(name=f"cluster_as{asn}") as sub:
            sub.attr(label=f"AS {asn}", style="rounded,filled", fillcolor=color,
                     color=border, penwidth="2", fontname="Helvetica Bold",
                     fontsize="12", fontcolor=border, margin="40")
            for router in members:
                clustered_routers.add(router.name)
                _add_router_node(sub, config, router, in_cluster=True)

            # Add tiny spacer nodes at all 4 corners to pad the cluster boundary
            positions = [r.graph_pos for r in members if r.graph_pos]
            if positions:
                xs = [p[0] for p in positions]
                ys = [p[1] for p in positions]
                px, py = 80, 45  # horizontal and vertical padding
                corners = [
                    (min(xs) - px, min(ys) - py),
                    (max(xs) + px, min(ys) - py),
                    (min(xs) - px, max(ys) + py),
                    (max(xs) + px, max(ys) + py),
                ]
                for ci, (cx, cy) in enumerate(corners):
                    spacer_id = f"_spacer_{asn}_{ci}"
                    sx = cx / 72
                    sy = cy / 72
                    sub.node(spacer_id, label="", shape="point",
                             width="0.01", height="0.01",
                             color=color, fillcolor=color, style="filled",
                             pos=f"{sx},{sy}!")

    # Add non-clustered routers
    for router in config.routers:
        if router.name not in clustered_routers:
            _add_router_node(g, config, router)

    # Add edges — use hub nodes for mesh links (>2 peers)
    for i, link in enumerate(config.links):
        peer_names = [p.router for p in link.peers]

        if len(peer_names) <= 2:
            # Point-to-point link: direct edge
            if len(peer_names) == 2:
                a, b = peer_names
                pair = tuple(sorted([a, b]))
                is_down = pair in down_peers
                attrs = _edge_attrs(is_down)
                g.edge(a, b, **attrs)
        else:
            # Mesh link: add a small hub dot, connect all peers to it
            hub_id = f"_hub_{i}"
            hub_attrs = {
                "shape": "point", "width": "0.15", "height": "0.15",
                "fillcolor": "#666666", "color": "#666666",
                "style": "filled", "label": "",
            }
            if link.graph_pos:
                gv_x = link.graph_pos[0] / 72
                gv_y = link.graph_pos[1] / 72
                hub_attrs["pos"] = f"{gv_x},{gv_y}!"
            g.node(hub_id, **hub_attrs)

            for peer_name in peer_names:
                any_down = any(
                    tuple(sorted([peer_name, other])) in down_peers
                    for other in peer_names if other != peer_name
                )
                attrs = _edge_attrs(any_down)
                g.edge(hub_id, peer_name, **attrs)

    # Add trace path arrows (separate from topology edges)
    if forward_path:
        for i in range(len(forward_path) - 1):
            g.edge(f"{forward_path[i]}:w", f"{forward_path[i + 1]}:w",
                   color="#22aa22", penwidth="2.5", style="bold",
                   arrowhead="normal", arrowsize="0.8")
    if backward_path:
        for i in range(len(backward_path) - 1):
            g.edge(f"{backward_path[i]}:e", f"{backward_path[i + 1]}:e",
                   color="#4488cc", penwidth="2.5", style="bold",
                   arrowhead="normal", arrowsize="0.8")

    return g


def _edge_attrs(is_down: bool) -> dict:
    """Return graphviz edge attributes based on link state."""
    if is_down:
        return {"color": "red", "penwidth": "2.5", "style": "dashed", "dir": "none"}
    else:
        return {"color": "#888888", "penwidth": "1.2", "dir": "none"}


def _add_router_node(graph, config: LabConfig, router,
                     in_cluster: bool = False):
    """Add a router node with optional network prefix labels."""
    nets = config.networks.get(router.name, [])
    show_asn = router.asn and not in_cluster

    if nets:
        label = f"<<TABLE BORDER='0' CELLBORDER='0' CELLSPACING='2'>" \
                f"<TR><TD><B>{router.name}</B></TD></TR>"
        if show_asn:
            label += f"<TR><TD><FONT POINT-SIZE='8'>AS {router.asn}</FONT></TD></TR>"
        label += "<HR/>"
        for n in nets:
            label += f"<TR><TD><FONT POINT-SIZE='8' COLOR='#555555'>{n.prefix}</FONT></TD></TR>"
        label += "</TABLE>>"
    else:
        label = f"<<B>{router.name}</B>>"
        if show_asn:
            label = f"<<B>{router.name}</B><BR/><FONT POINT-SIZE='8'>AS {router.asn}</FONT>>"

    attrs = {"label": label}

    # graph_pos: [x, y] where negative x = left, negative y = down
    # graphviz neato: pos="x,y!" where y increases upward — same convention
    if router.graph_pos:
        gv_x = router.graph_pos[0] / 72  # convert to inches (graphviz uses inches)
        gv_y = router.graph_pos[1] / 72
        attrs["pos"] = f"{gv_x},{gv_y}!"

    graph.node(router.name, **attrs)


def _render(g: graphviz.Digraph | graphviz.Graph, output: str | None, fmt: str = "svg",
            fallback_name: str = "/tmp/nl-graph") -> None:
    """Render a graphviz graph to file or display interactively."""
    if output:
        if "." in output:
            base, ext = output.rsplit(".", 1)
            g.format = ext
        else:
            base = output
            g.format = fmt
        g.render(base, cleanup=True)
        print(f"Graph saved to {output}")
    else:
        g.format = fmt
        g.render(fallback_name, view=True, cleanup=True)


def generate_graph(lab_name: str, output: str | None = None, fmt: str = "svg") -> None:
    podman = Podman()
    config = _load_lab_config(lab_name, podman)

    try:
        down_peers = _get_down_peers(config, podman)
    except Exception:
        down_peers = set()

    g = _build_dot(config, down_peers=down_peers)
    _render(g, output, fmt=fmt, fallback_name="/tmp/nl-graph")


def generate_trace_graph(lab_name: str, forward_hops: list[dict],
                         backward_hops: list[dict], output: str | None = None,
                         fmt: str = "svg") -> None:
    """Generate topology graph with traced path highlighted."""
    podman = Podman()
    config = _load_lab_config(lab_name, podman)

    try:
        down_peers = _get_down_peers(config, podman)
    except Exception:
        down_peers = set()

    forward_routers = [h["router"] for h in forward_hops] if forward_hops else None
    backward_routers = [h["router"] for h in backward_hops] if backward_hops else None

    g = _build_dot(config, down_peers=down_peers,
                   forward_path=forward_routers, backward_path=backward_routers)
    _render(g, output, fmt=fmt, fallback_name="/tmp/nl-trace-graph")
