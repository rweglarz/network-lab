from dataclasses import dataclass
from ipaddress import ip_interface

from network_lab.config import LabConfig, Router


@dataclass
class Neighbor:
    ip: str
    remote_asn: int


def get_router_id(config: LabConfig, router_name: str) -> str:
    """Derive router-id from the first link IP of this router."""
    for link in config.links:
        for peer in link.peers:
            if peer.router == router_name:
                return str(ip_interface(peer.ip).ip)
    return "0.0.0.0"


def get_neighbors(config: LabConfig, router_name: str) -> list[Neighbor]:
    """Derive BGP neighbors from links: other peers on the same link are neighbors."""
    router_asns = {r.name: r.asn for r in config.routers}
    neighbors = []

    for link in config.links:
        peer_names = [p.router for p in link.peers]
        if router_name not in peer_names:
            continue
        for peer in link.peers:
            if peer.router == router_name:
                continue
            remote_asn = router_asns.get(peer.router)
            if remote_asn is None:
                continue
            neighbor_ip = str(ip_interface(peer.ip).ip)
            neighbors.append(Neighbor(ip=neighbor_ip, remote_asn=remote_asn))

    return neighbors


def generate_gobgp_config(router: Router, router_id: str, neighbors: list[Neighbor]) -> str:
    """Generate gobgpd TOML config."""
    lines = [
        "[global.config]",
        f'  as = {router.asn}',
        f'  router-id = "{router_id}"',
        "",
    ]

    for n in neighbors:
        lines.extend([
            "[[neighbors]]",
            "  [neighbors.config]",
            f'    neighbor-address = "{n.ip}"',
            f"    peer-as = {n.remote_asn}",
            "",
        ])

    return "\n".join(lines)


def generate_bird_config(router: Router, router_id: str, neighbors: list[Neighbor]) -> str:
    """Generate BIRD2 config."""
    lines = [
        f'router id {router_id};',
        "",
        "protocol device {",
        "}",
        "",
        "protocol direct {",
        "  ipv4;",
        "}",
        "",
    ]

    for i, n in enumerate(neighbors):
        lines.extend([
            f"protocol bgp peer{i + 1} {{",
            f"  local as {router.asn};",
            f"  neighbor {n.ip} as {n.remote_asn};",
            "  ipv4 {",
            "    import all;",
            "    export all;",
            "  };",
            "}",
            "",
        ])

    return "\n".join(lines)


def generate_config(config: LabConfig, router: Router) -> str:
    """Generate BGP config for a router based on its kind."""
    kind = config.kind_for_router(router.name)
    router_id = get_router_id(config, router.name)
    neighbors = get_neighbors(config, router.name)

    if kind.name == "gobgp":
        return generate_gobgp_config(router, router_id, neighbors)
    elif kind.name == "bird":
        return generate_bird_config(router, router_id, neighbors)
    else:
        raise ValueError(f"Unknown kind '{kind.name}' for router '{router.name}'")
