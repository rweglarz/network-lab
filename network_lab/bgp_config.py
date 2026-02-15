from dataclasses import dataclass, field
from ipaddress import ip_interface

from network_lab.config import LabConfig, Router


@dataclass
class Neighbor:
    name: str
    ip: str
    remote_asn: int
    as_prepend: list[int] = field(default_factory=list)


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
            neighbors.append(Neighbor(name=peer.router, ip=neighbor_ip, remote_asn=remote_asn, as_prepend=link.as_prepend))

    return neighbors


def generate_gobgp_config(router: Router, router_id: str, neighbors: list[Neighbor]) -> str:
    """Generate gobgpd TOML config."""
    lines = [
        "[global.config]",
        f'  as = {router.asn}',
        f'  router-id = "{router_id}"',
        "",
    ]

    # Collect prepend policies needed
    prepend_policies: dict[str, list[int]] = {}
    for n in neighbors:
        if n.as_prepend:
            policy_name = f"prepend-to-{n.name}"
            prepend_policies[policy_name] = n.as_prepend

    # Define policy statements for AS prepending
    for policy_name, prepend_asns in prepend_policies.items():
        asn = prepend_asns[0]
        repeat_n = len(prepend_asns)
        lines.extend([
            f'[[policy-definitions]]',
            f'  name = "{policy_name}"',
            f'  [[policy-definitions.statements]]',
            f'    [policy-definitions.statements.actions]',
            f'      route-disposition = "accept-route"',
            f'    [policy-definitions.statements.actions.bgp-actions.set-as-path-prepend]',
            f'      as = "{asn}"',
            f'      repeat-n = {repeat_n}',
            "",
        ])

    for n in neighbors:
        lines.extend([
            "[[neighbors]]",
            "  [neighbors.config]",
            f'    neighbor-address = "{n.ip}"',
            f"    peer-as = {n.remote_asn}",
            f'    description = "{n.name}"',
        ])
        if n.as_prepend:
            policy_name = f"prepend-to-{n.name}"
            lines.extend([
                "  [neighbors.apply-policy.config]",
                f'    export-policy-list = ["{policy_name}"]',
                f'    default-export-policy = "accept-route"',
            ])
        lines.append("")

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

    for n in neighbors:
        bird_name = n.name.replace("-", "_")
        if n.as_prepend:
            asn = n.as_prepend[0]
            repeat_n = len(n.as_prepend)
            prepend_lines = "\n".join(f"  bgp_path.prepend({asn});" for _ in range(repeat_n))
            lines.extend([
                f"filter prepend_to_{bird_name} {{",
                prepend_lines,
                "  accept;",
                "}",
                "",
            ])

        lines.extend([
            f"protocol bgp {bird_name} {{",
            f"  local as {router.asn};",
            f"  neighbor {n.ip} as {n.remote_asn};",
            "  ipv4 {",
            "    import all;",
        ])
        if n.as_prepend:
            lines.append(f"    export filter prepend_to_{bird_name};")
        else:
            lines.append("    export all;")
        lines.extend([
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
