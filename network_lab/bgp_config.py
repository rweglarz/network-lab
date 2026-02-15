from dataclasses import dataclass, field
from ipaddress import ip_interface

from network_lab.config import LabConfig, Network, Router


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


def generate_gobgp_config(router: Router, router_id: str, neighbors: list[Neighbor],
                          networks: list[Network] | None = None) -> str:
    """Generate gobgpd TOML config."""
    networks = networks or []
    lines = [
        "[global.config]",
        f'  as = {router.asn}',
        f'  router-id = "{router_id}"',
        "",
    ]

    # Define prefix sets for networks with communities
    community_nets = [n for n in networks if n.community]
    if community_nets:
        for net in community_nets:
            safe_name = net.prefix.replace("/", "-").replace(".", "-")
            lines.extend([
                '[[defined-sets.prefix-sets]]',
                f'  prefix-set-name = "net-{safe_name}"',
                '  [[defined-sets.prefix-sets.prefix-list]]',
                f'    ip-prefix = "{net.prefix}"',
                "",
            ])

    # Community tagging policy
    if community_nets:
        lines.extend([
            '[[policy-definitions]]',
            '  name = "set-communities"',
        ])
        for net in community_nets:
            safe_name = net.prefix.replace("/", "-").replace(".", "-")
            lines.extend([
                '  [[policy-definitions.statements]]',
                f'    name = "community-{safe_name}"',
                '    [policy-definitions.statements.conditions.match-prefix-set]',
                f'      prefix-set = "net-{safe_name}"',
                '    [policy-definitions.statements.actions]',
                '      route-disposition = "accept-route"',
                '    [policy-definitions.statements.actions.bgp-actions.set-community]',
                '      options = "add"',
                '    [policy-definitions.statements.actions.bgp-actions.set-community.set-community-method]',
                f'      communities-list = ["{net.community}"]',
            ])
        lines.append("")

    # Collect prepend policies needed
    for n in neighbors:
        if n.as_prepend:
            policy_name = f"prepend-to-{n.name}"
            asn = n.as_prepend[0]
            repeat_n = len(n.as_prepend)
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

        # Build per-neighbor export policy list
        neighbor_policies = []
        if community_nets:
            neighbor_policies.append("set-communities")
        if n.as_prepend:
            neighbor_policies.append(f"prepend-to-{n.name}")

        if neighbor_policies:
            policy_list = ", ".join(f'"{p}"' for p in neighbor_policies)
            lines.extend([
                "  [neighbors.apply-policy.config]",
                f'    export-policy-list = [{policy_list}]',
                f'    default-export-policy = "accept-route"',
            ])
        lines.append("")

    return "\n".join(lines)


def generate_bird_config(router: Router, router_id: str, neighbors: list[Neighbor],
                         networks: list[Network] | None = None) -> str:
    """Generate BIRD2 config."""
    networks = networks or []
    has_communities = any(n.community for n in networks)
    needs_export_filter = has_communities or any(n.as_prepend for n in neighbors)

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

    # Generate per-neighbor export filters combining community tagging and AS prepending
    for n in neighbors:
        bird_name = n.name.replace("-", "_")
        if not has_communities and not n.as_prepend:
            continue

        lines.append(f"filter export_{bird_name} {{")
        if has_communities:
            for net in networks:
                if net.community:
                    asn_part, val_part = net.community.split(":")
                    lines.append(f"  if net = {net.prefix} then bgp_community.add(({asn_part}, {val_part}));")
        if n.as_prepend:
            asn = n.as_prepend[0]
            for _ in range(len(n.as_prepend)):
                lines.append(f"  bgp_path.prepend({asn});")
        lines.extend([
            "  accept;",
            "}",
            "",
        ])

    for n in neighbors:
        bird_name = n.name.replace("-", "_")
        has_filter = has_communities or n.as_prepend

        lines.extend([
            f"protocol bgp {bird_name} {{",
            f"  local as {router.asn};",
            f"  neighbor {n.ip} as {n.remote_asn};",
            "  ipv4 {",
            "    import all;",
        ])
        if has_filter:
            lines.append(f"    export filter export_{bird_name};")
        else:
            lines.append("    export all;")
        lines.extend([
            "  };",
            "}",
            "",
        ])

    return "\n".join(lines)


def generate_frr_config(router: Router, router_id: str, neighbors: list[Neighbor],
                        networks: list[Network] | None = None) -> str:
    """Generate FRR unified config."""
    networks = networks or []
    community_nets = [n for n in networks if n.community]
    lines = [
        "frr defaults traditional",
        f"hostname {router.name}",
        "!",
    ]

    # Prefix-lists for community tagging
    if community_nets:
        for i, net in enumerate(community_nets):
            safe_name = net.prefix.replace("/", "-").replace(".", "-")
            lines.append(f"ip prefix-list NET-{safe_name} seq 5 permit {net.prefix}")
        lines.append("!")

    # Per-neighbor export route-maps
    for n in neighbors:
        safe_neighbor = n.name.replace("-", "_")
        rm_name = f"EXPORT-{safe_neighbor}"
        seq = 10

        # Community tagging entries
        for net in community_nets:
            safe_name = net.prefix.replace("/", "-").replace(".", "-")
            lines.extend([
                f"route-map {rm_name} permit {seq}",
                f"  match ip address prefix-list NET-{safe_name}",
                f"  set community {net.community} additive",
            ])
            if n.as_prepend:
                asn = n.as_prepend[0]
                prepend_str = " ".join(str(asn) for _ in n.as_prepend)
                lines.append(f"  set as-path prepend {prepend_str}")
            seq += 10

        # AS prepend catch-all (for routes without community match)
        if n.as_prepend:
            asn = n.as_prepend[0]
            prepend_str = " ".join(str(asn) for _ in n.as_prepend)
            lines.extend([
                f"route-map {rm_name} permit {seq}",
                f"  set as-path prepend {prepend_str}",
            ])
            seq += 10

        # Catch-all accept
        if community_nets or n.as_prepend:
            lines.extend([
                f"route-map {rm_name} permit {seq}",
            ])

        lines.append("!")

    # Router BGP section
    lines.extend([
        f"router bgp {router.asn}",
        f"  bgp router-id {router_id}",
    ])

    for n in neighbors:
        lines.extend([
            f"  neighbor {n.ip} remote-as {n.remote_asn}",
            f"  neighbor {n.ip} description {n.name}",
        ])

    lines.extend([
        "  !",
        "  address-family ipv4 unicast",
        "    redistribute connected",
    ])

    for n in neighbors:
        safe_neighbor = n.name.replace("-", "_")
        if community_nets or n.as_prepend:
            lines.append(f"    neighbor {n.ip} route-map EXPORT-{safe_neighbor} out")

    lines.extend([
        "  exit-address-family",
        "!",
    ])

    return "\n".join(lines)


def generate_config(config: LabConfig, router: Router) -> str:
    """Generate BGP config for a router based on its kind."""
    kind = config.kind_for_router(router.name)
    router_id = get_router_id(config, router.name)
    neighbors = get_neighbors(config, router.name)

    networks = config.networks.get(router.name, [])

    if kind.name == "gobgp":
        return generate_gobgp_config(router, router_id, neighbors, networks)
    elif kind.name == "bird":
        return generate_bird_config(router, router_id, neighbors, networks)
    elif kind.name == "frr":
        return generate_frr_config(router, router_id, neighbors, networks)
    else:
        raise ValueError(f"Unknown kind '{kind.name}' for router '{router.name}'")
