from dataclasses import dataclass, field
from ipaddress import ip_interface

from network_lab.config import BgpSessionType, LabConfig, Network, Router


@dataclass
class Neighbor:
    name: str
    ip: str
    remote_asn: int
    as_prepend: list[int] = field(default_factory=list)
    rr_client: bool = False


def get_router_id(config: LabConfig, router_name: str) -> str:
    """Derive router-id from the first link IP of this router."""
    for link in config.links:
        for device in link.devices:
            if device.router == router_name:
                return str(ip_interface(device.ip).ip)
    return "0.0.0.0"


def _find_peer_ip_from_links(config: LabConfig, router_a: str, router_b: str) -> str | None:
    """Find the IP that router_b uses on a link shared with router_a."""
    for link in config.links:
        device_names = [d.router for d in link.devices]
        if router_a in device_names and router_b in device_names:
            for d in link.devices:
                if d.router == router_b:
                    return str(ip_interface(d.ip).ip)
    return None


def get_neighbors(config: LabConfig, router_name: str) -> list[Neighbor]:
    """Derive BGP neighbors from bgp sessions."""
    router_asns = {r.name: r.asn for r in config.routers}
    neighbors = []
    seen: set[str] = set()

    for session in config.bgp_sessions:
        if router_name not in session.routers:
            continue

        if session.type == BgpSessionType.MESH:
            for other in session.routers:
                if other == router_name or other in seen:
                    continue
                remote_asn = router_asns.get(other)
                if remote_asn is None:
                    continue
                peer_ip = _find_peer_ip_from_links(config, router_name, other)
                if peer_ip is None:
                    raise ValueError(f"No link connecting {router_name} and {other} for BGP session")
                seen.add(other)
                neighbors.append(Neighbor(
                    name=other, ip=peer_ip, remote_asn=remote_asn,
                    as_prepend=session.as_prepend,
                ))

        elif session.type == BgpSessionType.PEERS:
            other = [r for r in session.routers if r != router_name][0]
            if other in seen:
                continue
            remote_asn = router_asns.get(other)
            if remote_asn is None:
                continue
            peer_ip = _find_peer_ip_from_links(config, router_name, other)
            if peer_ip is None:
                raise ValueError(f"No link connecting {router_name} and {other} for BGP session")
            seen.add(other)
            neighbors.append(Neighbor(
                name=other, ip=peer_ip, remote_asn=remote_asn,
                as_prepend=session.as_prepend,
            ))

        elif session.type == BgpSessionType.RR:
            if router_name == session.rr_server:
                for client in session.rr_clients:
                    if client in seen:
                        continue
                    remote_asn = router_asns.get(client)
                    if remote_asn is None:
                        continue
                    peer_ip = _find_peer_ip_from_links(config, router_name, client)
                    if peer_ip is None:
                        raise ValueError(f"No link connecting {router_name} and {client}")
                    seen.add(client)
                    neighbors.append(Neighbor(
                        name=client, ip=peer_ip, remote_asn=remote_asn,
                        as_prepend=session.as_prepend, rr_client=True,
                    ))
            else:
                other = session.rr_server
                if other in seen:
                    continue
                remote_asn = router_asns.get(other)
                if remote_asn is None:
                    continue
                peer_ip = _find_peer_ip_from_links(config, router_name, other)
                if peer_ip is None:
                    raise ValueError(f"No link connecting {router_name} and {other}")
                seen.add(other)
                neighbors.append(Neighbor(
                    name=other, ip=peer_ip, remote_asn=remote_asn,
                    as_prepend=session.as_prepend,
                ))

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

        if n.rr_client:
            lines.extend([
                "  [neighbors.route-reflector.config]",
                "    route-reflector-client = true",
                f'    route-reflector-cluster-id = "{router_id}"',
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
        "protocol kernel {",
        "  ipv4 {",
        "    export all;",
        "  };",
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
        is_ibgp = n.remote_asn == router.asn

        lines.extend([
            f"protocol bgp {bird_name} {{",
            f"  local as {router.asn};",
            f"  neighbor {n.ip} as {n.remote_asn};",
        ])
        if n.rr_client:
            lines.append("  rr client;")
        lines.append("  ipv4 {")
        if is_ibgp:
            lines.append("    next hop self;")
        lines.append("    import all;")
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

    # Import permit-all route-map
    lines.extend([
        "route-map IMPORT-ALLOW permit 10",
        "!",
    ])

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
        if n.remote_asn == router.asn:
            lines.append(f"    neighbor {n.ip} next-hop-self")
        if n.rr_client:
            lines.append(f"    neighbor {n.ip} route-reflector-client")
        lines.append(f"    neighbor {n.ip} route-map IMPORT-ALLOW in")
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
