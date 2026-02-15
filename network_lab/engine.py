import json
import re
import sys
from ipaddress import ip_network
from pathlib import Path

from network_lab.bgp_config import generate_config
from network_lab.config import LabConfig, parse_config
from network_lab.podman import Podman, PodmanError


LABEL_KEY = "nl-lab"

# Map kind name to config mount path inside the container
KIND_CONFIG = {
    "gobgp": "/etc/gobgp/gobgp.conf",
    "bird": "/etc/bird/bird.conf",
    "frr": "/etc/frr/frr.conf",
}


def _config_dir(config: LabConfig) -> Path:
    return Path("configs") / config.name


def ensure_configs(config: LabConfig, force: bool = False) -> dict[str, Path]:
    """Generate BGP configs for all routers. Returns {router_name: config_path}."""
    config_dir = _config_dir(config)
    config_dir.mkdir(parents=True, exist_ok=True)

    paths = {}
    for router in config.routers:
        kind = config.kind_for_router(router.name)
        conf_path = config_dir / f"{router.name}.conf"

        if conf_path.exists() and not force:
            print(f"  Config for {router.name} already exists, skipping.")
        else:
            print(f"  Generating {kind.name} config for {router.name}...")
            content = generate_config(config, router)
            conf_path.write_text(content)

        paths[router.name] = conf_path.resolve()

    return paths


def start(config: LabConfig) -> None:
    print(f"Starting lab '{config.name}'...")
    podman = Podman()

    lab_labels = {LABEL_KEY: config.name, "nl-config": config.config_path}

    # Build a map of router -> list of (network_name, peer_data) for connection ordering
    # Assign default interface names (ethN) for peers without an explicit interface
    router_networks: dict[str, list[tuple[str, dict]]] = {r.name: [] for r in config.routers}
    router_iface_counter: dict[str, int] = {r.name: 1 for r in config.routers}  # eth0 = mgmt
    for i, link in enumerate(config.links):
        net_name = config.network_name(i)
        for peer in link.peers:
            iface = peer.interface if peer.interface is not None else f"eth{router_iface_counter[peer.router]}"
            router_iface_counter[peer.router] += 1
            router_networks[peer.router].append((net_name, {"interface": iface, "ip": peer.ip}))

    # Generate BGP configs (only if missing)
    print("Generating BGP configs...")
    config_paths = ensure_configs(config)

    # Create link networks (L2 only — no IPAM, internal, no DNS)
    for i, link in enumerate(config.links):
        net_name = config.network_name(i)
        if podman.network_exists(net_name):
            print(f"  Network {net_name} already exists, skipping.")
            continue
        print(f"Creating network {net_name}...")
        podman.network_create(net_name, labels=lab_labels, internal=True,
                              disable_dns=True, ipam_driver="none")

    # Create a management network (eth0 for all containers)
    mgmt_net = f"{config.prefix}-mgmt"
    if not podman.network_exists(mgmt_net):
        print(f"Creating management network {mgmt_net}...")
        podman.network_create(mgmt_net, labels={LABEL_KEY: config.name})

    # Start containers on the management network (eth0)
    for router in config.routers:
        container_name = config.container_name(router.name)
        image = config.image_for_router(router.name)
        kind = config.kind_for_router(router.name)

        # Mount config file into the container
        mount_path = KIND_CONFIG.get(kind.name)
        volumes = []
        if mount_path:
            host_path = config_paths[router.name]
            volumes = [f"{host_path}:{mount_path}:ro,Z"]

        caps = ["NET_ADMIN", "NET_RAW"]
        if kind.name == "frr":
            caps.append("SYS_ADMIN")

        print(f"Starting container {container_name}...")
        try:
            podman.container_run(
                image,
                name=container_name,
                hostname=router.name,
                labels=lab_labels,
                cap_add=caps,
                network=mgmt_net,
                volumes=volumes,
            )
        except PodmanError as e:
            print(f"  Error: {e}", file=sys.stderr)
            sys.exit(1)

    # Connect link networks in order (become eth1, eth2, ...)
    for router in config.routers:
        container_name = config.container_name(router.name)
        for net_name, _ in router_networks[router.name]:
            print(f"  Connecting {container_name} to {net_name}...")
            podman.network_connect(net_name, container_name)

    # Configure IP addresses on link interfaces
    for router in config.routers:
        container_name = config.container_name(router.name)
        print(f"Configuring {container_name}")
        for idx, (_, peer_data) in enumerate(router_networks[router.name]):
            # eth0 = mgmt, so link interfaces start at eth1
            kernel_iface = f"eth{idx + 1}"
            iface = peer_data["interface"]
            ip = peer_data["ip"]

            # Rename interface if configured name differs from kernel-assigned name
            if iface != kernel_iface:
                print(f"  Renaming {kernel_iface} to {iface}")
                podman.container_exec(container_name, ["ip", "link", "set", kernel_iface, "down"])
                podman.container_exec(container_name, ["ip", "link", "set", kernel_iface, "name", iface])

            print(f"  Configuring {iface} with {ip}...")
            podman.container_exec(container_name, ["ip", "addr", "add", ip, "dev", iface])
            podman.container_exec(container_name, ["ip", "link", "set", iface, "up"])

    # Create dummy interfaces for network prefixes
    for router in config.routers:
        router_nets = config.networks.get(router.name, [])
        if not router_nets:
            continue
        container_name = config.container_name(router.name)
        for i, net in enumerate(router_nets):
            iface = f"dummy{i}"
            network = ip_network(net.prefix, strict=False)
            host_ip = f"{network.network_address + 1}/{network.prefixlen}"
            print(f"  Creating {iface} on {container_name} with {host_ip}...")
            podman.container_exec(container_name, ["ip", "link", "add", iface, "type", "dummy"])
            podman.container_exec(container_name, ["ip", "addr", "add", host_ip, "dev", iface])
            podman.container_exec(container_name, ["ip", "link", "set", iface, "up"])

    # Inject network prefixes into gobgp RIB (gobgp doesn't redistribute connected routes)
    for router in config.routers:
        kind = config.kind_for_router(router.name)
        if kind.name != "gobgp":
            continue
        router_nets = config.networks.get(router.name, [])
        if not router_nets:
            continue
        container_name = config.container_name(router.name)
        for net in router_nets:
            cmd = ["gobgp", "global", "rib", "add", net.prefix]
            if net.community:
                cmd.extend(["community", net.community])
            print(f"  Injecting {net.prefix} into gobgp on {container_name}...")
            podman.container_exec(container_name, cmd)

    print(f"Lab '{config.name}' started successfully.")


def stop(lab_name: str) -> None:
    print(f"Stopping lab '{lab_name}'...")
    podman = Podman()

    # Find and remove containers
    containers = podman.container_list(label=f"{LABEL_KEY}={lab_name}")
    for c in containers:
        name = c["Names"][0]
        print(f"  Removing container {name}...")
        podman.container_remove(name)

    # Find and remove networks
    networks = podman.network_list(label=f"{LABEL_KEY}={lab_name}")
    for name in networks:
        print(f"  Removing network {name}...")
        podman.network_remove(name)

    print(f"Lab '{lab_name}' stopped.")


def restart(lab_name: str) -> None:
    podman = Podman()

    containers = podman.container_list(label=f"{LABEL_KEY}={lab_name}")
    config_path = None
    if containers:
        config_path = containers[0].get("Labels", {}).get("nl-config")

    if not config_path:
        print(f"Error: Cannot find config for lab '{lab_name}'. Use 'start -f <file>' instead.", file=sys.stderr)
        sys.exit(1)

    stop(lab_name)

    from network_lab.config import parse_config
    config = parse_config(config_path)
    start(config)


def list_containers(lab_name: str) -> None:
    podman = Podman()

    containers = podman.container_list(label=f"{LABEL_KEY}={lab_name}")
    if not containers:
        print(f"No containers found for lab '{lab_name}'.")
        return

    print(f"{'NAME':<35} {'STATUS':<20} {'IMAGE':<30}")
    for c in containers:
        name = c["Names"][0]
        status = c.get("State", "unknown")
        image = c.get("Image", "unknown")
        print(f"{name:<35} {status:<20} {image:<30}")


# gobgp session_state mapping
_GOBGP_STATES = {
    0: "idle", 1: "active", 2: "connect", 3: "opensent",
    4: "openconfirm", 5: "established", 6: "established",
}


def _parse_gobgp_peers(output: str) -> list[dict]:
    """Parse gobgp -j neighbor JSON output into unified peer dicts."""
    peers = []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return peers
    for entry in data:
        state = entry.get("state", {})
        session_state = _GOBGP_STATES.get(state.get("session_state", 0), "unknown")
        peers.append({
            "neighbor": state.get("neighbor_address", "?"),
            "remote_asn": state.get("peer_asn", 0),
            "state": session_state,
        })
    return peers


def _parse_bird_peers(output: str) -> list[dict]:
    """Parse 'birdc show protocols' output into unified peer dicts."""
    peers = []
    for line in output.splitlines():
        parts = line.split()
        # bird protocol table: Name Proto Table State Since Info
        if len(parts) >= 6 and parts[1] == "BGP":
            state = parts[3].lower()
            # Need detail to get neighbor/ASN — use birdc show protocols all
            peers.append({
                "neighbor": parts[0],
                "remote_asn": "?",
                "state": state,
            })
    return peers


def _parse_frr_peers(output: str) -> list[dict]:
    """Parse 'vtysh -c show bgp summary json' output into unified peer dicts."""
    peers = []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return peers
    ipv4 = data.get("ipv4Unicast", {})
    for addr, info in ipv4.get("peers", {}).items():
        state = info.get("state", "unknown")
        if state == "Established":
            state = "established"
        peers.append({
            "neighbor": addr,
            "remote_asn": info.get("remoteAs", "?"),
            "state": state,
        })
    return peers


def show_bgp_peers(lab_name: str) -> None:
    podman = Podman()

    containers = podman.container_list(label=f"{LABEL_KEY}={lab_name}")
    if not containers:
        print(f"No containers found for lab '{lab_name}'.")
        return

    running = [c for c in containers if c.get("State") == "running"]
    if not running:
        print(f"No running containers in lab '{lab_name}'.")
        return

    print(f"{'ROUTER':<30} {'NEIGHBOR':<18} {'REMOTE AS':<12} {'STATE':<15}")
    for c in running:
        container_name = c["Names"][0]
        labels = c.get("Labels", {})
        image = c.get("Image", "")

        # Determine kind from image name
        peers = []
        if "gobgp" in image:
            result = podman.container_exec(container_name, ["gobgp", "-j", "neighbor"])
            if result.returncode == 0 and result.stdout.strip():
                peers = _parse_gobgp_peers(result.stdout)
        elif "bird" in image:
            result = podman.container_exec(container_name, ["birdc", "show", "protocols"])
            if result.returncode == 0 and result.stdout.strip():
                peers = _parse_bird_peers(result.stdout)
        elif "frr" in image:
            result = podman.container_exec(container_name, ["vtysh", "-c", "show bgp summary json"])
            if result.returncode == 0 and result.stdout.strip():
                peers = _parse_frr_peers(result.stdout)

        # Strip lab prefix from container name for display
        display_name = container_name.removeprefix(f"nl-{lab_name}-")

        if not peers:
            print(f"{display_name:<30} {'(no peers)':<18} {'':<12} {'':<15}")
        else:
            for peer in peers:
                print(f"{display_name:<30} {peer['neighbor']:<18} {str(peer['remote_asn']):<12} {peer['state']:<15}")


# ---------------------------------------------------------------------------
# trace – hop-by-hop path tracing with BGP route details
# ---------------------------------------------------------------------------

def _load_lab_config(lab_name: str, podman: Podman) -> LabConfig:
    """Recover LabConfig for a running lab from container labels."""
    containers = podman.container_list(label=f"{LABEL_KEY}={lab_name}")
    if not containers:
        print(f"No containers found for lab '{lab_name}'.", file=sys.stderr)
        sys.exit(1)
    config_path = containers[0].get("Labels", {}).get("nl-config")
    if not config_path:
        print(f"Cannot find config path for lab '{lab_name}'.", file=sys.stderr)
        sys.exit(1)
    return parse_config(config_path)


def _build_ip_map(config: LabConfig) -> dict[str, str]:
    """Build mapping of bare IP address -> router name from links and networks."""
    ip_map: dict[str, str] = {}
    for link in config.links:
        for peer in link.peers:
            bare_ip = peer.ip.split("/")[0]
            ip_map[bare_ip] = peer.router
    for router_name, nets in config.networks.items():
        for net in nets:
            network = ip_network(net.prefix, strict=False)
            bare_ip = str(network.network_address + 1)
            ip_map[bare_ip] = router_name
    return ip_map


def _container_kind(image: str) -> str:
    """Determine daemon kind from container image name."""
    if "gobgp" in image:
        return "gobgp"
    elif "bird" in image:
        return "bird"
    elif "frr" in image:
        return "frr"
    return "unknown"


def _parse_ip_route_get(output: str) -> str | None:
    """Extract next-hop IP from 'ip route get' output.

    Examples:
      '172.17.11.1 via 192.168.3.2 dev eth2 src ...'  -> '192.168.3.2'
      '172.17.11.1 dev dummy0 src 172.17.11.1'        -> None (local)
    """
    m = re.search(r"via\s+(\S+)", output)
    if m:
        return m.group(1)
    return None


def _query_bgp_route(podman: Podman, container: str, kind: str, dst_ip: str) -> dict:
    """Query BGP daemon for route details towards dst_ip.

    Returns dict with keys: prefix, as_path, localpref, communities, metric
    """
    empty = {"prefix": "-", "as_path": "-", "localpref": "-", "communities": "-", "metric": "-"}
    try:
        if kind == "gobgp":
            return _query_gobgp_route(podman, container, dst_ip)
        elif kind == "bird":
            return _query_bird_route(podman, container, dst_ip)
        elif kind == "frr":
            return _query_frr_route(podman, container, dst_ip)
    except PodmanError:
        pass
    return empty


def _query_gobgp_route(podman: Podman, container: str, dst_ip: str) -> dict:
    """Query gobgp for best route to dst_ip."""
    empty = {"prefix": "-", "as_path": "-", "localpref": "-", "communities": "-", "metric": "-"}
    result = podman.container_exec(container, ["gobgp", "-j", "global", "rib", "-a", "ipv4", dst_ip])
    if not result.stdout.strip():
        return empty
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return empty
    if not data:
        return empty
    # gobgp returns a list of destinations; pick the first with best path
    dest = data[0]
    prefix = dest.get("prefix", "-")
    # Find the best path
    paths = dest.get("paths", [])
    best = paths[0] if paths else {}
    attrs = {a["type"]: a for a in best.get("attrs", [])}
    as_path_attr = attrs.get(2, {})  # type 2 = AS_PATH
    as_path_segs = as_path_attr.get("as_paths", [])
    as_nums = []
    for seg in as_path_segs:
        as_nums.extend(seg.get("asns", []))
    as_path = " ".join(str(a) for a in as_nums) if as_nums else "-"
    localpref = str(attrs.get(5, {}).get("value", "-"))  # type 5 = LOCAL_PREF
    communities_attr = attrs.get(8, {})  # type 8 = COMMUNITIES
    comms = communities_attr.get("communities", [])
    # Convert 32-bit community integers to x:y format
    communities = " ".join(f"{c >> 16}:{c & 0xFFFF}" for c in comms) if comms else "-"
    med = str(attrs.get(4, {}).get("value", "-"))  # type 4 = MULTI_EXIT_DISC
    return {"prefix": prefix, "as_path": as_path, "localpref": localpref,
            "communities": communities, "metric": med}


def _query_bird_route(podman: Podman, container: str, dst_ip: str) -> dict:
    """Query bird for best route to dst_ip."""
    empty = {"prefix": "-", "as_path": "-", "localpref": "-", "communities": "-", "metric": "-"}
    result = podman.container_exec(container, ["birdc", "show", "route", "for", dst_ip, "all"])
    if not result.stdout.strip():
        return empty
    output = result.stdout
    prefix = "-"
    as_path = "-"
    localpref = "-"
    communities = "-"
    metric = "-"
    for line in output.splitlines():
        line = line.strip()
        # First line with a prefix: "172.17.11.0/24 unicast [dc_eu_west ...]"
        if "/" in line and "unicast" in line:
            prefix = line.split()[0]
        if line.startswith("BGP.as_path:"):
            val = line.split(":", 1)[1].strip()
            as_path = val if val else "-"
        if line.startswith("BGP.local_pref:"):
            localpref = line.split(":", 1)[1].strip()
        if line.startswith("BGP.community:"):
            val = line.split(":", 1)[1].strip()
            # Bird uses (x,y) format — convert to x:y
            val = re.sub(r"\((\d+),(\d+)\)", r"\1:\2", val)
            communities = val if val else "-"
        if line.startswith("BGP.med:"):
            metric = line.split(":", 1)[1].strip()
    return {"prefix": prefix, "as_path": as_path, "localpref": localpref,
            "communities": communities, "metric": metric}


def _query_frr_route(podman: Podman, container: str, dst_ip: str) -> dict:
    """Query FRR for best route to dst_ip."""
    empty = {"prefix": "-", "as_path": "-", "localpref": "-", "communities": "-", "metric": "-"}
    result = podman.container_exec(
        container, ["vtysh", "-c", f"show bgp ipv4 unicast {dst_ip} json"])
    if not result.stdout.strip():
        return empty
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return empty
    prefix = data.get("prefix", "-")
    pfxlen = data.get("prefixLen")
    if prefix != "-" and pfxlen is not None:
        prefix = f"{prefix}/{pfxlen}"
    paths = data.get("paths", [])
    if not paths:
        return empty
    best = paths[0]
    for p in paths:
        if p.get("bestpath", {}).get("overall", False):
            best = p
            break
    aspath = best.get("aspath", {})
    as_path_str = aspath.get("string", "").strip()
    as_path = as_path_str if as_path_str else "-"
    localpref = str(best.get("locPrf", "-"))
    med = str(best.get("metric", "-"))
    comm_list = best.get("community", {})
    if isinstance(comm_list, dict):
        communities = comm_list.get("string", "-")
    elif isinstance(comm_list, list):
        communities = " ".join(str(c) for c in comm_list) if comm_list else "-"
    else:
        communities = "-"
    return {"prefix": prefix, "as_path": as_path, "localpref": localpref,
            "communities": communities, "metric": med}


def _find_router_for_ip(ip: str, ip_map: dict[str, str]) -> str | None:
    """Find which router owns a given IP address."""
    return ip_map.get(ip)


def _trace_one_direction(
    podman: Podman,
    config: LabConfig,
    ip_map: dict[str, str],
    containers: list[dict],
    src_ip: str,
    dst_ip: str,
) -> list[dict]:
    """Trace from src_ip to dst_ip, returning list of hop dicts."""
    container_map = {}
    for c in containers:
        name = c["Names"][0]
        router_name = name.removeprefix(f"nl-{config.name}-")
        container_map[router_name] = (name, _container_kind(c.get("Image", "")))

    hops = []
    current_router = _find_router_for_ip(src_ip, ip_map)
    if not current_router:
        print(f"  Could not find router for {src_ip}", file=sys.stderr)
        return hops

    visited = set()
    max_hops = 20
    while current_router and current_router not in visited and len(hops) < max_hops:
        visited.add(current_router)
        if current_router not in container_map:
            break
        container_name, kind = container_map[current_router]

        # Check if dst_ip is local to this router
        dst_is_local = _find_router_for_ip(dst_ip, ip_map) == current_router

        if dst_is_local:
            hops.append({
                "router": current_router,
                "prefix": "-", "as_path": "origin", "localpref": "-",
                "communities": "-", "metric": "-",
            })
            break

        # Get BGP route details
        route_info = _query_bgp_route(podman, container_name, kind, dst_ip)

        hops.append({
            "router": current_router,
            **route_info,
        })

        # Get next hop via ip route get
        try:
            result = podman.container_exec(container_name, ["ip", "route", "get", dst_ip])
            next_hop = _parse_ip_route_get(result.stdout)
        except PodmanError:
            break

        if not next_hop:
            break

        next_router = _find_router_for_ip(next_hop, ip_map)
        if not next_router:
            break
        current_router = next_router

    return hops


def _print_trace(direction: str, src_ip: str, dst_ip: str, hops: list[dict]) -> None:
    """Print a formatted trace table."""
    print(f"\n{direction}: {src_ip} -> {dst_ip}")
    print(f"{'HOP':<5} {'ROUTER':<20} {'PREFIX':<20} {'AS PATH':<30} {'LP':<6} {'MED':<6} {'COMMUNITIES'}")
    for i, hop in enumerate(hops, 1):
        print(f"{i:<5} {hop['router']:<20} {hop['prefix']:<20} "
              f"{hop['as_path']:<30} {hop['localpref']:<6} {hop['metric']:<6} {hop['communities']}")


def trace_path(lab_name: str, src_ip: str, dst_ip: str) -> None:
    """Trace path between two IPs, showing BGP route details at each hop."""
    podman = Podman()
    config = _load_lab_config(lab_name, podman)

    containers = podman.container_list(label=f"{LABEL_KEY}={lab_name}")
    running = [c for c in containers if c.get("State") == "running"]
    if not running:
        print(f"No running containers in lab '{lab_name}'.")
        return

    ip_map = _build_ip_map(config)

    # Forward trace
    forward_hops = _trace_one_direction(podman, config, ip_map, running, src_ip, dst_ip)
    _print_trace("Forward path", src_ip, dst_ip, forward_hops)

    # Backward trace
    backward_hops = _trace_one_direction(podman, config, ip_map, running, dst_ip, src_ip)
    _print_trace("Backward path", dst_ip, src_ip, backward_hops)

    # Compare paths
    forward_routers = [h["router"] for h in forward_hops]
    backward_routers = [h["router"] for h in backward_hops]
    backward_reversed = list(reversed(backward_routers))

    if forward_routers == backward_reversed:
        print(f"\nPaths are symmetric.")
    else:
        print(f"\n!! Forward and backward paths differ!")
        print(f"   Forward:  {' -> '.join(forward_routers)}")
        print(f"   Backward: {' -> '.join(backward_routers)}")
