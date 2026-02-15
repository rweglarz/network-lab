import json
import sys
from pathlib import Path

from network_lab.bgp_config import generate_config
from ipaddress import ip_network

from network_lab.config import LabConfig
from network_lab.podman import Podman, PodmanError


LABEL_KEY = "nl-lab"

# Map kind name to config mount path inside the container
KIND_CONFIG = {
    "gobgp": "/etc/gobgp/gobgp.conf",
    "bird": "/etc/bird/bird.conf",
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
    router_networks: dict[str, list[tuple[str, dict]]] = {r.name: [] for r in config.routers}
    for i, link in enumerate(config.links):
        net_name = config.network_name(i)
        for peer in link.peers:
            router_networks[peer.router].append((net_name, {"interface": peer.interface, "ip": peer.ip}))

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

        print(f"Starting container {container_name}...")
        try:
            podman.container_run(
                image,
                name=container_name,
                hostname=router.name,
                labels=lab_labels,
                cap_add=["NET_ADMIN", "NET_RAW"],
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
        for idx, (_, peer_data) in enumerate(router_networks[router.name]):
            # eth0 = mgmt, so link interfaces start at eth1
            iface = f"eth{idx + 1}"
            ip = peer_data["ip"]

            print(f"  Configuring {iface} on {container_name} with {ip}...")
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

        # Strip lab prefix from container name for display
        display_name = container_name.removeprefix(f"nl-{lab_name}-")

        if not peers:
            print(f"{display_name:<30} {'(no peers)':<18} {'':<12} {'':<15}")
        else:
            for peer in peers:
                print(f"{display_name:<30} {peer['neighbor']:<18} {str(peer['remote_asn']):<12} {peer['state']:<15}")
