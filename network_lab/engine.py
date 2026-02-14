import sys

from network_lab.config import LabConfig
from network_lab.podman import Podman, PodmanError


LABEL_KEY = "nl-lab"


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

        print(f"Starting container {container_name}...")
        try:
            podman.container_run(
                image,
                name=container_name,
                hostname=router.name,
                labels=lab_labels,
                cap_add=["NET_ADMIN"],
                network=mgmt_net,
                command=["sleep", "infinity"],
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
