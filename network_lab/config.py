from dataclasses import dataclass, field
from enum import Enum
from ipaddress import ip_network
from pathlib import Path

import yaml


@dataclass
class Device:
    router: str
    interface: str | None
    ip: str


@dataclass
class Link:
    devices: list[Device]
    type: str | None = None
    graph_pos: list[float] | None = None


@dataclass
class Router:
    name: str
    asn: int | None = None
    kind: str | None = None
    graph_pos: list[float] | None = None


@dataclass
class Network:
    prefix: str
    community: str | None = None


@dataclass
class Kind:
    name: str
    image: str


class BgpSessionType(Enum):
    MESH = "mesh"
    PEERS = "peers"
    RR = "rr"


@dataclass
class BgpSession:
    type: BgpSessionType
    routers: list[str]
    rr_server: str | None = None
    rr_clients: list[str] = field(default_factory=list)
    as_prepend: list[int] = field(default_factory=list)
    graph_pos: list[float] | None = None


@dataclass
class LabConfig:
    name: str
    config_path: str
    kinds: list[Kind] = field(default_factory=list)
    routers: list[Router] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    bgp_sessions: list[BgpSession] = field(default_factory=list)
    networks: dict[str, list[Network]] = field(default_factory=dict)

    @property
    def prefix(self) -> str:
        return f"nl-{self.name}"

    def container_name(self, router_name: str) -> str:
        return f"{self.prefix}-{router_name}"

    def network_name(self, index: int) -> str:
        return f"{self.prefix}-link{index}"

    def kind_for_router(self, router_name: str) -> Kind:
        router = next((r for r in self.routers if r.name == router_name), None)
        if router and router.kind:
            kind = next((k for k in self.kinds if k.name == router.kind), None)
            if kind:
                return kind
        if self.kinds:
            return self.kinds[0]
        raise ValueError(f"No kind defined for router {router_name}")

    def image_for_router(self, router_name: str) -> str:
        return self.kind_for_router(router_name).image


def normalize_lab_name(name: str) -> str:
    return name.replace(" ", "-").lower()


def parse_config(path: str) -> LabConfig:
    config_path = str(Path(path).resolve())
    with open(path) as f:
        raw = yaml.safe_load(f)

    lab_name = normalize_lab_name(raw["lab"]["name"])

    kinds = []
    for kind_entry in raw.get("kinds", []):
        for kind_name, kind_data in kind_entry.items():
            kinds.append(Kind(name=kind_name, image=kind_data["image"]))

    routers = []
    for router_name, router_data in raw.get("routers", {}).items():
        routers.append(Router(
            name=router_name,
            asn=router_data.get("asn"),
            kind=router_data.get("kind"),
            graph_pos=router_data.get("graph_pos"),
        ))

    links = []
    for link_entry in raw.get("links", []):
        cidr = link_entry.get("cidr")
        raw_devices = link_entry.get("devices", {})
        sorted_names = sorted(raw_devices.keys())

        host_iter = None
        prefix_len = None
        if cidr:
            network = ip_network(cidr, strict=False)
            prefix_len = network.prefixlen
            host_iter = iter(network.hosts())

        devices = []
        for dev_name in sorted_names:
            dev_data = raw_devices[dev_name] or {}
            if "ip" in dev_data:
                ip = dev_data["ip"]
            elif host_iter is not None:
                host_ip = next(host_iter)
                ip = f"{host_ip}/{prefix_len}"
            else:
                raise ValueError(f"Device '{dev_name}' has no IP and link has no cidr")
            devices.append(Device(
                router=dev_name,
                interface=dev_data.get("interface"),
                ip=ip,
            ))
        link_type = link_entry.get("type")
        graph_pos = link_entry.get("graph_pos")
        links.append(Link(devices=devices, type=link_type, graph_pos=graph_pos))

    bgp_sessions = []
    for bgp_entry in raw.get("bgp", []):
        if "mesh" in bgp_entry:
            bgp_sessions.append(BgpSession(
                type=BgpSessionType.MESH,
                routers=bgp_entry["mesh"],
                as_prepend=bgp_entry.get("as_prepend", []),
                graph_pos=bgp_entry.get("graph_pos"),
            ))
        elif "peers" in bgp_entry:
            bgp_sessions.append(BgpSession(
                type=BgpSessionType.PEERS,
                routers=bgp_entry["peers"],
                as_prepend=bgp_entry.get("as_prepend", []),
                graph_pos=bgp_entry.get("graph_pos"),
            ))
        elif "rr_server" in bgp_entry:
            server = bgp_entry["rr_server"]
            clients = bgp_entry.get("rr_clients", [])
            bgp_sessions.append(BgpSession(
                type=BgpSessionType.RR,
                routers=[server] + clients,
                rr_server=server,
                rr_clients=clients,
                as_prepend=bgp_entry.get("as_prepend", []),
                graph_pos=bgp_entry.get("graph_pos"),
            ))

    networks: dict[str, list[Network]] = {}
    for router_name, net_entries in raw.get("networks", {}).items():
        networks[router_name] = [
            Network(
                prefix=entry["prefix"],
                community=str(entry["community"]) if "community" in entry else None,
            )
            for entry in net_entries
        ]

    return LabConfig(
        name=lab_name,
        config_path=config_path,
        kinds=kinds,
        routers=routers,
        links=links,
        bgp_sessions=bgp_sessions,
        networks=networks,
    )
