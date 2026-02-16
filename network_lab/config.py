from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Peer:
    router: str
    interface: str | None
    ip: str


@dataclass
class Link:
    peers: list[Peer]
    as_prepend: list[int] = field(default_factory=list)
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


@dataclass
class LabConfig:
    name: str
    config_path: str
    kinds: list[Kind] = field(default_factory=list)
    routers: list[Router] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
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
        peers = []
        for peer_name, peer_data in link_entry["peers"].items():
            peers.append(Peer(
                router=peer_name,
                interface=peer_data.get("interface"),
                ip=peer_data["ip"],
            ))
        as_prepend = link_entry.get("as_prepend", [])
        graph_pos = link_entry.get("graph_pos")
        links.append(Link(peers=peers, as_prepend=as_prepend, graph_pos=graph_pos))

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
        networks=networks,
    )
