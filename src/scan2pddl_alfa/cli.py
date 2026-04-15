from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from ipaddress import ip_interface
from pathlib import Path
from typing import Any, Iterable
from xml.etree import ElementTree


_INVALID_IDENTIFIER = re.compile(r"[^a-zA-Z0-9_]+")
_VERSION_NUMBERS = re.compile(r"\d+")


@dataclass(frozen=True, order=True)
class ProductEntry:
    token: str
    version: tuple[str, str, str] | None = None


@dataclass(frozen=True, order=True)
class ServiceEntry:
    protocol: str
    product_token: str


@dataclass
class HostEntry:
    name: str
    ip: str | None = None
    networks: set[str] = field(default_factory=set)
    products: set[ProductEntry] = field(default_factory=set)
    services: set[ServiceEntry] = field(default_factory=set)
    keys: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        self._register_key(self.name)
        if self.ip:
            self._register_key(self.ip)

    def rename(self, value: str) -> None:
        self.name = sanitize_identifier(value)
        self._register_key(value)
        self._register_key(self.name)

    def matches(self, value: str) -> bool:
        raw = value.strip().lower()
        sanitized = sanitize_identifier(value)
        return raw in self.keys or sanitized in self.keys

    def _register_key(self, value: str) -> None:
        self.keys.add(value.strip().lower())
        self.keys.add(sanitize_identifier(value))


@dataclass
class InventoryMetadata:
    goal_host: str | None = None
    attacker_networks: list[str] = field(default_factory=list)
    attacker_host: str | None = None
    agent_name: str | None = None
    domain_name: str | None = None
    problem_name: str | None = None


@dataclass
class PddlBuildConfig:
    goal_host: str
    attacker_networks: list[str]
    problem_name: str
    domain_name: str = "alfa_chains"
    attacker_host: str = "attacker_host"
    attacker_privilege: str = "ROOT_PRIVILEGES"
    goal_privilege: str = "ROOT_PRIVILEGES"
    agent_name: str = "agent"


def sanitize_identifier(value: str) -> str:
    cleaned = _INVALID_IDENTIFIER.sub("_", value.strip().lower())
    cleaned = cleaned.strip("_")
    return cleaned or "unknown"


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _parse_cpe(cpe: str) -> tuple[str, str, str, str | None] | None:
    cpe = cpe.strip()
    if cpe.startswith("cpe:2.3:"):
        fields = cpe.split(":")
        if len(fields) < 6:
            return None
        part, vendor, product, version = fields[2], fields[3], fields[4], fields[5]
        return part, vendor, product, None if version in {"*", "-", ""} else version

    if cpe.startswith("cpe:/"):
        fields = cpe[5:].split(":")
        if len(fields) < 4:
            return None
        part, vendor, product, version = fields[0], fields[1], fields[2], fields[3]
        return part, vendor, product, None if version in {"*", "-", ""} else version

    return None


def _guess_vendor_and_product(label: str | None) -> tuple[str, str] | None:
    if not label:
        return None

    pieces = [sanitize_identifier(part) for part in label.split() if part.strip()]
    pieces = [part for part in pieces if part]
    if not pieces:
        return None
    if len(pieces) == 1:
        return "unknown", pieces[0]
    return pieces[0], "_".join(pieces[1:])


def _version_triplet(version: str | None) -> tuple[str, str, str] | None:
    if not version or version in {"*", "-", ""}:
        return None

    numbers = _VERSION_NUMBERS.findall(version)
    if not numbers:
        return None

    major = int(numbers[0])
    minor = int(numbers[1]) if len(numbers) > 1 else 0
    patch = int(numbers[2]) if len(numbers) > 2 else 0
    return f"ma{major}", f"mi{minor}", f"pa{patch}"


def _product_entry_from_fields(
    *,
    part: str,
    vendor: str,
    product: str,
    version: str | None,
) -> ProductEntry | None:
    if not vendor or not product:
        return None

    token = f"{sanitize_identifier(part)}--{sanitize_identifier(vendor)}--{sanitize_identifier(product)}"
    return ProductEntry(token=token, version=_version_triplet(version))


def _product_entries_from_cpes(cpes: Iterable[str]) -> list[ProductEntry]:
    entries: list[ProductEntry] = []
    for cpe in cpes:
        parsed = _parse_cpe(cpe)
        if parsed is None:
            continue
        part, vendor, product, version = parsed
        entry = _product_entry_from_fields(
            part=part,
            vendor=vendor,
            product=product,
            version=version,
        )
        if entry is not None:
            entries.append(entry)
    return entries


def _product_entry_from_text(
    *,
    label: str | None,
    version: str | None,
    part: str,
) -> ProductEntry | None:
    guess = _guess_vendor_and_product(label)
    if guess is None:
        return None
    vendor, product = guess
    return _product_entry_from_fields(
        part=part,
        vendor=vendor,
        product=product,
        version=version,
    )


def _infer_network_name(ip_value: str, prefix: int) -> str:
    network = ip_interface(f"{ip_value}/{prefix}").network
    return sanitize_identifier(f"net_{network.network_address}_{network.prefixlen}")


def _first_open_state(port_element: ElementTree.Element) -> bool:
    state = port_element.find("state")
    return state is not None and state.get("state") == "open"


def _parse_service_entries(service_element: ElementTree.Element | None) -> list[ProductEntry]:
    if service_element is None:
        return []

    cpes = [item.text.strip() for item in service_element.findall("cpe") if item.text]
    entries = _product_entries_from_cpes(cpes)
    if entries:
        return entries

    product_label = service_element.get("product") or service_element.get("name")
    version = service_element.get("version")
    fallback = _product_entry_from_text(label=product_label, version=version, part="a")
    return [fallback] if fallback is not None else []


def _parse_os_entries(host_element: ElementTree.Element) -> list[ProductEntry]:
    cpes = [item.text.strip() for item in host_element.findall(".//os//cpe") if item.text]
    entries = _product_entries_from_cpes(cpes)
    if entries:
        return entries

    osclass = host_element.find(".//os//osclass")
    if osclass is None:
        return []

    label = " ".join(filter(None, [osclass.get("vendor"), osclass.get("osfamily")]))
    version = osclass.get("osgen")
    fallback = _product_entry_from_text(label=label, version=version, part="o")
    return [fallback] if fallback is not None else []


def parse_nmap_xml(path: Path, subnet_prefix: int = 24) -> tuple[list[HostEntry], InventoryMetadata]:
    root = ElementTree.parse(path).getroot()
    hosts: list[HostEntry] = []

    for host_element in root.findall("host"):
        status = host_element.find("status")
        if status is not None and status.get("state") != "up":
            continue

        address = host_element.find("./address[@addrtype='ipv4']")
        if address is None:
            address = host_element.find("./address")
        if address is None:
            continue

        ip_value = address.get("addr")
        if not ip_value:
            continue

        hostname = host_element.find("./hostnames/hostname")
        display_name = hostname.get("name") if hostname is not None else ip_value
        host = HostEntry(name=sanitize_identifier(display_name), ip=ip_value)
        host.networks.add(_infer_network_name(ip_value, subnet_prefix))

        for entry in _parse_os_entries(host_element):
            host.products.add(entry)

        for port in host_element.findall("./ports/port"):
            if not _first_open_state(port):
                continue

            protocol = (port.get("protocol") or "").upper()
            for entry in _parse_service_entries(port.find("service")):
                host.products.add(entry)
                if protocol in {"TCP", "UDP"}:
                    host.services.add(ServiceEntry(protocol=protocol, product_token=entry.token))

        hosts.append(host)

    return hosts, InventoryMetadata(problem_name=path.stem)


def _coerce_product_entry(payload: Any, default_part: str = "a") -> ProductEntry | None:
    if isinstance(payload, str):
        entries = _product_entries_from_cpes([payload])
        if entries:
            return entries[0]
        return _product_entry_from_text(label=payload, version=None, part=default_part)

    if not isinstance(payload, dict):
        return None

    cpe = payload.get("cpe")
    if isinstance(cpe, str):
        entries = _product_entries_from_cpes([cpe])
        if entries:
            return entries[0]

    part = str(payload.get("part", default_part))
    vendor = payload.get("vendor")
    product = payload.get("product") or payload.get("name")
    version = payload.get("version")

    if vendor and product:
        return _product_entry_from_fields(
            part=part,
            vendor=str(vendor),
            product=str(product),
            version=str(version) if version is not None else None,
        )

    label = payload.get("label") or product
    if label:
        return _product_entry_from_text(
            label=str(label),
            version=str(version) if version is not None else None,
            part=part,
        )

    return None


def parse_json_inventory(path: Path) -> tuple[list[HostEntry], InventoryMetadata]:
    payload = _load_json(path)

    if isinstance(payload, list):
        raw_hosts = payload
        metadata = InventoryMetadata(problem_name=path.stem)
    elif isinstance(payload, dict):
        raw_hosts = payload.get("hosts")
        if not isinstance(raw_hosts, list):
            raise ValueError("JSON input must contain a top-level 'hosts' list.")
        metadata = InventoryMetadata(
            goal_host=payload.get("goal_host"),
            attacker_networks=list(payload.get("attacker_networks", [])),
            attacker_host=payload.get("attacker_host"),
            agent_name=payload.get("agent_name"),
            domain_name=payload.get("domain_name"),
            problem_name=payload.get("problem_name") or path.stem,
        )
    else:
        raise ValueError("JSON input must be an object or a list of hosts.")

    hosts: list[HostEntry] = []
    for raw_host in raw_hosts:
        if not isinstance(raw_host, dict):
            raise ValueError("Every host entry in JSON input must be an object.")

        raw_name = raw_host.get("name") or raw_host.get("hostname") or raw_host.get("ip")
        if not raw_name:
            raise ValueError("Each host entry requires 'name', 'hostname', or 'ip'.")

        host = HostEntry(
            name=sanitize_identifier(str(raw_name)),
            ip=str(raw_host.get("ip")) if raw_host.get("ip") is not None else None,
        )

        for network in raw_host.get("networks", []):
            host.networks.add(sanitize_identifier(str(network)))

        for product in raw_host.get("products", []):
            entry = _coerce_product_entry(product, default_part="a")
            if entry is not None:
                host.products.add(entry)

        for service in raw_host.get("services", []):
            if not isinstance(service, dict):
                continue
            protocol = str(service.get("protocol", "tcp")).upper()
            entry = _coerce_product_entry(service, default_part="a")
            if entry is not None:
                host.products.add(entry)
                if protocol in {"TCP", "UDP"}:
                    host.services.add(ServiceEntry(protocol=protocol, product_token=entry.token))

        hosts.append(host)

    return hosts, metadata


def _load_overlay(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}

    payload = _load_json(path)
    if not isinstance(payload, dict):
        raise ValueError("Overlay JSON must be an object.")
    return payload


def _find_host(hosts: list[HostEntry], key: str) -> HostEntry | None:
    for host in hosts:
        if host.matches(key):
            return host
    return None


def apply_overlay(hosts: list[HostEntry], overlay: dict[str, Any]) -> InventoryMetadata:
    host_aliases = overlay.get("host_aliases", {})
    if isinstance(host_aliases, dict):
        for key, alias in host_aliases.items():
            host = _find_host(hosts, str(key))
            if host is not None:
                host.rename(str(alias))

    host_networks = overlay.get("host_networks", {})
    if isinstance(host_networks, dict):
        for key, networks in host_networks.items():
            host = _find_host(hosts, str(key))
            if host is None:
                continue
            if isinstance(networks, list):
                host.networks = {sanitize_identifier(str(item)) for item in networks}

    host_products = overlay.get("host_products", {})
    if isinstance(host_products, dict):
        for key, products in host_products.items():
            host = _find_host(hosts, str(key))
            if host is None or not isinstance(products, list):
                continue
            for payload in products:
                entry = _coerce_product_entry(payload)
                if entry is not None:
                    host.products.add(entry)

    host_services = overlay.get("host_services", {})
    if isinstance(host_services, dict):
        for key, services in host_services.items():
            host = _find_host(hosts, str(key))
            if host is None or not isinstance(services, list):
                continue
            for payload in services:
                if not isinstance(payload, dict):
                    continue
                protocol = str(payload.get("protocol", "tcp")).upper()
                entry = _coerce_product_entry(payload)
                if entry is None:
                    continue
                host.products.add(entry)
                if protocol in {"TCP", "UDP"}:
                    host.services.add(ServiceEntry(protocol=protocol, product_token=entry.token))

    return InventoryMetadata(
        goal_host=overlay.get("goal_host"),
        attacker_networks=list(overlay.get("attacker_networks", [])),
        attacker_host=overlay.get("attacker_host"),
        agent_name=overlay.get("agent_name"),
        domain_name=overlay.get("domain_name"),
        problem_name=overlay.get("problem_name"),
    )


def _merge_metadata(primary: InventoryMetadata, secondary: InventoryMetadata) -> InventoryMetadata:
    return InventoryMetadata(
        goal_host=secondary.goal_host or primary.goal_host,
        attacker_networks=secondary.attacker_networks or primary.attacker_networks,
        attacker_host=secondary.attacker_host or primary.attacker_host,
        agent_name=secondary.agent_name or primary.agent_name,
        domain_name=secondary.domain_name or primary.domain_name,
        problem_name=secondary.problem_name or primary.problem_name,
    )


def _resolve_goal_host(hosts: list[HostEntry], value: str) -> str:
    host = _find_host(hosts, value)
    if host is None:
        raise ValueError(f"Goal host '{value}' was not found in the parsed inventory.")
    return host.name


def _object_lines(values: list[str], type_name: str) -> list[str]:
    if not values:
        return []
    return [f"    {' '.join(values)} - {type_name}"]


def render_pddl_problem(hosts: list[HostEntry], config: PddlBuildConfig) -> str:
    if not hosts:
        raise ValueError("No hosts were parsed from the input inventory.")

    attacker_host = sanitize_identifier(config.attacker_host)
    agent_name = sanitize_identifier(config.agent_name)
    attacker_networks = [sanitize_identifier(value) for value in config.attacker_networks]

    host_names = [attacker_host] + sorted(host.name for host in hosts)
    network_names = sorted({name for host in hosts for name in host.networks} | set(attacker_networks))
    product_names = sorted({entry.token for host in hosts for entry in host.products})
    major_names = sorted(
        {
            entry.version[0]
            for host in hosts
            for entry in host.products
            if entry.version is not None
        }
    )
    minor_names = sorted(
        {
            entry.version[1]
            for host in hosts
            for entry in host.products
            if entry.version is not None
        }
    )
    patch_names = sorted(
        {
            entry.version[2]
            for host in hosts
            for entry in host.products
            if entry.version is not None
        }
    )

    lines = [
        f"(define (problem {sanitize_identifier(config.problem_name)})",
        f"  (:domain {sanitize_identifier(config.domain_name)})",
        "  (:objects",
    ]

    lines.extend(_object_lines(host_names, "Host"))
    lines.extend(_object_lines([agent_name], "Agent"))
    lines.extend(_object_lines(network_names, "Network"))
    lines.extend(_object_lines(["LOW_PRIVILEGES", "HIGH_PRIVILEGES", "ROOT_PRIVILEGES"], "Privilege"))
    lines.extend(_object_lines(product_names, "Product"))
    lines.extend(_object_lines(major_names, "Major"))
    lines.extend(_object_lines(minor_names, "Minor"))
    lines.extend(_object_lines(patch_names, "Patch"))
    lines.append("  )")
    lines.append("  (:init")
    lines.append(f"    (is_compromised {attacker_host} {agent_name} {config.attacker_privilege})")

    for network_name in attacker_networks:
        lines.append(f"    (connected_to_network {attacker_host} {network_name})")

    for host in sorted(hosts, key=lambda item: item.name):
        if host.ip:
            lines.append(f"    ;; {host.name} ({host.ip})")
        else:
            lines.append(f"    ;; {host.name}")

        for network_name in sorted(host.networks):
            lines.append(f"    (connected_to_network {host.name} {network_name})")

        product_tokens = sorted({entry.token for entry in host.products})
        for product_name in product_tokens:
            lines.append(f"    (has_product {host.name} {product_name})")

        versions = sorted(
            {
                (entry.token, entry.version[0], entry.version[1], entry.version[2])
                for entry in host.products
                if entry.version is not None
            }
        )
        for product_name, major_name, minor_name, patch_name in versions:
            lines.append(
                f"    (has_version {host.name} {product_name} {major_name} {minor_name} {patch_name})"
            )

        for service in sorted(host.services):
            predicate = "TCP_listen" if service.protocol == "TCP" else "UDP_listen"
            lines.append(f"    ({predicate} {host.name} {service.product_token})")

    lines.append("  )")
    lines.append("  (:goal")
    lines.append(f"    (is_compromised {config.goal_host} {agent_name} {config.goal_privilege})")
    lines.append("  )")
    lines.append(")")
    return "\n".join(lines) + "\n"


def build_pddl_problem(
    input_path: Path,
    *,
    input_format: str = "auto",
    overlay_path: Path | None = None,
    goal_host: str | None = None,
    attacker_networks: list[str] | None = None,
    attacker_host: str | None = None,
    agent_name: str | None = None,
    domain_name: str | None = None,
    problem_name: str | None = None,
    subnet_prefix: int = 24,
) -> str:
    selected_format = input_format.lower()
    if selected_format == "auto":
        selected_format = "json" if input_path.suffix.lower() == ".json" else "nmap-xml"

    if selected_format == "nmap-xml":
        hosts, metadata = parse_nmap_xml(input_path, subnet_prefix=subnet_prefix)
    elif selected_format == "json":
        hosts, metadata = parse_json_inventory(input_path)
    else:
        raise ValueError("Unsupported input format. Use auto, nmap-xml, or json.")

    overlay_metadata = apply_overlay(hosts, _load_overlay(overlay_path))
    metadata = _merge_metadata(metadata, overlay_metadata)

    resolved_goal_host = goal_host or metadata.goal_host
    if not resolved_goal_host:
        raise ValueError("Provide --goal-host or define goal_host in the input/overlay.")

    resolved_attacker_networks = attacker_networks or metadata.attacker_networks
    if not resolved_attacker_networks:
        raise ValueError(
            "Provide at least one --attacker-network or define attacker_networks in the input/overlay."
        )

    config = PddlBuildConfig(
        goal_host=_resolve_goal_host(hosts, resolved_goal_host),
        attacker_networks=[sanitize_identifier(value) for value in resolved_attacker_networks],
        attacker_host=attacker_host or metadata.attacker_host or "attacker_host",
        agent_name=agent_name or metadata.agent_name or "agent",
        domain_name=domain_name or metadata.domain_name or "alfa_chains",
        problem_name=problem_name or metadata.problem_name or input_path.stem,
    )
    return render_pddl_problem(hosts, config)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scan2pddl-alfa",
        description="Convert Nmap XML or normalized JSON host inventories into ALFA-Chains-style PDDL problem files.",
    )
    parser.add_argument("input", type=Path, help="Path to an Nmap XML file or normalized JSON inventory.")
    parser.add_argument(
        "--format",
        choices=["auto", "nmap-xml", "json"],
        default="auto",
        help="Input format. Defaults to auto-detection based on the file extension.",
    )
    parser.add_argument(
        "--overlay",
        type=Path,
        help="Optional JSON overlay with host_networks, attacker_networks, goal_host, and host aliases.",
    )
    parser.add_argument(
        "--goal-host",
        help="Target host that should be compromised in the goal state.",
    )
    parser.add_argument(
        "--attacker-network",
        action="append",
        dest="attacker_networks",
        help="Repeatable attacker entry network, for example dmz.",
    )
    parser.add_argument(
        "--attacker-host",
        default=None,
        help="Name to use for the external attacker host object. Defaults to attacker_host.",
    )
    parser.add_argument(
        "--agent-name",
        default=None,
        help="Name to use for the agent object. Defaults to agent.",
    )
    parser.add_argument(
        "--domain-name",
        default=None,
        help="PDDL domain name. Defaults to alfa_chains.",
    )
    parser.add_argument(
        "--problem-name",
        default=None,
        help="Problem name written into the generated PDDL file.",
    )
    parser.add_argument(
        "--subnet-prefix",
        type=int,
        default=24,
        help="CIDR prefix used to infer network membership from host IP addresses when no overlay is provided.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to write the generated .pddl file. If omitted, the problem is printed to stdout.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        problem = build_pddl_problem(
            args.input,
            input_format=args.format,
            overlay_path=args.overlay,
            goal_host=args.goal_host,
            attacker_networks=args.attacker_networks,
            attacker_host=args.attacker_host,
            agent_name=args.agent_name,
            domain_name=args.domain_name,
            problem_name=args.problem_name,
            subnet_prefix=args.subnet_prefix,
        )
    except ValueError as exc:
        parser.exit(status=2, message=f"error: {exc}\n")

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(problem, encoding="utf-8")
    else:
        print(problem, end="")


if __name__ == "__main__":
    main()
