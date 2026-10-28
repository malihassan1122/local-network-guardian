from __future__ import annotations

import ipaddress
import socket
from typing import Iterable

DEFAULT_PORTS = [22, 80, 443, 3389, 445, 8080, 5900, 53]


def normalize_cidr(cidr: str | None, ip: str | None) -> str:
    if cidr:
        ipaddress.ip_network(cidr, strict=False)
        return cidr
    if ip:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 4:
            return str(ipaddress.ip_network(f"{ip}/24", strict=False))
        raise ValueError("IPv6 scanning is not supported in this release.")
    raise ValueError("Either --cidr or --ip must be provided.")


def build_scan_targets(cidr: str) -> list[str]:
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = list(network.hosts())
    # Skip the network and broadcast addresses for safety and clarity.
    if len(hosts) > 1:
        hosts = hosts[1:-1]
    return [str(host) for host in hosts]


def port_is_open(ip: str, port: int, timeout: float) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        return result == 0
    finally:
        sock.close()


def scan_network(cidr: str | None = None, ip: str | None = None, ports: Iterable[int] | None = None, timeout: float = 0.35) -> list[dict]:
    network = normalize_cidr(cidr, ip)
    targets = build_scan_targets(network)
    scan_ports = list(ports) if ports is not None else DEFAULT_PORTS

    findings: list[dict] = []
    for host in targets:
        open_ports = [port for port in scan_ports if port_is_open(host, port, timeout)]
        if not open_ports:
            continue
        findings.append(
            {
                "ip": host,
                "open_ports": open_ports,
            }
        )
    return findings
