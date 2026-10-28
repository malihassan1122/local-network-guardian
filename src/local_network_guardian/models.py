from __future__ import annotations

from .config import HIGH_RISK_PORTS, MEDIUM_RISK_PORTS, RISK_RULES


def classify_risk(open_ports: list[int]) -> str:
    if not open_ports:
        return "LOW"

    if any(port in HIGH_RISK_PORTS for port in open_ports):
        return "HIGH"
    if any(port in MEDIUM_RISK_PORTS for port in open_ports):
        return "MEDIUM"
    return "LOW"


def build_security_notes(open_ports: list[int]) -> list[str]:
    notes: list[str] = []
    for port in sorted(open_ports):
        message = RISK_RULES.get(port)
        if message:
            notes.append(f"Port {port}: {message}")
    return notes


def security_recommendations(open_ports: list[int]) -> list[str]:
    recommendations: list[str] = []
    if not open_ports:
        return ["No obvious exposed services found on the scanned addresses."]

    if 445 in open_ports or 3389 in open_ports or 5900 in open_ports:
        recommendations.append("Close administrative ports unless they are explicitly required for business use.")
    if 22 in open_ports:
        recommendations.append("Restrict SSH to trusted IP ranges and prefer key-based authentication only.")
    if 80 in open_ports or 443 in open_ports:
        recommendations.append("Confirm that web services are running on the intended hosts and enforce TLS where necessary.")
    if not recommendations:
        recommendations.append("Review service exposure and ensure firewall rules limit access to approved devices.")
    return recommendations
