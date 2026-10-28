from __future__ import annotations

DEFAULT_PORTS = [22, 80, 443, 3389, 445, 8080, 5900, 53]

RISK_RULES = {
    22: "SSH is exposed; restrict access to trusted IPs or use key-based authentication.",
    80: "HTTP is open; verify that only required services are exposed.",
    443: "HTTPS is open; ensure certificates and TLS settings are current.",
    445: "SMB is exposed; close it unless strictly required. It often indicates high exposure.",
    3389: "RDP is exposed; restrict access with MFA or firewall rules.",
    5900: "VNC is exposed; restrict access to trusted internal networks only.",
    8080: "A web app is exposed on a non-standard port; confirm it is expected and hardened.",
    53: "DNS is exposed; ensure recursive access is limited to trusted networks.",
}

HIGH_RISK_PORTS = {22, 445, 3389, 5900}
MEDIUM_RISK_PORTS = {80, 443, 8080, 53}
