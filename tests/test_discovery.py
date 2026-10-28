from __future__ import annotations

from .models import DeviceFinding
from .security_checks import build_security_notes, classify_risk, security_recommendations


def build_device_findings(raw_findings: list[dict]) -> list[DeviceFinding]:
    devices: list[DeviceFinding] = []
    for item in raw_findings:
        open_ports = item.get("open_ports", [])
        risk = classify_risk(open_ports)
        notes = build_security_notes(open_ports)
        recs = security_recommendations(open_ports)
        devices.append(
            DeviceFinding(
                ip=item["ip"],
                open_ports=open_ports,
                risk=risk,
                notes=notes,
                recommendations=recs,
            )
        )
    return devices


def render_report(raw_findings: list[dict]) -> str:
    devices = build_device_findings(raw_findings)
    lines: list[str] = ["Local Network Guardian scan report", "=" * 34]

    if not devices:
        return lines[0] + "\nNo open services were found during the scan."

    for device in devices:
        lines.append(f"Device {device.ip}")
        lines.append(f"  Risk: {device.risk}")
        lines.append(f"  Open ports: {', '.join(str(port) for port in device.open_ports) if device.open_ports else 'None'}")
        if device.notes:
            lines.append("  Notes:")
            for note in device.notes:
                lines.append(f"    - {note}")
        if device.recommendations:
            lines.append("  Recommendations:")
            for rec in device.recommendations:
                lines.append(f"    - {rec}")
        lines.append("")

    return "\n".join(lines).rstrip()
