from __future__ import annotations

import argparse
import sys
from pathlib import Path

from local_network_guardian.discovery import scan_network
from local_network_guardian.reporting import render_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Scan a local network range and identify risky services for hardening. "
            "Run only on networks you own or are authorized to audit."
        )
    )
    parser.add_argument(
        "--cidr",
        default=None,
        help="CIDR range to scan, such as 192.168.1.0/24",
    )
    parser.add_argument(
        "--ip",
        default=None,
        help="Single host IP to scan (used when CIDR is not provided)",
    )
    parser.add_argument(
        "--ports",
        default="22,80,443,3389,445,8080,5900,53",
        help="Comma-separated list of ports to probe",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.35,
        help="Socket timeout in seconds per host/port attempt",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    port_list = [int(part.strip()) for part in args.ports.split(",") if part.strip()]
    if not port_list:
        print("No ports provided for scanning.", file=sys.stderr)
        return 2

    try:
        findings = scan_network(
            cidr=args.cidr,
            ip=args.ip,
            ports=port_list,
            timeout=args.timeout,
        )
    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2

    report = render_report(findings)
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
