# local-network-guardian

Local Network Guardian is a safe, permission-aware local network scanner. It helps you discover devices on your LAN, check which ports are open, and flag risky services that may require hardening.

Features:
- Detect probable local network range
- Scan common service ports safely and locally
- Classify risk from exposed ports
- Print actionable hardening recommendations
- Small CLI first version designed for home or office networks

Important:
- Only run this on networks you own or have explicit permission to audit.
- This tool is designed for discovery and security posture checks, not exploitation.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m local_network_guardian --cidr 192.168.1.0/24 --ports 22,80,443,8080,3389,445,5900
```

## Example output

```text
Local network scan results for 192.168.1.0/24
Device 192.168.1.12 - Windows Desktop
  - Open ports: 80, 445
  - Risk: HIGH
  - Notes: SMB is exposed; ensure firewall and account lockout settings are enabled.

Recommended actions:
  1. Restrict SMB to trusted devices only.
  2. Close port 445 unless required.
  3. Enable automatic updates and firewall logging.
```

## Project structure

```text
.
├── README.md
├── pyproject.toml
├── requirements.txt
├── src/
│   └── local_network_guardian/
│       ├── __init__.py
│       ├── __main__.py
│       ├── config.py
│       ├── discovery.py
│       ├── security_checks.py
│       ├── models.py
│       └── reporting.py
├── tests/
│   ├── test_discovery.py
│   └── test_security_checks.py
└── .gitignore
```

## License

MIT
