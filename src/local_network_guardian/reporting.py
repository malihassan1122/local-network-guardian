from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DeviceFinding:
    ip: str
    open_ports: list[int] = field(default_factory=list)
    risk: str = "LOW"
    notes: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
