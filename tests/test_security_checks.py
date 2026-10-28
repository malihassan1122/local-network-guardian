from local_network_guardian.discovery import build_scan_targets, normalize_cidr


def test_normalize_cidr_with_explicit_cidr():
    assert normalize_cidr("192.168.1.0/24", None) == "192.168.1.0/24"


def test_normalize_cidr_with_ip_uses_24_bit_mask():
    assert normalize_cidr(None, "192.168.1.42") == "192.168.1.0/24"


def test_build_scan_targets_excludes_network_and_broadcast_hosts():
    targets = build_scan_targets("192.168.1.0/30")
    assert targets == ["192.168.1.1", "192.168.1.2"]
