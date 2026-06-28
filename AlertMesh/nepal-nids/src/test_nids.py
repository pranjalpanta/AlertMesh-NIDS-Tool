import nids


def test_detection_rules_include_core_services():
    assert {"SSH", "FTP", "TELNET", "RDP", "SMB", "NETBIOS", "ICMP"}.issubset(
        nids.DETECTION_RULES
    )


def test_active_alert_categories_are_normalized():
    assert nids.normalize_attack_type("Port Scan Detected (scan)") == "PORT_SCAN"
    assert nids.normalize_attack_type("Brute Force Attack - SSH") == "BRUTE_FORCE"
    assert nids.normalize_attack_type("ICMP Probe / Ping Activity") == "ICMP_ATTACK"
