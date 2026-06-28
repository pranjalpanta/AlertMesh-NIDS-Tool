import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("XDG_CACHE_HOME", os.path.join(BASE_DIR, ".cache"))
sys.path.insert(0, ".")

from scapy.all import ICMP, IP, TCP, UDP

import nids


def reset_trackers():
    nids.PORT_SCAN_TRACKER.clear()
    nids.STEALTH_SCAN_TRACKER.clear()
    nids.connection_tracker.clear()
    nids.event_cooldown_tracker.clear()
    nids.icmp_tracker.clear()
    nids.seen_connection_attempts.clear()
    nids.PROTECTED_NETWORKS = nids.parse_protected_networks("192.168.1.0/24")


def test_http_payload_is_out_of_scope():
    pkt = IP(src="8.8.8.8", dst="192.168.1.10") / TCP(sport=44444, dport=80, flags="PA")
    alerts = nids.process_packet(pkt)
    assert not alerts, alerts


def test_icmp_probe_alert():
    reset_trackers()
    alerts = []
    for _ in range(nids.ICMP_THRESHOLD):
        pkt = IP(src="8.8.8.8", dst="192.168.1.10") / ICMP(type=8)
        alerts.extend(nids.process_packet(pkt))
    assert any(alert["attack_type"] == "ICMP_ATTACK" for alert in alerts), alerts


def test_icmp_echo_replies_do_not_trigger_probe_alert():
    reset_trackers()
    alerts = []
    for _ in range(nids.ICMP_THRESHOLD):
        pkt = IP(src="8.8.8.8", dst="192.168.1.10") / ICMP(type=0)
        alerts.extend(nids.process_packet(pkt))
    assert not alerts, alerts


def test_icmp_echo_replies_from_protected_host_infer_probe_alert():
    reset_trackers()
    alerts = []
    for _ in range(nids.ICMP_THRESHOLD):
        pkt = IP(src="192.168.1.10", dst="8.8.8.8") / ICMP(type=0)
        alerts.extend(nids.process_packet(pkt))
    assert any(alert["attack_type"] == "ICMP_ATTACK" for alert in alerts), alerts
    assert alerts[-1]["src_ip"] == "8.8.8.8"
    assert alerts[-1]["dst_ip"] == "192.168.1.10"


def test_single_icmp_ping_is_not_alert():
    reset_trackers()
    pkt = IP(src="8.8.8.8", dst="192.168.1.10") / ICMP(type=8)
    alerts = nids.process_packet(pkt)
    assert not alerts, alerts


def test_subnet_broadcast_destination_is_not_alerted():
    reset_trackers()
    alerts = []
    for _ in range(nids.ICMP_THRESHOLD):
        pkt = IP(src="8.8.8.8", dst="192.168.1.255") / ICMP(type=8)
        alerts.extend(nids.process_packet(pkt))
    assert not alerts, alerts


def test_single_host_protected_network_is_alerted():
    reset_trackers()
    nids.PROTECTED_NETWORKS = nids.parse_protected_networks("192.168.1.106/32")
    alerts = []
    for index, dport in enumerate(range(20, 30), start=1):
        pkt = IP(src="8.8.8.8", dst="192.168.1.106") / TCP(sport=40000 + index, dport=dport, flags="S")
        alerts.extend(nids.process_packet(pkt))
    assert any(alert["attack_type"] == "PORT_SCAN" for alert in alerts), alerts


def test_multicast_source_is_not_alerted():
    reset_trackers()
    alerts = []
    for index, dport in enumerate(range(20, 30), start=1):
        pkt = IP(src="224.0.0.1", dst="192.168.1.10") / TCP(sport=40000 + index, dport=dport, flags="S")
        alerts.extend(nids.process_packet(pkt))
    assert not alerts, alerts


def test_ssh_brute_force_alert():
    reset_trackers()
    alerts = []
    for sport in range(50000, 50005):
        pkt = IP(src="8.8.8.8", dst="192.168.1.10") / TCP(sport=sport, dport=22, flags="S")
        alerts.extend(nids.process_packet(pkt))
    assert any(alert["attack_type"] == "BRUTE_FORCE" for alert in alerts), alerts


def test_retransmitted_syn_does_not_count_as_brute_force():
    reset_trackers()
    alerts = []
    pkt = IP(src="8.8.8.8", dst="192.168.1.10") / TCP(sport=50000, dport=22, flags="S")
    for _ in range(nids.DETECTION_RULES["SSH"]["brute_force_threshold"]):
        alerts.extend(nids.process_packet(pkt))
    assert not any(alert["attack_type"] == "BRUTE_FORCE" for alert in alerts), alerts


def test_port_scan_alert():
    reset_trackers()
    alerts = []
    for index, dport in enumerate(range(20, 30), start=1):
        pkt = IP(src="8.8.8.8", dst="192.168.1.10") / TCP(sport=40000 + index, dport=dport, flags="S")
        alerts.extend(nids.process_packet(pkt))
    assert any(alert["attack_type"] == "PORT_SCAN" for alert in alerts), alerts


def test_high_ephemeral_ports_do_not_trigger_port_scan():
    reset_trackers()
    alerts = []
    for index, dport in enumerate(range(51000, 51015), start=1):
        pkt = IP(src="149.154.167.91", dst="192.168.1.106") / TCP(sport=443, dport=dport, flags="S")
        alerts.extend(nids.process_packet(pkt))
    assert not any(alert["attack_type"] == "PORT_SCAN" for alert in alerts), alerts


def test_outbound_client_syns_are_not_inferred_as_inbound_scans():
    reset_trackers()
    alerts = []
    for index, sport in enumerate(range(51000, 51015), start=1):
        pkt = IP(src="192.168.1.106", dst="149.154.167.91") / TCP(sport=sport, dport=443, flags="S")
        alerts.extend(nids.process_packet(pkt))
    assert not any(
        alert["attack_type"] == "PORT_SCAN" and alert["src_ip"] == "149.154.167.91"
        for alert in alerts
    ), alerts


def test_tcp_reset_responses_from_protected_host_infer_port_scan():
    reset_trackers()
    alerts = []
    for index, sport in enumerate(range(20, 30), start=1):
        pkt = IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=sport, dport=40000 + index, flags="RA")
        alerts.extend(nids.process_packet(pkt))
    assert any(alert["attack_type"] == "PORT_SCAN" for alert in alerts), alerts
    assert alerts[-1]["src_ip"] == "8.8.8.8"
    assert alerts[-1]["dst_ip"] == "192.168.1.10"


def test_udp_does_not_trigger_generic_port_scan():
    reset_trackers()
    alerts = []
    for index, dport in enumerate(range(20, 40), start=1):
        pkt = IP(src="8.8.8.8", dst="192.168.1.10") / UDP(sport=40000 + index, dport=dport)
        alerts.extend(nids.process_packet(pkt))
    assert not any(alert["attack_type"] == "PORT_SCAN" for alert in alerts), alerts


def test_unprotected_destination_is_not_alerted():
    reset_trackers()
    alerts = []
    for index, dport in enumerate(range(20, 30), start=1):
        pkt = IP(src="8.8.8.8", dst="93.184.216.34") / TCP(sport=40000 + index, dport=dport, flags="S")
        alerts.extend(nids.process_packet(pkt))
    assert not alerts, alerts


def test_trusted_source_is_not_alerted():
    reset_trackers()
    old_trusted = list(nids.TRUSTED_SOURCE_NETWORKS)
    old_reject_trusted = nids.REJECT_TRUSTED_SOURCES
    try:
        nids.TRUSTED_SOURCE_NETWORKS = nids.parse_protected_networks("8.8.8.8/32")
        nids.REJECT_TRUSTED_SOURCES = True
        alerts = []
        for index, dport in enumerate(range(20, 30), start=1):
            pkt = IP(src="8.8.8.8", dst="192.168.1.10") / TCP(sport=40000 + index, dport=dport, flags="S")
            alerts.extend(nids.process_packet(pkt))
        assert not alerts, alerts
    finally:
        nids.TRUSTED_SOURCE_NETWORKS = old_trusted
        nids.REJECT_TRUSTED_SOURCES = old_reject_trusted


def test_resolve_capture_interfaces_keeps_explicit_name():
    assert nids.resolve_capture_interfaces("Wi-Fi") == "Wi-Fi"


def test_resolve_capture_interfaces_supports_auto(monkeypatch):
    class Iface:
        def __init__(self, name, description):
            self.name = name
            self.description = description

    monkeypatch.setattr(
        nids,
        "get_working_ifaces",
        lambda: [
            Iface("Wi-Fi", "Wireless"),
            Iface("VMware Network Adapter VMnet8", "VMware"),
            Iface("Loopback Pseudo-Interface 1", "Software Loopback Interface"),
            Iface("Local Area Connection* 10", "WAN Miniport (IP)"),
        ],
    )

    assert nids.resolve_capture_interfaces("auto") == [
        "Wi-Fi",
        "VMware Network Adapter VMnet8",
    ]


def test_first_protected_host_supports_single_host_network():
    reset_trackers()
    nids.PROTECTED_NETWORKS = nids.parse_protected_networks("192.168.1.106/32")
    assert nids.first_protected_host() == "192.168.1.106"


def test_demo_once_uses_normal_alert_pipeline(monkeypatch):
    reset_trackers()
    nids.PROTECTED_NETWORKS = nids.parse_protected_networks("192.168.1.106/32")
    stored = []
    monkeypatch.setattr(nids, "log_alert", lambda alert: stored.append(alert))

    produced = nids.run_demo_once(target_ip="192.168.1.106", source_ip="192.168.1.77")

    assert produced >= 5
    assert {alert["attack_type"] for alert in stored}.issuperset({
        "BRUTE_FORCE",
        "EXPOSED_SERVICE_ACCESS",
        "ICMP_ATTACK",
        "PORT_SCAN",
    })


def test_stealth_fin_scan_alert():
    reset_trackers()
    alerts = []
    for index in range(nids.STEALTH_SCAN_THRESHOLD):
        pkt = IP(src="8.8.8.8", dst="192.168.1.10") / TCP(sport=41000 + index, dport=20 + index, flags="F")
        alerts.extend(nids.process_packet(pkt))
    assert any("FIN Stealth Scan" in alert["msg"] for alert in alerts), alerts


def test_stealth_null_scan_alert():
    reset_trackers()
    alerts = []
    for index in range(nids.STEALTH_SCAN_THRESHOLD):
        pkt = IP(src="8.8.8.8", dst="192.168.1.10") / TCP(sport=42000 + index, dport=20 + index, flags=0)
        alerts.extend(nids.process_packet(pkt))
    assert any("NULL Stealth Scan" in alert["msg"] for alert in alerts), alerts


def test_stealth_xmas_scan_alert():
    reset_trackers()
    alerts = []
    for index in range(nids.STEALTH_SCAN_THRESHOLD):
        pkt = IP(src="8.8.8.8", dst="192.168.1.10") / TCP(sport=43000 + index, dport=20 + index, flags="FPU")
        alerts.extend(nids.process_packet(pkt))
    assert any("XMAS Stealth Scan" in alert["msg"] for alert in alerts), alerts


def test_syn_ack_responses_from_protected_service_infer_exposed_service_access():
    reset_trackers()
    alerts = []
    for index in range(nids.EXPOSED_SERVICE_THRESHOLD):
        pkt = IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=445, dport=50000 + index, flags="SA")
        alerts.extend(nids.process_packet(pkt))
    assert any(alert["attack_type"] == "EXPOSED_SERVICE_ACCESS" for alert in alerts), alerts


def test_oversized_icmp_alerts_immediately():
    reset_trackers()
    pkt = IP(src="8.8.8.8", dst="192.168.1.10") / ICMP(type=8) / ("X" * nids.PING_OF_DEATH_MIN_BYTES)
    alerts = nids.process_packet(pkt)
    assert any("Oversized ICMP" in alert["msg"] for alert in alerts), alerts


def test_protected_source_port_scan_is_alerted():
    reset_trackers()
    alerts = []
    for index, dport in enumerate(range(20, 30), start=1):
        pkt = IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=40000 + index, dport=dport, flags="S")
        alerts.extend(nids.process_packet(pkt))
    assert any(alert["attack_type"] == "PORT_SCAN" for alert in alerts), alerts


def test_exposed_service_tracker_survives_cleanup_window():
    reset_trackers()
    nids.connection_tracker["service_probe:8.8.8.8:192.168.1.10:RDP"] = [
        nids.time.time() - 40
    ]
    nids.cleanup_trackers(force=True)
    assert nids.connection_tracker["service_probe:8.8.8.8:192.168.1.10:RDP"]


def main():
    test_http_payload_is_out_of_scope()
    test_single_icmp_ping_is_not_alert()
    test_icmp_probe_alert()
    test_ssh_brute_force_alert()
    test_port_scan_alert()
    test_udp_does_not_trigger_generic_port_scan()
    test_protected_source_port_scan_is_alerted()
    test_exposed_service_tracker_survives_cleanup_window()
    print("network attack vector tests passed")


if __name__ == "__main__":
    main()
