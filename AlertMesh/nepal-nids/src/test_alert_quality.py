import os
import sqlite3
import tempfile

import alert_analysis
import database
import geo_utils
import nids
import snort_ingest


PROTECTED = alert_analysis.parse_networks("192.168.1.0/24")


def make_alert(**overrides):
    alert = {
        "timestamp": "2026-05-21 12:00:00",
        "src_ip": "8.8.8.8",
        "dst_ip": "192.168.1.20",
        "src_port": 44444,
        "dst_port": 22,
        "protocol": "TCP",
        "attack_type": "BRUTE_FORCE",
        "severity": "HIGH",
        "signature_id": "9000005",
        "message": "NIDS: SSH Brute Force / Connection Attempts",
    }
    alert.update(overrides)
    return alert


def test_analysis_accepts_real_inbound_signature():
    decision = alert_analysis.analyze_alert(make_alert(), PROTECTED)
    assert decision.accepted, decision
    assert decision.confidence >= 55, decision


def test_cgnat_source_is_labeled_shared_address_space():
    geo_utils.COUNTRY_CACHE.clear()
    assert geo_utils.get_country_from_ip("100.127.255.165") == "Shared Address Space"


def test_geolocation_failure_cache_expires(monkeypatch):
    geo_utils.COUNTRY_CACHE.clear()
    calls = []

    def failing_get(*args, **kwargs):
        calls.append((args, kwargs))
        raise geo_utils.requests.RequestException("temporary failure")

    monkeypatch.setattr(geo_utils.requests, "get", failing_get)
    monkeypatch.setenv("GEOLOCATION_FAILURE_CACHE_SECONDS", "0")

    assert geo_utils.get_country_from_ip("8.8.8.8", geolocation_enabled=True, timeout=0.1) == "Unknown"
    assert geo_utils.get_country_from_ip("8.8.8.8", geolocation_enabled=True, timeout=0.1) == "Unknown"
    assert len(calls) == 2


def test_geolocation_success_cache_expires(monkeypatch):
    geo_utils.COUNTRY_CACHE.clear()
    responses = iter(["Firstland", "Secondland"])

    class Response:
        status_code = 200

        def __init__(self, text):
            self.text = text

    def fake_get(*args, **kwargs):
        return Response(next(responses))

    monkeypatch.setattr(geo_utils.requests, "get", fake_get)
    monkeypatch.setenv("GEOLOCATION_SUCCESS_CACHE_SECONDS", "0")

    assert geo_utils.get_country_from_ip("8.8.4.4", geolocation_enabled=True, timeout=0.1) == "Firstland"
    assert geo_utils.get_country_from_ip("8.8.4.4", geolocation_enabled=True, timeout=0.1) == "Secondland"


def test_snort_parser_labels_private_source_origin():
    sample = (
        "05/21-15:04:03.123456 [**] [1:9000005:2] NIDS: SSH Brute Force / Connection Attempts [**] "
        "[Classification: Attempted Administrator Privilege Gain] [Priority: 1] "
        "{TCP} 192.168.1.69:53122 -> 192.168.1.10:22"
    )
    alert = snort_ingest.parse_fast_alert(sample)
    assert alert["country"] == "Private Network"


def test_analysis_rejects_out_of_scope_destination():
    decision = alert_analysis.analyze_alert(make_alert(dst_ip="93.184.216.34"), PROTECTED)
    assert not decision.accepted, decision
    assert "outside PROTECTED_NETWORKS" in decision.note, decision


def test_analysis_rejects_protected_broadcast_destination():
    decision = alert_analysis.analyze_alert(make_alert(dst_ip="192.168.1.255"), PROTECTED)
    assert not decision.accepted, decision
    assert "network boundary" in decision.note, decision


def test_analysis_accepts_single_host_protected_destination():
    protected = alert_analysis.parse_networks("192.168.1.106/32")
    decision = alert_analysis.analyze_alert(make_alert(dst_ip="192.168.1.106"), protected)
    assert decision.accepted, decision


def test_analysis_rejects_multicast_source_address():
    decision = alert_analysis.analyze_alert(make_alert(src_ip="224.0.0.1"), PROTECTED)
    assert not decision.accepted, decision
    assert "valid host address" in decision.note, decision


def test_analysis_rejects_unknown_attack_type_by_default():
    decision = alert_analysis.analyze_alert(
        make_alert(attack_type="UNKNOWN_EVENT", signature_id=None),
        PROTECTED,
    )
    assert not decision.accepted, decision
    assert "unrecognized attack type" in decision.note, decision


def test_analysis_can_allow_unknown_attack_types_for_custom_rules():
    old_value = os.environ.get("ALERT_ALLOW_UNKNOWN_ATTACK_TYPES")
    try:
        os.environ["ALERT_ALLOW_UNKNOWN_ATTACK_TYPES"] = "true"
        decision = alert_analysis.analyze_alert(
            make_alert(attack_type="CUSTOM_RULE", signature_id=None),
            PROTECTED,
        )
        assert decision.accepted, decision
    finally:
        if old_value is None:
            os.environ.pop("ALERT_ALLOW_UNKNOWN_ATTACK_TYPES", None)
        else:
            os.environ["ALERT_ALLOW_UNKNOWN_ATTACK_TYPES"] = old_value


def test_analysis_allows_protected_loopback_destination():
    protected = alert_analysis.parse_networks("127.0.0.0/8")
    decision = alert_analysis.analyze_alert(make_alert(dst_ip="127.0.0.1"), protected)
    assert decision.accepted, decision


def test_analysis_rejects_unprotected_loopback_destination():
    decision = alert_analysis.analyze_alert(make_alert(dst_ip="127.0.0.1"), PROTECTED)
    assert not decision.accepted, decision
    assert "loopback destination" in decision.note, decision


def test_analysis_rejects_ignored_source():
    old_ignore = os.environ.get("IGNORE_SOURCE_IPS")
    try:
        os.environ["IGNORE_SOURCE_IPS"] = "8.8.8.8/32"
        decision = alert_analysis.analyze_alert(make_alert(), PROTECTED)
        assert not decision.accepted, decision
        assert "IGNORE_SOURCE_IPS" in decision.note, decision
    finally:
        if old_ignore is None:
            os.environ.pop("IGNORE_SOURCE_IPS", None)
        else:
            os.environ["IGNORE_SOURCE_IPS"] = old_ignore


def test_strict_mode_rejects_unknown_alert_source():
    old_strict = os.environ.get("ALERT_STRICT_MODE")
    try:
        os.environ["ALERT_STRICT_MODE"] = "true"
        decision = alert_analysis.analyze_alert(make_alert(source="unknown"), PROTECTED)
        assert not decision.accepted, decision
        assert "unknown alert source" in decision.note, decision
    finally:
        if old_strict is None:
            os.environ.pop("ALERT_STRICT_MODE", None)
        else:
            os.environ["ALERT_STRICT_MODE"] = old_strict


def test_strict_mode_rejects_unallowlisted_snort_sid():
    old_strict = os.environ.get("ALERT_STRICT_MODE")
    try:
        os.environ["ALERT_STRICT_MODE"] = "true"
        decision = alert_analysis.analyze_alert(
            make_alert(source="snort", signature_id="9999999"),
            PROTECTED,
        )
        assert not decision.accepted, decision
        assert "not allowlisted" in decision.note, decision
    finally:
        if old_strict is None:
            os.environ.pop("ALERT_STRICT_MODE", None)
        else:
            os.environ["ALERT_STRICT_MODE"] = old_strict


def test_rejected_snort_alerts_are_audited():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    old_networks = snort_ingest.PROTECTED_NETWORKS
    old_email_enabled = snort_ingest.EMAIL_ENABLED
    old_db_env = os.environ.get("ALERTMESH_DB_PATH")
    old_strict = os.environ.get("ALERT_STRICT_MODE")
    try:
        os.environ["ALERTMESH_DB_PATH"] = db_path
        os.environ["ALERT_STRICT_MODE"] = "true"
        snort_ingest.PROTECTED_NETWORKS = PROTECTED
        snort_ingest.EMAIL_ENABLED = False
        snort_ingest.initialize_database()
        sample = """05/21-15:04:03.123456 [**] [1:9999999:1] NIDS: Forged Alert [**]
[Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 8.8.8.8:53122 -> 192.168.1.10:22
"""
        inserted, skipped, rejected = snort_ingest.ingest_text(sample)
        assert inserted == 0, (inserted, skipped, rejected)
        assert skipped == 0, (inserted, skipped, rejected)
        assert rejected == 1, (inserted, skipped, rejected)

        connection = sqlite3.connect(db_path)
        count = connection.execute("SELECT COUNT(*) FROM rejected_alerts").fetchone()[0]
        note = connection.execute("SELECT rejection_note FROM rejected_alerts").fetchone()[0]
        connection.close()
        assert count == 1, count
        assert "not allowlisted" in note, note
    finally:
        snort_ingest.PROTECTED_NETWORKS = old_networks
        snort_ingest.EMAIL_ENABLED = old_email_enabled
        if old_db_env is None:
            os.environ.pop("ALERTMESH_DB_PATH", None)
        else:
            os.environ["ALERTMESH_DB_PATH"] = old_db_env
        if old_strict is None:
            os.environ.pop("ALERT_STRICT_MODE", None)
        else:
            os.environ["ALERT_STRICT_MODE"] = old_strict
        try:
            os.remove(db_path)
        except OSError:
            pass


def test_snort_ingest_deduplicates_alerts():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    old_networks = snort_ingest.PROTECTED_NETWORKS
    old_email_enabled = snort_ingest.EMAIL_ENABLED
    old_db_env = os.environ.get("ALERTMESH_DB_PATH")
    try:
        os.environ["ALERTMESH_DB_PATH"] = db_path
        snort_ingest.PROTECTED_NETWORKS = PROTECTED
        snort_ingest.EMAIL_ENABLED = False
        snort_ingest.initialize_database()
        sample = """05/21-15:04:03.123456 [**] [1:9000005:2] NIDS: SSH Brute Force / Connection Attempts [**]
[Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 8.8.8.8:53122 -> 192.168.1.10:22

05/21-15:04:04.123456 [**] [1:9000005:2] NIDS: SSH Brute Force / Connection Attempts [**]
[Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 8.8.8.8:53122 -> 192.168.1.10:22
"""
        inserted, skipped, rejected = snort_ingest.ingest_text(sample)
        assert inserted == 1, (inserted, skipped, rejected)
        assert skipped == 1, (inserted, skipped, rejected)
        assert rejected == 0, (inserted, skipped, rejected)

        connection = sqlite3.connect(db_path)
        count = connection.execute("SELECT COUNT(*) FROM intrusion_logs").fetchone()[0]
        confidence = connection.execute("SELECT confidence FROM intrusion_logs").fetchone()[0]
        connection.close()
        assert count == 1, count
        assert confidence >= 55, confidence
    finally:
        snort_ingest.PROTECTED_NETWORKS = old_networks
        snort_ingest.EMAIL_ENABLED = old_email_enabled
        if old_db_env is None:
            os.environ.pop("ALERTMESH_DB_PATH", None)
        else:
            os.environ["ALERTMESH_DB_PATH"] = old_db_env
        try:
            os.remove(db_path)
        except OSError:
            pass


def test_snort_ingest_keeps_partial_trailing_alert_for_next_poll():
    alert_fd, alert_path = tempfile.mkstemp(suffix=".ids")
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    state_fd, state_path = tempfile.mkstemp(suffix=".offset")
    os.close(alert_fd)
    os.close(db_fd)
    os.close(state_fd)

    old_networks = snort_ingest.PROTECTED_NETWORKS
    old_email_enabled = snort_ingest.EMAIL_ENABLED
    old_db_env = os.environ.get("ALERTMESH_DB_PATH")
    old_state_file = snort_ingest.STATE_FILE
    try:
        os.environ["ALERTMESH_DB_PATH"] = db_path
        snort_ingest.PROTECTED_NETWORKS = PROTECTED
        snort_ingest.EMAIL_ENABLED = False
        snort_ingest.STATE_FILE = snort_ingest.Path(state_path)
        snort_ingest.initialize_database()

        first_chunk = "05/21-15:04:03.123456 [**] [1:9000005:2] NIDS: SSH Brute Force"
        second_chunk = """ / Connection Attempts [**]
[Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 8.8.8.8:53122 -> 192.168.1.10:22
"""
        with open(alert_path, "w", encoding="utf-8") as handle:
            handle.write(first_chunk)

        inserted, skipped, rejected, offset = snort_ingest.ingest_file_once(snort_ingest.Path(alert_path))
        assert (inserted, skipped, rejected, offset) == (0, 0, 0, 0)

        with open(alert_path, "a", encoding="utf-8") as handle:
            handle.write(second_chunk)

        inserted, skipped, rejected, offset = snort_ingest.ingest_file_once(snort_ingest.Path(alert_path))
        assert inserted == 1, (inserted, skipped, rejected, offset)
        assert skipped == 0, (inserted, skipped, rejected, offset)
        assert rejected == 0, (inserted, skipped, rejected, offset)
    finally:
        snort_ingest.PROTECTED_NETWORKS = old_networks
        snort_ingest.EMAIL_ENABLED = old_email_enabled
        snort_ingest.STATE_FILE = old_state_file
        if old_db_env is None:
            os.environ.pop("ALERTMESH_DB_PATH", None)
        else:
            os.environ["ALERTMESH_DB_PATH"] = old_db_env
        for path in (alert_path, db_path, state_path):
            try:
                os.remove(path)
            except OSError:
                pass


def test_snort_ingest_resets_offset_after_rotation():
    alert_fd, alert_path = tempfile.mkstemp(suffix=".ids")
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    state_fd, state_path = tempfile.mkstemp(suffix=".offset")
    os.close(alert_fd)
    os.close(db_fd)
    os.close(state_fd)

    old_networks = snort_ingest.PROTECTED_NETWORKS
    old_email_enabled = snort_ingest.EMAIL_ENABLED
    old_db_env = os.environ.get("ALERTMESH_DB_PATH")
    old_state_file = snort_ingest.STATE_FILE
    try:
        os.environ["ALERTMESH_DB_PATH"] = db_path
        snort_ingest.PROTECTED_NETWORKS = PROTECTED
        snort_ingest.EMAIL_ENABLED = False
        snort_ingest.STATE_FILE = snort_ingest.Path(state_path)
        snort_ingest.initialize_database()

        first_alert = """05/21-15:04:03.123456 [**] [1:9000005:2] NIDS: SSH Brute Force / Connection Attempts [**]
[Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 8.8.8.8:53122 -> 192.168.1.10:22
"""
        second_alert = """05/21-15:07:03.123456 [**] [1:9000006:2] NIDS: Telnet Access Attempt [**]
[Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 8.8.4.4:53122 -> 192.168.1.10:23
"""
        with open(alert_path, "w", encoding="utf-8") as handle:
            handle.write(first_alert)
        inserted, skipped, rejected, offset = snort_ingest.ingest_file_once(snort_ingest.Path(alert_path))
        assert inserted == 1, (inserted, skipped, rejected, offset)

        os.remove(alert_path)
        with open(alert_path, "w", encoding="utf-8") as handle:
            handle.write(second_alert)
        inserted, skipped, rejected, offset = snort_ingest.ingest_file_once(snort_ingest.Path(alert_path))
        assert inserted == 1, (inserted, skipped, rejected, offset)
    finally:
        snort_ingest.PROTECTED_NETWORKS = old_networks
        snort_ingest.EMAIL_ENABLED = old_email_enabled
        snort_ingest.STATE_FILE = old_state_file
        if old_db_env is None:
            os.environ.pop("ALERTMESH_DB_PATH", None)
        else:
            os.environ["ALERTMESH_DB_PATH"] = old_db_env
        for path in (alert_path, db_path, state_path):
            try:
                os.remove(path)
            except OSError:
                pass


def test_snort_parser_accepts_ipv6_endpoints():
    sample = (
        "05/21-15:04:03.123456 [**] [1:9000005:2] NIDS: SSH Brute Force / Connection Attempts [**] "
        "[Classification: Attempted Administrator Privilege Gain] [Priority: 1] "
        "{TCP} [2001:db8::1]:53122 -> [fd00::10]:22"
    )
    alert = snort_ingest.parse_fast_alert(sample)
    assert alert["src_ip"] == "2001:db8::1"
    assert alert["src_port"] == 53122
    assert alert["dst_ip"] == "fd00::10"
    assert alert["dst_port"] == 22


def test_port_scan_dedup_ignores_destination_port():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    old_db_env = os.environ.get("ALERTMESH_DB_PATH")
    try:
        os.environ["ALERTMESH_DB_PATH"] = db_path
        database.initialize_database()
        decision = alert_analysis.AlertDecision(True, 80, ["test"])
        first_alert = make_alert(
            attack_type="PORT_SCAN",
            dst_port=20,
            signature_id=None,
            message="Port Scan Detected",
        )
        second_alert = make_alert(
            attack_type="PORT_SCAN",
            dst_port=21,
            signature_id=None,
            message="Port Scan Detected",
        )
        connection = database.get_db_connection()
        try:
            database.insert_intrusion_alert(connection, first_alert, decision)
            connection.commit()
            assert alert_analysis.alert_is_duplicate(connection, second_alert)
        finally:
            connection.close()
    finally:
        if old_db_env is None:
            os.environ.pop("ALERTMESH_DB_PATH", None)
        else:
            os.environ["ALERTMESH_DB_PATH"] = old_db_env
        try:
            os.remove(db_path)
        except OSError:
            pass


def test_snort_email_success_sets_cooldown(monkeypatch):
    alert = make_alert(source="snort")
    decision = alert_analysis.AlertDecision(True, 80, ["test"])

    calls = []

    def fake_send_message(*args, **kwargs):
        calls.append((args, kwargs))
        return True

    try:
        snort_ingest.email_cooldown.clear()
        monkeypatch.setattr(snort_ingest, "send_email_message", fake_send_message)

        sent = snort_ingest.send_email_alert(alert, decision)
        second = snort_ingest.send_email_alert(alert, decision)

        assert sent is True
        assert second is False
        assert len(calls) == 1
        assert snort_ingest.email_cooldown
    finally:
        snort_ingest.email_cooldown.clear()


def test_snort_email_cooldown_uses_destination_port():
    old_cooldown = dict(snort_ingest.email_cooldown)
    try:
        first = make_alert(source="snort", dst_port=22)
        second = make_alert(source="snort", dst_port=23)
        snort_ingest.email_cooldown.clear()
        snort_ingest.email_cooldown[snort_ingest.email_cooldown_key(first)] = snort_ingest.time.time()

        assert not snort_ingest.should_send_email(first)
        assert snort_ingest.should_send_email(second)
    finally:
        snort_ingest.email_cooldown.clear()
        snort_ingest.email_cooldown.update(old_cooldown)


def test_python_nids_email_cooldown_uses_alert_target_and_type():
    old_cooldown = dict(nids.alert_cooldown_tracker)
    try:
        nids.alert_cooldown_tracker.clear()
        first = {
            "src_ip": "8.8.8.8",
            "dst_ip": "192.168.1.10",
            "dst_port": 22,
            "attack_type": "BRUTE_FORCE",
        }
        second = {
            "src_ip": "8.8.8.8",
            "dst_ip": "192.168.1.20",
            "dst_port": 3389,
            "attack_type": "EXPOSED_SERVICE_ACCESS",
        }
        nids.alert_cooldown_tracker[nids.alert_cooldown_key(first)] = nids.time.time()

        assert not nids.should_send_alert(first)
        assert nids.should_send_alert(second)
    finally:
        nids.alert_cooldown_tracker.clear()
        nids.alert_cooldown_tracker.update(old_cooldown)


def test_python_nids_email_success_sends_message(monkeypatch):
    alert = make_alert(msg="email success", proto="TCP")
    calls = []
    old_cooldown = dict(nids.alert_cooldown_tracker)
    try:
        nids.alert_cooldown_tracker.clear()

        def fake_send_message(subject, text):
            calls.append((subject, text))
            return True

        monkeypatch.setattr(nids, "send_email_message", fake_send_message)

        sent = nids.send_email_alert(alert, "Nepal")

        assert sent is True
        assert len(calls) == 1
        assert "AlertMesh" in calls[0][0]
        assert "email success" in calls[0][1]
        assert nids.alert_cooldown_tracker
    finally:
        nids.alert_cooldown_tracker.clear()
        nids.alert_cooldown_tracker.update(old_cooldown)


def test_python_nids_response_action_runs_only_after_store_accepts(monkeypatch):
    alert = make_alert(msg="test alert", proto="TCP")
    calls = []
    fd, log_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)

    try:
        monkeypatch.setattr(nids, "LOG_FILE", log_path)
        monkeypatch.setattr(nids, "send_email_alert", lambda current_alert, country: None)
        monkeypatch.setattr(nids, "store_alert", lambda current_alert: None)
        monkeypatch.setattr(nids, "take_response_action", lambda current_alert: calls.append(current_alert))
        nids.log_alert(alert)
        assert calls == []

        monkeypatch.setattr(nids, "store_alert", lambda current_alert: "Unknown")
        nids.log_alert(alert)
        assert calls == [alert]
    finally:
        try:
            os.remove(log_path)
        except OSError:
            pass


if __name__ == "__main__":
    test_analysis_accepts_real_inbound_signature()
    test_cgnat_source_is_labeled_shared_address_space()
    test_snort_parser_labels_private_source_origin()
    test_analysis_rejects_out_of_scope_destination()
    test_analysis_rejects_ignored_source()
    test_strict_mode_rejects_unknown_alert_source()
    test_strict_mode_rejects_unallowlisted_snort_sid()
    test_rejected_snort_alerts_are_audited()
    test_snort_ingest_deduplicates_alerts()
    test_snort_ingest_keeps_partial_trailing_alert_for_next_poll()
    test_snort_ingest_resets_offset_after_rotation()
    test_snort_parser_accepts_ipv6_endpoints()
    test_port_scan_dedup_ignores_destination_port()
    print("alert quality tests passed")

