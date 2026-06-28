import os
import queue
import tempfile

import pytest
import alert_analysis
import app as app_module
import database
from scapy.all import IP, TCP


def drain_alert_queue():
    while True:
        try:
            app_module.ALERT_QUEUE.get_nowait()
            app_module.ALERT_QUEUE.task_done()
        except queue.Empty:
            return


def test_client_ip_ignores_forwarded_for_by_default():
    with app_module.app.test_request_context(
        "/login",
        headers={"X-Forwarded-For": "1.2.3.4"},
        environ_base={"REMOTE_ADDR": "5.6.7.8"},
    ):
        assert app_module.get_client_ip() == "5.6.7.8"


def test_client_ip_only_trusts_forwarded_for_from_trusted_proxy():
    old_trust = app_module.TRUST_PROXY_HEADERS
    old_networks = list(app_module.TRUSTED_PROXY_NETWORKS)
    try:
        app_module.TRUST_PROXY_HEADERS = True
        app_module.TRUSTED_PROXY_NETWORKS = app_module.parse_proxy_networks("127.0.0.1/32")
        with app_module.app.test_request_context(
            "/login",
            headers={"X-Forwarded-For": "1.2.3.4"},
            environ_base={"REMOTE_ADDR": "5.6.7.8"},
        ):
            assert app_module.get_client_ip() == "5.6.7.8"

        with app_module.app.test_request_context(
            "/login",
            headers={"X-Forwarded-For": "1.2.3.4"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        ):
            assert app_module.get_client_ip() == "1.2.3.4"

        with app_module.app.test_request_context(
            "/login",
            headers={"X-Forwarded-For": "not-an-ip"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        ):
            assert app_module.get_client_ip() == "127.0.0.1"
    finally:
        app_module.TRUST_PROXY_HEADERS = old_trust
        app_module.TRUSTED_PROXY_NETWORKS = old_networks


def test_csv_cells_are_formula_safe():
    assert app_module.sanitize_csv_cell("=HYPERLINK(\"http://example.test\")").startswith("'=")
    assert app_module.sanitize_csv_cell("  @SUM(1,2)").startswith("'  @")
    assert app_module.sanitize_csv_cell("normal packet summary") == "normal packet summary"


def test_packet_exports_are_disabled_by_default():
    client = app_module.app.test_client()
    with client.session_transaction() as session:
        session["logged_in"] = True
    response = client.get("/export_csv")
    assert response.status_code == 403


def test_intrusion_data_empty_sqlite_database_returns_success():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    old_db_env = os.environ.get("ALERTMESH_DB_PATH")
    old_backend = os.environ.get("ALERTMESH_DB_BACKEND")
    old_initialized = app_module.DB_INITIALIZED
    try:
        os.environ["ALERTMESH_DB_BACKEND"] = "sqlite"
        os.environ["ALERTMESH_DB_PATH"] = db_path
        app_module.DB_INITIALIZED = False
        database.initialize_database()

        client = app_module.app.test_client()
        with client.session_transaction() as session:
            session["logged_in"] = True

        response = client.get("/intrusion_data")
        assert response.status_code == 200, response.get_data(as_text=True)
        payload = response.get_json()
        assert payload["logs"] == []
        assert payload["stats"]["filtered_total"] == 0
        assert payload["stats"]["total_today"] == 0
        assert set(payload["filter_options"]["attack_types"]).issuperset({
            "BRUTE_FORCE",
            "EXPOSED_SERVICE_ACCESS",
            "ICMP_ATTACK",
            "PORT_SCAN",
        })
    finally:
        app_module.DB_INITIALIZED = old_initialized
        if old_db_env is None:
            os.environ.pop("ALERTMESH_DB_PATH", None)
        else:
            os.environ["ALERTMESH_DB_PATH"] = old_db_env
        if old_backend is None:
            os.environ.pop("ALERTMESH_DB_BACKEND", None)
        else:
            os.environ["ALERTMESH_DB_BACKEND"] = old_backend
        try:
            os.remove(db_path)
        except OSError:
            pass


def test_system_status_reports_database_and_email(monkeypatch):
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    old_db_env = os.environ.get("ALERTMESH_DB_PATH")
    old_backend = os.environ.get("ALERTMESH_DB_BACKEND")
    old_initialized = app_module.DB_INITIALIZED
    old_error = app_module.DB_INIT_ERROR
    try:
        os.environ["ALERTMESH_DB_BACKEND"] = "sqlite"
        os.environ["ALERTMESH_DB_PATH"] = db_path
        monkeypatch.setattr(app_module.nids_detector, "EMAIL_ENABLED", True)
        monkeypatch.setattr(app_module.nids_detector, "SMTP_HOST", "smtp.example.test")
        monkeypatch.setattr(app_module.nids_detector, "SMTP_FROM", "from@example.test")
        monkeypatch.setattr(app_module.nids_detector, "SMTP_TO", ["to@example.test"])
        monkeypatch.setattr(app_module.nids_detector, "SMTP_USERNAME", "from@example.test")
        monkeypatch.setattr(app_module.nids_detector, "SMTP_PASSWORD", "password")
        app_module.DB_INITIALIZED = False
        app_module.DB_INIT_ERROR = None
        database.initialize_database()

        client = app_module.app.test_client()
        with client.session_transaction() as session:
            session["logged_in"] = True

        response = client.get("/system_status")
        assert response.status_code == 200
        payload = response.get_json()
        assert payload["database"]["backend"] == "sqlite"
        assert payload["database"]["intrusion_logs"] == 0
        assert payload["email"]["ready"] is True
        assert payload["email"]["smtp_host_set"] is True
        assert payload["email"]["smtp_to"] == ["to@example.test"]
    finally:
        app_module.DB_INITIALIZED = old_initialized
        app_module.DB_INIT_ERROR = old_error
        if old_db_env is None:
            os.environ.pop("ALERTMESH_DB_PATH", None)
        else:
            os.environ["ALERTMESH_DB_PATH"] = old_db_env
        if old_backend is None:
            os.environ.pop("ALERTMESH_DB_BACKEND", None)
        else:
            os.environ["ALERTMESH_DB_BACKEND"] = old_backend
        try:
            os.remove(db_path)
        except OSError:
            pass


def test_runtime_status_updates_payload_timestamp():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    old_db_env = os.environ.get("ALERTMESH_DB_PATH")
    old_backend = os.environ.get("ALERTMESH_DB_BACKEND")
    try:
        os.environ["ALERTMESH_DB_BACKEND"] = "sqlite"
        os.environ["ALERTMESH_DB_PATH"] = db_path
        database.initialize_database()

        database.write_runtime_status(
            "email.test",
            {
                "last_attempt": "2026-06-19 10:00:00",
                "updated_at": "2000-01-01 00:00:00",
            },
        )
        status = database.read_runtime_status("email.")["email.test"]

        assert status["updated_at"] != "2000-01-01 00:00:00"
    finally:
        if old_backend is None:
            os.environ.pop("ALERTMESH_DB_BACKEND", None)
        else:
            os.environ["ALERTMESH_DB_BACKEND"] = old_backend
        if old_db_env is None:
            os.environ.pop("ALERTMESH_DB_PATH", None)
        else:
            os.environ["ALERTMESH_DB_PATH"] = old_db_env
        try:
            os.remove(db_path)
        except OSError:
            pass


def test_email_test_route_sends_dashboard_test_alert(monkeypatch):
    captured = {}

    def fake_send(alert, country, bypass_cooldown=False):
        captured["alert"] = alert
        captured["country"] = country
        captured["bypass_cooldown"] = bypass_cooldown
        return True

    monkeypatch.setattr(app_module.nids_detector, "send_email_alert", fake_send)
    monkeypatch.setattr(app_module.nids_detector, "email_config_ready", lambda: (True, None))
    client = app_module.app.test_client()
    with client.session_transaction() as session:
        session["logged_in"] = True
        session["csrf_token"] = "test-token"

    response = client.post("/email_test", headers={"X-CSRF-Token": "test-token"})
    assert response.status_code == 200
    assert response.get_json()["sent"] is True
    assert captured["alert"]["msg"] == "AlertMesh email test alert"
    assert captured["country"] == "Local Test"
    assert captured["bypass_cooldown"] is True


def test_email_test_route_reports_failure(monkeypatch):
    def fake_send(alert, country, bypass_cooldown=False):
        return False

    monkeypatch.setattr(app_module.nids_detector, "send_email_alert", fake_send)
    monkeypatch.setattr(app_module.nids_detector, "email_config_ready", lambda: (False, "SMTP_TO is missing"))
    client = app_module.app.test_client()
    with client.session_transaction() as session:
        session["logged_in"] = True
        session["csrf_token"] = "test-token"

    response = client.post("/email_test", headers={"X-CSRF-Token": "test-token"})
    assert response.status_code == 502
    payload = response.get_json()
    assert payload["sent"] is False
    assert payload["email"]["reason"] == "SMTP_TO is missing"


def test_delete_filtered_removes_all_matching_logs():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    old_db_env = os.environ.get("ALERTMESH_DB_PATH")
    old_initialized = app_module.DB_INITIALIZED
    try:
        os.environ["ALERTMESH_DB_PATH"] = db_path
        app_module.DB_INITIALIZED = False
        database.initialize_database()
        decision = alert_analysis.AlertDecision(True, 80, ["test"])
        with database.get_db_connection() as connection:
            for index, severity in enumerate(("HIGH", "HIGH", "LOW"), start=1):
                database.insert_intrusion_alert(
                    connection,
                    {
                        "timestamp": f"2026-05-29 10:00:0{index}",
                        "src_ip": "8.8.8.8",
                        "dst_ip": "192.168.1.106",
                        "src_port": 40000 + index,
                        "dst_port": 22,
                        "protocol": "TCP",
                        "attack_type": "BRUTE_FORCE",
                        "severity": severity,
                        "country": "Unknown",
                        "detected_os": "Unknown",
                        "source": "python",
                    },
                    decision,
                )
            connection.commit()

        client = app_module.app.test_client()
        with client.session_transaction() as session:
            session["logged_in"] = True
            session["csrf_token"] = "test-token"

        response = client.post(
            "/intrusion_logs/delete",
            json={"delete_filtered": True, "filters": {"severity": "HIGH"}},
            headers={"X-CSRF-Token": "test-token"},
        )
        assert response.status_code == 200, response.get_data(as_text=True)
        assert response.get_json()["deleted"] == 2

        with database.get_db_connection() as connection:
            remaining = connection.execute("SELECT severity FROM intrusion_logs").fetchall()
        assert [row["severity"] for row in remaining] == ["LOW"]
    finally:
        app_module.DB_INITIALIZED = old_initialized
        if old_db_env is None:
            os.environ.pop("ALERTMESH_DB_PATH", None)
        else:
            os.environ["ALERTMESH_DB_PATH"] = old_db_env
        try:
            os.remove(db_path)
        except OSError:
            pass


def test_delete_filtered_requires_real_filter_or_delete_all():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    old_db_env = os.environ.get("ALERTMESH_DB_PATH")
    old_initialized = app_module.DB_INITIALIZED
    try:
        os.environ["ALERTMESH_DB_PATH"] = db_path
        app_module.DB_INITIALIZED = False
        database.initialize_database()
        decision = alert_analysis.AlertDecision(True, 80, ["test"])
        with database.get_db_connection() as connection:
            database.insert_intrusion_alert(
                connection,
                {
                    "timestamp": "2026-05-29 10:00:00",
                    "src_ip": "8.8.8.8",
                    "dst_ip": "192.168.1.106",
                    "src_port": 40001,
                    "dst_port": 22,
                    "protocol": "TCP",
                    "attack_type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "country": "Unknown",
                    "detected_os": "Unknown",
                    "source": "python",
                },
                decision,
            )
            connection.commit()

        client = app_module.app.test_client()
        with client.session_transaction() as session:
            session["logged_in"] = True
            session["csrf_token"] = "test-token"

        response = client.post(
            "/intrusion_logs/delete",
            json={"delete_filtered": True, "filters": {}},
            headers={"X-CSRF-Token": "test-token"},
        )
        assert response.status_code == 400

        response = client.post(
            "/intrusion_logs/delete",
            json={"delete_all": True},
            headers={"X-CSRF-Token": "test-token"},
        )
        assert response.status_code == 400

        response = client.post(
            "/intrusion_logs/delete",
            json={"delete_all": True, "confirm": "DELETE_ALL"},
            headers={"X-CSRF-Token": "test-token"},
        )
        assert response.status_code == 200, response.get_data(as_text=True)
        assert response.get_json()["deleted"] == 1
    finally:
        app_module.DB_INITIALIZED = old_initialized
        if old_db_env is None:
            os.environ.pop("ALERTMESH_DB_PATH", None)
        else:
            os.environ["ALERTMESH_DB_PATH"] = old_db_env
        try:
            os.remove(db_path)
        except OSError:
            pass


def test_mongodb_search_escapes_regex_metacharacters():
    query = database.mongo_filter_from_args({"q": "192.168.1.(106)+"})
    regex = query["$or"][0]["src_ip"]["$regex"]
    assert regex == r"192\.168\.1\.\(106\)\+"


def test_mongodb_uri_safety_helpers():
    assert database.mongo_uri_is_local("mongodb://localhost:27017")
    assert database.mongo_uri_is_local("mongodb://127.0.0.1:27017")
    assert not database.mongo_uri_is_local("mongodb://192.0.2.10:27017")
    assert database.mongo_uri_has_credentials("mongodb://user:pass@192.0.2.10:27017")
    assert not database.mongo_uri_has_credentials("mongodb://192.0.2.10:27017")
    assert database.redact_mongo_uri("mongodb://user:secret@192.0.2.10:27017/db") == (
        "mongodb://user:***@192.0.2.10:27017/db"
    )
    assert database.redact_mongo_uri("mongodb://user:p%40ss%3Aword@192.0.2.10:27017/db") == (
        "mongodb://user:***@192.0.2.10:27017/db"
    )


def test_dashboard_refuses_network_bind_without_real_credentials():
    old_username = os.environ.get("USERNAME")
    old_password = os.environ.get("PASSWORD")
    old_alertmesh_username = os.environ.get("ALERTMESH_USERNAME")
    old_alertmesh_password = os.environ.get("ALERTMESH_PASSWORD")
    old_secret = os.environ.get("SECRET_KEY")
    old_env_values = dict(app_module.ENV_FILE_VALUES)
    try:
        os.environ.pop("USERNAME", None)
        os.environ.pop("PASSWORD", None)
        os.environ.pop("ALERTMESH_USERNAME", None)
        os.environ.pop("ALERTMESH_PASSWORD", None)
        os.environ["SECRET_KEY"] = "strong-test-secret"
        app_module.ENV_FILE_VALUES.pop("USERNAME", None)
        app_module.ENV_FILE_VALUES.pop("PASSWORD", None)
        app_module.ENV_FILE_VALUES.pop("ALERTMESH_USERNAME", None)
        app_module.ENV_FILE_VALUES.pop("ALERTMESH_PASSWORD", None)
        with pytest.raises(RuntimeError) as exc_info:
            app_module.enforce_dashboard_security_for_host("0.0.0.0")
        assert "USERNAME and PASSWORD" in str(exc_info.value)
    finally:
        if old_username is None:
            os.environ.pop("USERNAME", None)
        else:
            os.environ["USERNAME"] = old_username
        if old_password is None:
            os.environ.pop("PASSWORD", None)
        else:
            os.environ["PASSWORD"] = old_password
        if old_alertmesh_username is None:
            os.environ.pop("ALERTMESH_USERNAME", None)
        else:
            os.environ["ALERTMESH_USERNAME"] = old_alertmesh_username
        if old_alertmesh_password is None:
            os.environ.pop("ALERTMESH_PASSWORD", None)
        else:
            os.environ["ALERTMESH_PASSWORD"] = old_alertmesh_password
        if old_secret is None:
            os.environ.pop("SECRET_KEY", None)
        else:
            os.environ["SECRET_KEY"] = old_secret
        app_module.ENV_FILE_VALUES.clear()
        app_module.ENV_FILE_VALUES.update(old_env_values)


def test_login_attempt_tracker_prunes_stale_clients():
    old_attempts = dict(app_module.LOGIN_ATTEMPTS)
    try:
        app_module.LOGIN_ATTEMPTS.clear()
        app_module.LOGIN_ATTEMPTS["old-client"] = [0]
        app_module.prune_login_attempts()
        assert "old-client" not in app_module.LOGIN_ATTEMPTS
    finally:
        app_module.LOGIN_ATTEMPTS.clear()
        app_module.LOGIN_ATTEMPTS.update(old_attempts)


def test_capture_packet_errors_are_recorded():
    old_status = dict(app_module.CAPTURE_STATUS)
    try:
        app_module.CAPTURE_STATUS["packet_errors"] = 0
        app_module.CAPTURE_STATUS["last_packet_error"] = None
        app_module.record_packet_error(ValueError("test packet failure"))

        assert app_module.CAPTURE_STATUS["packet_errors"] == 1
        assert app_module.CAPTURE_STATUS["last_packet_error"] == "test packet failure"
    finally:
        app_module.CAPTURE_STATUS.clear()
        app_module.CAPTURE_STATUS.update(old_status)


def test_dashboard_capture_interface_auto_excludes_loopback_and_miniports(monkeypatch):
    class Iface:
        def __init__(self, name, description):
            self.name = name
            self.description = description

    monkeypatch.setattr(
        app_module,
        "get_working_ifaces",
        lambda: [
            Iface("Wi-Fi", "Wireless"),
            Iface("VMware Network Adapter VMnet8", "VMware"),
            Iface("Loopback Pseudo-Interface 1", "Software Loopback Interface"),
            Iface("Local Area Connection* 10", "WAN Miniport (IP)"),
        ],
    )

    assert app_module.resolve_capture_interfaces("auto") == [
        "Wi-Fi",
        "VMware Network Adapter VMnet8",
    ]


def test_dashboard_packet_processing_logs_nids_alerts(monkeypatch):
    old_enabled = app_module.DASHBOARD_INTRUSION_DETECTION_ENABLED
    old_meta = list(app_module.PACKETS_META)
    old_raw = list(app_module.PACKETS_RAW)
    try:
        app_module.DASHBOARD_INTRUSION_DETECTION_ENABLED = True
        app_module.PACKETS_META.clear()
        app_module.PACKETS_RAW.clear()
        drain_alert_queue()
        packet = IP(src="8.8.8.8", dst="192.168.1.10") / TCP(sport=44444, dport=22, flags="S")
        alert = {
            "timestamp": "2026-05-29 10:00:00",
            "src_ip": "8.8.8.8",
            "dst_ip": "192.168.1.10",
            "src_port": 44444,
            "dst_port": 22,
            "proto": "TCP",
            "attack_type": "BRUTE_FORCE",
            "severity": "HIGH",
            "msg": "test alert",
        }
        logged = []

        monkeypatch.setattr(app_module.nids_detector, "process_packet", lambda current_packet: [alert])
        monkeypatch.setattr(app_module.nids_detector, "log_alert", lambda current_alert: logged.append(current_alert))

        app_module.process_captured_packet(packet)

        queued_alert = app_module.ALERT_QUEUE.get_nowait()
        app_module.ALERT_QUEUE.task_done()
        assert queued_alert == alert
        assert logged == []
        assert len(app_module.PACKETS_META) == 1
        assert app_module.PACKETS_META[0]["src"] == "8.8.8.8"
    finally:
        app_module.DASHBOARD_INTRUSION_DETECTION_ENABLED = old_enabled
        app_module.PACKETS_META.clear()
        app_module.PACKETS_META.extend(old_meta)
        app_module.PACKETS_RAW.clear()
        app_module.PACKETS_RAW.extend(old_raw)
        drain_alert_queue()


def test_dashboard_detection_failure_does_not_drop_packet(monkeypatch):
    old_enabled = app_module.DASHBOARD_INTRUSION_DETECTION_ENABLED
    old_status = dict(app_module.CAPTURE_STATUS)
    old_meta = list(app_module.PACKETS_META)
    old_raw = list(app_module.PACKETS_RAW)
    try:
        app_module.DASHBOARD_INTRUSION_DETECTION_ENABLED = True
        app_module.CAPTURE_STATUS["packet_errors"] = 0
        app_module.CAPTURE_STATUS["last_packet_error"] = None
        app_module.PACKETS_META.clear()
        app_module.PACKETS_RAW.clear()
        packet = IP(src="8.8.8.8", dst="192.168.1.10") / TCP(sport=44444, dport=22, flags="S")

        def fail_detection(current_packet):
            raise ValueError("detector failure")

        monkeypatch.setattr(app_module.nids_detector, "process_packet", fail_detection)

        app_module.process_captured_packet(packet)

        assert app_module.CAPTURE_STATUS["packet_errors"] == 1
        assert app_module.CAPTURE_STATUS["last_packet_error"] == "detector failure"
        assert len(app_module.PACKETS_META) == 1
    finally:
        app_module.DASHBOARD_INTRUSION_DETECTION_ENABLED = old_enabled
        app_module.CAPTURE_STATUS.clear()
        app_module.CAPTURE_STATUS.update(old_status)
        app_module.PACKETS_META.clear()
        app_module.PACKETS_META.extend(old_meta)
        app_module.PACKETS_RAW.clear()
        app_module.PACKETS_RAW.extend(old_raw)
