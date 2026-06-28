from flask import (
    Flask,
    render_template,
    jsonify,
    request,
    redirect,
    url_for,
    session,
    send_file,
    abort,
)
from datetime import datetime, timedelta, timezone
from functools import wraps
from threading import Thread, Lock
from queue import Queue, Full
import os
import csv
import io
import time
import ipaddress
import secrets
import socket
import tempfile
from dotenv import load_dotenv
from dotenv import dotenv_values
import sqlite3

try:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
except ImportError:
    ZoneInfo = None
    ZoneInfoNotFoundError = ValueError

from database import (
    delete_intrusion_logs_selected,
    fetch_intrusion_dashboard_data,
    get_db_connection,
    get_intrusion_collection,
    get_rejected_collection,
    get_storage_description,
    initialize_database,
    using_mongodb,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("XDG_CACHE_HOME", os.path.join(tempfile.gettempdir(), "alertmesh-scapy-cache"))

from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap, get_working_ifaces
import nids as nids_detector


def get_int_env(name, default, minimum=None):
    try:
        value = int(os.getenv(name, default))
    except (TypeError, ValueError):
        print(f"WARNING: {name} must be an integer. Using {default}.")
        value = default
    if minimum is not None and value < minimum:
        print(f"WARNING: {name} must be at least {minimum}. Using {minimum}.")
        value = minimum
    return value


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def dashboard_timezone():
    configured_timezone = os.getenv("DASHBOARD_TIMEZONE", "Asia/Kathmandu")
    if ZoneInfo is None:
        if configured_timezone in {"Asia/Kathmandu", "Asia/Katmandu"}:
            return timezone(timedelta(hours=5, minutes=45), "Asia/Kathmandu")
        print(f"WARNING: DASHBOARD_TIMEZONE requires Python 3.9+ zoneinfo. Using UTC.")
        return timezone.utc
    try:
        return ZoneInfo(configured_timezone)
    except ZoneInfoNotFoundError:
        print(f"WARNING: Invalid DASHBOARD_TIMEZONE '{configured_timezone}'. Using UTC.")
        return timezone.utc


def sql_timestamp(value):
    return value.strftime("%Y-%m-%d %H:%M:%S")


def today_utc_range(tz=None):
    tz = tz or dashboard_timezone()
    now = datetime.now(tz)
    local_start = datetime(now.year, now.month, now.day, tzinfo=tz)
    local_end = local_start + timedelta(days=1)
    utc_start = local_start.astimezone(timezone.utc).replace(tzinfo=None)
    utc_end = local_end.astimezone(timezone.utc).replace(tzinfo=None)
    return sql_timestamp(utc_start), sql_timestamp(utc_end)


def is_port_available(host, port):
    """Return True when the dashboard can bind to the requested port."""
    for probe_host in ("127.0.0.1", "localhost"):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.25)
            if sock.connect_ex((probe_host, port)) == 0:
                return False

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def choose_dashboard_port(preferred_port, host="0.0.0.0", attempts=50):
    """Use the configured port when possible, otherwise pick the next free port."""
    preferred_port = max(1, min(preferred_port, 65535))
    for port in range(preferred_port, min(65535, preferred_port + attempts) + 1):
        if is_port_available(host, port):
            return port
    raise RuntimeError(
        f"No available dashboard port found from {preferred_port} to "
        f"{min(65535, preferred_port + attempts)}."
    )


def is_local_bind_host(host):
    host = (host or "").strip().lower()
    return host in {"127.0.0.1", "localhost", "::1"}


def session_cookie_secure_value():
    configured = os.getenv("SESSION_COOKIE_SECURE", "auto").strip().lower()
    if configured in {"true", "1", "yes", "on"}:
        return True
    if configured in {"false", "0", "no", "off"}:
        return False
    return os.getenv("DASHBOARD_PUBLIC_HTTPS", "false").strip().lower() in {"true", "1", "yes", "on"}


def enforce_dashboard_security_for_host(host):
    if is_local_bind_host(host):
        return
    if not dashboard_config_value("ALERTMESH_USERNAME", "USERNAME") or not dashboard_config_value("ALERTMESH_PASSWORD", "PASSWORD"):
        raise RuntimeError(
            "Refusing to expose dashboard without USERNAME and PASSWORD. "
            "Set both in src/.env or bind DASHBOARD_HOST/WEBSITES_HOST to 127.0.0.1."
        )
    configured_secret = (
        os.getenv("ALERTMESH_SECRET_KEY")
        or ENV_FILE_VALUES.get("ALERTMESH_SECRET_KEY")
        or ENV_FILE_VALUES.get("SECRET_KEY")
        or os.getenv("SECRET_KEY", "")
    )
    if not configured_secret or configured_secret.startswith("change_this"):
        raise RuntimeError(
            "Refusing to expose dashboard without a strong SECRET_KEY. "
            "Set SECRET_KEY in src/.env before using a non-local dashboard host."
        )


def configure_console_encoding():
    import sys

    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


configure_console_encoding()

# Load environment variables
ENV_FILE = os.path.join(BASE_DIR, ".env")
load_dotenv(ENV_FILE, override=False, encoding="utf-8-sig")
ENV_FILE_VALUES = {
    key.lstrip("\ufeff"): value
    for key, value in dotenv_values(ENV_FILE, encoding="utf-8-sig").items()
}

app = Flask(__name__)
configured_secret = (
    os.getenv("ALERTMESH_SECRET_KEY")
    or ENV_FILE_VALUES.get("ALERTMESH_SECRET_KEY")
    or ENV_FILE_VALUES.get("SECRET_KEY")
    or os.getenv("SECRET_KEY", "")
)
if configured_secret and not configured_secret.startswith("change_this"):
    app.secret_key = configured_secret
else:
    app.secret_key = secrets.token_hex(32)
    print("WARNING: SECRET_KEY is missing or still set to a placeholder. Using a temporary random key.")

app.config['SESSION_COOKIE_SECURE'] = session_cookie_secure_value()
app.config['SESSION_COOKIE_HTTPONLY'] = os.getenv('SESSION_COOKIE_HTTPONLY', 'True').lower() == 'true'
app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')

def dashboard_config_value(primary_name, legacy_name=None):
    """Prefer app-specific env and .env values over OS variables like Windows USERNAME."""
    return (
        os.getenv(primary_name)
        or ENV_FILE_VALUES.get(primary_name)
        or (ENV_FILE_VALUES.get(legacy_name) if legacy_name else None)
        or (os.getenv(legacy_name) if legacy_name else None)
    )


# Simple local authentication
CONFIGURED_USERNAME = dashboard_config_value("ALERTMESH_USERNAME", "USERNAME")
CONFIGURED_PASSWORD = dashboard_config_value("ALERTMESH_PASSWORD", "PASSWORD")
VALID_USERNAME = CONFIGURED_USERNAME or "alertmesh_admin"
VALID_PASSWORD = CONFIGURED_PASSWORD or secrets.token_urlsafe(16)
LOGIN_ATTEMPTS = {}
LOGIN_MAX_ATTEMPTS = get_int_env("LOGIN_MAX_ATTEMPTS", 5, minimum=1)
LOGIN_RATE_LIMIT_SECONDS = get_int_env("LOGIN_RATE_LIMIT_SECONDS", 300, minimum=1)
LOGIN_TRACKER_MAX_CLIENTS = get_int_env("LOGIN_TRACKER_MAX_CLIENTS", 1000, minimum=10)
if not CONFIGURED_USERNAME or not CONFIGURED_PASSWORD:
    print("WARNING: USERNAME or PASSWORD is missing. Using temporary dashboard credentials for this run.")
    if os.getenv("ALLOW_TEMP_CREDENTIAL_PRINT", "false").lower() == "true":
        print(f"Temporary dashboard username: {VALID_USERNAME}")
        print(f"Temporary dashboard password: {VALID_PASSWORD}")
    else:
        print("Set ALERTMESH_USERNAME and ALERTMESH_PASSWORD in src/.env to log in.")

PACKETS_META = []  # dicts for UI
PACKETS_RAW = []   # original scapy packets for pcap export
ALERT_QUEUE = Queue(maxsize=get_int_env("ALERT_QUEUE_MAXSIZE", 1000, minimum=10))
alert_worker_lock = Lock()
ALERT_WORKER_STARTED = False
CAPTURE_STATUS = {
    "running": False,
    "error": None,
    "packet_errors": 0,
    "last_packet_error": None,
    "alert_queue_dropped": 0,
}
lock = Lock()
db_init_lock = Lock()
DB_INITIALIZED = False
DB_INIT_ERROR = None
DB_INIT_LAST_ATTEMPT = 0
DB_INIT_RETRY_SECONDS = get_int_env("DB_INIT_RETRY_SECONDS", 10, minimum=1)
MAX_HISTORY = get_int_env("MAX_HISTORY", 2000, minimum=1)
INCLUDE_DISCOVERY_TRAFFIC = os.getenv("INCLUDE_DISCOVERY_TRAFFIC", "false").lower() == "true"
DASHBOARD_PACKET_CAPTURE_ENABLED = os.getenv("DASHBOARD_PACKET_CAPTURE_ENABLED", "true").lower() == "true"
DASHBOARD_PACKET_CAPTURE_INTERFACE = os.getenv("DASHBOARD_PACKET_CAPTURE_INTERFACE") or os.getenv("NIDS_INTERFACE")
DASHBOARD_INTRUSION_DETECTION_ENABLED = os.getenv("DASHBOARD_INTRUSION_DETECTION_ENABLED", "true").lower() == "true"
PACKET_EXPORTS_ENABLED = os.getenv("PACKET_EXPORTS_ENABLED", "false").lower() == "true"
TRUST_PROXY_HEADERS = os.getenv("TRUST_PROXY_HEADERS", "false").lower() == "true"


def parse_proxy_networks(raw_networks):
    networks = []
    for value in (raw_networks or "").split(","):
        value = value.strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value))
        except ValueError:
            print(f"WARNING: Ignoring invalid TRUSTED_PROXY_NETWORKS entry: {value}")
    return networks


TRUSTED_PROXY_NETWORKS = parse_proxy_networks(os.getenv("TRUSTED_PROXY_NETWORKS", "127.0.0.1/32,::1/128"))
KNOWN_ATTACK_TYPES = [
    "BRUTE_FORCE",
    "EXPOSED_SERVICE_ACCESS",
    "ICMP_ATTACK",
    "PORT_SCAN",
]

ATTACK_TYPE_ALIASES = {}


def normalize_display_attack_type(attack_type):
    return ATTACK_TYPE_ALIASES.get(attack_type, attack_type)


def get_client_ip():
    if TRUST_PROXY_HEADERS:
        remote_ip = request.remote_addr or ""
        try:
            remote_addr = ipaddress.ip_address(remote_ip)
        except ValueError:
            remote_addr = None
        trusted_proxy = remote_addr is not None and any(
            remote_addr in network for network in TRUSTED_PROXY_NETWORKS
        )
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        if forwarded_for and trusted_proxy:
            candidate = forwarded_for.split(",")[0].strip()
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                print(f"WARNING: Ignoring invalid X-Forwarded-For value: {candidate}")
    return request.remote_addr or "unknown"


def too_many_login_attempts(client_ip):
    prune_login_attempts()
    now = time.time()
    attempts = [
        timestamp for timestamp in LOGIN_ATTEMPTS.get(client_ip, [])
        if now - timestamp < LOGIN_RATE_LIMIT_SECONDS
    ]
    LOGIN_ATTEMPTS[client_ip] = attempts
    return len(attempts) >= LOGIN_MAX_ATTEMPTS


def record_failed_login(client_ip):
    prune_login_attempts()
    LOGIN_ATTEMPTS.setdefault(client_ip, []).append(time.time())
    if len(LOGIN_ATTEMPTS) > LOGIN_TRACKER_MAX_CLIENTS:
        oldest_client = min(
            LOGIN_ATTEMPTS,
            key=lambda key: min(LOGIN_ATTEMPTS[key]) if LOGIN_ATTEMPTS[key] else 0,
        )
        LOGIN_ATTEMPTS.pop(oldest_client, None)


def clear_failed_logins(client_ip):
    LOGIN_ATTEMPTS.pop(client_ip, None)


def prune_login_attempts():
    now = time.time()
    for client_ip, attempts in list(LOGIN_ATTEMPTS.items()):
        recent_attempts = [
            timestamp for timestamp in attempts
            if now - timestamp < LOGIN_RATE_LIMIT_SECONDS
        ]
        if recent_attempts:
            LOGIN_ATTEMPTS[client_ip] = recent_attempts
        else:
            LOGIN_ATTEMPTS.pop(client_ip, None)


def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def validate_csrf_token():
    expected = session.get("csrf_token", "")
    provided = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
    if not expected or not provided or not secrets.compare_digest(expected, provided):
        abort(400, description="Invalid CSRF token")


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": csrf_token}

def ensure_database_initialized():
    global DB_INITIALIZED, DB_INIT_ERROR, DB_INIT_LAST_ATTEMPT
    if DB_INITIALIZED:
        return
    now = time.time()
    if DB_INIT_ERROR and now - DB_INIT_LAST_ATTEMPT < DB_INIT_RETRY_SECONDS:
        return
    with db_init_lock:
        now = time.time()
        if not DB_INITIALIZED and (not DB_INIT_ERROR or now - DB_INIT_LAST_ATTEMPT >= DB_INIT_RETRY_SECONDS):
            DB_INIT_LAST_ATTEMPT = now
            try:
                DB_INITIALIZED = initialize_database()
                DB_INIT_ERROR = None
            except Exception as exc:
                DB_INIT_ERROR = str(exc)
                print(f"ERROR: Database initialization failed: {exc}")


def log_server_error(context, exc):
    print(f"ERROR: {context}: {exc}")


def record_packet_error(exc):
    with lock:
        CAPTURE_STATUS["packet_errors"] = CAPTURE_STATUS.get("packet_errors", 0) + 1
        CAPTURE_STATUS["last_packet_error"] = str(exc)


def record_alert_queue_drop():
    with lock:
        CAPTURE_STATUS["alert_queue_dropped"] = CAPTURE_STATUS.get("alert_queue_dropped", 0) + 1


def enqueue_alert(alert):
    try:
        ALERT_QUEUE.put_nowait(alert)
    except Full:
        record_alert_queue_drop()
        print("WARNING: Alert queue is full. Dropping alert for async processing.")


def alert_worker():
    while True:
        alert = ALERT_QUEUE.get()
        try:
            nids_detector.log_alert(alert)
        except Exception as exc:
            record_packet_error(exc)
            log_server_error("Dashboard alert worker failed", exc)
        finally:
            ALERT_QUEUE.task_done()


def start_alert_worker():
    global ALERT_WORKER_STARTED
    if ALERT_WORKER_STARTED:
        return
    with alert_worker_lock:
        if ALERT_WORKER_STARTED:
            return
        worker = Thread(target=alert_worker, daemon=True)
        worker.start()
        ALERT_WORKER_STARTED = True


def auto_capture_interfaces():
    interfaces = []
    skipped_markers = ("loopback", "miniport")
    for iface in get_working_ifaces():
        name = getattr(iface, "name", "")
        description = getattr(iface, "description", "")
        label = f"{name} {description}".lower()
        if any(marker in label for marker in skipped_markers):
            continue
        interfaces.append(name or iface)
    return interfaces


def resolve_capture_interfaces(interface=None):
    if interface and interface.strip().lower() not in {"auto", "all", "*"}:
        return interface
    interfaces = auto_capture_interfaces()
    if not interfaces:
        return None
    return interfaces


def categorize_packet(pkt):
    """Return high-level category based on ports: HTTP/HTTPS/DNS/OTHER."""
    try:
        sport = None
        dport = None
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        ports = {sport, dport}
        if 53 in ports:
            return "DNS"
        if 80 in ports or 8080 in ports:
            return "HTTP"
        if 443 in ports:
            return "HTTPS"
    except Exception:
        pass
    return "OTHER"


def is_noisy_discovery_packet(pkt):
    """Hide routine LAN discovery traffic from the dashboard by default."""
    if IP not in pkt:
        return True

    try:
        src_ip = ipaddress.ip_address(pkt[IP].src)
        dst_ip = ipaddress.ip_address(pkt[IP].dst)
    except ValueError:
        return True

    if dst_ip.is_multicast or dst_ip.is_unspecified or dst_ip.is_loopback:
        return True

    if dst_ip.version == 4 and pkt[IP].dst == "255.255.255.255":
        return True

    if UDP in pkt:
        ports = {pkt[UDP].sport, pkt[UDP].dport}
        noisy_ports = {137, 138, 1900, 5353, 5355}
        if ports & noisy_ports:
            return True

    summary = pkt.summary().lower()
    noisy_markers = ("mdns", "llmnr", "ssdp", "nbns", "netbios")
    return any(marker in summary for marker in noisy_markers)


def detect_intrusions_from_packet(pkt):
    if not DASHBOARD_INTRUSION_DETECTION_ENABLED:
        return []

    try:
        alerts = nids_detector.process_packet(pkt)
        for alert in alerts:
            enqueue_alert(alert)
        return alerts
    except Exception as exc:
        record_packet_error(exc)
        log_server_error("Dashboard intrusion detection failed", exc)
        return []


def process_captured_packet(pkt):
    if IP not in pkt:
        return

    detect_intrusions_from_packet(pkt)

    if not INCLUDE_DISCOVERY_TRAFFIC and is_noisy_discovery_packet(pkt):
        return

    record = {
        "time": utc_now().strftime("%H:%M:%S"),
        "src": pkt[IP].src,
        "dst": pkt[IP].dst,
        "len": len(pkt),
        "info": pkt.summary(),
    }

    if TCP in pkt:
        proto = "TCP"
    elif UDP in pkt:
        proto = "UDP"
    elif ICMP in pkt:
        proto = "ICMP"
    elif IP in pkt:
        proto = str(pkt[IP].proto)
    else:
        proto = pkt.name

    record["proto"] = proto
    record["category"] = categorize_packet(pkt)

    with lock:
        PACKETS_META.append(record)
        PACKETS_RAW.append(pkt)

        if len(PACKETS_META) > MAX_HISTORY:
            overflow = len(PACKETS_META) - MAX_HISTORY
            del PACKETS_META[:overflow]
            del PACKETS_RAW[:overflow]


def capture(interface=None):
    """Background thread: capture real packets using scapy and store in memory."""
    start_alert_worker()

    def process(pkt):
        try:
            process_captured_packet(pkt)
        except Exception as exc:
            record_packet_error(exc)

    try:
        sniff_interfaces = resolve_capture_interfaces(interface)
        with lock:
            CAPTURE_STATUS["running"] = True
            CAPTURE_STATUS["error"] = None
        if sniff_interfaces:
            print(f"Dashboard packet capture interface: {sniff_interfaces}")
            sniff(iface=sniff_interfaces, prn=process, store=False)
        else:
            sniff(prn=process, store=False)  # capture forever
    except Exception as e:
        with lock:
            CAPTURE_STATUS["running"] = False
            CAPTURE_STATUS["error"] = str(e)
        print(f"ERROR: Real packet capture is unavailable: {e}")
        if os.name == "nt":
            print("Install Npcap and run this terminal as Administrator. No synthetic traffic will be generated.")
        else:
            print("Install libpcap and run packet capture with sudo/root. No synthetic traffic will be generated.")


# -------------------- Auth Helpers --------------------
def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapper


# -------------------- Routes --------------------------
@app.before_request
def before_request():
    ensure_database_initialized()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        validate_csrf_token()
        client_ip = get_client_ip()
        if too_many_login_attempts(client_ip):
            return render_template("login.html", error="Too many failed attempts. Try again later."), 429

        user = request.form.get("username", "")
        pw = request.form.get("password", "")
        valid_user = secrets.compare_digest(user, VALID_USERNAME)
        valid_password = secrets.compare_digest(pw, VALID_PASSWORD)
        if valid_user and valid_password:
            clear_failed_logins(client_ip)
            session["logged_in"] = True
            session["username"] = user
            return redirect(url_for("index"))
        else:
            record_failed_login(client_ip)
            return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    validate_csrf_token()
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template(
        "index.html",
        username=session.get("username", "admin"),
        packet_exports_enabled=PACKET_EXPORTS_ENABLED,
    )


@app.route("/intrusion_logs")
@login_required
def intrusion_logs():
    return render_template(
        "intrusion_logs.html",
        username=session.get("username", "admin"),
        packet_exports_enabled=PACKET_EXPORTS_ENABLED,
    )


@app.route("/data")
@login_required
def get_data():
    protocol_filter = request.args.get("protocol", "ALL")
    category_filter = request.args.get("category", "ALL")
    try:
        limit = int(request.args.get("limit", 200))
    except ValueError:
        limit = 200
    limit = max(1, min(limit, MAX_HISTORY))

    with lock:
        packets = list(PACKETS_META)
        capture_status = dict(CAPTURE_STATUS)

    # Filter
    filtered = []
    for p in packets:
        if protocol_filter != "ALL" and p["proto"] != protocol_filter:
            continue
        if category_filter != "ALL" and p["category"] != category_filter:
            continue
        filtered.append(p)

    filtered_total = len(filtered)
    filtered = filtered[-limit:]

    # Protocol stats
    proto_stats = {}
    cat_stats = {}
    for p in filtered:
        proto_stats[p["proto"]] = proto_stats.get(p["proto"], 0) + 1
        cat_stats[p["category"]] = cat_stats.get(p["category"], 0) + 1

    # For line chart: just use index as x-axis
    size_series = [pkt["len"] for pkt in filtered]
    time_labels = [pkt["time"] for pkt in filtered]

    return jsonify(
        {
            "packets": filtered,
            "stats": proto_stats,
            "cat_stats": cat_stats,
            "total": filtered_total,
            "capture_total": len(packets),
            "sizes": size_series,
            "time_labels": time_labels,
            "capture_status": capture_status,
        }
    )


@app.route("/system_status")
@login_required
def system_status():
    """Report storage and notification readiness for the dashboard."""
    ensure_database_initialized()
    email_ready, email_reason = nids_detector.email_config_ready()
    status = {
        "database": {
            "backend": "mongodb" if using_mongodb() else "sqlite",
            "storage": get_storage_description(),
            "initialized": DB_INITIALIZED,
            "error": DB_INIT_ERROR,
            "intrusion_logs": 0,
            "rejected_alerts": 0,
        },
        "email": {
            "enabled": nids_detector.EMAIL_ENABLED,
            "ready": email_ready,
            "reason": email_reason,
            "smtp_host_set": bool(nids_detector.SMTP_HOST),
            "smtp_from_set": bool(nids_detector.SMTP_FROM),
            "smtp_to_set": bool(nids_detector.SMTP_TO),
            "smtp_to": list(nids_detector.SMTP_TO),
        },
        "scope": {
            "protected_networks": os.getenv("PROTECTED_NETWORKS", ""),
            "geolocation_enabled": os.getenv("GEOLOCATION_ENABLED", "false").lower() == "true",
        },
        "alert_queue": {
            "pending": ALERT_QUEUE.qsize(),
            "dropped": CAPTURE_STATUS.get("alert_queue_dropped", 0),
        },
    }

    try:
        if using_mongodb():
            status["database"]["intrusion_logs"] = get_intrusion_collection().count_documents({})
            status["database"]["rejected_alerts"] = get_rejected_collection().count_documents({})
        else:
            with get_db_connection() as connection:
                status["database"]["intrusion_logs"] = connection.execute(
                    "SELECT COUNT(*) FROM intrusion_logs"
                ).fetchone()[0]
                status["database"]["rejected_alerts"] = connection.execute(
                    "SELECT COUNT(*) FROM rejected_alerts"
                ).fetchone()[0]
    except Exception as exc:
        status["database"]["error"] = str(exc)

    return jsonify(status)


@app.route("/email_test", methods=["POST"])
@login_required
def email_test():
    """Send a real email test message without writing an intrusion log."""
    validate_csrf_token()
    test_alert = {
        "timestamp": utc_now().strftime("%Y-%m-%d %H:%M:%S"),
        "msg": "AlertMesh email test alert",
        "attack_type": "SYSTEM_TEST",
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "proto": "TEST",
        "src_port": None,
        "dst_port": None,
        "severity": "LOW",
        "detected_os": "Dashboard",
    }
    sent = nids_detector.send_email_alert(
        test_alert,
        "Local Test",
        bypass_cooldown=True,
    )
    email_ready, email_reason = nids_detector.email_config_ready()
    return jsonify({
        "sent": bool(sent),
        "email": {
            "enabled": nids_detector.EMAIL_ENABLED,
            "ready": email_ready,
            "reason": email_reason,
            "smtp_to": list(nids_detector.SMTP_TO),
        },
    }), 200 if sent else 502


@app.route("/intrusion_data")
@login_required
def get_intrusion_data():
    """Fetch intrusion logs from the configured database backend."""
    if using_mongodb():
        try:
            today_start, today_end = today_utc_range()
            return jsonify(fetch_intrusion_dashboard_data(
                request.args,
                today_start,
                today_end,
                KNOWN_ATTACK_TYPES,
            ))
        except Exception as e:
            log_server_error("MongoDB intrusion data query failed", e)
            return jsonify({"error": "Unable to load intrusion data."}), 500

    connection = None
    try:
        connection = get_db_connection()
        if not connection:
            return jsonify({"error": "Database connection failed"}), 500

        cursor = connection.cursor()

        today_start, today_end = today_utc_range()
        filters, params = build_intrusion_filters(request.args)

        # Get stats
        cursor.execute("""
            SELECT COUNT(*) as total_today
            FROM intrusion_logs
            WHERE timestamp >= ? AND timestamp < ?
        """, (today_start, today_end))
        total_today = cursor.fetchone()['total_today']

        cursor.execute("""
            SELECT COUNT(*) as high_severity
            FROM intrusion_logs
            WHERE severity IN ('HIGH', 'CRITICAL')
              AND timestamp >= ? AND timestamp < ?
        """, (today_start, today_end))
        high_severity = cursor.fetchone()['high_severity']

        cursor.execute("""
            SELECT dst_port, COUNT(*) as count
            FROM intrusion_logs
            WHERE dst_port IS NOT NULL
              AND timestamp >= ? AND timestamp < ?
            GROUP BY dst_port
            ORDER BY count DESC
            LIMIT 1
        """, (today_start, today_end))
        most_attacked = cursor.fetchone()
        most_attacked_port = most_attacked['dst_port'] if most_attacked else "N/A"

        cursor.execute(f"""
            SELECT COUNT(*) as filtered_total
            FROM intrusion_logs
            WHERE 1 = 1
              {filters}
        """, params)
        filtered_total = cursor.fetchone()['filtered_total']

        # Get recent logs with OS
        cursor.execute(f"""
            SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port,
                   protocol, attack_type, severity, country, detected_os,
                   source, signature_id, classification, confidence, analysis_note
            FROM intrusion_logs
            WHERE 1 = 1
              {filters}
            ORDER BY timestamp DESC
            LIMIT 100
        """, params)
        logs = [dict(row) for row in cursor.fetchall()]
        for log in logs:
            log["attack_type"] = normalize_display_attack_type(log.get("attack_type"))

        # Get attack type stats for chart
        cursor.execute(f"""
            SELECT attack_type, COUNT(*) as count
            FROM intrusion_logs
            WHERE 1 = 1
              {filters}
            GROUP BY attack_type
            ORDER BY count DESC
        """, params)
        raw_attack_stats = [dict(row) for row in cursor.fetchall()]
        attack_counts = {}
        for row in raw_attack_stats:
            attack_type = normalize_display_attack_type(row["attack_type"])
            attack_counts[attack_type] = attack_counts.get(attack_type, 0) + row["count"]
        attack_stats = [
            {"attack_type": attack_type, "count": count}
            for attack_type, count in sorted(attack_counts.items(), key=lambda item: item[1], reverse=True)
        ]

        # Get severity distribution for pie chart
        cursor.execute(f"""
            SELECT severity, COUNT(*) as count
            FROM intrusion_logs
            WHERE 1 = 1
              {filters}
            GROUP BY severity
        """, params)
        severity_stats = [dict(row) for row in cursor.fetchall()]

        cursor.execute("""
            SELECT DISTINCT attack_type
            FROM intrusion_logs
            WHERE attack_type IS NOT NULL AND attack_type != ''
            ORDER BY attack_type
        """)
        db_attack_types = [
            normalize_display_attack_type(row["attack_type"])
            for row in cursor.fetchall()
        ]
        attack_types = sorted(set(KNOWN_ATTACK_TYPES).union(db_attack_types))

        cursor.execute("""
            SELECT DISTINCT severity
            FROM intrusion_logs
            WHERE severity IS NOT NULL AND severity != ''
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END,
                severity
        """)
        severities = [row["severity"] for row in cursor.fetchall()]

        return jsonify({
            "stats": {
                "total_today": total_today,
                "high_severity": high_severity,
                "most_attacked_port": most_attacked_port,
                "filtered_total": filtered_total,
            },
            "logs": logs,
            "attack_stats": attack_stats,
            "severity_stats": severity_stats,
            "filter_options": {
                "attack_types": attack_types,
                "severities": severities
            }
        })

    except sqlite3.Error as e:
        log_server_error("SQLite intrusion data query failed", e)
        return jsonify({"error": "Unable to load intrusion data."}), 500
    finally:
        if connection:
            connection.close()


def build_intrusion_filters(args):
    filters = []
    params = []

    severity = (args.get("severity") or "ALL").strip().upper()
    if severity != "ALL":
        filters.append("AND severity = ?")
        params.append(severity)

    attack_type = (args.get("attack_type") or "ALL").strip()
    if attack_type != "ALL":
        filters.append("AND attack_type = ?")
        params.append(attack_type)

    since = (args.get("since") or "").strip()
    if since:
        filters.append("AND timestamp > ?")
        params.append(since)

    query = (args.get("q") or "").strip()
    if query:
        like_query = f"%{query}%"
        filters.append(
            """
            AND (
                src_ip LIKE ?
                OR dst_ip LIKE ?
                OR country LIKE ?
                OR detected_os LIKE ?
                OR attack_type LIKE ?
                OR severity LIKE ?
                OR protocol LIKE ?
                OR source LIKE ?
                OR signature_id LIKE ?
                OR classification LIKE ?
                OR analysis_note LIKE ?
            )
            """
        )
        params.extend([like_query] * 11)

    return "\n              ".join(filters), params


def require_packet_exports_enabled():
    if not PACKET_EXPORTS_ENABLED:
        abort(403, description="Packet exports are disabled. Set PACKET_EXPORTS_ENABLED=true to enable them.")


def sanitize_csv_cell(value):
    text = "" if value is None else str(value)
    stripped = text.lstrip()
    if stripped and stripped[0] in ("=", "+", "-", "@"):
        return f"'{text}"
    return text


def sanitize_csv_record(record):
    return {key: sanitize_csv_cell(value) for key, value in record.items()}


@app.route("/intrusion_logs/delete", methods=["POST"])
@login_required
def delete_intrusion_logs():
    """Delete one alert or the currently filtered intrusion alert set."""
    validate_csrf_token()
    if not request.is_json:
        return jsonify({"error": "JSON request body required"}), 400

    payload = request.get_json(silent=True) or {}
    try:
        deleted = delete_intrusion_logs_selected(payload, sqlite_filter_builder=build_intrusion_filters)
        return jsonify({"deleted": deleted})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except sqlite3.Error as e:
        log_server_error("SQLite intrusion log delete failed", e)
        return jsonify({"error": "Unable to delete intrusion logs."}), 500
    except Exception as e:
        log_server_error("Intrusion log delete failed", e)
        return jsonify({"error": "Unable to delete intrusion logs."}), 500


@app.route("/export_pcap")
@login_required
def export_pcap():
    require_packet_exports_enabled()
    with lock:
        if not PACKETS_RAW:
            return "No packets to export yet.", 400
        packets = list(PACKETS_RAW)

    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tmp_path = tmp.name
    tmp.close()
    wrpcap(tmp_path, packets)

    response = send_file(
        tmp_path,
        mimetype="application/vnd.tcpdump.pcap",
        as_attachment=True,
        download_name="network_capture.pcap",
    )

    @response.call_on_close
    def cleanup():
        try:
            os.remove(tmp_path)
        except OSError:
            pass

    return response


@app.route("/export_csv")
@login_required
def export_csv():
    require_packet_exports_enabled()
    protocol_filter = request.args.get("protocol", "ALL")
    category_filter = request.args.get("category", "ALL")

    with lock:
        packets = list(PACKETS_META)

    # Filter packets
    filtered = []
    for p in packets:
        if protocol_filter != "ALL" and p["proto"] != protocol_filter:
            continue
        if category_filter != "ALL" and p["category"] != category_filter:
            continue
        filtered.append(p)

    if not filtered:
        return "No packets to export.", 400

    # Create CSV in memory
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["time", "src", "dst", "proto", "category", "len", "info"])
    writer.writeheader()
    writer.writerows(sanitize_csv_record(row) for row in filtered)

    # Convert to bytes
    output.seek(0)
    csv_data = output.getvalue()

    return (
        csv_data,
        200,
        {
            "Content-Type": "text/csv",
            "Content-Disposition": 'attachment; filename="network_packets.csv"',
        },
    )


if __name__ == "__main__":
    ensure_database_initialized()

    # Get port from environment or use default
    dashboard_host = os.getenv("DASHBOARD_HOST") or os.getenv("WEBSITES_HOST", "127.0.0.1")
    enforce_dashboard_security_for_host(dashboard_host)
    preferred_port = get_int_env("WEBSITES_PORT", 5001, minimum=1)
    port = choose_dashboard_port(preferred_port, host=dashboard_host)
    debug = os.getenv("FLASK_DEBUG", "False").lower() == "true"

    start_alert_worker()

    if DASHBOARD_PACKET_CAPTURE_ENABLED:
        t = Thread(target=capture, args=(DASHBOARD_PACKET_CAPTURE_INTERFACE,), daemon=True)
        t.start()
    else:
        CAPTURE_STATUS["running"] = False
        CAPTURE_STATUS["error"] = "Dashboard packet capture disabled by DASHBOARD_PACKET_CAPTURE_ENABLED=false"

    if port != preferred_port:
        print(f"WARNING: Port {preferred_port} is already in use. Using port {port} instead.")
    display_host = "127.0.0.1" if is_local_bind_host(dashboard_host) else dashboard_host
    print(f"Dashboard URL: http://{display_host}:{port}")
    print(f"Login username: {VALID_USERNAME}")
    print("Login password: use PASSWORD from src/.env")

    app.run(host=dashboard_host, port=port, debug=debug, use_reloader=False)
