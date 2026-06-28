import logging
import time
import json
import os
import sys
import ipaddress
import argparse
import tempfile
import smtplib
from email.message import EmailMessage
from datetime import datetime, timezone
import sqlite3
from dotenv import load_dotenv
from collections import defaultdict
import random

from alert_analysis import (
    alert_is_duplicate,
    analyze_alert,
    is_in_networks,
)
from database import (
    alert_is_duplicate_selected,
    get_db_connection,
    get_storage_description,
    initialize_database,
    insert_intrusion_alert,
    insert_rejected_alert,
    insert_intrusion_alert_selected,
    insert_rejected_alert_selected,
    write_runtime_status,
)
from geo_utils import get_country_from_ip as resolve_country_from_ip


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("XDG_CACHE_HOME", os.path.join(tempfile.gettempdir(), "alertmesh-scapy-cache"))

from scapy.all import sniff, IP, TCP, UDP, ICMP, get_working_ifaces

LOG_DIR = os.path.join(BASE_DIR, "logs")


def configure_console_encoding():
    """Avoid UnicodeEncodeError in the default Windows console code page."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


configure_console_encoding()

# Load environment variables from .env file
load_dotenv(os.path.join(BASE_DIR, ".env"), override=False, encoding="utf-8-sig")

# Configuration
LOG_FILE = os.path.join(LOG_DIR, "alerts.json")
os.makedirs(LOG_DIR, exist_ok=True)

# Alert cooldown settings (seconds)
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


def get_float_env(name, default, minimum=None):
    try:
        value = float(os.getenv(name, default))
    except (TypeError, ValueError):
        print(f"WARNING: {name} must be a number. Using {default}.")
        value = default
    if minimum is not None and value < minimum:
        print(f"WARNING: {name} must be at least {minimum}. Using {minimum}.")
        value = minimum
    return value


ALERT_COOLDOWN = get_int_env("ALERT_COOLDOWN", 60, minimum=0)
EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "false").lower() == "true"
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = get_int_env("SMTP_PORT", 587, minimum=1)
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip()
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USERNAME).strip()
SMTP_TO = [value.strip() for value in os.getenv("SMTP_TO", "").split(",") if value.strip()]
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"


def email_config_ready():
    if not EMAIL_ENABLED:
        return False, "Email alerts are disabled"
    if not SMTP_HOST:
        return False, "SMTP_HOST is missing"
    if not SMTP_FROM:
        return False, "SMTP_FROM or SMTP_USERNAME is missing"
    if not SMTP_TO:
        return False, "SMTP_TO is missing"
    if SMTP_USERNAME and not SMTP_PASSWORD:
        return False, "SMTP_PASSWORD is missing"
    return True, None


def send_email_message(subject, text):
    ready, reason = email_config_ready()
    if not ready:
        print(f"    [EMAIL] {reason}. Skipping email alert.")
        return False

    try:
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = SMTP_FROM
        message["To"] = ", ".join(SMTP_TO)
        message.set_content(text)

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
            if SMTP_USE_TLS:
                smtp.starttls()
            if SMTP_USERNAME:
                smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
            smtp.send_message(message)
        print("    [EMAIL] Alert sent successfully")
        return True
    except Exception as exc:
        print(f"    [EMAIL] Error sending email alert: {exc}")
        return False
GEOLOCATION_ENABLED = os.getenv("GEOLOCATION_ENABLED", "false").lower() == "true"

def parse_protected_networks(raw_networks):
    networks = []
    for network in raw_networks.split(","):
        network = network.strip()
        if not network:
            continue
        try:
            networks.append(ipaddress.ip_network(network))
        except ValueError:
            print(f"WARNING: Ignoring invalid PROTECTED_NETWORKS entry: {network}")
    return networks


# Alert only for attempts targeting protected/local networks by default. This
# avoids treating normal outbound browsing/API traffic as inbound attacks.
PROTECTED_NETWORKS = parse_protected_networks(os.getenv(
    "PROTECTED_NETWORKS",
    "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
))
IGNORE_SOURCE_NETWORKS = parse_protected_networks(os.getenv("IGNORE_SOURCE_IPS", ""))
TRUSTED_SOURCE_NETWORKS = parse_protected_networks(os.getenv("TRUSTED_SOURCE_IPS", ""))
REJECT_TRUSTED_SOURCES = os.getenv("ALERT_REJECT_TRUSTED_SOURCES", "true").lower() == "true"
MONITOR_PROTECTED_SOURCES = os.getenv("ALERT_MONITOR_PROTECTED_SOURCES", "true").lower() == "true"

# Track last alert sent time per IP
alert_cooldown_tracker = {}

# Track connection attempts for brute force detection
connection_tracker = defaultdict(list)
event_cooldown_tracker = {}
icmp_tracker = defaultdict(list)
last_tracker_cleanup = 0

# Keep the active Python fallback narrow and network-focused. Snort is the
# preferred detector; this list exists for practical service probes only.
BRUTE_FORCE_SERVICES = {"SSH", "FTP", "RDP"}

EXPOSED_SERVICE_ALERTS = {"TELNET", "RDP", "SMB", "NETBIOS"}

EVENT_COOLDOWN_SECONDS = 120
PORT_SCAN_EVENT_COOLDOWN_SECONDS = get_int_env("PORT_SCAN_EVENT_COOLDOWN_SECONDS", 300, minimum=0)
TRACKER_CLEANUP_SECONDS = get_int_env("TRACKER_CLEANUP_SECONDS", 300, minimum=30)
ICMP_THRESHOLD = get_int_env("ICMP_ALERT_THRESHOLD", 5, minimum=1)
ICMP_WINDOW = get_int_env("ICMP_ALERT_WINDOW", 10, minimum=1)
EXPOSED_SERVICE_THRESHOLD = get_int_env("EXPOSED_SERVICE_ALERT_THRESHOLD", 3, minimum=1)
EXPOSED_SERVICE_WINDOW = get_int_env("EXPOSED_SERVICE_ALERT_WINDOW", 60, minimum=1)
ATTACK_TYPE_ALIASES = {}
DEBUG_PACKETS = False
DEBUG_HOSTS = set()

# Setup Logging
logging.basicConfig(filename=os.path.join(LOG_DIR, 'nids.log'), level=logging.INFO, format='%(asctime)s - %(message)s')


def print_startup_banner():
    print("=" * 60)
    print("  AlertMesh NIDS - Network Intrusion Detection System")
    print("=" * 60)
    print(f"Logging alerts to: {LOG_FILE}")
    print(f"Database: {get_storage_description()}")
    print(f"Email Alerts: {'Enabled' if EMAIL_ENABLED else 'Disabled'}")
    print("=" * 60)

# ============================================================
# DETECTION RULES - Network Intrusion Detection System
# ============================================================
# Format: {"proto": "TCP/UDP/ICMP", "dst_port": port, "msg": "Description", "severity": "LOW/MEDIUM/HIGH"}
# Special: "any" for any port

DETECTION_RULES = {
    # ---- PRACTICAL NETWORK SERVICES ----
    "SSH": {
        "port": 22,
        "severity": "MEDIUM",
        "description": "SSH Connection Attempt",
        "brute_force_threshold": 5,  # alerts after X attempts
        "brute_force_window": 30     # in seconds
    },
    "FTP": {
        "port": 21,
        "severity": "MEDIUM",
        "description": "FTP Connection Attempt",
        "brute_force_threshold": 5,
        "brute_force_window": 30
    },
    "TELNET": {
        "port": 23,
        "severity": "HIGH",
        "description": "Telnet Connection (Insecure Protocol)",
        "brute_force_threshold": 3,
        "brute_force_window": 30
    },
    "RDP": {
        "port": 3389,
        "severity": "HIGH",
        "description": "RDP Connection Attempt",
        "brute_force_threshold": 5,
        "brute_force_window": 30
    },
    "SMB": {
        "port": 445,
        "severity": "HIGH",
        "description": "SMB Connection (Ransomware Risk)",
        "brute_force_threshold": 5,
        "brute_force_window": 30
    },
    "NETBIOS": {
        "port": 139,
        "severity": "MEDIUM",
        "description": "NetBIOS Connection Attempt",
        "brute_force_threshold": 5,
        "brute_force_window": 30
    },
    "ICMP": {
        "port": None,
        "severity": "LOW",
        "description": "ICMP Ping",
        "brute_force_threshold": 20,
        "brute_force_window": 10
    },
}

# ============================================================
# PORT SCAN DETECTION
# ============================================================
PORT_SCAN_TRACKER = defaultdict(list)
PORT_SCAN_THRESHOLD = 10  # connections to different ports in window = port scan
PORT_SCAN_WINDOW = 30     # seconds
PORT_SCAN_MAX_TRACKED_PORT = get_int_env("PORT_SCAN_MAX_TRACKED_PORT", 1024, minimum=1)
PORT_SCAN_INCLUDE_HIGH_PORTS = os.getenv("PORT_SCAN_INCLUDE_HIGH_PORTS", "false").lower() == "true"
STEALTH_SCAN_TRACKER = defaultdict(list)
STEALTH_SCAN_THRESHOLD = get_int_env("STEALTH_SCAN_THRESHOLD", 6, minimum=1)
STEALTH_SCAN_WINDOW = get_int_env("STEALTH_SCAN_WINDOW", 15, minimum=1)
seen_connection_attempts = {}
CONNECTION_ATTEMPT_DEDUP_SECONDS = get_int_env("CONNECTION_ATTEMPT_DEDUP_SECONDS", 3, minimum=0)
OVERSIZED_ICMP_MIN_BYTES = get_int_env(
    "OVERSIZED_ICMP_MIN_BYTES",
    get_int_env("PING_OF_DEATH_MIN_BYTES", 1200, minimum=1),
    minimum=1,
)
PING_OF_DEATH_MIN_BYTES = OVERSIZED_ICMP_MIN_BYTES


def is_connection_attempt(packet, proto):
    """Return True for packets that represent a new connection attempt."""
    if proto == "TCP":
        if TCP not in packet:
            return False
        flags = packet[TCP].flags
        return bool(flags & 0x02) and not bool(flags & 0x10)  # SYN without ACK
    return False


def tcp_flag_bits(packet):
    if TCP not in packet:
        return 0
    return int(packet[TCP].flags)


def classify_stealth_scan(packet):
    if TCP not in packet:
        return None
    flags = tcp_flag_bits(packet)
    if flags == 0:
        return "NULL"
    if flags == 0x01:
        return "FIN"
    if flags & 0x29 == 0x29 and not flags & 0x12:
        return "XMAS"
    return None


def is_new_connection_attempt(src_ip, dst_ip, src_port, dst_port, proto):
    current_time = time.time()
    key = f"{proto}:{src_ip}:{src_port}:{dst_ip}:{dst_port}"
    last_seen = seen_connection_attempts.get(key)
    if last_seen is not None and current_time - last_seen < CONNECTION_ATTEMPT_DEDUP_SECONDS:
        return False
    seen_connection_attempts[key] = current_time
    return True


def is_protected_destination(dst_ip):
    try:
        ip_addr = ipaddress.ip_address(dst_ip)
    except ValueError:
        return False
    return any(ip_addr in network for network in PROTECTED_NETWORKS)


def is_protected_source(src_ip):
    try:
        ip_addr = ipaddress.ip_address(src_ip)
    except ValueError:
        return False
    return any(ip_addr in network for network in PROTECTED_NETWORKS)


def is_protected_network_boundary(dst_ip):
    try:
        ip_addr = ipaddress.ip_address(dst_ip)
    except ValueError:
        return False
    for network in PROTECTED_NETWORKS:
        if ip_addr.version != network.version:
            continue
        if network.num_addresses <= 2:
            continue
        if ip_addr == network.network_address:
            return True
        broadcast_address = getattr(network, "broadcast_address", None)
        if broadcast_address is not None and ip_addr == broadcast_address:
            return True
    return False


def is_bad_source_address(src_ip):
    try:
        ip_addr = ipaddress.ip_address(src_ip)
    except ValueError:
        return True
    return ip_addr.is_multicast or ip_addr.is_unspecified or ip_addr.is_reserved


def should_ignore_source(src_ip):
    if is_in_networks(src_ip, IGNORE_SOURCE_NETWORKS):
        return True
    if REJECT_TRUSTED_SOURCES and is_in_networks(src_ip, TRUSTED_SOURCE_NETWORKS):
        return not (MONITOR_PROTECTED_SOURCES and is_protected_source(src_ip))
    return False


def utc_timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def normalize_attack_type(attack_type):
    if not attack_type:
        return attack_type
    if attack_type.startswith("Port Scan Detected"):
        return "PORT_SCAN"
    if attack_type.startswith("Brute Force Attack"):
        return "BRUTE_FORCE"
    if attack_type.startswith("ICMP"):
        return "ICMP_ATTACK"
    return ATTACK_TYPE_ALIASES.get(attack_type, attack_type)


def create_database_and_table():
    """Create database schema if it does not exist."""
    try:
        initialize_database()
        print("[+] Database and table created/verified successfully.")
    except Exception as e:
        print(f"Error creating database/table: {e}")
        raise SystemExit(1)

def get_country_from_ip(ip):
    """Return source origin/country for dashboard and notification display."""
    return resolve_country_from_ip(ip, geolocation_enabled=GEOLOCATION_ENABLED)

def alert_cooldown_key(alert):
    return ":".join(str(alert.get(field, "")) for field in ("src_ip", "dst_ip", "dst_port", "attack_type"))


def should_send_alert(alert):
    """Check if alert should be sent based on cooldown"""
    key = alert_cooldown_key(alert)
    current_time = time.time()

    if key in alert_cooldown_tracker:
        last_sent = alert_cooldown_tracker[key]
        if current_time - last_sent < ALERT_COOLDOWN:
            return False

    return True


def send_email_alert(alert, country, bypass_cooldown=False):
    """Send an SMTP alert for accepted intrusion detections."""
    if not bypass_cooldown and not should_send_alert(alert):
        reason = f"Cooldown active for {alert['src_ip']}"
        print(f"    [EMAIL] {reason}. Skipping alert.")
        return False

    alert_time = alert.get('timestamp', time.strftime("%Y-%m-%d %H:%M:%S"))
    dst_info = f"{alert.get('dst_ip', 'N/A')}"
    if alert.get('dst_port'):
        dst_info += f":{alert['dst_port']}"
    src_info = f"{alert.get('src_ip', 'N/A')}"
    if alert.get('src_port'):
        src_info += f":{alert['src_port']}"

    subject = f"AlertMesh {alert.get('severity', 'MEDIUM')} alert: {alert.get('attack_type', 'UNKNOWN')}"
    text = f"""ALERT: {alert.get('msg', 'Intrusion alert')}

Severity: {alert.get('severity', 'MEDIUM')}
Attack Type: {alert.get('attack_type', 'UNKNOWN')}

Source: {src_info}
Origin / Country: {country}
OS Estimate: {alert.get('detected_os', 'Unknown')}
Target: {dst_info}

Time: {alert_time}

AlertMesh NIDS - Email Alert"""
    sent = send_email_message(subject, text)
    if sent:
        alert_cooldown_tracker[alert_cooldown_key(alert)] = time.time()
    return sent

def store_alert(alert):
    """Validate and store an alert in the configured database backend."""
    if os.getenv("ALERTMESH_DB_BACKEND", "sqlite").strip().lower() in {"mongo", "mongodb"}:
        try:
            attack_type = normalize_attack_type(alert.get('attack_type', alert['msg']))
            alert_for_analysis = {
                **alert,
                "attack_type": attack_type,
                "protocol": alert["proto"],
                "source": "python",
            }
            decision = analyze_alert(alert_for_analysis, PROTECTED_NETWORKS)
            if not decision.accepted:
                insert_rejected_alert_selected(alert_for_analysis, decision)
                print(
                    f"    [ANALYSIS] Rejected alert: {decision.note}"
                )
                return None

            if alert_is_duplicate_selected(alert_for_analysis):
                print("    [ANALYSIS] Duplicate alert suppressed.")
                return None

            country = get_country_from_ip(alert['src_ip'])
            alert_for_insert = {
                **alert_for_analysis,
                "country": country,
                "detected_os": alert.get('detected_os', 'Unknown'),
            }
            insert_intrusion_alert_selected(alert_for_insert, decision)
            print(f"    [DB] Logged to MongoDB - Origin/Country: {country}, OS: {alert_for_insert['detected_os']}")
            return country
        except Exception as e:
            print(f"Error logging to MongoDB: {e}")
            return None

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        if connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.cursor()
            attack_type = normalize_attack_type(alert.get('attack_type', alert['msg']))
            alert_for_analysis = {
                **alert,
                "attack_type": attack_type,
                "protocol": alert["proto"],
                "source": "python",
            }
            decision = analyze_alert(alert_for_analysis, PROTECTED_NETWORKS)
            if not decision.accepted:
                insert_rejected_alert(connection, alert_for_analysis, decision)
                connection.commit()
                print(
                    f"    [ANALYSIS] Rejected alert: {decision.note}"
                )
                return None

            if alert_is_duplicate(connection, alert_for_analysis):
                print("    [ANALYSIS] Duplicate alert suppressed.")
                connection.commit()
                return None

            # Get source origin/country from source IP.
            country = get_country_from_ip(alert['src_ip'])
            detected_os = alert.get('detected_os', 'Unknown')
            alert_for_insert = {
                **alert_for_analysis,
                "country": country,
                "detected_os": detected_os,
            }
            insert_intrusion_alert(connection, alert_for_insert, decision)
            connection.commit()

            print(f"    [DB] Logged to SQLite - Origin/Country: {country}, OS estimate: {detected_os}")

            return country

    except (sqlite3.Error, KeyError, ValueError) as e:
        if connection:
            connection.rollback()
        print(f"Error storing alert in SQLite: {e}")
        return None
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

def take_response_action(alert):
    """
    Placeholder for manual response workflow.

    AlertMesh intentionally does not perform automatic blocking because false
    positives in a learning/demo IDS should not change host firewall state.
    """
    print(f"    [RESPONSE] Review required for source IP: {alert['src_ip']}")

def log_alert(alert):
    """Log alert to JSON backup, configured database, and console."""
    print(f"[ALERT] {alert['timestamp']} - {alert['msg']} - Src: {alert['src_ip']} -> Dst: {alert['dst_ip']}")

    # Store in the configured database and get source origin/country.
    country = store_alert(alert)
    if country is None:
        return

    # Trigger Response Mechanism only after validation/deduplication accepts the alert.
    take_response_action(alert)

    # Send email alert after validation/deduplication accepts the alert.
    send_email_alert(alert, country)

    # Append to JSON log file (backup)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert) + "\n")
    except Exception as e:
        print(f"Error writing to log: {e}")

def get_service_name(port):
    """Get service name from port number"""
    for service, config in DETECTION_RULES.items():
        if config.get("port") == port:
            return service
    return "UNKNOWN"


def should_track_port_scan_port(dst_port):
    """Avoid treating normal client ephemeral reply ports as inbound scans."""
    if dst_port is None:
        return False
    if PORT_SCAN_INCLUDE_HIGH_PORTS:
        return True
    if dst_port <= PORT_SCAN_MAX_TRACKED_PORT:
        return True
    service_ports = {
        config.get("port")
        for config in DETECTION_RULES.values()
        if isinstance(config.get("port"), int)
    }
    return dst_port in service_ports


def detect_port_scan(src_ip, dst_ip, dst_port):
    """Detect port scanning activity"""
    if not should_track_port_scan_port(dst_port):
        return False

    current_time = time.time()
    key = f"{src_ip}_{dst_ip}_scan"

    # Add this connection
    PORT_SCAN_TRACKER[key].append({"port": dst_port, "time": current_time})

    # Clean old entries
    PORT_SCAN_TRACKER[key] = [
        x for x in PORT_SCAN_TRACKER[key]
        if current_time - x["time"] < PORT_SCAN_WINDOW
    ]

    # Count unique ports
    unique_ports = len(set(x["port"] for x in PORT_SCAN_TRACKER[key]))

    if unique_ports >= PORT_SCAN_THRESHOLD:
        # Clear the tracker for this IP to avoid repeat alerts
        PORT_SCAN_TRACKER[key] = []
        return True
    return False


def detect_stealth_scan(src_ip, dst_ip, scan_type):
    current_time = time.time()
    key = f"stealth_scan:{src_ip}:{dst_ip}:{scan_type}"
    STEALTH_SCAN_TRACKER[key].append(current_time)
    STEALTH_SCAN_TRACKER[key] = [
        seen for seen in STEALTH_SCAN_TRACKER[key]
        if current_time - seen < STEALTH_SCAN_WINDOW
    ]
    count = len(STEALTH_SCAN_TRACKER[key])
    if count >= STEALTH_SCAN_THRESHOLD:
        STEALTH_SCAN_TRACKER[key] = []
        return True, count
    return False, count


def detect_brute_force(src_ip, dst_ip, service_name):
    """Detect brute force attacks"""
    if service_name not in DETECTION_RULES:
        return False, None
    if service_name not in BRUTE_FORCE_SERVICES:
        return False, None

    config = DETECTION_RULES[service_name]
    threshold = config.get("brute_force_threshold", 5)
    window = config.get("brute_force_window", 30)
    current_time = time.time()
    key = f"{src_ip}_{dst_ip}_{service_name}"

    # Add this attempt
    connection_tracker[key].append(current_time)

    # Clean old entries
    connection_tracker[key] = [
        x for x in connection_tracker[key]
        if current_time - x < window
    ]

    # Count attempts in window
    attempts = len(connection_tracker[key])

    if attempts >= threshold:
        # Clear to avoid spam
        connection_tracker[key] = []
        return True, attempts
    return False, attempts


def should_emit_event(event_key):
    """Throttle noisy single-packet detections without affecting brute force counts."""
    return should_emit_event_with_cooldown(event_key, EVENT_COOLDOWN_SECONDS)


def should_emit_event_with_cooldown(event_key, cooldown_seconds):
    """Throttle noisy detections by event key."""
    current_time = time.time()
    last_seen = event_cooldown_tracker.get(event_key)
    if last_seen and current_time - last_seen < cooldown_seconds:
        return False
    event_cooldown_tracker[event_key] = current_time
    return True


def detect_threshold_event(tracker, key, threshold, window):
    current_time = time.time()
    tracker[key].append(current_time)
    tracker[key] = [seen for seen in tracker[key] if current_time - seen < window]
    count = len(tracker[key])
    if count >= threshold:
        tracker[key] = []
        return True, count
    return False, count


def cleanup_trackers(force=False):
    global last_tracker_cleanup
    current_time = time.time()
    if not force and current_time - last_tracker_cleanup < TRACKER_CLEANUP_SECONDS:
        return
    last_tracker_cleanup = current_time

    for tracker, max_age in (
        (PORT_SCAN_TRACKER, PORT_SCAN_WINDOW),
        (STEALTH_SCAN_TRACKER, STEALTH_SCAN_WINDOW),
        (
            connection_tracker,
            max(
                EXPOSED_SERVICE_WINDOW,
                *(config.get("brute_force_window", 30) for config in DETECTION_RULES.values()),
            ),
        ),
        (icmp_tracker, ICMP_WINDOW),
    ):
        for key in list(tracker.keys()):
            tracker[key] = [
                item for item in tracker[key]
                if current_time - (item["time"] if isinstance(item, dict) else item) < max_age
            ]
            if not tracker[key]:
                del tracker[key]

    for tracker, max_age in (
        (event_cooldown_tracker, max(EVENT_COOLDOWN_SECONDS, PORT_SCAN_EVENT_COOLDOWN_SECONDS)),
        (alert_cooldown_tracker, ALERT_COOLDOWN),
        (seen_connection_attempts, CONNECTION_ATTEMPT_DEDUP_SECONDS),
    ):
        for key, seen in list(tracker.items()):
            if current_time - seen >= max_age:
                del tracker[key]

def get_os_from_ttl_and_window(ttl, window_size):
    """Detect OS based on TTL and TCP Window Size"""
    if ttl is None:
        return "Unknown"

    # Estimate initial TTL based on remaining TTL
    # Common initial TTLs: 64 (Linux), 128 (Windows), 255 (network devices)
    if ttl >= 60 and ttl <= 68:
        init_ttl = 64
    elif ttl >= 120 and ttl <= 132:
        init_ttl = 128
    elif ttl >= 240 and ttl <= 260:
        init_ttl = 255
    else:
        init_ttl = 64

    # Refine with window size
    if window_size:
        if window_size == 65535 and init_ttl == 128:
            return "Windows (SMB optimized)"
        if window_size in [29200, 65535] or (5800 <= window_size <= 65535):
            if init_ttl == 64:
                return "Linux"
            elif init_ttl == 128:
                return "Windows"
        elif window_size == 4128:
            return "macOS"
        elif window_size == 16384:
            return "FreeBSD/OpenBSD"
        elif init_ttl == 255:
            return "Network Device"

    # Fallback based on TTL
    if init_ttl == 64:
        return "Linux/Unix"
    elif init_ttl == 128:
        return "Windows"
    elif init_ttl == 255:
        return "Network Device"
    return "Unknown OS"

def detect_os_from_packet(packet):
    """Extract OS fingerprint from packet"""
    ttl = None
    window_size = None

    if IP in packet:
        ttl = packet[IP].ttl

    if TCP in packet:
        window_size = packet[TCP].window

    return get_os_from_ttl_and_window(ttl, window_size)


def is_icmp_echo_request(packet):
    return ICMP in packet and packet[ICMP].type == 8


def is_icmp_echo_reply(packet):
    return ICMP in packet and packet[ICMP].type == 0


def observed_flow(packet, proto, src_ip, dst_ip, src_port, dst_port, protected_source, protected_destination):
    """Normalize packets so response-only captures can still show inbound probes."""
    flow = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protected_destination": protected_destination,
        "protected_source": protected_source,
        "monitored": protected_destination or (MONITOR_PROTECTED_SOURCES and protected_source),
        "connection_attempt": is_connection_attempt(packet, proto),
        "response_inferred": False,
        "icmp_echo_request": is_icmp_echo_request(packet),
    }

    if protected_source and not protected_destination:
        if proto == "TCP" and TCP in packet:
            flags = tcp_flag_bits(packet)
            response_to_probe = bool(flags & 0x04) or ((flags & 0x12) == 0x12 and src_port is not None)
            if response_to_probe:
                flow.update({
                    "src_ip": dst_ip,
                    "dst_ip": src_ip,
                    "src_port": dst_port,
                    "dst_port": src_port,
                    "protected_destination": True,
                    "protected_source": False,
                    "monitored": True,
                    "connection_attempt": True,
                    "response_inferred": True,
                })
        elif proto == "ICMP" and is_icmp_echo_reply(packet):
            flow.update({
                "src_ip": dst_ip,
                "dst_ip": src_ip,
                "protected_destination": True,
                "protected_source": False,
                "monitored": True,
                "response_inferred": True,
                "icmp_echo_request": True,
            })

    return flow


def packet_debug_line(packet):
    if IP not in packet:
        return None
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    if DEBUG_HOSTS and src_ip not in DEBUG_HOSTS and dst_ip not in DEBUG_HOSTS:
        return None
    if TCP in packet:
        flags = packet[TCP].sprintf("%TCP.flags%")
        return f"[PACKET] TCP {src_ip}:{packet[TCP].sport} -> {dst_ip}:{packet[TCP].dport} flags={flags}"
    if UDP in packet:
        return f"[PACKET] UDP {src_ip}:{packet[UDP].sport} -> {dst_ip}:{packet[UDP].dport}"
    if ICMP in packet:
        return f"[PACKET] ICMP type={packet[ICMP].type} {src_ip} -> {dst_ip} len={len(packet)}"
    return f"[PACKET] IP proto={packet[IP].proto} {src_ip} -> {dst_ip} len={len(packet)}"


def process_packet(packet):
    """Process a single packet and detect intrusions"""
    if IP not in packet:
        return []

    alerts = []
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    if is_bad_source_address(src_ip):
        return []
    if should_ignore_source(src_ip):
        return []

    cleanup_trackers()
    timestamp = utc_timestamp()
    protected_destination = is_protected_destination(dst_ip)
    if protected_destination and is_protected_network_boundary(dst_ip):
        return []
    protected_source = is_protected_source(src_ip)
    monitored_traffic = protected_destination or (MONITOR_PROTECTED_SOURCES and protected_source)

    # Detect OS from packet
    detected_os = detect_os_from_packet(packet)

    proto = None
    dst_port = None
    src_port = None

    # Determine protocol and extract info
    if TCP in packet:
        proto = "TCP"
        dst_port = packet[TCP].dport
        src_port = packet[TCP].sport
    elif UDP in packet:
        proto = "UDP"
        dst_port = packet[UDP].dport
        src_port = packet[UDP].sport
    elif ICMP in packet:
        proto = "ICMP"
        dst_port = None
        src_port = None

    flow = observed_flow(packet, proto, src_ip, dst_ip, src_port, dst_port, protected_source, protected_destination)
    src_ip = flow["src_ip"]
    dst_ip = flow["dst_ip"]
    src_port = flow["src_port"]
    dst_port = flow["dst_port"]
    protected_destination = flow["protected_destination"]
    protected_source = flow["protected_source"]
    monitored_traffic = flow["monitored"]
    connection_attempt = flow["connection_attempt"]
    if connection_attempt and not is_new_connection_attempt(src_ip, dst_ip, src_port, dst_port, proto):
        connection_attempt = False

    # === CHECK FOR PORT SCAN ===
    if proto == "TCP" and dst_port and connection_attempt and monitored_traffic:
        # Check for port scan from new connection attempts only.
        port_scan_key = f"port_scan:{src_ip}:{dst_ip}"
        if detect_port_scan(src_ip, dst_ip, dst_port) and should_emit_event_with_cooldown(
            port_scan_key,
            PORT_SCAN_EVENT_COOLDOWN_SECONDS,
        ):
            alert = {
                "timestamp": timestamp,
                "msg": f"Port Scan Detected ({src_ip} scanned multiple ports)",
                "attack_type": "PORT_SCAN",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "proto": proto,
                "dst_port": dst_port,
                "src_port": src_port,
                "severity": "HIGH",
                "detected_os": detected_os
            }
            alerts.append(alert)
            print(f"[PORT SCAN] {src_ip} - Scanning activity detected")

    if proto == "TCP" and monitored_traffic:
        stealth_scan_type = classify_stealth_scan(packet)
        if stealth_scan_type:
            stealth_key = f"stealth_scan:{src_ip}:{dst_ip}:{stealth_scan_type}"
            is_scan_alert, scan_count = detect_stealth_scan(src_ip, dst_ip, stealth_scan_type)
            if is_scan_alert and should_emit_event_with_cooldown(
                stealth_key,
                PORT_SCAN_EVENT_COOLDOWN_SECONDS,
            ):
                alert = {
                    "timestamp": timestamp,
                    "msg": f"{stealth_scan_type} Stealth Scan Detected ({scan_count} packets in {STEALTH_SCAN_WINDOW}s)",
                    "attack_type": "PORT_SCAN",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "proto": proto,
                    "dst_port": dst_port,
                    "src_port": src_port,
                    "severity": "HIGH",
                    "detected_os": detected_os
                }
                alerts.append(alert)
                print(f"[STEALTH SCAN] {src_ip} -> {dst_ip} ({stealth_scan_type})")

    # === CHECK FOR SERVICE CONNECTION ===
    if proto == "ICMP" and monitored_traffic:
        icmp_echo_request = flow["icmp_echo_request"]
        if icmp_echo_request and len(packet) >= OVERSIZED_ICMP_MIN_BYTES:
            event_key = f"oversized_icmp:{src_ip}:{dst_ip}"
            if should_emit_event(event_key):
                alert = {
                    "timestamp": timestamp,
                    "msg": f"Oversized ICMP Echo Request ({len(packet)} bytes)",
                    "attack_type": "ICMP_ATTACK",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "proto": proto,
                    "dst_port": dst_port,
                    "src_port": src_port,
                    "severity": "HIGH",
                    "detected_os": detected_os
                }
                alerts.append(alert)
                print(f"[ICMP] Oversized ping {src_ip} -> {dst_ip} ({len(packet)} bytes)")

        if icmp_echo_request:
            is_icmp_alert, icmp_count = detect_threshold_event(
                icmp_tracker,
                f"icmp_echo:{src_ip}:{dst_ip}",
                ICMP_THRESHOLD,
                ICMP_WINDOW,
            )
        else:
            is_icmp_alert, icmp_count = False, 0
    else:
        is_icmp_alert, icmp_count = False, 0

    if proto == "ICMP" and monitored_traffic and is_icmp_alert and should_emit_event(f"icmp_echo:{src_ip}:{dst_ip}"):
        alert = {
            "timestamp": timestamp,
            "msg": f"ICMP Probe / Ping Activity ({icmp_count} packets in {ICMP_WINDOW}s)",
            "attack_type": "ICMP_ATTACK",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "proto": proto,
            "dst_port": dst_port,
            "src_port": src_port,
            "severity": "LOW",
            "detected_os": detected_os
        }
        alerts.append(alert)
        print(f"[ICMP] {src_ip} -> {dst_ip} ({icmp_count} packets)")

    if proto in ["TCP", "UDP", "ICMP"]:
        service_name = None

        if proto == "ICMP":
            service_name = "ICMP"
        elif dst_port:
            service_name = get_service_name(dst_port)

        if service_name and service_name in DETECTION_RULES and monitored_traffic:
            config = DETECTION_RULES[service_name]

            # Check brute force from new connection attempts only.
            is_brute_force, attempts = (False, None)
            if connection_attempt:
                is_brute_force, attempts = detect_brute_force(src_ip, dst_ip, service_name)

            if is_brute_force:
                alert = {
                    "timestamp": timestamp,
                    "msg": f"Brute Force Attack - {config['description']}",
                    "attack_type": "BRUTE_FORCE",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "proto": proto,
                    "dst_port": dst_port,
                    "src_port": src_port,
                    "severity": "HIGH",
                    "attempts": attempts,
                    "detected_os": detected_os
                }
                alerts.append(alert)
                print(f"[BRUTE FORCE] {src_ip} -> {service_name} ({attempts} attempts)")
            elif (
                connection_attempt
                and service_name in EXPOSED_SERVICE_ALERTS
            ):
                event_key = f"service_probe:{src_ip}:{dst_ip}:{service_name}"
                is_service_alert, service_count = detect_threshold_event(
                    connection_tracker,
                    event_key,
                    EXPOSED_SERVICE_THRESHOLD,
                    EXPOSED_SERVICE_WINDOW,
                )
                if is_service_alert and should_emit_event(event_key):
                    alert = {
                        "timestamp": timestamp,
                        "msg": f"Exposed Service Access - {config['description']} ({service_count} attempts in {EXPOSED_SERVICE_WINDOW}s)",
                        "attack_type": "EXPOSED_SERVICE_ACCESS",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "proto": proto,
                        "dst_port": dst_port,
                        "src_port": src_port,
                        "severity": config.get("severity", "MEDIUM"),
                        "detected_os": detected_os
                    }
                    alerts.append(alert)
                    print(f"[SERVICE PROBE] {src_ip} -> {service_name} ({service_count} attempts)")
            elif dst_port == config["port"] or (proto == "ICMP" and service_name == "ICMP"):
                # Log normal connection (but not as alert to avoid spam)
                # You can enable this if you want all connections logged
                pass

    return alerts

def check_rules(packet):
    """Legacy function - now uses new detection system"""
    alerts = process_packet(packet)
    for alert in alerts:
        log_alert(alert)


def run_demo_once(target_ip=None, source_ip=None):
    """Generate a controlled local verification set through the normal detector pipeline."""
    target_ip = target_ip or os.getenv("DEMO_TARGET_IP") or first_protected_host()
    if not target_ip:
        print("ERROR: Could not determine demo target. Set --demo-target or PROTECTED_NETWORKS.")
        raise SystemExit(1)

    source_ip = source_ip or os.getenv("DEMO_SOURCE_IP") or random_demo_source(target_ip)
    print(f"[DEMO] Generating controlled verification traffic: {source_ip} -> {target_ip}")

    demo_packets = []
    for _ in range(ICMP_THRESHOLD):
        demo_packets.append(IP(src=source_ip, dst=target_ip) / ICMP(type=8))
    demo_packets.append(IP(src=source_ip, dst=target_ip) / ICMP(type=8) / ("X" * OVERSIZED_ICMP_MIN_BYTES))

    for index, dport in enumerate(range(20, 30), start=1):
        demo_packets.append(IP(src=source_ip, dst=target_ip) / TCP(sport=40000 + index, dport=dport, flags="S"))

    for index in range(STEALTH_SCAN_THRESHOLD):
        demo_packets.append(IP(src=source_ip, dst=target_ip) / TCP(sport=41000 + index, dport=120 + index, flags="F"))
    for index in range(STEALTH_SCAN_THRESHOLD):
        demo_packets.append(IP(src=source_ip, dst=target_ip) / TCP(sport=42000 + index, dport=220 + index, flags=0))
    for index in range(STEALTH_SCAN_THRESHOLD):
        demo_packets.append(IP(src=source_ip, dst=target_ip) / TCP(sport=43000 + index, dport=320 + index, flags="FPU"))

    for index in range(DETECTION_RULES["SSH"]["brute_force_threshold"]):
        demo_packets.append(IP(src=source_ip, dst=target_ip) / TCP(sport=50000 + index, dport=22, flags="S"))

    for index in range(EXPOSED_SERVICE_THRESHOLD):
        demo_packets.append(IP(src=source_ip, dst=target_ip) / TCP(sport=51000 + index, dport=445, flags="S"))

    stored = 0
    produced = 0
    for packet in demo_packets:
        alerts = process_packet(packet)
        produced += len(alerts)
        for alert in alerts:
            log_alert(alert)
            stored += 1

    print(f"[DEMO] Produced {produced} alert event(s). Check Dashboard -> Intrusion Logs.")
    return produced


def first_protected_host():
    for network in PROTECTED_NETWORKS:
        if network.version != 4:
            continue
        if network.prefixlen == 32:
            return str(network.network_address)
        if network.num_addresses > 2:
            return str(next(network.hosts()))
    return None


def random_demo_source(target_ip):
    try:
        target = ipaddress.ip_address(target_ip)
    except ValueError:
        return "192.168.1.250"
    if target.version != 4:
        return "192.168.1.250"
    octets = str(target).split(".")
    last = int(octets[-1])
    candidate = last
    while candidate == last:
        candidate = random.randint(50, 250)
    return ".".join([*octets[:3], str(candidate)])

def packet_callback(packet):
    try:
        if DEBUG_PACKETS:
            debug_line = packet_debug_line(packet)
            if debug_line:
                print(debug_line)
        check_rules(packet)
    except Exception as e:
        print(f"Error processing packet: {e}")


def interface_display_name(iface):
    name = getattr(iface, "name", "")
    description = getattr(iface, "description", "")
    if name and description and name != description:
        return f"{name} ({description})"
    return name or description or str(iface)


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


def start_sniffing(interface=None):
    sniff_interfaces = resolve_capture_interfaces(interface)
    if isinstance(sniff_interfaces, list):
        print("Monitoring real network traffic on interfaces:")
        for current_interface in sniff_interfaces:
            print(f"  - {current_interface}")
        print("(Press Ctrl+C to stop)")
    elif sniff_interfaces:
        print(f"Monitoring real network traffic on interface: {sniff_interfaces} (Press Ctrl+C to stop)")
    else:
        print("Monitoring real network traffic... (Press Ctrl+C to stop)")
    try:
        if sniff_interfaces:
            sniff(iface=sniff_interfaces, prn=packet_callback, store=0)
        else:
            sniff(prn=packet_callback, store=0)
    except Exception as e:
        error_msg = str(e).lower()
        if "permission" in error_msg or "denied" in error_msg or "/dev/bpf" in error_msg or "root" in error_msg:
            print("WARNING: Packet capture requires administrator/root privileges.")
            print("=" * 50)
            if os.name == "nt":
                print("For real detection on Windows, install Npcap and run this terminal as Administrator.")
            else:
                print("For real detection on Linux/macOS, install libpcap and run this detector with sudo/root.")
            print("=" * 50)
        else:
            print(f"ERROR: Real packet capture failed: {e}")
        print("No synthetic alerts will be generated.")
        raise SystemExit(1)


def list_interfaces():
    """Print Scapy capture interfaces that can be used with --interface."""
    print("Available Scapy capture interfaces:")
    for iface in get_working_ifaces():
        name = getattr(iface, "name", "")
        description = getattr(iface, "description", "")
        ip = getattr(iface, "ip", "")
        print(f"  - {name} | {description} | {ip}")


def parse_args():
    parser = argparse.ArgumentParser(description="AlertMesh Python/Scapy NIDS detector")
    parser.add_argument(
        "-i",
        "--interface",
        default=os.getenv("NIDS_INTERFACE"),
        help="Interface name to sniff, for example eth0, wlan0, or Wi-Fi. Use auto/all to sniff all real adapters. Defaults to NIDS_INTERFACE or Scapy default.",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List Scapy capture interfaces and exit.",
    )
    parser.add_argument(
        "--debug-packets",
        action="store_true",
        default=os.getenv("NIDS_DEBUG_PACKETS", "false").lower() == "true",
        help="Print IPv4 packet summaries before detection. Use with --debug-host to reduce noise.",
    )
    parser.add_argument(
        "--debug-host",
        action="append",
        default=[
            host.strip()
            for host in os.getenv("NIDS_DEBUG_HOSTS", "").split(",")
            if host.strip()
        ],
        help="Only print debug packet summaries where this IP is source or destination. Can be used more than once.",
    )
    parser.add_argument(
        "--demo-once",
        action="store_true",
        help="Run a controlled one-shot demo through the normal detection and database pipeline, then exit.",
    )
    parser.add_argument(
        "--demo-target",
        default=os.getenv("DEMO_TARGET_IP"),
        help="Target IP for --demo-once. Defaults to the first PROTECTED_NETWORKS host.",
    )
    parser.add_argument(
        "--demo-source",
        default=os.getenv("DEMO_SOURCE_IP"),
        help="Source IP for --demo-once. Defaults to a random IP near the target.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    print_startup_banner()
    args = parse_args()
    DEBUG_PACKETS = args.debug_packets
    DEBUG_HOSTS = set(args.debug_host or [])
    if args.list_interfaces:
        list_interfaces()
        raise SystemExit(0)

    ready, reason = email_config_ready()
    if ready:
        print(f"Email alerts will be sent to: {', '.join(SMTP_TO)}")
    else:
        print(f"WARNING: Email alerts are not ready: {reason}")
        print("Configure EMAIL_ENABLED and SMTP_* values in src/.env to receive email notifications.")

    # Initialize database and table
    create_database_and_table()

    if args.demo_once:
        run_demo_once(target_ip=args.demo_target, source_ip=args.demo_source)
        raise SystemExit(0)

    start_sniffing(args.interface)
