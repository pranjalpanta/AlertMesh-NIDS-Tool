import argparse
import hashlib
import json
import os
import re
import smtplib
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path

from dotenv import load_dotenv

try:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
except ImportError:
    ZoneInfo = None
    ZoneInfoNotFoundError = ValueError

from alert_analysis import (
    alert_is_duplicate,
    analyze_alert,
    protected_networks_from_env,
)
from database import (
    alert_is_duplicate_selected,
    get_db_connection,
    get_db_path,
    get_storage_description,
    initialize_database as initialize_shared_database,
    insert_intrusion_alert,
    insert_rejected_alert,
    insert_intrusion_alert_selected,
    insert_rejected_alert_selected,
    using_mongodb,
)
from geo_utils import get_country_from_ip


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", override=False, encoding="utf-8-sig")

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


POLL_SECONDS = get_float_env("SNORT_INGEST_POLL_SECONDS", 1.0, minimum=0.1)
PROTECTED_NETWORKS = protected_networks_from_env()
EMAIL_COOLDOWN_SECONDS = get_int_env("ALERT_COOLDOWN", 60, minimum=0)
EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "false").lower() == "true"
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = get_int_env("SMTP_PORT", 587, minimum=1)
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip()
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USERNAME).strip()
SMTP_TO = [value.strip() for value in os.getenv("SMTP_TO", "").split(",") if value.strip()]
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
GEOLOCATION_ENABLED = os.getenv("GEOLOCATION_ENABLED", "false").lower() == "true"
email_cooldown = {}


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
        print(f"[EMAIL] {reason}. Skipping email alert.")
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
        print("[EMAIL] Alert sent successfully")
        return True
    except Exception as exc:
        print(f"[EMAIL] Error sending email alert: {exc}")
        return False


def resolve_path(value, default):
    path = Path(value or default)
    return path if path.is_absolute() else BASE_DIR / path


DB_PATH = get_db_path()
SNORT_ALERT_FILE = resolve_path(os.getenv("SNORT_ALERT_FILE"), BASE_DIR / "logs" / "alert.ids")
STATE_FILE = resolve_path(os.getenv("SNORT_INGEST_STATE"), BASE_DIR / "logs" / "snort_ingest.offset")

FAST_ALERT_RE = re.compile(
    r"(?P<timestamp>\d{2}/\d{2}(?:/\d{2,4})?-\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
    r"\s+\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<message>.*?)\s+\[\*\*\]"
    r"(?:\s+\[Classification:\s*(?P<classification>.*?)\])?"
    r"(?:\s+\[Priority:\s*(?P<priority>\d+)\])?"
    r"\s+\{(?P<protocol>[A-Za-z0-9]+)\}\s+"
    r"(?P<src_endpoint>\S+)"
    r"\s+->\s+"
    r"(?P<dst_endpoint>\S+)(?:\s|$)",
    re.DOTALL,
)
ALERT_START_RE = re.compile(r"(?m)^\d{2}/\d{2}(?:/\d{2,4})?-\d{2}:\d{2}:\d{2}")
ALERT_START_BYTES_RE = re.compile(rb"(?m)^\d{2}/\d{2}(?:/\d{2,4})?-\d{2}:\d{2}:\d{2}")


def configure_console_encoding():
    import sys

    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def initialize_database():
    global DB_PATH
    initialize_shared_database()
    DB_PATH = get_db_path()


def sensor_timezone():
    configured_timezone = os.getenv("SNORT_TIMEZONE") or os.getenv("DASHBOARD_TIMEZONE", "Asia/Kathmandu")
    if ZoneInfo is None:
        if configured_timezone in {"Asia/Kathmandu", "Asia/Katmandu"}:
            return timezone(timedelta(hours=5, minutes=45), "Asia/Kathmandu")
        if configured_timezone.upper() == "UTC":
            return timezone.utc
        print(f"WARNING: SNORT_TIMEZONE requires Python 3.9+ zoneinfo. Using UTC.")
        return timezone.utc
    try:
        return ZoneInfo(configured_timezone)
    except ZoneInfoNotFoundError:
        print(f"WARNING: Invalid SNORT_TIMEZONE '{configured_timezone}'. Using UTC.")
        return timezone.utc


def parse_snort_timestamp(raw_timestamp, now=None):
    tz = sensor_timezone()
    if now is None:
        local_now = datetime.now(tz)
    elif now.tzinfo is None:
        local_now = now.replace(tzinfo=tz)
    else:
        local_now = now.astimezone(tz)
    now_naive = local_now.replace(tzinfo=None)
    formats = [
        ("%m/%d/%Y-%H:%M:%S.%f", raw_timestamp),
        ("%m/%d/%y-%H:%M:%S.%f", raw_timestamp),
        ("%m/%d-%H:%M:%S.%f", f"{raw_timestamp}/{now_naive.year}" if "/" not in raw_timestamp[6:8] else raw_timestamp),
        ("%m/%d/%Y-%H:%M:%S", raw_timestamp),
        ("%m/%d/%y-%H:%M:%S", raw_timestamp),
    ]

    if re.match(r"^\d{2}/\d{2}-", raw_timestamp):
        formats.insert(0, ("%m/%d/%Y-%H:%M:%S.%f", raw_timestamp.replace("-", f"/{now_naive.year}-", 1)))
        formats.insert(1, ("%m/%d/%Y-%H:%M:%S", raw_timestamp.replace("-", f"/{now_naive.year}-", 1)))

    for fmt, value in formats:
        try:
            parsed = datetime.strptime(value, fmt)
            if parsed > now_naive + timedelta(days=1):
                parsed = parsed.replace(year=parsed.year - 1)
            local_time = parsed.replace(tzinfo=tz)
            utc_time = local_time.astimezone(timezone.utc).replace(tzinfo=None)
            return utc_time.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")


def priority_to_severity(priority, message=""):
    if "critical" in message.lower():
        return "CRITICAL"
    return {
        "1": "HIGH",
        "2": "MEDIUM",
        "3": "LOW",
        "4": "LOW",
    }.get(str(priority or ""), "MEDIUM")


def classify_attack_type(message, classification=""):
    text = f"{message} {classification}".lower()
    checks = [
        ("BRUTE_FORCE", ("brute force", "login failure", "failed password")),
        ("ICMP_ATTACK", ("icmp", "ping of death", "ping sweep", "sweep scan", "flood", "dos")),
        ("PORT_SCAN", ("port scan", "syn scan", "fin scan", "null scan", "xmas scan", "nmap", "recon")),
        ("EXPOSED_SERVICE_ACCESS", ("rdp", "telnet", "smb", "netbios")),
    ]
    for attack_type, markers in checks:
        if any(marker in text for marker in markers):
            return attack_type
    return "SNORT_ALERT"


def to_int(value):
    try:
        return int(value) if value not in (None, "") else None
    except ValueError:
        return None


def parse_endpoint(endpoint):
    endpoint = (endpoint or "").strip()
    if not endpoint:
        return "", None

    if endpoint.startswith("[") and "]" in endpoint:
        address, _, rest = endpoint[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else None
        return address, to_int(port)

    if endpoint.count(":") == 1:
        address, port = endpoint.rsplit(":", 1)
        parsed_port = to_int(port)
        return (address, parsed_port) if parsed_port is not None else (endpoint, None)

    if endpoint.count(":") > 1:
        try:
            import ipaddress

            ipaddress.ip_address(endpoint)
            return endpoint, None
        except ValueError:
            address, port = endpoint.rsplit(":", 1)
            parsed_port = to_int(port)
            if parsed_port is not None:
                try:
                    import ipaddress

                    ipaddress.ip_address(address)
                    return address, parsed_port
                except ValueError:
                    pass

    return endpoint, None


def parse_fast_alert(block):
    normalized = " ".join(line.strip() for line in block.splitlines() if line.strip())
    match = FAST_ALERT_RE.search(normalized)
    if not match:
        return None

    data = match.groupdict()
    message = data["message"].strip()
    classification = (data.get("classification") or "").strip()
    timestamp = parse_snort_timestamp(data["timestamp"])
    src_ip, src_port = parse_endpoint(data["src_endpoint"])
    dst_ip, dst_port = parse_endpoint(data["dst_endpoint"])

    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": data["protocol"].upper(),
        "attack_type": classify_attack_type(message, classification),
        "severity": priority_to_severity(data.get("priority"), message),
        "country": get_country_from_ip(src_ip, geolocation_enabled=GEOLOCATION_ENABLED),
        "detected_os": "Unknown",
        "message": message,
        "signature_id": data.get("sid"),
        "classification": classification,
        "source": "snort",
    }


def split_alert_blocks(text):
    starts = [match.start() for match in ALERT_START_RE.finditer(text)]
    if not starts:
        return []
    starts.append(len(text))
    return [text[starts[i]:starts[i + 1]].strip() for i in range(len(starts) - 1)]


def split_alert_blocks_bytes(data):
    starts = [match.start() for match in ALERT_START_BYTES_RE.finditer(data)]
    if not starts:
        return []
    starts.append(len(data))
    return [
        (starts[i], starts[i + 1], data[starts[i]:starts[i + 1]].strip())
        for i in range(len(starts) - 1)
    ]


def decode_alert_bytes(data):
    return data.decode("utf-8", errors="replace")


def insert_alert(alert, decision):
    if using_mongodb():
        if alert_is_duplicate_selected(alert):
            print(
                f"[SKIP] Duplicate alert within dedup window: "
                f"{alert['attack_type']} {alert['src_ip']} -> {alert['dst_ip']}"
            )
            return False
        insert_intrusion_alert_selected(alert, decision)
        return True

    with get_db_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if alert_is_duplicate(connection, alert):
            print(
                f"[SKIP] Duplicate alert within dedup window: "
                f"{alert['attack_type']} {alert['src_ip']} -> {alert['dst_ip']}"
            )
            connection.commit()
            return False

        insert_intrusion_alert(connection, alert, decision)
        connection.commit()
    return True


def audit_rejected_alert(alert, decision):
    if using_mongodb():
        insert_rejected_alert_selected(alert, decision)
        return
    with get_db_connection() as connection:
        insert_rejected_alert(connection, alert, decision)
        connection.commit()


def should_send_email(alert):
    key = email_cooldown_key(alert)
    current_time = time.time()
    last_sent = email_cooldown.get(key)
    if last_sent and current_time - last_sent < EMAIL_COOLDOWN_SECONDS:
        return False
    return True


def email_cooldown_key(alert):
    return ":".join(str(alert.get(field, "")) for field in ("src_ip", "dst_ip", "dst_port", "attack_type"))


def mark_email_sent(alert):
    email_cooldown[email_cooldown_key(alert)] = time.time()


def send_email_alert(alert, decision):
    if not should_send_email(alert):
        reason = f"Cooldown active for {alert['src_ip']}"
        print(f"[EMAIL] {reason}. Skipping alert.")
        return False

    target = alert["dst_ip"]
    if alert.get("dst_port"):
        target += f":{alert['dst_port']}"

    source = alert["src_ip"]
    if alert.get("src_port"):
        source += f":{alert['src_port']}"

    subject = f"AlertMesh {alert['severity']} Snort alert: {alert['attack_type']}"
    text = (
        f"ALERT: {alert['message']}\n\n"
        f"Severity: {alert['severity']}\n"
        f"Attack Type: {alert['attack_type']}\n"
        f"Source: {source}\n"
        f"Target: {target}\n"
        f"Protocol: {alert['protocol']}\n"
        f"Signature: {alert.get('signature_id') or 'N/A'}\n\n"
        f"Analysis: {decision.note}\n"
        f"Time: {alert['timestamp']}\n\n"
        "AlertMesh Snort - Email Alert"
    )
    sent = send_email_message(subject, text)
    if sent:
        mark_email_sent(alert)
    return sent


def state_key_for_path(alert_file):
    resolved = Path(alert_file).resolve()
    digest = hashlib.sha256(str(resolved).encode("utf-8")).hexdigest()
    return digest


def file_identity(alert_file):
    stat = Path(alert_file).stat()
    return {
        "path": str(Path(alert_file).resolve()),
        "device": getattr(stat, "st_dev", None),
        "inode": getattr(stat, "st_ino", None),
    }


def read_state():
    try:
        raw = STATE_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return {"version": 2, "files": {}}
    if not raw:
        return {"version": 2, "files": {}}
    try:
        return {"version": 1, "legacy_offset": int(raw), "files": {}}
    except ValueError:
        pass
    try:
        state = json.loads(raw)
    except json.JSONDecodeError:
        return {"version": 2, "files": {}}
    if not isinstance(state, dict):
        return {"version": 2, "files": {}}
    state.setdefault("version", 2)
    state.setdefault("files", {})
    return state


def write_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    temp_state = STATE_FILE.with_name(f"{STATE_FILE.name}.tmp")
    with temp_state.open("w", encoding="utf-8") as handle:
        handle.write(json.dumps(state, sort_keys=True))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_state, STATE_FILE)


def read_offset(alert_file, file_size):
    state = read_state()
    key = state_key_for_path(alert_file)
    current_identity = file_identity(alert_file)
    entry = state.get("files", {}).get(key)
    if entry is None and state.get("version") == 1:
        entry = {
            "offset": state.get("legacy_offset", 0),
            "identity": current_identity,
            "size": file_size,
        }

    if not entry:
        return 0

    saved_identity = entry.get("identity") or {}
    if saved_identity and saved_identity != current_identity:
        return 0

    try:
        offset = int(entry.get("offset", 0))
    except (TypeError, ValueError):
        return 0

    saved_size = entry.get("size")
    if offset > file_size or (isinstance(saved_size, int) and file_size < saved_size):
        return 0
    return max(0, offset)


def write_offset(alert_file, offset, file_size):
    state = read_state()
    state["version"] = 2
    state.setdefault("files", {})
    state["files"][state_key_for_path(alert_file)] = {
        "offset": int(offset),
        "size": int(file_size),
        "identity": file_identity(alert_file),
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    }
    state.pop("legacy_offset", None)
    write_state(state)


def ingest_text(text):
    inserted = 0
    skipped = 0
    rejected = 0
    for block in split_alert_blocks(text):
        alert = parse_fast_alert(block)
        if not alert:
            skipped += 1
            continue

        decision = analyze_alert(alert, PROTECTED_NETWORKS)
        if not decision.accepted:
            rejected += 1
            audit_rejected_alert(alert, decision)
            print(
                f"[REJECT] {alert['attack_type']} {alert['src_ip']} -> {alert['dst_ip']} "
                f"{decision.note}"
            )
            continue

        if not insert_alert(alert, decision):
            skipped += 1
            continue

        send_email_alert(alert, decision)
        inserted += 1
        print(
            f"[SNORT] {alert['timestamp']} {alert['severity']} "
            f"{alert['attack_type']} {alert['src_ip']} -> {alert['dst_ip']} "
            f"({alert['message']})"
        )
    return inserted, skipped, rejected


def ingest_file_once(alert_file, remember_offset=True):
    if not alert_file.exists():
        alert_file.parent.mkdir(parents=True, exist_ok=True)
        alert_file.touch()

    file_size = alert_file.stat().st_size
    offset = read_offset(alert_file, file_size) if remember_offset else 0

    with alert_file.open("rb") as handle:
        handle.seek(offset)
        data = handle.read()

    process_upto = len(data)
    blocks = split_alert_blocks_bytes(data)
    if blocks:
        last_start, last_end, last_block = blocks[-1]
        is_trailing_block = last_end == len(data)
        if is_trailing_block and parse_fast_alert(decode_alert_bytes(last_block)) is None:
            process_upto = last_start
    elif data.strip():
        process_upto = 0

    inserted, skipped, rejected = ingest_text(decode_alert_bytes(data[:process_upto]))
    new_offset = offset + process_upto
    if remember_offset:
        write_offset(alert_file, new_offset, file_size)
    return inserted, skipped, rejected, new_offset


def follow_alert_file(alert_file):
    alert_file.parent.mkdir(parents=True, exist_ok=True)
    if not alert_file.exists():
        alert_file.touch()
        print(f"[+] Created empty alert file: {alert_file}")

    print(f"[+] Watching Snort alert file: {alert_file}")
    print(f"[+] Writing alerts to: {get_storage_description()}")
    print("[+] Waiting for Snort to append alerts...")
    consecutive_errors = 0
    while True:
        try:
            inserted, skipped, rejected, _ = ingest_file_once(alert_file, remember_offset=True)
            consecutive_errors = 0
            if skipped:
                print(f"[SNORT] Skipped {skipped} unparsable alert block(s).")
            if rejected:
                print(f"[SNORT] Rejected {rejected} out-of-scope alert(s).")
            if not inserted:
                time.sleep(POLL_SECONDS)
        except KeyboardInterrupt:
            print("\n[+] Snort ingest stopped.")
            return
        except Exception as exc:
            consecutive_errors += 1
            sleep_seconds = min(30, POLL_SECONDS * consecutive_errors)
            print(f"[SNORT] Ingest error: {exc}. Retrying in {sleep_seconds:.1f}s.")
            time.sleep(sleep_seconds)


def main():
    configure_console_encoding()
    parser = argparse.ArgumentParser(description="Ingest Snort fast alerts into the configured AlertMesh database.")
    parser.add_argument("--file", default=str(SNORT_ALERT_FILE), help="Path to Snort alert_fast output file.")
    parser.add_argument("--once", action="store_true", help="Ingest current file contents and exit.")
    parser.add_argument("--from-start", action="store_true", help="Ignore saved offset and ingest from file start.")
    args = parser.parse_args()

    alert_file = Path(args.file)
    initialize_database()

    if args.from_start:
        alert_file.parent.mkdir(parents=True, exist_ok=True)
        if not alert_file.exists():
            alert_file.touch()
        write_offset(alert_file, 0, alert_file.stat().st_size)

    if args.once:
        inserted, skipped, rejected, _ = ingest_file_once(alert_file, remember_offset=not args.from_start)
        print(f"[+] Inserted {inserted} alert(s), skipped {skipped}, rejected {rejected}.")
        return

    follow_alert_file(alert_file)


if __name__ == "__main__":
    main()
