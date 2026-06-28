import ipaddress
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

@dataclass
class AlertDecision:
    accepted: bool
    confidence: int
    reasons: list

    @property
    def note(self):
        return "; ".join(self.reasons)


def parse_networks(raw_networks):
    networks = []
    for network in (raw_networks or "").split(","):
        network = network.strip()
        if not network:
            continue
        try:
            networks.append(ipaddress.ip_network(network))
        except ValueError:
            print(f"WARNING: Ignoring invalid protected network: {network}")
    return networks


def protected_networks_from_env():
    return parse_networks(os.getenv(
        "PROTECTED_NETWORKS",
        "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
    ))


def source_networks_from_env(name):
    return parse_networks(os.getenv(name, ""))


def parse_csv_set(value):
    return {item.strip().lower() for item in (value or "").split(",") if item.strip()}


def parse_sid_ranges(value):
    ranges = []
    for part in (value or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                start, end = part.split("-", 1)
                ranges.append((int(start), int(end)))
            else:
                sid = int(part)
                ranges.append((sid, sid))
        except ValueError:
            print(f"WARNING: Ignoring invalid ALERT_ALLOWED_SNORT_SID_RANGES entry: {part}")
    return ranges


def sid_in_ranges(signature_id, ranges):
    try:
        sid = int(signature_id)
    except (TypeError, ValueError):
        return False
    return any(start <= sid <= end for start, end in ranges)


def parse_ip(value):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def is_protected_ip(value, protected_networks):
    ip_addr = parse_ip(value)
    if not ip_addr:
        return False
    return any(ip_addr in network for network in protected_networks)


def is_network_boundary_ip(value, protected_networks):
    ip_addr = parse_ip(value)
    if not ip_addr:
        return False
    for network in protected_networks:
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


def is_in_networks(value, networks):
    ip_addr = parse_ip(value)
    if not ip_addr:
        return False
    return any(ip_addr in network for network in networks)


def is_bad_destination(ip_addr):
    return (
        ip_addr.is_multicast
        or ip_addr.is_unspecified
        or ip_addr.is_reserved
    )


def is_bad_source(ip_addr):
    return (
        ip_addr.is_multicast
        or ip_addr.is_unspecified
        or ip_addr.is_reserved
    )


def severity_score(severity):
    return SEVERITY_RANK.get((severity or "").upper(), 2)


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


def analyze_alert(alert, protected_networks=None):
    protected_networks = protected_networks if protected_networks is not None else protected_networks_from_env()
    ignored_sources = source_networks_from_env("IGNORE_SOURCE_IPS")
    trusted_sources = source_networks_from_env("TRUSTED_SOURCE_IPS")
    reject_trusted_sources = os.getenv("ALERT_REJECT_TRUSTED_SOURCES", "true").lower() == "true"
    require_protected_dst = os.getenv("ALERT_REQUIRE_PROTECTED_DESTINATION", "true").lower() == "true"
    monitor_protected_sources = os.getenv("ALERT_MONITOR_PROTECTED_SOURCES", "true").lower() == "true"
    min_confidence = get_int_env("ALERT_MIN_CONFIDENCE", 55, minimum=0)
    allow_low_confidence = os.getenv("ALERT_ALLOW_LOW_CONFIDENCE", "false").lower() == "true"
    allow_unknown_attack_types = os.getenv("ALERT_ALLOW_UNKNOWN_ATTACK_TYPES", "false").lower() == "true"
    strict_mode = os.getenv("ALERT_STRICT_MODE", "false").lower() == "true"
    allowed_sources = parse_csv_set(os.getenv("ALERT_ALLOWED_SOURCES", "python,snort"))
    allowed_snort_sid_ranges = parse_sid_ranges(os.getenv(
        "ALERT_ALLOWED_SNORT_SID_RANGES",
        "9000001-9000013,9000024,9000026-9000029",
    ))

    reasons = []
    confidence = 35

    src_ip = parse_ip(alert.get("src_ip", ""))
    dst_ip = parse_ip(alert.get("dst_ip", ""))
    message = (alert.get("message") or alert.get("msg") or "").lower()
    attack_type = (alert.get("attack_type") or "").upper()
    severity = (alert.get("severity") or "MEDIUM").upper()
    signature_id = alert.get("signature_id") or alert.get("sid")
    source = (alert.get("source") or "unknown").lower()
    recognized_attack_types = {"BRUTE_FORCE", "PORT_SCAN", "ICMP_ATTACK", "EXPOSED_SERVICE_ACCESS"}
    signature_allowed = sid_in_ranges(signature_id, allowed_snort_sid_ranges)

    if not src_ip or not dst_ip:
        return AlertDecision(False, 0, ["rejected: invalid source or destination IP"])

    if is_in_networks(str(src_ip), ignored_sources):
        return AlertDecision(False, 0, ["rejected: source is in IGNORE_SOURCE_IPS"])

    if reject_trusted_sources and is_in_networks(str(src_ip), trusted_sources):
        return AlertDecision(False, 0, ["rejected: source is in TRUSTED_SOURCE_IPS"])

    if strict_mode:
        if source not in allowed_sources:
            return AlertDecision(False, 0, [f"rejected: unknown alert source {source}"])
        if source == "snort" and not signature_allowed:
            return AlertDecision(False, 0, [f"rejected: Snort signature {signature_id or 'missing'} is not allowlisted"])

    if source == "snort" and attack_type not in recognized_attack_types and not signature_allowed:
        return AlertDecision(
            False,
            0,
            [f"rejected: Snort signature {signature_id or 'missing'} is not allowlisted and attack type is not recognized"],
        )

    if attack_type not in recognized_attack_types and not allow_unknown_attack_types:
        return AlertDecision(False, 0, [f"rejected: unrecognized attack type {attack_type or 'missing'}"])

    if src_ip == dst_ip:
        return AlertDecision(False, 0, ["rejected: source and destination are identical"])

    if is_bad_source(src_ip):
        return AlertDecision(False, 0, ["rejected: source is not a valid host address"])

    if is_bad_destination(dst_ip):
        return AlertDecision(False, 0, ["rejected: destination is not a routable monitored host"])

    protected_dst = is_protected_ip(str(dst_ip), protected_networks)
    protected_src = is_protected_ip(str(src_ip), protected_networks)

    if dst_ip.is_loopback and not protected_dst:
        return AlertDecision(False, 0, ["rejected: loopback destination is not in PROTECTED_NETWORKS"])

    if protected_dst and is_network_boundary_ip(str(dst_ip), protected_networks):
        return AlertDecision(False, 0, ["rejected: destination is a protected network boundary address"])

    if require_protected_dst and not protected_dst and not (monitor_protected_sources and protected_src):
        return AlertDecision(False, 0, ["rejected: destination is outside PROTECTED_NETWORKS"])

    if protected_dst:
        confidence += 20
        reasons.append("destination is protected")
    elif protected_src:
        confidence += 15
        reasons.append("source is a protected host")

    if not protected_src:
        confidence += 10
        reasons.append("source is outside protected networks")
    else:
        reasons.append("source is internal or lab traffic")

    if signature_id and (source != "snort" or signature_allowed):
        confidence += 20
        reasons.append(f"IDS signature {signature_id} matched")
    elif signature_id:
        reasons.append(f"unallowlisted IDS signature {signature_id} did not increase confidence")

    confidence += severity_score(severity) * 5
    reasons.append(f"severity {severity}")

    if attack_type in recognized_attack_types:
        confidence += 10
        reasons.append(f"recognized attack type {attack_type}")

    confidence = max(0, min(100, confidence))
    if confidence < min_confidence and not allow_low_confidence:
        return AlertDecision(False, confidence, [f"rejected: confidence {confidence} below {min_confidence}", *reasons])

    return AlertDecision(True, confidence, reasons)


def parse_sql_timestamp(value):
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            return value.astimezone(timezone.utc).replace(tzinfo=None)
        return value
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"):
        try:
            return datetime.strptime(str(value), fmt)
        except ValueError:
            continue
    return datetime.now(timezone.utc).replace(tzinfo=None)


def alert_is_duplicate(connection, alert, seconds=None):
    seconds = int(seconds) if seconds is not None else get_int_env("ALERT_DEDUP_SECONDS", 120, minimum=0)
    timestamp = parse_sql_timestamp(alert.get("timestamp"))
    since = (timestamp - timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S")
    until = (timestamp + timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S")
    attack_type = alert.get("attack_type")
    ignore_src_port = attack_type in {
        "BRUTE_FORCE",
        "PORT_SCAN",
        "ICMP_ATTACK",
        "EXPOSED_SERVICE_ACCESS",
    }
    ignore_dst_port = attack_type == "PORT_SCAN"

    cursor = connection.cursor()
    query = [
        """
        SELECT id
        FROM intrusion_logs
        WHERE timestamp BETWEEN ? AND ?
          AND src_ip = ?
          AND dst_ip = ?
          AND protocol = ?
          AND attack_type = ?
        """
    ]
    params = [
        since,
        until,
        alert.get("src_ip"),
        alert.get("dst_ip"),
        alert.get("protocol") or alert.get("proto"),
        attack_type,
    ]
    if not ignore_dst_port:
        query.append("AND COALESCE(dst_port, -1) = COALESCE(?, -1)")
        params.append(alert.get("dst_port"))

    if not ignore_src_port:
        query.append("AND COALESCE(src_port, -1) = COALESCE(?, -1)")
        params.append(alert.get("src_port"))

    query.append("LIMIT 1")
    cursor.execute("\n          ".join(query), params)
    return cursor.fetchone() is not None


def add_analysis_columns(cursor):
    columns = {
        "source": "TEXT DEFAULT 'unknown'",
        "signature_id": "TEXT",
        "classification": "TEXT",
        "confidence": "INTEGER DEFAULT 0",
        "analysis_note": "TEXT",
    }
    for column, definition in columns.items():
        try:
            cursor.execute(f"ALTER TABLE intrusion_logs ADD COLUMN {column} {definition}")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc).lower():
                raise
