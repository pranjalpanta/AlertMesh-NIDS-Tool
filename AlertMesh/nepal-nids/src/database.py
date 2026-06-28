import os
import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse, quote

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", override=False, encoding="utf-8-sig")
DEFAULT_DB_PATH = BASE_DIR / "alertmesh.db"
_MONGO_CLIENT = None

from alert_analysis import add_analysis_columns, alert_is_duplicate as sqlite_alert_is_duplicate, parse_sql_timestamp


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


def resolve_path(value, default=DEFAULT_DB_PATH):
    path = Path(value or default)
    return path if path.is_absolute() else BASE_DIR / path


def get_db_path():
    return resolve_path(os.getenv("ALERTMESH_DB_PATH"), DEFAULT_DB_PATH)


def get_database_backend():
    return os.getenv("ALERTMESH_DB_BACKEND", "sqlite").strip().lower()


def using_mongodb():
    return get_database_backend() in {"mongo", "mongodb"}


def get_db_connection(row_factory=True):
    db_path = get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path, timeout=5)
    if row_factory:
        connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def mongo_uri_is_local(uri):
    parsed = urlparse(uri)
    host = parsed.hostname or ""
    return host.lower() in {"localhost", "127.0.0.1", "::1"}


def mongo_uri_has_credentials(uri):
    parsed = urlparse(uri)
    return bool(parsed.username)


def redact_mongo_uri(uri):
    parsed = urlparse(uri)
    if not parsed.password:
        return uri
    username = quote(parsed.username or "", safe="")
    hostname = parsed.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    netloc = f"{username}:***@{hostname}"
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return parsed._replace(netloc=netloc).geturl()


def get_mongo_client():
    global _MONGO_CLIENT
    if _MONGO_CLIENT is None:
        try:
            from pymongo import MongoClient
        except ImportError as exc:
            raise RuntimeError(
                "pymongo is required for ALERTMESH_DB_BACKEND=mongodb. "
                "Run: pip install pymongo"
            ) from exc
        uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
        if not mongo_uri_is_local(uri) and not mongo_uri_has_credentials(uri):
            raise RuntimeError(
                "Refusing to connect to a non-local MongoDB URI without credentials. "
                "Use MongoDB authentication or keep MONGODB_URI on localhost."
            )
        _MONGO_CLIENT = MongoClient(uri, serverSelectionTimeoutMS=3000)
        _MONGO_CLIENT.admin.command("ping")
    return _MONGO_CLIENT


def get_mongo_database():
    return get_mongo_client()[os.getenv("MONGODB_DATABASE", "alertmesh")]


def get_intrusion_collection():
    return get_mongo_database()[os.getenv("MONGODB_INTRUSION_COLLECTION", "intrusion_logs")]


def get_rejected_collection():
    return get_mongo_database()[os.getenv("MONGODB_REJECTED_COLLECTION", "rejected_alerts")]


def get_runtime_status_collection():
    return get_mongo_database()[os.getenv("MONGODB_RUNTIME_STATUS_COLLECTION", "runtime_status")]


def get_storage_description():
    if using_mongodb():
        uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
        return (
            f"MongoDB: {redact_mongo_uri(uri)} / "
            f"{os.getenv('MONGODB_DATABASE', 'alertmesh')}"
        )
    return str(get_db_path())


def configure_sqlite_database(connection):
    try:
        connection.execute("PRAGMA journal_mode = WAL")
    except sqlite3.Error as exc:
        print(f"WARNING: Could not enable SQLite WAL mode: {exc}")


def migrate_attack_types(cursor):
    cursor.execute(
        """
        UPDATE intrusion_logs
        SET attack_type = 'PORT_SCAN'
        WHERE attack_type LIKE 'Port Scan Detected%'
        """
    )
    cursor.execute(
        """
        UPDATE intrusion_logs
        SET attack_type = 'BRUTE_FORCE'
        WHERE attack_type LIKE 'Brute Force Attack%'
        """
    )


def cleanup_old_alerts(cursor, retention_days=None):
    days = get_int_env("ALERT_RETENTION_DAYS", 0, minimum=0) if retention_days is None else retention_days
    if not days:
        return 0

    cutoff = f"-{int(days)} days"
    cursor.execute(
        """
        DELETE FROM intrusion_logs
        WHERE timestamp < datetime('now', ?)
        """,
        (cutoff,),
    )
    return cursor.rowcount


def add_columns_if_missing(cursor, table_name, columns):
    for column, definition in columns.items():
        try:
            cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column} {definition}")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc).lower():
                raise


def add_rejected_alert_columns(cursor):
    add_columns_if_missing(
        cursor,
        "rejected_alerts",
        {
            "created_at": "DATETIME",
            "timestamp": "DATETIME",
            "src_ip": "TEXT",
            "dst_ip": "TEXT",
            "src_port": "INTEGER",
            "dst_port": "INTEGER",
            "protocol": "TEXT",
            "attack_type": "TEXT",
            "severity": "TEXT",
            "source": "TEXT",
            "signature_id": "TEXT",
            "classification": "TEXT",
            "confidence": "INTEGER DEFAULT 0",
            "rejection_note": "TEXT",
            "raw_alert": "TEXT",
        },
    )


def initialize_database(cleanup=True):
    if using_mongodb():
        return initialize_mongodb(cleanup=cleanup)

    with get_db_connection() as connection:
        configure_sqlite_database(connection)
        cursor = connection.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS intrusion_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                attack_type TEXT,
                severity TEXT,
                country TEXT,
                detected_os TEXT DEFAULT 'Unknown'
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS rejected_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                timestamp DATETIME,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                attack_type TEXT,
                severity TEXT,
                source TEXT,
                signature_id TEXT,
                classification TEXT,
                confidence INTEGER DEFAULT 0,
                rejection_note TEXT,
                raw_alert TEXT
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS runtime_status (
                component TEXT PRIMARY KEY,
                updated_at DATETIME,
                payload TEXT
            )
            """
        )
        add_columns_if_missing(cursor, "intrusion_logs", {"detected_os": "TEXT DEFAULT 'Unknown'"})

        add_analysis_columns(cursor)
        add_rejected_alert_columns(cursor)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON intrusion_logs(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp_severity ON intrusion_logs(timestamp, severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp_dst_port ON intrusion_logs(timestamp, dst_port)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity ON intrusion_logs(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_attack_type ON intrusion_logs(attack_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rejected_created_at ON rejected_alerts(created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rejected_source ON rejected_alerts(source)")
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alert_dedup
            ON intrusion_logs(timestamp, src_ip, dst_ip, protocol, attack_type)
            """
        )
        migrate_attack_types(cursor)
        if cleanup:
            cleanup_old_alerts(cursor)
        connection.commit()
    return True


def initialize_mongodb(cleanup=True):
    collection = get_intrusion_collection()
    collection.create_index("timestamp")
    collection.create_index([("timestamp", 1), ("severity", 1)])
    collection.create_index([("timestamp", 1), ("dst_port", 1)])
    collection.create_index("severity")
    collection.create_index("attack_type")
    collection.create_index([("timestamp", 1), ("src_ip", 1), ("dst_ip", 1), ("protocol", 1), ("attack_type", 1)])

    rejected = get_rejected_collection()
    rejected.create_index("created_at")
    rejected.create_index("source")
    get_runtime_status_collection().create_index("component", unique=True)

    if cleanup:
        days = get_int_env("ALERT_RETENTION_DAYS", 0, minimum=0)
        if days:
            cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)
            cutoff_text = cutoff.strftime("%Y-%m-%d %H:%M:%S")
            collection.delete_many({"timestamp": {"$lt": cutoff_text}})
    return True


def utc_status_timestamp():
    return datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")


def write_runtime_status(component, payload):
    payload = dict(payload or {})
    updated_at = utc_status_timestamp()
    payload["updated_at"] = updated_at
    if using_mongodb():
        get_runtime_status_collection().update_one(
            {"component": component},
            {"$set": {
                "component": component,
                "updated_at": updated_at,
                "payload": payload,
            }},
            upsert=True,
        )
        return True

    with get_db_connection() as connection:
        connection.execute(
            """
            INSERT INTO runtime_status (component, updated_at, payload)
            VALUES (?, ?, ?)
            ON CONFLICT(component) DO UPDATE SET
                updated_at = excluded.updated_at,
                payload = excluded.payload
            """,
            (component, updated_at, json.dumps(payload, sort_keys=True, default=str)),
        )
        connection.commit()
    return True


def read_runtime_status(prefix=None):
    if using_mongodb():
        query = {}
        if prefix:
            query["component"] = {"$regex": f"^{re.escape(prefix)}"}
        rows = get_runtime_status_collection().find(query)
        return {
            row["component"]: {
                **(row.get("payload") or {}),
                "updated_at": row.get("updated_at"),
            }
            for row in rows
        }

    with get_db_connection() as connection:
        if prefix:
            rows = connection.execute(
                "SELECT component, updated_at, payload FROM runtime_status WHERE component LIKE ?",
                (f"{prefix}%",),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT component, updated_at, payload FROM runtime_status"
            ).fetchall()

    statuses = {}
    for row in rows:
        try:
            payload = json.loads(row["payload"] or "{}")
        except json.JSONDecodeError:
            payload = {}
        payload.setdefault("updated_at", row["updated_at"])
        statuses[row["component"]] = payload
    return statuses


def normalize_timestamp(value):
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value.strftime("%Y-%m-%d %H:%M:%S")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(str(value), fmt).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"):
        try:
            return datetime.strptime(str(value), fmt).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def insert_intrusion_alert(connection, alert, decision):
    cursor = connection.cursor()
    cursor.execute(
        """
        INSERT INTO intrusion_logs
        (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, attack_type,
         severity, country, detected_os, source, signature_id, classification,
         confidence, analysis_note)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            normalize_timestamp(alert.get("timestamp")),
            alert["src_ip"],
            alert["dst_ip"],
            alert.get("src_port"),
            alert.get("dst_port"),
            alert.get("protocol") or alert.get("proto"),
            alert["attack_type"],
            alert["severity"],
            alert.get("country", "Unknown"),
            alert.get("detected_os", "Unknown"),
            alert.get("source", "unknown"),
            alert.get("signature_id") or alert.get("sid"),
            alert.get("classification"),
            decision.confidence,
            decision.note,
        ),
    )
    return cursor.lastrowid


def insert_rejected_alert(connection, alert, decision):
    cursor = connection.cursor()
    cursor.execute(
        """
        INSERT INTO rejected_alerts
        (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, attack_type,
         severity, source, signature_id, classification, confidence,
         rejection_note, raw_alert)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            normalize_timestamp(alert.get("timestamp")),
            alert.get("src_ip"),
            alert.get("dst_ip"),
            alert.get("src_port"),
            alert.get("dst_port"),
            alert.get("protocol") or alert.get("proto"),
            alert.get("attack_type"),
            alert.get("severity"),
            alert.get("source", "unknown"),
            alert.get("signature_id") or alert.get("sid"),
            alert.get("classification"),
            decision.confidence,
            decision.note,
            json.dumps(alert, sort_keys=True, default=str),
        ),
    )
    return cursor.lastrowid


def intrusion_alert_document(alert, decision):
    return {
        "timestamp": normalize_timestamp(alert.get("timestamp")),
        "src_ip": alert["src_ip"],
        "dst_ip": alert["dst_ip"],
        "src_port": alert.get("src_port"),
        "dst_port": alert.get("dst_port"),
        "protocol": alert.get("protocol") or alert.get("proto"),
        "attack_type": alert["attack_type"],
        "severity": alert["severity"],
        "country": alert.get("country", "Unknown"),
        "detected_os": alert.get("detected_os", "Unknown"),
        "source": alert.get("source", "unknown"),
        "signature_id": alert.get("signature_id") or alert.get("sid"),
        "classification": alert.get("classification"),
        "confidence": decision.confidence,
        "analysis_note": decision.note,
    }


def rejected_alert_document(alert, decision):
    return {
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "timestamp": normalize_timestamp(alert.get("timestamp")),
        "src_ip": alert.get("src_ip"),
        "dst_ip": alert.get("dst_ip"),
        "src_port": alert.get("src_port"),
        "dst_port": alert.get("dst_port"),
        "protocol": alert.get("protocol") or alert.get("proto"),
        "attack_type": alert.get("attack_type"),
        "severity": alert.get("severity"),
        "source": alert.get("source", "unknown"),
        "signature_id": alert.get("signature_id") or alert.get("sid"),
        "classification": alert.get("classification"),
        "confidence": decision.confidence,
        "rejection_note": decision.note,
        "raw_alert": alert,
    }


def insert_intrusion_alert_selected(alert, decision):
    if using_mongodb():
        result = get_intrusion_collection().insert_one(intrusion_alert_document(alert, decision))
        return str(result.inserted_id)
    with get_db_connection() as connection:
        row_id = insert_intrusion_alert(connection, alert, decision)
        connection.commit()
        return row_id


def insert_rejected_alert_selected(alert, decision):
    if using_mongodb():
        result = get_rejected_collection().insert_one(rejected_alert_document(alert, decision))
        return str(result.inserted_id)
    with get_db_connection() as connection:
        row_id = insert_rejected_alert(connection, alert, decision)
        connection.commit()
        return row_id


def alert_is_duplicate_selected(alert, seconds=None):
    if not using_mongodb():
        with get_db_connection() as connection:
            return sqlite_alert_is_duplicate(connection, alert, seconds=seconds)

    seconds = int(seconds) if seconds is not None else get_int_env("ALERT_DEDUP_SECONDS", 120, minimum=0)
    timestamp = parse_sql_timestamp(alert.get("timestamp"))
    since = (timestamp - timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S")
    until = (timestamp + timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S")
    attack_type = alert.get("attack_type")
    query = {
        "timestamp": {"$gte": since, "$lte": until},
        "src_ip": alert.get("src_ip"),
        "dst_ip": alert.get("dst_ip"),
        "protocol": alert.get("protocol") or alert.get("proto"),
        "attack_type": attack_type,
    }
    if attack_type != "PORT_SCAN":
        query["dst_port"] = alert.get("dst_port")
    if attack_type not in {"BRUTE_FORCE", "PORT_SCAN", "ICMP_ATTACK", "EXPOSED_SERVICE_ACCESS"}:
        query["src_port"] = alert.get("src_port")
    return get_intrusion_collection().find_one(query, {"_id": 1}) is not None


def mongo_filter_from_args(args):
    query = {}
    severity = (args.get("severity") or "ALL").strip().upper()
    if severity != "ALL":
        query["severity"] = severity

    attack_type = (args.get("attack_type") or "ALL").strip()
    if attack_type != "ALL":
        query["attack_type"] = attack_type

    since = (args.get("since") or "").strip()
    if since:
        query["timestamp"] = {"$gt": since}

    search = (args.get("q") or "").strip()
    if search:
        regex = {"$regex": re.escape(search), "$options": "i"}
        query["$or"] = [
            {"src_ip": regex},
            {"dst_ip": regex},
            {"country": regex},
            {"detected_os": regex},
            {"attack_type": regex},
            {"severity": regex},
            {"protocol": regex},
            {"source": regex},
            {"signature_id": regex},
            {"classification": regex},
            {"analysis_note": regex},
        ]
    return query


def delete_filter_is_explicit(args):
    args = args or {}
    severity = (args.get("severity") or "ALL").strip().upper()
    attack_type = (args.get("attack_type") or "ALL").strip()
    return any((
        severity != "ALL",
        attack_type != "ALL",
        bool((args.get("since") or "").strip()),
        bool((args.get("q") or "").strip()),
    ))


def mongo_log_to_api(document):
    result = dict(document)
    result["id"] = str(result.pop("_id"))
    return result


def mongo_group_counts(collection, query, field):
    pipeline = [
        {"$match": query},
        {"$group": {"_id": f"${field}", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    return [
        {field: row["_id"], "count": row["count"]}
        for row in collection.aggregate(pipeline)
        if row["_id"] not in (None, "")
    ]


def fetch_intrusion_dashboard_data(args, today_start, today_end, known_attack_types):
    if not using_mongodb():
        raise RuntimeError("fetch_intrusion_dashboard_data is only used for MongoDB")

    collection = get_intrusion_collection()
    filters = mongo_filter_from_args(args)
    today_query = {"timestamp": {"$gte": today_start, "$lt": today_end}}
    high_query = {**today_query, "severity": {"$in": ["HIGH", "CRITICAL"]}}

    total_today = collection.count_documents(today_query)
    high_severity = collection.count_documents(high_query)
    filtered_total = collection.count_documents(filters)

    most_attacked_pipeline = [
        {"$match": {**today_query, "dst_port": {"$ne": None}}},
        {"$group": {"_id": "$dst_port", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 1},
    ]
    most_attacked = list(collection.aggregate(most_attacked_pipeline))
    most_attacked_port = most_attacked[0]["_id"] if most_attacked else "N/A"

    logs = [
        mongo_log_to_api(row)
        for row in collection.find(filters).sort("timestamp", -1).limit(100)
    ]

    attack_stats = [
        {"attack_type": row["attack_type"], "count": row["count"]}
        for row in mongo_group_counts(collection, filters, "attack_type")
    ]
    severity_stats = [
        {"severity": row["severity"], "count": row["count"]}
        for row in mongo_group_counts(collection, filters, "severity")
    ]

    db_attack_types = [
        value for value in collection.distinct("attack_type")
        if value not in (None, "")
    ]
    severities = [
        value for value in collection.distinct("severity")
        if value not in (None, "")
    ]
    severity_order = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
    severities = sorted(severities, key=lambda value: (severity_order.get(value, 5), value))

    return {
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
            "attack_types": sorted(set(known_attack_types).union(db_attack_types)),
            "severities": severities,
        },
    }


def delete_intrusion_logs_selected(payload, sqlite_filter_builder=None):
    def require_delete_all_confirmation():
        if payload.get("confirm") != "DELETE_ALL":
            raise ValueError("Full purge requires confirm='DELETE_ALL'.")

    if using_mongodb():
        collection = get_intrusion_collection()
        if payload.get("id") is not None:
            try:
                from bson import ObjectId

                result = collection.delete_one({"_id": ObjectId(str(payload["id"]))})
            except Exception:
                result = collection.delete_one({"id": payload["id"]})
            return result.deleted_count
        if isinstance(payload.get("ids"), list):
            object_ids = []
            legacy_ids = []
            for item in payload["ids"]:
                try:
                    from bson import ObjectId

                    object_ids.append(ObjectId(str(item)))
                except Exception:
                    legacy_ids.append(item)
            delete_query = []
            if object_ids:
                delete_query.append({"_id": {"$in": object_ids}})
            if legacy_ids:
                delete_query.append({"id": {"$in": legacy_ids}})
            if not delete_query:
                return 0
            return collection.delete_many({"$or": delete_query}).deleted_count
        if payload.get("delete_all"):
            require_delete_all_confirmation()
            return collection.delete_many({}).deleted_count
        if payload.get("delete_filtered"):
            filter_args = payload.get("filters") or {}
            if not delete_filter_is_explicit(filter_args):
                raise ValueError("Refusing to delete all logs through delete_filtered. Use delete_all for a full purge.")
            return collection.delete_many(mongo_filter_from_args(filter_args)).deleted_count
        raise ValueError("Provide id, ids, delete_filtered, or delete_all to delete")

    if sqlite_filter_builder is None:
        raise RuntimeError("sqlite_filter_builder is required for SQLite deletes")
    connection = get_db_connection()
    try:
        cursor = connection.cursor()
        log_id = payload.get("id")
        log_ids = payload.get("ids")
        if log_id is not None:
            cursor.execute("DELETE FROM intrusion_logs WHERE id = ?", (log_id,))
        elif payload.get("delete_all"):
            require_delete_all_confirmation()
            cursor.execute("DELETE FROM intrusion_logs")
        elif payload.get("delete_filtered"):
            filter_args = payload.get("filters") or {}
            if not delete_filter_is_explicit(filter_args):
                raise ValueError("Refusing to delete all logs through delete_filtered. Use delete_all for a full purge.")
            filters, params = sqlite_filter_builder(filter_args)
            cursor.execute(f"DELETE FROM intrusion_logs WHERE 1 = 1 {filters}", params)
        elif isinstance(log_ids, list):
            clean_ids = []
            for item in log_ids:
                try:
                    clean_ids.append(int(item))
                except (TypeError, ValueError):
                    continue
            if not clean_ids:
                return 0
            placeholders = ",".join("?" for _ in clean_ids)
            cursor.execute(f"DELETE FROM intrusion_logs WHERE id IN ({placeholders})", clean_ids)
        else:
            raise ValueError("Provide id, ids, delete_filtered, or delete_all to delete")
        deleted = cursor.rowcount
        connection.commit()
        return deleted
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
