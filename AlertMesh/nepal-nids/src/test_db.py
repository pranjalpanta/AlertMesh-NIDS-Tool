"""
Verify the AlertMesh SQLite database schema.
"""

import os
import sqlite3
import sys
import tempfile

from database import (
    get_db_connection,
    get_db_path,
    get_intrusion_collection,
    get_rejected_collection,
    get_storage_description,
    initialize_database,
    using_mongodb,
)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def configure_console_encoding():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def check_connection():
    print("Testing configured database connection...")
    print("-" * 50)

    try:
        initialize_database()
        print(f"[OK] Storage backend: {get_storage_description()}")

        if using_mongodb():
            intrusion_count = get_intrusion_collection().count_documents({})
            rejected_count = get_rejected_collection().count_documents({})
            print("[OK] Connected to MongoDB")
            print(f"[OK] Collection 'intrusion_logs' has {intrusion_count} document(s)")
            print(f"[OK] Collection 'rejected_alerts' has {rejected_count} document(s)")
            print("\nDatabase setup test completed successfully.")
            return True

        connection = get_db_connection()
        cursor = connection.cursor()

        print(f"[OK] Connected to database '{get_db_path()}'")
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='intrusion_logs'")

        if cursor.fetchone():
            print("[OK] Table 'intrusion_logs' exists")
            cursor.execute("PRAGMA table_info(intrusion_logs)")
            print("\nTable structure:")
            print("-" * 50)
            for row in cursor.fetchall():
                print(f"  {str(row[1]):20s} {str(row[2]):20s}")
        else:
            print("[ERROR] Table 'intrusion_logs' does not exist")

        cursor.close()
        connection.close()

        print("\nDatabase setup test completed successfully.")
        return True
    except sqlite3.Error as exc:
        print(f"\n[ERROR] {exc}")
        return False


def test_connection():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    old_backend = os.environ.get("ALERTMESH_DB_BACKEND")
    old_path = os.environ.get("ALERTMESH_DB_PATH")
    try:
        os.environ["ALERTMESH_DB_BACKEND"] = "sqlite"
        os.environ["ALERTMESH_DB_PATH"] = db_path
        assert check_connection()
    finally:
        if old_backend is None:
            os.environ.pop("ALERTMESH_DB_BACKEND", None)
        else:
            os.environ["ALERTMESH_DB_BACKEND"] = old_backend
        if old_path is None:
            os.environ.pop("ALERTMESH_DB_PATH", None)
        else:
            os.environ["ALERTMESH_DB_PATH"] = old_path
        try:
            os.remove(db_path)
        except OSError:
            pass


if __name__ == "__main__":
    configure_console_encoding()
    print("=" * 50)
    print("ALERTMESH DATABASE SETUP TEST")
    print("=" * 50)
    raise SystemExit(0 if check_connection() else 1)
