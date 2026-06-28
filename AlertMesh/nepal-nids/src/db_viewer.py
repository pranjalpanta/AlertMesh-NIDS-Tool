"""
Database Viewer for AlertMesh NIDS
View and query intrusion logs from the configured database backend.
"""

import re
import sqlite3
from datetime import datetime, timedelta
import sys
import os
from dotenv import load_dotenv


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"), override=False, encoding="utf-8-sig")

from database import (
    get_db_connection,
    get_intrusion_collection,
    get_storage_description,
    mongo_log_to_api,
    using_mongodb,
)


def configure_console_encoding():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


configure_console_encoding()

def get_stats():
    """Get statistics from the database"""
    try:
        if using_mongodb():
            collection = get_intrusion_collection()
            total = collection.count_documents({})
            severity_stats = [
                {"severity": row["_id"], "count": row["count"]}
                for row in collection.aggregate([
                    {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}},
                ])
                if row["_id"] not in (None, "")
            ]
            origin_stats = [
                {"origin": row["_id"], "count": row["count"]}
                for row in collection.aggregate([
                    {"$group": {"_id": "$country", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}},
                    {"$limit": 10},
                ])
                if row["_id"] not in (None, "")
            ]
            attack_stats = [
                {"attack_type": row["_id"], "count": row["count"]}
                for row in collection.aggregate([
                    {"$group": {"_id": "$attack_type", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}},
                ])
                if row["_id"] not in (None, "")
            ]
            return {
                'total': total,
                'severity': severity_stats,
                'origin': origin_stats,
                'attack': attack_stats
            }

        connection = get_db_connection()
        if not connection:
            return None

        cursor = connection.cursor()

        # Total alerts
        cursor.execute("SELECT COUNT(*) as total FROM intrusion_logs")
        total = cursor.fetchone()['total']

        # By severity
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM intrusion_logs
            GROUP BY severity
        """)
        severity_stats = cursor.fetchall()

        # By source origin/country
        cursor.execute("""
            SELECT country AS origin, COUNT(*) as count
            FROM intrusion_logs
            GROUP BY country
            ORDER BY count DESC
            LIMIT 10
        """)
        origin_stats = cursor.fetchall()

        # By attack type
        cursor.execute("""
            SELECT attack_type, COUNT(*) as count
            FROM intrusion_logs
            GROUP BY attack_type
            ORDER BY count DESC
        """)
        attack_stats = cursor.fetchall()

        cursor.close()
        connection.close()

        return {
            'total': total,
            'severity': severity_stats,
            'origin': origin_stats,
            'attack': attack_stats
        }

    except sqlite3.Error as e:
        print(f"Database error getting stats: {e}")
        return None
    except Exception as e:
        print(f"Error getting stats: {e}")
        return None

def get_recent_alerts(limit=20):
    """Get recent alerts from the database"""
    try:
        if using_mongodb():
            return [
                mongo_log_to_api(row)
                for row in get_intrusion_collection().find({}).sort("timestamp", -1).limit(limit)
            ]

        connection = get_db_connection()
        if not connection:
            return []

        cursor = connection.cursor()

        query = """
            SELECT * FROM intrusion_logs
            ORDER BY timestamp DESC
            LIMIT ?
        """
        cursor.execute(query, (limit,))
        alerts = cursor.fetchall()

        cursor.close()
        connection.close()

        return alerts

    except sqlite3.Error as e:
        print(f"Database error getting alerts: {e}")
        return []
    except Exception as e:
        print(f"Error getting alerts: {e}")
        return []

def get_alerts_by_severity(severity, limit=20):
    """Get alerts filtered by severity"""
    try:
        if using_mongodb():
            return [
                mongo_log_to_api(row)
                for row in get_intrusion_collection()
                .find({"severity": severity})
                .sort("timestamp", -1)
                .limit(limit)
            ]

        connection = get_db_connection()
        if not connection:
            return []

        cursor = connection.cursor()

        query = """
            SELECT * FROM intrusion_logs
            WHERE severity = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """
        cursor.execute(query, (severity, limit))
        alerts = cursor.fetchall()

        cursor.close()
        connection.close()

        return alerts

    except sqlite3.Error as e:
        print(f"Database error getting alerts: {e}")
        return []
    except Exception as e:
        print(f"Error getting alerts: {e}")
        return []


def search_alerts_by_ip(ip_query, limit=20):
    """Get recent alerts where source or destination matches an IP fragment."""
    try:
        if using_mongodb():
            regex = {"$regex": re.escape(ip_query), "$options": "i"}
            return [
                mongo_log_to_api(row)
                for row in get_intrusion_collection()
                .find({"$or": [{"src_ip": regex}, {"dst_ip": regex}]})
                .sort("timestamp", -1)
                .limit(limit)
            ]

        connection = get_db_connection()
        if not connection:
            return []

        cursor = connection.cursor()
        like_query = f"%{ip_query}%"
        cursor.execute(
            """
            SELECT *
            FROM intrusion_logs
            WHERE src_ip LIKE ? OR dst_ip LIKE ?
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (like_query, like_query, limit),
        )
        alerts = cursor.fetchall()
        cursor.close()
        connection.close()
        return alerts

    except sqlite3.Error as e:
        print(f"Database error searching alerts: {e}")
        return []
    except Exception as e:
        print(f"Error searching alerts: {e}")
        return []

def print_alert(alert):
    """Print a single alert in formatted way"""
    severity_colors = {
        'LOW': '\033[92m',      # Green
        'MEDIUM': '\033[93m',   # Yellow
        'HIGH': '\033[91m',     # Red
        'CRITICAL': '\033[95m',
    }
    reset = '\033[0m'
    keys = set(alert.keys())

    def value(name, default="N/A"):
        return alert[name] if name in keys and alert[name] not in (None, "") else default

    color = severity_colors.get(value('severity', ''), '')
    print(f"\n{'='*80}")
    print(f"ID: {value('id')} | {color}{value('severity')}{reset} | {value('timestamp')}")
    print(f"{'='*80}")
    print(f"Attack Type: {value('attack_type')}")
    print(f"Source:      {value('src_ip')}:{value('src_port')}")
    print(f"Destination: {value('dst_ip')}:{value('dst_port')}")
    print(f"Protocol:    {value('protocol')}")
    print(f"Origin:      {value('country')}")
    print(f"Engine:      {value('source', 'unknown')}")
    if value('analysis_note', ''):
        print(f"Analysis:    {value('analysis_note', '')}")
    print(f"{'='*80}")

def print_stats(stats):
    """Print statistics"""
    print(f"\n{'='*80}")
    print(f"NEPAL NIDS - INTRUSION LOG STATISTICS")
    print(f"{'='*80}")
    print(f"\nTotal Alerts: {stats['total']}\n")

    print("By Severity:")
    for stat in stats['severity']:
        print(f"  {stat['severity']:10s}: {stat['count']}")

    print("\nTop 10 Origins:")
    for stat in stats['origin']:
        print(f"  {stat['origin']:20s}: {stat['count']}")

    print("\nBy Attack Type:")
    for stat in stats['attack']:
        print(f"  {stat['attack_type']:40s}: {stat['count']}")

    print(f"{'='*80}\n")

def main():
    """Main menu"""
    while True:
        print("\n" + "="*80)
        print("NEPAL NIDS - DATABASE VIEWER")
        print(f"Storage: {get_storage_description()}")
        print("="*80)
        print("1. View Statistics")
        print("2. View Recent Alerts (20)")
        print("3. View High Severity Alerts")
        print("4. View Medium Severity Alerts")
        print("5. View Low Severity Alerts")
        print("6. Search Alerts by IP")
        print("0. Exit")
        print("="*80)

        choice = input("\nEnter your choice: ").strip()

        if choice == '1':
            stats = get_stats()
            if stats:
                print_stats(stats)
            else:
                print("Error retrieving statistics.")

        elif choice == '2':
            alerts = get_recent_alerts(20)
            if alerts:
                for alert in alerts:
                    print_alert(alert)
            else:
                print("No alerts found.")

        elif choice == '3':
            alerts = get_alerts_by_severity('HIGH', 20)
            if alerts:
                for alert in alerts:
                    print_alert(alert)
            else:
                print("No HIGH severity alerts found.")

        elif choice == '4':
            alerts = get_alerts_by_severity('MEDIUM', 20)
            if alerts:
                for alert in alerts:
                    print_alert(alert)
            else:
                print("No MEDIUM severity alerts found.")

        elif choice == '5':
            alerts = get_alerts_by_severity('LOW', 20)
            if alerts:
                for alert in alerts:
                    print_alert(alert)
            else:
                print("No LOW severity alerts found.")

        elif choice == '6':
            ip_query = input("\nEnter source/destination IP or fragment: ").strip()
            if ip_query:
                alerts = search_alerts_by_ip(ip_query, 20)
                if alerts:
                    for alert in alerts:
                        print_alert(alert)
                else:
                    print("No alerts matched that IP search.")
            else:
                print("Search value cannot be empty.")

        elif choice == '0':
            print("Goodbye!")
            sys.exit(0)

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
