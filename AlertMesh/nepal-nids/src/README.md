# AlertMesh NIDS - Source Code

This directory contains the core logic for the **AlertMesh Network-Based Intrusion Detection System**.

## Component Overview

- **`app.py`**: Flask dashboard, API routes, authentication, packet capture display, and exports.
- **`nids.py`**: Built-in Python/Scapy detection engine for practical network/IP attacks.
- **`snort_ingest.py`**: Imports Snort `alert_fast` logs into the configured storage backend for the dashboard.
- **`alert_analysis.py`**: Validates alerts, rejects out-of-scope or low-confidence detections, and suppresses duplicates before storage.
- **`database.py`**: Shared SQLite/MongoDB storage helpers, schema/index setup, retention cleanup, and alert insert helpers.
- **`start_snort_windows.bat`**: Helper script to test and run Snort on Windows.
- **`start_snort_ingest_windows.bat`**: Helper script to ingest Snort alerts on Windows.
- **`start_python_nids_linux.sh`**: Helper script to run the Python/Scapy detector on Linux/macOS.
- **`start_dashboard_linux.sh`**: Helper script to run the dashboard on Linux/macOS.
- **`start_snort_linux.sh`**: Helper script to test and run Snort on Linux.
- **`start_snort_ingest_linux.sh`**: Helper script to ingest Snort alerts on Linux/macOS.
- **`db_viewer.py`**: CLI utility to view and query intrusion logs directly from the terminal.
- **`test_db.py`**: Script to verify database connection and schema integrity.
- **`test_email.py`**: Setup helper for SMTP email alerts.
- **`runtime_hygiene.py`**: Lists or explicitly cleans generated runtime artifacts before sharing the project.

## Directory Structure

- **`static/`**: Frontend JavaScript and CSS assets.
- **`templates/`**: HTML templates for the dashboard and login gateway.
- **Runtime artifacts**: Files such as `alertmesh.db`, `logs/`, `.cache/`, `__pycache__/`, and packet captures are generated locally and are ignored by git. Run `python runtime_hygiene.py` to list them before sharing the project. Cleaning requires `python runtime_hygiene.py --clean --confirm CLEAN_RUNTIME`.

## Running Locally

1. **Python/Scapy Engine on Linux/macOS**: Run `sudo ./start_python_nids_linux.sh` from this directory.
2. **Dashboard on Linux/macOS**: Run `./start_dashboard_linux.sh` in another terminal. This helper disables dashboard packet capture by default so the dashboard does not need root privileges.
3. **Snort Engine on Windows**: Run `start_snort_windows.bat` from this directory.
4. **Snort Ingest**: Run the matching ingest helper, `start_snort_ingest_windows.bat` or `./start_snort_ingest_linux.sh`.
5. **Manual Dashboard**: Run `python app.py` to launch the web interface on port 5001 by default.
6. **Alerts**: Configure `.env` with SMTP email settings and run `python test_email.py`.

## Storage

AlertMesh supports both SQLite and MongoDB:

```env
ALERTMESH_DB_BACKEND=mongodb
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=alertmesh
```

For a local Windows demo, run `start_mongodb_windows.bat` before `python app.py`. Keep MongoDB bound to `127.0.0.1` unless you configure MongoDB users and authentication.

Accepted alerts include `source`, `confidence`, and `analysis_note` fields. Alert timestamps are stored in UTC. Tune the quality gate with `PROTECTED_NETWORKS`, `IGNORE_SOURCE_IPS`, `TRUSTED_SOURCE_IPS`, `ALERT_REQUIRE_PROTECTED_DESTINATION`, `ALERT_MIN_CONFIDENCE`, and `ALERT_DEDUP_SECONDS` in `.env`. Use `ALERT_RETENTION_DAYS` to automatically remove old intrusion logs during database initialization. If your machine uses DHCP, update `PROTECTED_NETWORKS` when your IP changes or use your lab subnet, for example `192.168.1.0/24`.

The dashboard packet sniffer feeds the Python IDS detector by default. Set `DASHBOARD_INTRUSION_DETECTION_ENABLED=false` when you want the live packet table without dashboard-side alert detection, or set `DASHBOARD_PACKET_CAPTURE_ENABLED=false` when you want the dashboard to show intrusion logs without running its own packet sniffer.

## Detection Scope

AlertMesh is intentionally scoped to a small, practical NIDS set:

1. **Port scans**: SYN/FIN/NULL/Xmas scan behavior against protected hosts.
2. **ICMP attacks/probes**: repeated ping probes, ICMP sweep behavior, ICMP flood, and oversized ping packets.
3. **Brute-force style connection attempts**: repeated SSH, FTP, and RDP connection attempts.
4. **Exposed service access**: repeated inbound attempts to risky services such as Telnet, RDP, SMB, and NetBIOS.

Web application payload categories such as SQL injection, XSS, command injection, and path traversal are intentionally not part of the active detector because they belong more naturally to a WAF or web scanner than to this network-focused NIDS.

---
**Network-Based Intrusion Alert System**  
Copyright (c) 2026 Pranjal Panta Lazarus. All rights reserved.
