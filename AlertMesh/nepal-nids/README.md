# AlertMesh NIDS - Network-Based Intrusion Detection System

AlertMesh is a Network-Based Intrusion Detection System (NIDS) for local, authorized network monitoring. It focuses on practical network/IP detections: port scans, ICMP ping/sweep/flood activity, brute-force style connection attempts, and exposed service access.

On Windows, AlertMesh can also use **Snort** as the detection engine. In that mode, Snort writes alerts to `src/logs/alert.ids`, `src/snort_ingest.py` imports them into SQLite, and the Flask dashboard shows them in Intrusion Logs.

Alerts are analyzed before they enter the dashboard: AlertMesh validates IP scope, requires protected destinations by default, suppresses duplicate alerts, rejects out-of-scope informational events, and stores an analysis note for each accepted alert.

[Features](#features) | [Installation](#installation) | [Usage](#usage) | [Email Setup](#email-alert-setup) | [License](#license)

---

## Features

### Core Security
- **Real-time Packet Capture**: Live monitoring of network traffic using Scapy.
- **Protocol Analysis**: Inspection of TCP, UDP, and ICMP traffic.
- **Intrusion Detection**: Practical network detections for port scans, ICMP attacks, repeated service connection attempts, and exposed services such as RDP, SMB, Telnet, SSH, and FTP.
- **Zero-Setup Database**: Integrated SQLite storage with configurable `ALERTMESH_DB_PATH`, WAL mode, and retention cleanup.
- **Real Traffic Only**: Packet and intrusion data come from live network capture; no synthetic alerts are generated.

### Dashboard
- **Live Telemetry**: Auto-refreshing packet and intrusion log views.
- **Interactive Visualizations**: Charts for protocol distribution, packet size trends, attack vectors, and severity.
- **Filtering and Search**: Filter by protocol/category and search packet rows.
- **Export Options**: Download packet data as CSV or PCAP.

### Alerts
- **Email Alert Integration**: Optional SMTP security notifications.
- **Smart Cooldown**: Alert throttling per source IP to reduce notification spam.
- **Optional Geolocation**: HTTPS country lookup for public source IPs when `GEOLOCATION_ENABLED=true`.
- **Snort Alert Ingestion**: Optional Windows Snort alert parser for stronger IDS rules than the built-in Scapy demo engine.
- **Alert Quality Gate**: Validates and deduplicates detections before they become dashboard/email alerts.

---

## System Architecture

1. **Packet Layer**: Scapy or Snort captures raw network traffic.
2. **Detection Layer**: Snort rules or the built-in Python rule engine analyze network/IP behavior.
3. **Data Layer**: SQLite stores intrusion logs locally.
4. **Notification Layer**: SMTP email delivers optional alerts.
5. **Dashboard Layer**: Flask provides the monitoring interface.

---

## Installation

### Prerequisites
- Python 3.8+
- Npcap on Windows for live packet capture: https://npcap.com/
- libpcap on Linux for live packet capture, for example `sudo apt install libpcap-dev`
- Optional but recommended on Windows: Snort from https://www.snort.org/downloads
- Optional on Linux: Snort from your package manager or https://www.snort.org/downloads
- Internet access for geolocation and email alerts

### Quick Setup

Windows:
```bash
install.bat
```

Linux / macOS:
```bash
chmod +x install.sh
./install.sh
```

---

## Usage

### 1. Configure Environment
Copy `src/.env.example` to `src/.env`, set a strong dashboard username/password, and configure SMTP email if you want alert notifications.

Important settings:
```env
SECRET_KEY=generate_a_long_random_value_here
USERNAME=your_dashboard_user
PASSWORD=your_dashboard_password
SESSION_COOKIE_SECURE=False
FLASK_DEBUG=False
PROTECTED_NETWORKS=192.168.1.0/24
ALERT_REQUIRE_PROTECTED_DESTINATION=true
ALERT_MIN_CONFIDENCE=55
ALERT_DEDUP_SECONDS=120
ALERT_ALLOW_UNKNOWN_ATTACK_TYPES=false
ALERT_STRICT_MODE=false
ALERT_ALLOWED_SOURCES=python,snort
ALERT_ALLOWED_SNORT_SID_RANGES=9000001-9000013,9000024,9000026-9000029
DASHBOARD_TIMEZONE=Asia/Kathmandu
LOGIN_MAX_ATTEMPTS=5
LOGIN_RATE_LIMIT_SECONDS=300
TRUST_PROXY_HEADERS=false
GEOLOCATION_ENABLED=false
ALERTMESH_DB_PATH=alertmesh.db
ALERTMESH_DB_BACKEND=sqlite
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=alertmesh
ALERT_RETENTION_DAYS=30
DASHBOARD_PACKET_CAPTURE_ENABLED=true
DASHBOARD_INTRUSION_DETECTION_ENABLED=true
PACKET_EXPORTS_ENABLED=false
IGNORE_SOURCE_IPS=
TRUSTED_SOURCE_IPS=
ALERT_REJECT_TRUSTED_SOURCES=true
ICMP_ALERT_THRESHOLD=5
ICMP_ALERT_WINDOW=10
EXPOSED_SERVICE_ALERT_THRESHOLD=3
EXPOSED_SERVICE_ALERT_WINDOW=60
EMAIL_ENABLED=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_gmail_app_password
SMTP_FROM=your_email@gmail.com
SMTP_TO=destination@example.com
```

Alert timestamps are stored in UTC; dashboard daily totals use `DASHBOARD_TIMEZONE`. Packet export downloads are disabled by default because PCAP files can contain sensitive network data. Use `IGNORE_SOURCE_IPS` for scanners or lab machines that should never create alerts, and `TRUSTED_SOURCE_IPS` for trusted internal systems that should be rejected by default.
Set `ALERT_STRICT_MODE=true` to reduce fake/forged alerts further: AlertMesh will reject unknown alert sources and Snort alerts whose signature IDs are outside `ALERT_ALLOWED_SNORT_SID_RANGES`. Unknown attack types are rejected by default; set `ALERT_ALLOW_UNKNOWN_ATTACK_TYPES=true` only when you add custom detector categories. Rejected alerts are stored in the `rejected_alerts` audit table instead of disappearing silently.

To use MongoDB instead of SQLite, install/start MongoDB Server and set:

```env
ALERTMESH_DB_BACKEND=mongodb
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=alertmesh
```
The dashboard packet sniffer feeds the Python IDS detector by default, so running `python app.py` can populate Intrusion Logs without a separate `nids.py` process. If Snort or `nids.py` is your main detector and you do not need the live packet table, set `DASHBOARD_PACKET_CAPTURE_ENABLED=false` to avoid running a second packet sniffer in the dashboard process. To keep the live packet table but disable dashboard-side alert detection, set `DASHBOARD_INTRUSION_DETECTION_ENABLED=false`.

### 2. Start the Detection Engine

Recommended on Windows with Snort:

```bat
cd src
start_snort_windows.bat
```

In a second terminal, ingest Snort alerts into the dashboard database:

```bat
cd src
start_snort_ingest_windows.bat
```

Alternative Python/Scapy detector:

```bash
cd src
python nids.py
```

Recommended on Linux/macOS with the Python/Scapy detector:

```bash
cd src
sudo ./start_python_nids_linux.sh
```

Start the Linux/macOS dashboard helper in a second terminal:

```bash
cd src
./start_dashboard_linux.sh
```

This helper runs the dashboard without root privileges and sets `DASHBOARD_PACKET_CAPTURE_ENABLED=false` unless you override it. Use `start_python_nids_linux.sh` for the privileged packet capture process.

Optional Linux Snort flow:

```bash
cd src
sudo SNORT_INTERFACE=eth0 ./start_snort_linux.sh
./start_snort_ingest_linux.sh
```

On Windows, if Snort cannot list interfaces, use the Python/Scapy detector:

```bat
cd src
start_python_nids_windows.bat
```

To choose a specific adapter:

```bat
set NIDS_INTERFACE=Wi-Fi
start_python_nids_windows.bat
```

### 3. Start the Dashboard
```bash
cd src
python app.py
```

Open http://localhost:5001 and log in with the `USERNAME` and `PASSWORD` from `src/.env`.

---

## Email Alert Setup

AlertMesh sends notifications by SMTP email. For Gmail, create a Gmail App Password and configure:

```env
EMAIL_ENABLED=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_gmail_app_password
SMTP_FROM=your_email@gmail.com
SMTP_TO=destination@example.com
```

Then test:

```bash
python src/test_email.py
```

---

## Technologies

- **Backend**: Python, Flask, Scapy, SQLite
- **Frontend**: Bootstrap 5, Chart.js, Inter, JetBrains Mono
- **Alerts**: SMTP email
- **Geolocation**: Optional HTTPS lookup through ipapi.co

---

## Disclaimer

This tool is intended for educational and authorized network testing only. Unauthorized network monitoring is illegal in most jurisdictions. Always obtain proper authorization before using this tool on any network.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

**Author: Pranjal Panta Lazarus**  
*Bachelor's Thesis Project*
