# AlertMesh NIDS User Guide

AlertMesh is a local, authorized network monitoring dashboard. It can show live packet telemetry from Scapy and intrusion alerts from either Snort or the built-in Python detector.

## Start The Dashboard

```bash
cd src
python app.py
```

Open:

```text
http://localhost:5001
```

If port 5001 is busy, the dashboard automatically tries the next available port and prints the final URL.

## Login

Use the credentials from `src/.env`:

```env
USERNAME=your_dashboard_user
PASSWORD=your_dashboard_password
```

After changing `.env`, restart the dashboard.

## Detection Options

### Recommended On Windows: Snort

Terminal 1:

```bat
cd src
start_snort_windows.bat
```

Terminal 2:

```bat
cd src
start_snort_ingest_windows.bat
```

Terminal 3:

```bat
cd src
python app.py
```

### Alternative: Python Detector

```bash
cd src
python nids.py
```

Run the dashboard in another terminal.

## Reducing False Alerts

Use these settings in `src/.env`:

```env
PROTECTED_NETWORKS=192.168.1.0/24
IGNORE_SOURCE_IPS=
TRUSTED_SOURCE_IPS=
ALERT_REJECT_TRUSTED_SOURCES=true
ICMP_ALERT_THRESHOLD=5
ICMP_ALERT_WINDOW=10
EXPOSED_SERVICE_ALERT_THRESHOLD=3
EXPOSED_SERVICE_ALERT_WINDOW=60
ALERT_MIN_CONFIDENCE=55
ALERT_DEDUP_SECONDS=120
ALERT_ALLOW_UNKNOWN_ATTACK_TYPES=false
```

Put lab scanners, trusted admin machines, or noisy test hosts in `IGNORE_SOURCE_IPS` if they should never create alerts.

## Performance Tips

- The dashboard packet sniffer also feeds the Python IDS detector by default. Set `DASHBOARD_INTRUSION_DETECTION_ENABLED=false` if you want the live packet table without dashboard-side alert detection.
- Set `DASHBOARD_PACKET_CAPTURE_ENABLED=false` if Snort or `nids.py` is already doing detection and you only need intrusion logs.
- Keep `MAX_HISTORY` modest, such as `2000`, for packet table performance.
- The dashboard pauses refreshes when the browser tab is hidden.
- SQLite retention is controlled with `ALERT_RETENTION_DAYS`.

## Exports

- Packet table: export CSV or PCAP from the dashboard.
- Intrusion logs: use `db_viewer.py` for terminal inspection.

## Troubleshooting

### No Packets

- Install Npcap on Windows.
- Run the terminal as Administrator.
- Generate traffic by browsing or pinging a known host.
- If using only Snort logs, packet table capture can be disabled with `DASHBOARD_PACKET_CAPTURE_ENABLED=false`.

### No Intrusion Logs

- Confirm `PROTECTED_NETWORKS` includes the destination host.
- If you only run `python app.py`, confirm `DASHBOARD_PACKET_CAPTURE_ENABLED=true` and `DASHBOARD_INTRUSION_DETECTION_ENABLED=true`.
- Confirm Snort is writing to `src/logs/alert.ids`.
- Confirm `start_snort_ingest_windows.bat` is running.
- Check whether `IGNORE_SOURCE_IPS` or `TRUSTED_SOURCE_IPS` is filtering the source.

### Login Fails

- Check `USERNAME` and `PASSWORD` in `src/.env`.
- Restart the dashboard after edits.
- If too many failed attempts occur, wait for `LOGIN_RATE_LIMIT_SECONDS`.

## Legal Notice

Use AlertMesh only on networks you own or are explicitly authorized to monitor.
