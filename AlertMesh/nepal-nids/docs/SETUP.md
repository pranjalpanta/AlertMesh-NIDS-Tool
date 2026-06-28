# AlertMesh NIDS - Setup and Run Instructions

## Administrator Privileges Required

Packet sniffing requires elevated privileges. Run the capture/dashboard process as Administrator on Windows or with `sudo` on Linux/macOS when you need live packet capture.

### Why Admin Privileges?
- Scapy needs access to raw network sockets.
- Network interfaces require raw packet privileges.
- Without admin rights, the dashboard can load but packet capture may show zero packets.

---

## Running on Windows

### Option 1: Run VS Code as Administrator
1. Close VS Code completely.
2. Right-click the VS Code shortcut.
3. Select **Run as administrator**.
4. Open the project folder.
5. Open a terminal in VS Code.
6. Run `python app.py` from the `src` directory.

### Option 2: Run Terminal as Administrator
1. Press `Win + R`.
2. Type `cmd` or `powershell`.
3. Right-click and select **Run as administrator**.
4. Navigate to the project `src` directory.
5. Run `python app.py`.

---

## Running on Linux / macOS

```bash
source venv/bin/activate
cd src
sudo python app.py
```

---

## Access the Dashboard

Once running:
- URL: http://localhost:5001
- Login: use `USERNAME` and `PASSWORD` from `src/.env`
- Start the NIDS engine separately with `python nids.py` for intrusion detection logs.

---

## Environment Variables

```bash
# Custom port
set WEBSITES_PORT=5001

# Custom credentials
set USERNAME=myuser
set PASSWORD=mypass123

# Debug mode
set FLASK_DEBUG=True
```

For normal local HTTP access, keep:

```env
SESSION_COOKIE_SECURE=False
```

Use `SESSION_COOKIE_SECURE=True` only when serving the dashboard over HTTPS.

---

## Cloud Deployment Notes

Azure App Service and similar managed cloud platforms generally cannot capture live packets because:
- Raw socket privileges are unavailable.
- Network interfaces are isolated.
- Security restrictions prevent raw packet capture.

This application is designed for local authorized network analysis, not managed cloud packet capture.

---

## Features

- Real-time packet capture and analysis
- Protocol distribution charts
- Filter by protocol and category
- Export to PCAP (Wireshark compatible)
- Export to CSV (Excel compatible)
- Simple authentication
- Dark-themed dashboard

---

## Troubleshooting

### Permission Denied
Run the terminal or application as Administrator/root.

### Port Already in Use
The dashboard starts with `WEBSITES_PORT` and automatically tries the next
available ports when that port is busy. Check the startup output for the line
that begins with `Dashboard URL`.

You can still request a different starting port:

```bash
set WEBSITES_PORT=8000
python app.py
```

### No Packets Showing
1. Verify the process is elevated.
2. Confirm Npcap is installed on Windows.
3. Try a different active network interface.

---

Network-Based Intrusion Alert System with Advanced IP Logging for Corporate Offices in Nepal.
