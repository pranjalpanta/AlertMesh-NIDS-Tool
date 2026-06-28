# AlertMesh Snort Rules

AlertMesh uses a deliberately small Snort rule set for practical network/IP detection. The active rules are not web-application signatures; they focus on behavior visible at the network layer.

## Active Categories

| Category | SIDs | Purpose |
|----------|------|---------|
| Port scans | 9000001-9000004 | Detect SYN, FIN, NULL, and Xmas scan behavior |
| SSH connection attempts | 9000005 | Detect repeated SSH connection attempts |
| FTP connection attempts | 9000008 | Detect repeated FTP connection attempts |
| ICMP activity | 9000011-9000013 | Detect ICMP flood, oversized ping, and sweep behavior |
| Telnet exposure | 9000024 | Detect inbound Telnet connection attempts |
| RDP activity | 9000026-9000027 | Detect repeated or exposed RDP connection attempts |
| SMB/NetBIOS exposure | 9000028-9000029 | Detect inbound SMB and NetBIOS connection attempts |

## Disabled By Scope

The following are intentionally not active in `local.rules`:

- SQL injection
- XSS
- command injection
- path traversal
- web admin URL checks
- web scanner User-Agent checks

Those detections belong more naturally to a WAF, reverse proxy, or web-application scanner. Keeping them disabled makes this project clearer as a NIDS focused on IP and network service behavior.

## Rule Tuning

Set `HOME_NET` in `snort.conf` to your protected subnet:

```conf
ipvar HOME_NET 192.168.1.0/24
ipvar EXTERNAL_NET !$HOME_NET
```

If your lab generates too many repeated connection alerts, increase the `count` or `seconds` values in the relevant threshold:

```conf
threshold:type both, track by_src, count 10, seconds 60
```

## Windows Run Flow

1. Install Npcap and Snort.
2. Run Snort as Administrator:

```bat
start_snort_windows.bat
```

3. In another terminal, ingest accepted alerts into the configured AlertMesh database:

```bat
start_snort_ingest_windows.bat
```

4. Run the dashboard:

```bat
python app.py
```
