# AlertMesh NIDS Documentation

AlertMesh currently uses:

- SQLite for intrusion logs (`src/alertmesh.db`)
- SMTP email for optional alerts
- Flask for the dashboard
- Scapy for live packet capture

Start here:

- [SETUP.md](SETUP.md) - setup and run instructions
- [USER_GUIDE.md](USER_GUIDE.md) - dashboard usage
- [FAVICON_SETUP.md](FAVICON_SETUP.md) - favicon notes
- [CONTRIBUTING.md](CONTRIBUTING.md) - contribution guidance
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - community rules

Older MySQL instructions were removed from this overview because the current application stores alerts in SQLite and sends alerts through SMTP email.
