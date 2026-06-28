#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p logs

PYTHON_BIN="${PYTHON_BIN:-python3}"
if [[ -x "../venv/bin/python" ]]; then
  PYTHON_BIN="${PYTHON_BIN_OVERRIDE:-../venv/bin/python}"
elif [[ -x "../.venv/bin/python" ]]; then
  PYTHON_BIN="${PYTHON_BIN_OVERRIDE:-../.venv/bin/python}"
fi

echo "=========================================="
echo "  AlertMesh - Start Python NIDS on Linux"
echo "=========================================="
echo
echo "This uses Scapy/libpcap and writes accepted alerts to the configured database."
echo "Live packet capture usually requires sudo/root privileges."
echo
echo "Available interfaces:"
"$PYTHON_BIN" nids.py --list-interfaces
echo
echo "Using interface: ${NIDS_INTERFACE:-Scapy default}"
echo
echo "Keep this terminal open. Press Ctrl+C to stop."
echo
if [[ -n "${NIDS_INTERFACE:-}" ]]; then
  exec "$PYTHON_BIN" nids.py --interface "$NIDS_INTERFACE"
else
  exec "$PYTHON_BIN" nids.py
fi
