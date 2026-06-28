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

# The Linux helper assumes packet capture runs in start_python_nids_linux.sh.
# This keeps the Flask dashboard from needing sudo/root privileges.
export DASHBOARD_PACKET_CAPTURE_ENABLED="${DASHBOARD_PACKET_CAPTURE_ENABLED:-false}"

echo "=========================================="
echo "  AlertMesh - Start Dashboard on Linux"
echo "=========================================="
echo
echo "Dashboard URL: http://localhost:${WEBSITES_PORT:-5001}"
echo "Login uses USERNAME and PASSWORD from src/.env."
echo "Dashboard packet capture: $DASHBOARD_PACKET_CAPTURE_ENABLED"
echo
exec "$PYTHON_BIN" app.py
