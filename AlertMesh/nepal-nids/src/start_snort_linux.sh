#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p logs

env_value() {
  local key="$1"
  if [[ -f ".env" ]]; then
    grep -E "^${key}=" .env | tail -n 1 | cut -d= -f2- | tr -d '\r'
  fi
}

SNORT_EXE="${SNORT_EXE:-$(env_value SNORT_EXE)}"
SNORT_EXE="${SNORT_EXE:-snort}"
SNORT_INTERFACE="${SNORT_INTERFACE:-$(env_value SNORT_INTERFACE)}"
SNORT_HOME_NET="${SNORT_HOME_NET:-$(env_value SNORT_HOME_NET)}"
SNORT_ALERT_FILE="${SNORT_ALERT_FILE:-$(env_value SNORT_ALERT_FILE)}"
SNORT_ALERT_FILE="${SNORT_ALERT_FILE:-$(pwd)/logs/alert.ids}"
if [[ "$SNORT_ALERT_FILE" != /* ]]; then
  SNORT_ALERT_FILE="$(pwd)/$SNORT_ALERT_FILE"
fi
SNORT_LOG_DIR="$(dirname "$SNORT_ALERT_FILE")"

echo "=========================================="
echo "  AlertMesh - Start Snort on Linux"
echo "=========================================="
echo

if ! command -v "$SNORT_EXE" >/dev/null 2>&1; then
  echo "[ERROR] Snort was not found."
  echo "Install Snort or set SNORT_EXE to the full executable path."
  echo "Example on Debian/Ubuntu: sudo apt install snort"
  exit 1
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "[ERROR] Snort packet capture must run with sudo/root privileges."
  echo "Run from the src directory with:"
  echo "  sudo ./start_snort_linux.sh"
  exit 1
fi

if [[ -z "${SNORT_INTERFACE:-}" ]]; then
  echo "[ERROR] SNORT_INTERFACE is not set."
  echo "List interfaces with: ip link show"
  echo "Then run, for example:"
  echo "  sudo SNORT_INTERFACE=eth0 ./start_snort_linux.sh"
  exit 1
fi

if [[ -z "${SNORT_HOME_NET:-}" ]]; then
  if [[ -f ".env" ]]; then
    SNORT_HOME_NET="$(grep -E '^PROTECTED_NETWORKS=' .env | cut -d= -f2- | cut -d, -f1 || true)"
  fi
fi
SNORT_HOME_NET="${SNORT_HOME_NET:-192.168.1.0/24}"
mkdir -p "$SNORT_LOG_DIR"

echo "Using Snort executable: $SNORT_EXE"
echo "Using interface: $SNORT_INTERFACE"
echo "Using HOME_NET: $SNORT_HOME_NET"
echo "Testing Snort configuration..."
"$SNORT_EXE" -T -S HOME_NET="$SNORT_HOME_NET" -c "$(pwd)/snort.conf" -l "$SNORT_LOG_DIR"

echo
echo "Starting Snort. Alerts will be written to: $SNORT_ALERT_FILE"
echo "Keep this terminal open."
touch "$SNORT_ALERT_FILE"
exec "$SNORT_EXE" -i "$SNORT_INTERFACE" -S HOME_NET="$SNORT_HOME_NET" -c "$(pwd)/snort.conf" -A fast -l "$SNORT_LOG_DIR"
