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

SNORT_ALERT_FILE="${SNORT_ALERT_FILE:-$(pwd)/logs/alert.ids}"
ALERTMESH_DB_PATH="${ALERTMESH_DB_PATH:-$(pwd)/alertmesh.db}"
touch "$SNORT_ALERT_FILE"

echo "=========================================="
echo "  AlertMesh - Snort Alert Ingest on Linux"
echo "=========================================="
echo
echo "Watching: $SNORT_ALERT_FILE"
if [[ "${ALERTMESH_DB_BACKEND:-sqlite}" == "mongodb" ]]; then
  echo "Writing to: MongoDB from .env"
else
  echo "Writing to: $ALERTMESH_DB_PATH"
fi
echo "Keep this terminal open while Snort is running."
echo

exec "$PYTHON_BIN" snort_ingest.py --file "$SNORT_ALERT_FILE"
