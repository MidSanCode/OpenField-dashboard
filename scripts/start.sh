#!/usr/bin/env bash
# OpenField Admin Panel - Linux/macOS launcher
set -e
cd "$(dirname "$0")/.."

# Install only when the environment is missing, and never silently upgrade.
#
# This unconditionally ran `pip install -r requirements.txt` on every start, which
# reached the network each time and could replace a working, tested version with
# whatever upstream had published that day. requirements.txt is now version-pinned,
# so an explicit install is reproducible; pass --install to run it.
if [ "${1:-}" = "--install" ] || ! python3 -c "import flask, psycopg2, bcrypt" >/dev/null 2>&1; then
  echo "[1/2] Installing Python dependencies (pinned)..."
  python3 -m pip install -r requirements.txt
else
  echo "[1/2] Dependencies already installed (pass --install to reinstall)."
fi

echo "[2/2] Starting admin panel at http://127.0.0.1:1343"
python3 app.py
