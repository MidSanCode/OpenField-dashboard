#!/usr/bin/env bash
# OpenField Admin Panel - Linux/macOS launcher
set -e
cd "$(dirname "$0")/.."

echo "[1/2] Installing Python dependencies..."
python3 -m pip install -r requirements.txt

echo "[2/2] Starting admin panel at http://127.0.0.1:5001"
python3 app.py
