#!/usr/bin/env bash
# One-time setup: creates a virtual environment and installs everything (Linux / Kali / macOS).
set -e
cd "$(dirname "$0")"                                   # Work from the project folder
echo "==> Creating virtual environment..."
python3 -m venv venv || { echo "Could not create venv. On Debian/Kali run: sudo apt install -y python3-venv python3-pip"; exit 1; }
echo "==> Installing dependencies..."
./venv/bin/python -m pip install --upgrade pip -q
./venv/bin/python -m pip install -r requirements-dev.txt -q
echo "==> Setup complete. Start the app with: ./run.sh"
