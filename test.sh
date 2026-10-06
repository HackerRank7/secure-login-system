#!/usr/bin/env bash
# Runs all automated tests (Linux / Kali / macOS).
set -e
cd "$(dirname "$0")"
[ -x venv/bin/python ] || { echo "Run ./setup.sh first."; exit 1; }
./venv/bin/python -m pytest -v
