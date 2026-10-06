#!/usr/bin/env bash
# Starts the app at http://127.0.0.1:5000 (Linux / Kali / macOS).
set -e
cd "$(dirname "$0")"
[ -x venv/bin/python ] || { echo "Run ./setup.sh first."; exit 1; }
if [ -z "$SECRET_KEY" ]; then                          # Keep one stable secret key so logins survive restarts
  [ -f .secret_key ] || { ./venv/bin/python -c "import secrets; print(secrets.token_hex(32))" > .secret_key; chmod 600 .secret_key; }
  export SECRET_KEY="$(cat .secret_key)"
fi
echo "==> Open http://127.0.0.1:${PORT:-5000} in your browser (Ctrl+C to stop)"
exec ./venv/bin/python app.py
