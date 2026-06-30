#!/usr/bin/env bash
# Run the attack map from source (Linux/macOS). Needs Python 3.8+.
# Config is read from a .env file in this folder (auto-loaded by app.py).
cd "$(dirname "$0")"
exec python3 app.py "$@"
