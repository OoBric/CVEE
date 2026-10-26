#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
if [ ! -d .venv ]; then python3 -m venv .venv; fi
.venv/bin/python -m pip install -r requirements.txt
printf '\nOpen http://127.0.0.1:8000 in your browser\n'
exec .venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8000
