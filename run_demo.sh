#!/usr/bin/env bash
# Start the ERIS analyst console on http://localhost:8000
#   ./run_demo.sh            keep existing alerts
#   ./run_demo.sh --reset    start with an empty alert database
set -eo pipefail
cd "$(dirname "$0")"
PORT=${PORT:-8000}
[ -x .venv/bin/python ] || { echo "No .venv found - see 'Setup' in README.md"; exit 1; }
if [ "$1" = "--reset" ]; then rm -f dashboard/eris.db; echo "alert database cleared"; fi
echo "ERIS analyst console -> http://localhost:$PORT  (Ctrl+C to stop)"
(sleep 4 && open "http://localhost:$PORT" 2>/dev/null) &
exec .venv/bin/python -m uvicorn --app-dir dashboard server:app --host 127.0.0.1 --port "$PORT" --log-level warning
