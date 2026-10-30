#!/usr/bin/env bash
# Reset the demo team to its original seed (same as the "Reset demo data" button). Your own node is untouched.
# The node must be running.
set -euo pipefail
curl -fsS -X POST -H "Content-Type: application/json" -d '{}' "http://127.0.0.1:${UI_PORT:-8000}/api/demo/reset" >/dev/null
echo "Demo team reset to the original seed (and started, if it was off)."
