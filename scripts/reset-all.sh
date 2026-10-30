#!/usr/bin/env bash
# Wipe EVERYTHING on this device: your vault, keys, pairings, logs and the demo team.
# Stop the node first (Ctrl+C in its terminal). The next start is fresh, with the sign-in user / user.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/common.sh
data="${DATA_DIR:-$PWD/data}"
if port_in_use "$UI_PORT"; then echo "P2PSec is still running. Stop it with Ctrl+C, then run this again." >&2; exit 1; fi
read -r -p "This permanently deletes your vault, keys and pairings on this device. Type DELETE to continue: " a
[ "$a" = "DELETE" ] || { echo "Cancelled."; exit 1; }
rm -rf -- "$data"
echo "Done. Start it again with ./scripts/start.sh and sign in as user / user."
