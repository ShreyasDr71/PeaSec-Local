#!/usr/bin/env bash
# Start P2PSec on this device (macOS/Linux), without Docker. Run the same script on every device on the Wi-Fi.
#   ./scripts/start.sh [LAN_IP]
# The first run creates .venv and installs the pinned packages. The node runs in this terminal; Ctrl+C stops it.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/common.sh

install_deps
ip="${1:-$(lan_ip)}"     # detected on every start, so a new network is picked up
open_firewall "$ip"
for port in "$UI_PORT" "$PEER_PORT"; do
  if port_in_use "$port"; then
    echo "Port $port is already in use. Is P2PSec already running (this copy, or the Docker one: docker compose stop)?" >&2
    exit 1
  fi
done

export ADVERTISE_ADDR="$ip:$PEER_PORT" TOM_ADVERTISE="$ip:7606" UI_HOST=127.0.0.1 UI_PORT PEER_PORT
export DATA_DIR="${DATA_DIR:-$PWD/data}" STATIC_DIR="$PWD/static"

cat <<EOF

P2PSec: http://127.0.0.1:$UI_PORT
  First sign-in: username 'user', password 'user' (change both in Node settings).
  Teammates on this Wi-Fi pair with you at:  $ip
  Demo mode (sign-in page) starts a seeded team; other devices can pair with its Tom at $ip:7606
  Your data is in $DATA_DIR. Press Ctrl+C to stop.

EOF
exec "$VENV_PY" -m p2psec
