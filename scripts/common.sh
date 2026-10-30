# Shared helpers for the P2PSec shell scripts (macOS/Linux).

UI_PORT="${UI_PORT:-8000}"
PEER_PORT="${PEER_PORT:-7600}"
VENV=.venv
VENV_PY="$VENV/bin/python"

lan_ip() {
  local ip=""
  if command -v ip >/dev/null 2>&1; then
    ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i=="src") print $(i+1)}' | head -1)
  fi
  if [ -z "$ip" ] && command -v route >/dev/null 2>&1; then          # macOS
    local ifc; ifc=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
    [ -n "$ifc" ] && ip=$(ipconfig getifaddr "$ifc" 2>/dev/null || true)
  fi
  [ -n "$ip" ] || { echo "Could not detect this device's Wi-Fi address; pass it as the first argument." >&2; exit 1; }
  echo "$ip"
}

find_python() {   # Python 3.11 or newer
  for py in python3.12 python3.11 python3 python; do
    if command -v "$py" >/dev/null 2>&1 && "$py" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
      echo "$py"; return
    fi
  done
  echo "Python 3.11 or newer is needed (python.org, or your package manager), then run this again." >&2
  exit 1
}

install_deps() {   # a venv in .venv, refreshed whenever requirements.txt changes
  if [ ! -x "$VENV_PY" ]; then
    echo "Creating a virtual environment in .venv ..."
    "$(find_python)" -m venv "$VENV" || { echo "Could not create the venv (on Debian/Ubuntu: sudo apt install python3-venv)." >&2; exit 1; }
  fi
  if [ ! -f "$VENV/requirements.installed" ] || [ requirements.txt -nt "$VENV/requirements.installed" ]; then
    echo "Installing the pinned packages from requirements.txt ..."
    "$VENV_PY" -m pip install --disable-pip-version-check -q -r requirements.txt
    date > "$VENV/requirements.installed"
  fi
}

open_firewall() {   # $1 = this device's LAN IP. Only acts if a host firewall is actually running.
  local subnet
  subnet=$(ip -o -4 route show scope link 2>/dev/null | awk -v ip="$1" '$0 ~ ("src " ip) {print $1; exit}')
  [ -n "$subnet" ] || subnet="$1/24"
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ufw 2>/dev/null; then
    echo "Firewall (ufw): allowing TCP 7600, 7606 and UDP 7601 from $subnet (sudo may ask for your password)."
    sudo ufw allow proto tcp from "$subnet" to any port 7600,7606 >/dev/null
    sudo ufw allow proto udp from "$subnet" to any port 7601 >/dev/null
  elif command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    echo "Firewall (firewalld): allowing TCP 7600, 7606 and UDP 7601 from $subnet (sudo may ask for your password)."
    for rule in "7600 tcp" "7606 tcp" "7601 udp"; do
      set -- $rule
      sudo firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$subnet port port=$1 protocol=$2 accept" >/dev/null
    done
    sudo firewall-cmd --reload >/dev/null
  else
    echo "Firewall: no ufw/firewalld running, nothing to open. (On macOS, click Allow if asked about Python.)"
  fi
}

port_in_use() {
  if command -v lsof >/dev/null 2>&1; then lsof -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
  elif command -v ss >/dev/null 2>&1; then ss -ltn "sport = :$1" | grep -q LISTEN
  else return 1; fi
}
