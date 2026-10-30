# P2PSec Local (PeaSec without Docker)

Peer-to-peer privileged access management for IT teams on a LAN, run straight from Python. This is the same node as
[PeaSec](https://github.com/ShreyasDr71/PeaSec), packaged for machines without Docker: a virtual environment, pinned
packages and a prebuilt web UI. You need **Python 3.11 or newer** and nothing else (no Node.js, no Docker).

**This is not a centralized system.** Every person runs their own P2PSec node on their own computer. There is no server,
no directory and no sync service. Secrets live only on the machines of the people who own them (personal credentials) or
who are custodians of them (group credentials). Nodes talk directly to each other over the local network.

- **Pairing with a six-digit code.** Two people pair once; both screens show the same code, and they confirm it out loud.
  The commit-then-reveal exchange behind it gives a man in the middle one 1-in-a-million guess, not a way to force a match.
- **Encrypted, authenticated sessions.** After pairing, every connection is a Noise_KK handshake against the pinned keys
  (X25519, ChaCha20-Poly1305, SHA-256), with forward secrecy and replay protection.
- **Checkouts, not copies.** You request a credential with a ticket number and a reason. Group members are approved
  automatically within policy; Critical accounts always need a custodian. A checkout has a timer, and when it ends the
  secret is deleted from the holder's machine and a rotation task is raised for the owner.
- **Groups held by custodians.** A group's credentials are held by 1–3 custodians, whose nodes share the group's
  activity. Group definitions are signed, hash-linked documents; changing custodians needs a majority of them.
- **Tamper-evident audit.** Every node keeps a hash-chained, signed log, and peers remember how far each other's logs
  have reached, so a rewritten or truncated log is flagged.
- **Encrypted at rest.** The master password unlocks (Argon2id) two keys. Locking the UI wipes the personal key; the
  node keeps serving group checkouts. "Lock and go offline" wipes everything.

## Get it

```bash
git clone https://github.com/ShreyasDr71/PeaSec-Local.git
cd PeaSec-Local
```

## Start it (same steps on every device)

```powershell
# Windows (the first run asks once for permission to open the firewall)
powershell -ExecutionPolicy Bypass -File scripts\start.ps1
```
```bash
# macOS / Linux
./scripts/start.sh
```

The first run creates `.venv` and installs the exact package versions in `requirements.txt` (produced with
`pip freeze`). The script then finds this device's Wi-Fi address, opens TCP 7600 and 7606 and UDP 7601 to your local
network only, and runs the node in that window; **Ctrl+C stops it**. The address is detected on every start, so moving
to another network just needs a restart. By hand it is:

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt          # .venv\Scripts\ on Windows
ADVERTISE_ADDR=<this device's Wi-Fi address>:7600 STATIC_DIR=static .venv/bin/python -m p2psec
```

Open **http://127.0.0.1:8000** and sign in as **`user` / `user`**. A fresh node is just you: no teammates, no
credentials, no history. A red banner reminds you to change the username and master password in *Node settings*
until you do. Your vault lives in `data/`.

## Use it between two devices on the same Wi-Fi

1. Run the start script on both devices and sign in on each.
2. On one device, go to *Pair a device*. Without Docker, broadcast discovery works, so the other device usually shows
   up under *Nearby on this network*; otherwise enter its IP address, which its script printed, such as `192.168.1.20`.
3. Accept the request on the other device and read the six-digit codes to each other. Confirm only if they match.
4. Add a credential on one device. From the other, *Request a credential → From a person*, then approve it.

If the script picks the wrong network, pass the address: `-LanIp 192.168.1.20` (PowerShell) or
`./scripts/start.sh 192.168.1.20`. If pairing says it *could not reach* the other computer, make sure that computer
was started with the start script (and you clicked Yes on Windows), then test with `nc -zv <ip> 7600` (Linux/macOS) or
`Test-NetConnection <ip> -Port 7600` (Windows). If that fails with both firewalls open, the router is isolating Wi-Fi
clients (common on campus and office Wi-Fi); turn that off or use a phone hotspot.

This copy and the Docker one use the same ports, so run only one of them on a computer at a time.

## Demo mode (optional)

Nothing is seeded unless you ask for it. Click **Demo mode** on the sign-in page (or in *Settings* when signed in),
then **Start demo mode**. Six fictional people from an IT team start inside the same process, already paired, with
groups, requests, checkouts and audit history. Each opens in its own tab at `http://127.0.0.1:8000/demo/<name>/` and
signs in with their own name and the password `p2psec-demo`.

| Person | Role | Sign in |
|---|---|---|
| Priya Nair | IT Operations Lead. Custodian: Infrastructure | `priya` |
| Marcus Chen | DBA. Custodian: Databases | `marcus` |
| Elena Rossi | Security Engineer. Custodian: Security Tools, Infrastructure | `elena` |
| Jamal Okafor | Backend Developer. Member: Databases, Infrastructure | `jamal` |
| Sofia Alvarez | Finance Systems Analyst. Custodian: Finance Apps | `sofia` |
| Tom Becker | Intern. Paired with nobody | `tom` |

Tom is paired with nobody: pair him with your own node (*Pair a device*, address `127.0.0.1:7606`) or with a node on
another device (`<this device's Wi-Fi address>:7606`). Demo users' keys come from a public seed: never put real secrets
in them. Your own node is never touched by demo mode.

## Reset

| What | How |
|---|---|
| Demo team back to its original seed | *Demo mode → Reset demo data*, or `scripts\reset-demo.ps1` / `./scripts/reset-demo.sh` while running |
| Turn demo mode off | *Demo mode → Stop demo mode* |
| Everything on this device (your vault, keys, pairings, and the demo) | Stop the node, then `scripts\reset-all.ps1` / `./scripts/reset-all.sh` (it asks you to type `DELETE`). You are back to `user` / `user`. |

## Security notes

| Threat | Mitigation |
|---|---|
| Eavesdropping on Wi-Fi/LAN | Every byte between nodes is inside Noise (ChaCha20-Poly1305) |
| Man in the middle at pairing | Commit-then-reveal key exchange + human-compared six-digit code |
| Man in the middle later | Noise_KK against the keys pinned at pairing; unknown keys are refused and logged |
| Replay | Noise nonces, per-message ids remembered for 24 h, 5-minute clock window |
| A paired peer lying about who it is | Identity always comes from the authenticated channel, never from message fields |
| Stolen laptop (powered off) | Argon2id-wrapped keys. Credential names are visible; secrets are not |
| Log tampering, even by the node's owner | Hash chain + signatures + peers' anchors of your log head |
| A removed custodian taking a group back | Versions must extend the chain you hold; forks are refused and alerted |
| A holder keeping a copy after checkout | Not preventable. Checkouts end with deletion, receipts and a rotation task |
| A malicious web page talking to your node | UI bound to 127.0.0.1, Host allow-list, SameSite=Strict cookie, CSRF header |

Not in scope: a compromised machine while it is unlocked, Bluetooth, internet/WAN use.

## Development

```bash
python -m venv .venv && .venv/Scripts/pip install -r requirements-dev.txt     # .venv/bin on macOS/Linux
.venv/Scripts/python -m pytest          # crypto, vault, audit, pairing (incl. MITM), channel, groups, engine, peers, API

cd frontend && npm ci && npm run dev    # UI on :5173, proxies /api to a node on 127.0.0.1:18001
npm run build                           # rebuilds the shipped UI into ../static
```

Both requirements files are `pip freeze` output from a clean Python 3.12 venv: `requirements.txt` is the runtime set,
`requirements-dev.txt` adds the test tools. To refresh them, install the top-level packages into a fresh venv and
freeze again.

```
p2psec/       the node: crypto, vault, audit, pairing, channel, peer, groups, engine, api, demo, seed
static/       the prebuilt web UI the node serves
frontend/     the UI source (React + Vite)
tests/        pytest suite
scripts/      start, reset-all and reset-demo for Windows (.ps1) and macOS/Linux (.sh)
```
