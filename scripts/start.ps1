# Start P2PSec on this device (Windows), without Docker. Run the same script on every device on the Wi-Fi.
#   powershell -ExecutionPolicy Bypass -File scripts\start.ps1 [-LanIp 192.168.1.10]
# The first run creates .venv, installs the pinned packages, and asks Windows once to open the firewall.
# The node runs in this window; press Ctrl+C to stop it.
param([string]$LanIp = "")
. "$PSScriptRoot\common.ps1"

Install-Deps
if (-not $LanIp) { $LanIp = Get-LanIp }     # detected on every start, so a new network is picked up
Open-P2PSecFirewall
Assert-PortsFree

$env:ADVERTISE_ADDR = "${LanIp}:$PeerPort"
$env:TOM_ADVERTISE = "${LanIp}:7606"
$env:UI_HOST = "127.0.0.1"
$env:UI_PORT = "$UiPort"
$env:PEER_PORT = "$PeerPort"
if (-not $env:DATA_DIR) { $env:DATA_DIR = Join-Path $Root "data" }
$env:STATIC_DIR = Join-Path $Root "static"

Write-Host ""
Write-Host "P2PSec: http://127.0.0.1:$UiPort" -ForegroundColor Green
Write-Host "  First sign-in: username 'user', password 'user' (change both in Node settings)."
Write-Host "  Teammates on this Wi-Fi pair with you at:  $LanIp"
Write-Host "  Demo mode (sign-in page) starts a seeded team; other devices can pair with its Tom at ${LanIp}:7606"
Write-Host "  Your data is in $($env:DATA_DIR). Press Ctrl+C to stop."
Write-Host ""
$ErrorActionPreference = "Continue"     # the node logs to stderr; that is not a failure
& $VenvPython -m p2psec
