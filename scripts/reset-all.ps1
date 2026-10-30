# Wipe EVERYTHING on this device: your vault, keys, pairings, logs and the demo team.
# Stop the node first (Ctrl+C in its window). The next start is fresh, with the sign-in user / user.
#   powershell -ExecutionPolicy Bypass -File scripts\reset-all.ps1
. "$PSScriptRoot\common.ps1"

$data = if ($env:DATA_DIR) { $env:DATA_DIR } else { Join-Path $Root "data" }
if (Get-NetTCPConnection -LocalPort $UiPort -State Listen -ErrorAction SilentlyContinue) {
    throw "P2PSec is still running. Stop it with Ctrl+C in its window, then run this again."
}
$a = Read-Host "This permanently deletes your vault, keys and pairings on this device. Type DELETE to continue"
if ($a -ne "DELETE") { Write-Host "Cancelled."; exit 1 }
if (Test-Path $data) { Remove-Item -Recurse -Force $data }
Write-Host "Done. Start it again with scripts\start.ps1 and sign in as user / user."
