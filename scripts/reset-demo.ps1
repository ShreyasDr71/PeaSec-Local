# Reset the demo team to its original seed (same as the "Reset demo data" button). Your own node is untouched.
# The node must be running.
#   powershell -ExecutionPolicy Bypass -File scripts\reset-demo.ps1
. "$PSScriptRoot\common.ps1"
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$UiPort/api/demo/reset" -ContentType "application/json" -Body "{}" | Out-Null
Write-Host "Demo team reset to the original seed (and started, if it was off)."
