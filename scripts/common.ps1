# Shared helpers for the P2PSec start/reset scripts (Windows PowerShell 5+ or PowerShell 7).

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$Venv = Join-Path $Root ".venv"
$VenvPython = Join-Path $Venv "Scripts\python.exe"
$UiPort = if ($env:UI_PORT) { [int]$env:UI_PORT } else { 8000 }
$PeerPort = if ($env:PEER_PORT) { [int]$env:PEER_PORT } else { 7600 }

function Get-LanIp {
    $cfg = Get-NetIPConfiguration |
        Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq "Up" } |
        Select-Object -First 1
    if (-not $cfg) { throw "No connected network adapter found. Join the Wi-Fi, or pass -LanIp <address>." }
    return $cfg.IPv4Address.IPAddress
}

function Invoke-Native([string]$Exe, [string[]]$Arguments) {
    # Windows PowerShell 5.1 turns a native program's stderr into a terminating error under "Stop",
    # so run it with "Continue" and judge it by its exit code alone.
    $ErrorActionPreference = "Continue"
    & $Exe @Arguments | Out-Host
    return $LASTEXITCODE
}

function Find-Python {
    # Python 3.11 or newer: the py launcher first, then whatever "python" is on PATH.
    # Returns the command and its leading arguments, such as @("py", "-3.12").
    foreach ($c in @(@("py", "-3.12"), @("py", "-3.11"), @("python"))) {
        $exe = $c[0]
        $pre = @($c | Select-Object -Skip 1)
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
        $check = $pre + @("-c", "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)")
        if ((Invoke-Native $exe $check) -eq 0) { return , $c }
    }
    throw "Python 3.11 or newer is needed. Install it from https://www.python.org/downloads/ and run this again."
}

function Install-Deps {
    # A venv in .venv, refreshed whenever requirements.txt changes.
    if (-not (Test-Path $VenvPython)) {
        $py = Find-Python
        Write-Host "Creating a virtual environment in .venv ..."
        $code = Invoke-Native $py[0] (@($py | Select-Object -Skip 1) + @("-m", "venv", $Venv))
        if ($code -ne 0) { throw "Could not create the virtual environment." }
    }
    $stamp = Join-Path $Venv "requirements.installed"
    $req = Join-Path $Root "requirements.txt"
    if (-not (Test-Path $stamp) -or (Get-Item $req).LastWriteTime -gt (Get-Item $stamp).LastWriteTime) {
        Write-Host "Installing the pinned packages from requirements.txt ..."
        $code = Invoke-Native $VenvPython @("-m", "pip", "install", "--disable-pip-version-check", "-q", "-r", $req)
        if ($code -ne 0) { throw "pip install failed." }
        Set-Content -Path $stamp -Value (Get-Date -Format o)
    }
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$P2PSecPorts = @(
    @{ Port = 7600; Protocol = "TCP"; Name = "P2PSec node 7600" },
    @{ Port = 7606; Protocol = "TCP"; Name = "P2PSec demo Tom 7606" },
    @{ Port = 7601; Protocol = "UDP"; Name = "P2PSec discovery 7601" }
)

function Test-FirewallReady {
    # A rule counts only if it lets the local network in on every network profile, so it also
    # works when Windows has marked the Wi-Fi as "Public" (the default for new networks).
    foreach ($p in $P2PSecPorts) {
        $rule = Get-NetFirewallRule -DisplayName $p.Name -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $rule -or $rule.Enabled -ne "True" -or "$($rule.Profile)" -ne "Any") { return $false }
        $scope = $rule | Get-NetFirewallAddressFilter
        if ("$($scope.RemoteAddress)" -ne "LocalSubnet") { return $false }
    }
    return $true
}

function Open-P2PSecFirewall {
    if (Test-FirewallReady) { Write-Host "Firewall: P2PSec ports are already open to your local network."; return }
    $cmds = foreach ($p in $P2PSecPorts) {
        "Remove-NetFirewallRule -DisplayName '$($p.Name)' -ErrorAction SilentlyContinue; " +
        "New-NetFirewallRule -DisplayName '$($p.Name)' -Direction Inbound -Protocol $($p.Protocol) -LocalPort $($p.Port) " +
        "-RemoteAddress LocalSubnet -Profile Any -Action Allow | Out-Null"
    }
    $script = $cmds -join "; "
    if (Test-Admin) {
        Invoke-Expression $script
    } else {
        Write-Host "Windows will ask once for permission to let devices on your Wi-Fi reach P2PSec"
        Write-Host "(TCP 7600 and 7606, UDP 7601 for discovery; local network only)."
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
        try {
            Start-Process powershell -Verb RunAs -Wait -WindowStyle Hidden `
                -ArgumentList "-NoProfile", "-EncodedCommand", $encoded | Out-Null
        } catch {
            Write-Warning "Permission was declined, so other devices cannot connect to this one yet."
            Write-Host  "  Run this script again and click Yes, or run it from an administrator PowerShell."
            return
        }
    }
    if (Test-FirewallReady) { Write-Host "Firewall: opened TCP 7600, 7606 and UDP 7601 to devices on your local network." }
    else { Write-Warning "The firewall rules could not be created. Other devices may not be able to connect." }
}

function Assert-PortsFree {
    foreach ($port in @($UiPort, $PeerPort)) {
        if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
            throw "Port $port is already in use. Is P2PSec already running (this copy, or the Docker one: docker compose stop)?"
        }
    }
}
