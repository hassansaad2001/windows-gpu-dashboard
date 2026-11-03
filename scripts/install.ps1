<#
.SYNOPSIS
  Installs the AI Server Dashboard as a Windows service (NSSM, LocalSystem).

.DESCRIPTION
  Copies the app to -InstallDir, builds a Python virtual environment, creates a
  self-signed TLS certificate, restricts the folder to Administrators/SYSTEM,
  registers the "AIDashboard" service with NSSM (auto-start, restart on
  failure), opens the firewall port for the local subnet and enlarges the
  System event log so restart history is kept longer.

  Re-running the script upgrades in place and keeps config.json, the database
  and the certificate.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\install.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -Port 8080 -NoHttps -RemoteAddress 192.168.1.0/24
#>
[CmdletBinding()]
param(
    [string]$InstallDir    = "C:\AIDashboard",
    [int]   $Port          = 8443,
    [switch]$NoHttps,
    [string]$RemoteAddress = "LocalSubnet",          # firewall scope, e.g. "192.168.1.0/24"
    [string]$PythonExe     = "",
    [string]$ServiceName   = "AIDashboard",
    [string]$NssmUrl       = "https://nssm.cc/release/nssm-2.24.zip",
    [int]   $SystemLogMB   = 256
)

$ErrorActionPreference = "Stop"
$src = Split-Path -Parent $PSScriptRoot

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

# ---------------------------------------------------------------- checks
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated (Administrator) PowerShell."
}
if (-not $PythonExe) {
    # All-users installs (newest first), then the py launcher, then PATH. The
    # Microsoft Store python.exe stub is skipped: LocalSystem can't run it.
    $cands = @(Get-ChildItem "$env:ProgramFiles\Python3*\python.exe" -ErrorAction SilentlyContinue |
               Sort-Object { [int]($_.Directory.Name -replace '\D', '') } -Descending | ForEach-Object FullName)
    if (Get-Command py.exe -ErrorAction SilentlyContinue) { $cands += @(& py.exe -3 -c "import sys; print(sys.executable)" 2>$null) }
    $cands += @(Get-Command python.exe -All -ErrorAction SilentlyContinue | ForEach-Object Source)
    $PythonExe = $cands | Where-Object {
        $_ -and (Test-Path $_) -and ($_ -notmatch "WindowsApps") -and
        ((& $_ -c "import sys; print(int(sys.version_info >= (3, 10)))" 2>$null) -eq "1")
    } | Select-Object -First 1
}
if (-not $PythonExe) { throw "Python 3.10+ not found. Install it for all users or pass -PythonExe." }
Step "Using Python: $PythonExe ($(& $PythonExe --version))"
if (-not (Get-Command nvidia-smi.exe -ErrorAction SilentlyContinue)) { Write-Warning "nvidia-smi.exe not on PATH; GPU metrics will be empty." }

# ---------------------------------------------------------------- stop old service
$nssm = Join-Path $InstallDir "bin\nssm.exe"
if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
    Step "Stopping existing service"
    Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep 2
}

# ---------------------------------------------------------------- copy files
Step "Copying application to $InstallDir"
New-Item -ItemType Directory -Force $InstallDir, "$InstallDir\data", "$InstallDir\logs", "$InstallDir\bin", "$InstallDir\certs" | Out-Null
robocopy (Join-Path $src "app") (Join-Path $InstallDir "app") /MIR /XD __pycache__ /R:2 /W:2 /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "Copying app failed (robocopy exit $LASTEXITCODE)" }
robocopy (Join-Path $src "scripts") (Join-Path $InstallDir "scripts") /MIR /R:2 /W:2 /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "Copying scripts failed (robocopy exit $LASTEXITCODE)" }
Copy-Item (Join-Path $src "requirements.txt"), (Join-Path $src "config.example.json") $InstallDir -Force
if (Test-Path (Join-Path $src "DEPLOYMENT.md")) { Copy-Item (Join-Path $src "DEPLOYMENT.md") $InstallDir -Force }

$cfgPath = Join-Path $InstallDir "config.json"
if (-not (Test-Path $cfgPath)) {
    Step "Creating config.json"
    $cfg = Get-Content (Join-Path $src "config.example.json") -Raw | ConvertFrom-Json
    $cfg.port  = $Port
    $cfg.https = -not $NoHttps
    $cfg | ConvertTo-Json -Depth 6 | Set-Content $cfgPath -Encoding UTF8
} else {
    Step "Keeping existing config.json"
    $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
    $Port = [int]$cfg.port
}

# ---------------------------------------------------------------- venv
$venvPy = Join-Path $InstallDir "venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
    Step "Creating virtual environment"
    & $PythonExe -m venv (Join-Path $InstallDir "venv")
}
Step "Installing Python packages"
# Ignore machine/user pip.ini: an unreachable extra index (e.g. pypi.ngc.nvidia.com)
# makes every package retry for minutes. Everything needed is on pypi.org.
$env:PIP_CONFIG_FILE = "nul"
& $venvPy -m pip install --disable-pip-version-check --quiet --upgrade pip
& $venvPy -m pip install --disable-pip-version-check --quiet -r (Join-Path $InstallDir "requirements.txt")
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

# ---------------------------------------------------------------- certificate
if ($cfg.https -and -not (Test-Path "$InstallDir\certs\server.crt")) {
    Step "Generating self-signed TLS certificate"
    & $venvPy (Join-Path $InstallDir "scripts\make_cert.py") --out (Join-Path $InstallDir "certs")
}

# ---------------------------------------------------------------- permissions
Step "Restricting $InstallDir to Administrators and SYSTEM"
# Explicit ACL on the root only; (OI)(CI) is invalid on files, so the contents are
# reset to inherit from the root instead of being granted one by one.
icacls $InstallDir /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" /Q | Out-Null
icacls "$InstallDir\*" /reset /T /C /Q | Out-Null

# ---------------------------------------------------------------- NSSM
if (-not (Test-Path $nssm)) {
    $sys = @((Get-Command nssm.exe -ErrorAction SilentlyContinue).Source, "C:\nssm\nssm.exe",
             "C:\nssm\win64\nssm.exe") | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
    if ($sys) {
        Copy-Item $sys $nssm
    } else {
        Step "Downloading NSSM"
        $zip = Join-Path $env:TEMP "nssm.zip"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $got = $false
        for ($i = 1; $i -le 3 -and -not $got; $i++) {
            try { Invoke-WebRequest -UseBasicParsing -Uri $NssmUrl -OutFile $zip; $got = $true }
            catch { Write-Warning "NSSM download attempt $i failed: $($_.Exception.Message)"; Start-Sleep 5 }
        }
        if ($got) {
            $tmp = Join-Path $env:TEMP "nssm-extract"
            Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
            Expand-Archive $zip -DestinationPath $tmp
            Copy-Item (Get-ChildItem $tmp -Recurse -Filter nssm.exe | Where-Object FullName -match "win64").FullName $nssm
            Remove-Item $zip, $tmp -Recurse -Force
        } elseif (Get-Command choco.exe -ErrorAction SilentlyContinue) {
            Step "nssm.cc unavailable; installing NSSM with Chocolatey"
            choco install nssm -y --no-progress | Out-Null
            $c = Get-ChildItem "$env:ProgramData\chocolatey\lib\nssm" -Recurse -Filter nssm.exe -ErrorAction SilentlyContinue |
                 Where-Object FullName -match "win64|tools" | Select-Object -First 1
            if (-not $c) { throw "Chocolatey did not provide nssm.exe" }
            Copy-Item $c.FullName $nssm
        } else {
            throw "Could not download NSSM. Copy nssm.exe (64-bit) to $nssm and re-run."
        }
    }
}

Step "Registering service $ServiceName"
if (-not (Get-Service $ServiceName -ErrorAction SilentlyContinue)) {
    & $nssm install $ServiceName $venvPy "-m app.main" | Out-Null
}
$set = @{
    Application    = $venvPy
    AppParameters  = "-m app.main"
    AppDirectory   = $InstallDir
    DisplayName    = "AI Server Dashboard"
    Description    = "Monitoring and management dashboard for a shared Windows AI/GPU server (CPU/RAM/GPU, storage, quotas, rogue processes)."
    Start          = "SERVICE_DELAYED_AUTO_START"
    ObjectName     = "LocalSystem"
    AppStdout      = "$InstallDir\logs\service.log"
    AppStderr      = "$InstallDir\logs\service.log"
    AppRotateFiles = "1"
    AppRotateOnline = "1"
    AppRotateBytes = "10485760"
    AppRestartDelay = "5000"
    AppThrottle    = "10000"
    AppStopMethodSkip = "6"   # go straight to TerminateProcess after Ctrl+C timeout
    AppStopMethodConsole = "5000"
}
foreach ($k in $set.Keys) { & $nssm set $ServiceName $k $set[$k] | Out-Null }
& $nssm set $ServiceName AppExit Default Restart | Out-Null
& $nssm set $ServiceName AppEnvironmentExtra "PYTHONUNBUFFERED=1" | Out-Null
sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/30000/restart/60000 | Out-Null

# ---------------------------------------------------------------- firewall
Step "Opening TCP $Port inbound for $RemoteAddress"
# Replace only this rule; others such as "AI Server Dashboard (Tailscale, TCP 8443)" are kept.
Get-NetFirewallRule -DisplayName "AI Server Dashboard (TCP *)" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
# Port-scoped rather than program-scoped: the venv python.exe is a launcher that
# re-executes the base interpreter, which is the process that owns the socket.
New-NetFirewallRule -DisplayName "AI Server Dashboard (TCP $Port)" -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort $Port -RemoteAddress $RemoteAddress -Profile Domain, Private `
    -Description "Web UI for the AI Server Dashboard service" | Out-Null

# ---------------------------------------------------------------- event log
$cur = [int64]((wevtutil gl System | Select-String "maxSize:") -replace "\D", "")
if ($cur -lt $SystemLogMB * 1MB) {
    Step "Enlarging System event log to $SystemLogMB MB (was $([math]::Round($cur / 1MB)) MB)"
    wevtutil sl System /ms:$($SystemLogMB * 1MB)
}

# ---------------------------------------------------------------- start
Step "Starting service"
Start-Service $ServiceName
$scheme = if ($cfg.https) { "https" } else { "http" }
$ok = $false
for ($i = 0; $i -lt 30 -and -not $ok; $i++) {
    Start-Sleep 1
    $ok = (Test-NetConnection 127.0.0.1 -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue)
}
$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin -ne "WellKnown" -and $_.IPAddress -notlike "169.254*" -and $_.InterfaceAlias -notmatch "WSL" } | Select-Object -First 1).IPAddress
if ($ok) {
    Write-Host ""
    Write-Host "Dashboard is running:  ${scheme}://$($env:COMPUTERNAME):$Port   (or ${scheme}://${ip}:$Port)" -ForegroundColor Green
    Write-Host "Logs: $InstallDir\logs\dashboard.log"
} else {
    Write-Warning "Service did not open port $Port within 30 s. Check $InstallDir\logs\service.log"
}
