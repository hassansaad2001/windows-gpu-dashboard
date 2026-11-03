<#
.SYNOPSIS
  Removes the AI Server Dashboard service and firewall rules.
  Quota warnings and limits the dashboard set are lifted first, so nobody stays
  blocked with no dashboard managing their grace period. Pass -KeepQuotaLimits to
  leave them. Quota tracking/enforcement on the volume itself is not changed.
  Pass -RemoveFiles to also delete the install folder (database included).
#>
[CmdletBinding()]
param(
    [string]$InstallDir  = "C:\AIDashboard",
    [string]$ServiceName = "AIDashboard",
    [switch]$KeepQuotaLimits,
    [switch]$RemoveFiles
)
$ErrorActionPreference = "Stop"
$nssm = Join-Path $InstallDir "bin\nssm.exe"
$venvPy = Join-Path $InstallDir "venv\Scripts\python.exe"
$svc = Get-Service $ServiceName -ErrorAction SilentlyContinue

# Stop first so a running evaluation can't re-apply a limit after it is lifted.
if ($svc) { Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue }

if (-not $KeepQuotaLimits -and (Test-Path $venvPy)) {
    Push-Location $InstallDir
    try {
        & $venvPy -m app.quota release
        if ($LASTEXITCODE -ne 0) { Write-Warning "Some quota entries could not be lifted; see the output above." }
    } finally { Pop-Location }
}

if ($svc) {
    if (Test-Path $nssm) { & $nssm remove $ServiceName confirm | Out-Null } else { sc.exe delete $ServiceName | Out-Null }
    Write-Host "Service $ServiceName removed."
}
Get-NetFirewallRule -DisplayName "AI Server Dashboard*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Write-Host "Firewall rules removed."

if ($RemoveFiles -and (Test-Path $InstallDir)) {
    Remove-Item $InstallDir -Recurse -Force
    Write-Host "Deleted $InstallDir."
}
