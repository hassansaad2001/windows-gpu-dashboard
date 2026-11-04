<#
.SYNOPSIS
  Locks the installed dashboard files so no account can change them, or unlocks
  them for an edit.

.DESCRIPTION
  Lock (default):
    - precompiles the Python files, so the service never needs to write next to them
    - records a SHA-256 baseline of every app file in manifest.json; the service
      re-checks it every intervals.integrity_minutes and alerts on any difference
    - makes SYSTEM the owner of everything and gives Administrators and SYSTEM
      read-only access; only the service's data and log folders stay writable,
      by SYSTEM alone
    - turns on File System auditing and audits writes, deletes, permission and
      ownership changes, so the Security event log records who changed what

  -Unlock makes Administrators the owner with full control again, so you can edit
  config.json or replace files. Run the script without -Unlock afterwards: until
  you do, the dashboard reports the changed files.

  An Administrator can always take ownership back; Windows cannot prevent that.
  The lock makes it a deliberate, logged step, and the baseline check catches any
  file that changes.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File C:\AIDashboard\scripts\protect.ps1 -Unlock
  notepad C:\AIDashboard\config.json
  powershell -ExecutionPolicy Bypass -File C:\AIDashboard\scripts\protect.ps1
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\AIDashboard",
    [switch]$Unlock
)

$ErrorActionPreference = "Stop"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated (Administrator) PowerShell."
}
if (-not (Test-Path -LiteralPath $InstallDir -PathType Container)) { throw "$InstallDir not found." }
$InstallDir = (Resolve-Path -LiteralPath $InstallDir).Path

$SYSTEM = "S-1-5-18"
$ADMINS = "S-1-5-32-544"
$FS_AUDIT_GUID = "{0CCE921D-69AE-11D9-BED3-505054503030}"   # Object Access > File System

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

function Invoke-Icacls {
    & icacls.exe @args /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls $($args -join ' ') failed (exit $LASTEXITCODE)" }
}

function Sid($value) { New-Object Security.Principal.SecurityIdentifier $value }

# Replaces the root's whole DACL: only SYSTEM and Administrators, nothing inherited
# from the drive, and any account added by hand is dropped.
function Set-RootAccess($rights) {
    $sec = New-Object Security.AccessControl.DirectorySecurity
    $sec.SetAccessRuleProtection($true, $false)
    foreach ($sid in $SYSTEM, $ADMINS) {
        $sec.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            (Sid $sid), $rights, "ContainerInherit, ObjectInherit", "None", "Allow")))
    }
    (Get-Item -LiteralPath $InstallDir).SetAccessControl($sec)
}

function Set-Audit($path, $rules, [bool]$protect) {
    $sec = New-Object Security.AccessControl.DirectorySecurity
    $sec.SetAuditRuleProtection($protect, $false)
    foreach ($r in $rules) { $sec.AddAuditRule($r) }
    (Get-Item -LiteralPath $path).SetAccessControl($sec)
}

function AuditRule($rights, $flags) {
    New-Object Security.AccessControl.FileSystemAuditRule((Sid "S-1-1-0"), $rights,
        "ContainerInherit, ObjectInherit", "None", $flags)
}

# ---------------------------------------------------------------- unlock
# Always the first step: re-locking an already locked folder needs ownership back too.
Step "Unlocking $InstallDir for Administrators"
Invoke-Icacls $InstallDir /setowner "*$ADMINS" /T
Set-RootAccess "FullControl"
Invoke-Icacls "$InstallDir\*" /reset /T

if ($Unlock) {
    Write-Host ""
    Write-Host "Unlocked. Administrators can change files in $InstallDir now." -ForegroundColor Yellow
    Write-Host "The dashboard reports changed files until you lock it again:"
    Write-Host "  powershell -ExecutionPolicy Bypass -File `"$InstallDir\scripts\protect.ps1`""
    return
}

# ---------------------------------------------------------------- baseline
$venvPy = Join-Path $InstallDir "venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) { throw "$venvPy not found; run install.ps1 first." }
Push-Location $InstallDir
try {
    Step "Precompiling Python files"
    # Locked files can't get __pycache__ later, so every import must find one already.
    & $venvPy -m compileall -q -j 0 app venv\Lib | Out-Null
    Step "Recording the file baseline"
    & $venvPy -m app.integrity build
    if ($LASTEXITCODE -ne 0) { throw "Writing the baseline failed." }
    # The same folders app.integrity leaves out of the baseline.
    $runtime = @(& $venvPy -c "from app.integrity import _runtime_dirs; print('\n'.join(map(str, _runtime_dirs())))")
} finally { Pop-Location }
$runtime = $runtime | Where-Object { $_ -and $_.StartsWith($InstallDir, [StringComparison]::OrdinalIgnoreCase) }
foreach ($d in $runtime) { New-Item -ItemType Directory -Force $d | Out-Null }

# ---------------------------------------------------------------- lock
Step "Making $InstallDir read-only for every account"
Set-RootAccess "ReadAndExecute"
Invoke-Icacls "$InstallDir\*" /reset /T
foreach ($d in $runtime) {
    Write-Host "    writable by the service only: $d"
    Invoke-Icacls $d /grant "*${SYSTEM}:(OI)(CI)M"
}

Step "Auditing changes to $InstallDir"
auditpol /set /subcategory:"$FS_AUDIT_GUID" /success:enable /failure:enable | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Warning "Could not enable File System auditing; changes will not be logged." }
$tamper = "Write, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership"
Set-Audit $InstallDir @((AuditRule $tamper "Success, Failure")) $true
# The service writes these folders all the time, so log only refused writes and
# permission or ownership changes there.
foreach ($d in $runtime) {
    Set-Audit $d @((AuditRule $tamper "Failure"), (AuditRule "ChangePermissions, TakeOwnership" "Success")) $true
}

# Last: once SYSTEM owns the files, Administrators can no longer change permissions.
Step "Making SYSTEM the owner"
Invoke-Icacls $InstallDir /setowner "*$SYSTEM" /T

# ---------------------------------------------------------------- verify
$probe = Join-Path $InstallDir "app\.write-test"
try {
    [IO.File]::WriteAllText($probe, "x")
    Remove-Item $probe -Force
    throw "Lock check failed: an Administrator could still write to $InstallDir\app."
} catch [UnauthorizedAccessException] {
    Write-Host ""
    Write-Host "Locked. Nobody can change files in $InstallDir, Administrators included." -ForegroundColor Green
    Write-Host "To edit config.json or other files, run this script with -Unlock first, then again without it."
}
