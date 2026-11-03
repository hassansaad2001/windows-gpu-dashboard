<#
.SYNOPSIS
  Inspect and configure NTFS disk quotas on a volume.

.DESCRIPTION
  The dashboard manages per-user quota entries itself once a policy is saved.
  This script is for the one-time volume setup and for manual checks:

    -Action Status    show quota state, defaults and per-user entries (default)
    -Action Track     turn on usage tracking only (nothing is blocked)
    -Action Enforce   turn on tracking + enforcement (users WITH a limit get blocked at it)
    -Action Disable   turn quotas off on the volume (all limits stop applying)
    -Action SetUser   set one user's warning/limit:  -User alice -WarningGB 180 -LimitGB 200
    -Action Report    list users over their warning level, and recent quota violations

  Defaults for new users are kept at "No limit" so enabling enforcement never
  affects anyone who has no explicit entry.

.EXAMPLE
  .\setup-quotas.ps1 -Volume C: -Action Track
.EXAMPLE
  .\setup-quotas.ps1 -Volume C: -Action SetUser -User alice -WarningGB 180 -LimitGB 200
#>
[CmdletBinding()]
param(
    [string]$Volume = "C:",
    [ValidateSet("Status", "Track", "Enforce", "Disable", "SetUser", "Report")]
    [string]$Action = "Status",
    [string]$User,
    [double]$WarningGB,
    [double]$LimitGB
)
$ErrorActionPreference = "Stop"
$Volume = $Volume.TrimEnd("\")
$NoLimit = "18446744073709551615"

function Set-NoLimitDefaults {
    # Win32_QuotaSetting.State: 0 = disabled, 1 = tracked, 2 = enforced
    $qs = Get-CimInstance Win32_QuotaSetting | Where-Object { $_.VolumePath -eq "$Volume\" }
    if ($qs -and ($qs.DefaultLimit -ne -1 -or $qs.DefaultWarningLimit -ne -1)) {
        Set-CimInstance -InputObject $qs -Property @{ DefaultLimit = [int64]-1; DefaultWarningLimit = [int64]-1 }
        Write-Host "Default limit for new users reset to No Limit."
    }
    # Log an event when users cross their warning level or limit (System log, source Ntfs, IDs 36/37).
    if ($qs) {
        Set-CimInstance -InputObject (Get-CimInstance Win32_QuotaSetting | Where-Object { $_.VolumePath -eq "$Volume\" }) `
            -Property @{ ExceededNotification = $true; WarningExceededNotification = $true }
    }
}

switch ($Action) {
    "Status" {
        fsutil quota query $Volume
        Get-CimInstance Win32_QuotaSetting | Where-Object { $_.VolumePath -eq "$Volume\" } |
            Format-List VolumePath, State, DefaultLimit, DefaultWarningLimit, ExceededNotification, WarningExceededNotification
    }
    "Track" {
        fsutil quota track $Volume
        Set-NoLimitDefaults
        Write-Host "Tracking enabled on $Volume. NTFS rebuilds usage in the background; give it a while on large volumes."
    }
    "Enforce" {
        Set-NoLimitDefaults
        fsutil quota enforce $Volume
        Write-Host "Enforcement enabled on $Volume. Only users with an explicit limit are affected."
    }
    "Disable" {
        fsutil quota disable $Volume
        Write-Host "Quotas disabled on $Volume."
    }
    "SetUser" {
        if (-not $User) { throw "-User is required" }
        $warn  = if ($WarningGB) { [string][int64]($WarningGB * 1GB) } else { $NoLimit }
        $limit = if ($LimitGB)   { [string][int64]($LimitGB * 1GB) }   else { $NoLimit }
        fsutil quota modify $Volume $warn $limit "$env:COMPUTERNAME\$User"
        fsutil quota query $Volume | Select-String -Context 0, 5 -Pattern "\\$User$"
    }
    "Report" {
        Write-Host "--- Per-user quota entries on $Volume"
        fsutil quota query $Volume | Out-String -Stream | Select-String -Context 0, 0 "SID Name|Quota Used|Quota Threshold|Quota Limit"
        Write-Host "--- Quota violations (System log)"
        fsutil quota violations
    }
}
