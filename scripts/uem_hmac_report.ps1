<#
.SYNOPSIS
  Report Windows devices in Workspace ONE UEM (SaaS) with HmacAuthenticationFailure events.

.NOTES
  Use a read only admin role
  Set these environment variables first (do not hard-code secrets):
    UEM_HOST            e.g. as1831.awmdm.com
    UEM_TENANT_CODE     API key (aw-tenant-code)
    UEM_CLIENT_ID       OAuth client id
    UEM_CLIENT_SECRET   OAuth client secret
    UEM_TOKEN_URL       e.g. https://uat.uemauth.workspaceone.com/connect/token
#>
param(
    [string]$OutFile  = "hmac_failures_windows.csv",
    [string]$Platform = "WinRT",
    [string]$EventName = "HmacAuthenticationFailure",
    [int]$PageSize = 500
)

$ErrorActionPreference = "Stop"
$base = "https://$($env:UEM_HOST)/api"

# --- OAuth token (client credentials) ---
$tok = Invoke-RestMethod -Method Post -Uri $env:UEM_TOKEN_URL -Body @{
    grant_type    = "client_credentials"
    client_id     = $env:UEM_CLIENT_ID
    client_secret = $env:UEM_CLIENT_SECRET
}
$headers = @{
    Authorization    = "Bearer $($tok.access_token)"
    "aw-tenant-code" = $env:UEM_TENANT_CODE
    Accept           = "application/json"
}

# --- All Windows devices (paged) ---
$devices = @()
$page = 0
do {
    $r = Invoke-RestMethod -Headers $headers -Uri "$base/mdm/devices/search?platform=$Platform&page=$page&pagesize=$PageSize"
    $batch = @($r.Devices)
    $devices += $batch
    $page++
} while ($batch.Count -eq $PageSize)
Write-Host "Windows devices found: $($devices.Count)"

# --- Per-device event log, keep the exact event ---
$rows = foreach ($d in $devices) {
    $id = if ($d.Id.Value) { $d.Id.Value } else { $d.Id }
    try {
        $log = Invoke-RestMethod -Headers $headers -Uri "$base/mdm/devices/$id/eventlog"
    } catch {
        Write-Warning "Device ${id}: $($_.Exception.Message)"
        continue
    }
    # HTTP 204 (no events) gives an empty response
    $hits = @($log.DeviceEventLogEntries | Where-Object { $_.Event -eq $EventName })
    if ($hits.Count -eq 0) { continue }

    $latest = $hits | Sort-Object { [datetime]$_.TimeStamp } -Descending | Select-Object -First 1
    $detail = ($latest.EventDataList | Where-Object { $_.EventDataType -eq "Hmac" } |
               Select-Object -First 1).NewValue
    $errCode = if ($detail -match "HMACAuthErrorCode - ([^\r\n]+)") { $Matches[1] } else { "" }

    [pscustomobject]@{
        DeviceId      = $id
        DeviceName    = $d.DeviceFriendlyName
        Serial        = $d.SerialNumber
        User          = $d.UserName
        LastSeen      = $d.LastSeen
        FailureCount  = $hits.Count
        LatestFailure = $latest.TimeStamp
        LatestError   = $errCode
    }
}

@($rows) | Export-Csv -NoTypeInformation -Path $OutFile
Write-Host "$(@($rows).Count) device(s) written to $OutFile"
