<#
.SYNOPSIS
Lists client secrets on applications and their service principals, one row per credential.
.EXAMPLE
./Get-ClientSecrets.ps1 -TenantId <tenant-guid> | Export-Csv ClientSecrets.csv
.EXAMPLE
./Get-ClientSecrets.ps1 | Format-Table
#>

[CmdletBinding()]
param([string]$TenantId)

# Reuse an existing Graph connection unless -TenantId asks for another tenant
$scopes = 'Application.Read.All'
$context = Get-MgContext
if ($context -and (-not $TenantId -or $context.TenantId -eq $TenantId)) {
    Write-Information "Using existing Graph session: $($context.Account ?? $context.AppName) ($($context.AuthType))" -InformationAction Continue
}
else {
    $connectParams = @{ Scopes = $scopes; NoWelcome = $true }
    if ($TenantId) { $connectParams.TenantId = $TenantId }
    Connect-MgGraph @connectParams
}

# This script only checks Applications and their cooresponding Service Principal.
# For a more complete list of all Applications (including those without an "App Registration") run Invoke-ApplicationChecks-v10.ps1
$applicationArray = Get-MgApplication -All
$servicePrincipalArray = Get-MgServicePrincipal -All 
$servicePrincipalByAppId = @{}
foreach ($sp in $servicePrincipalArray) {
    $servicePrincipalByAppId[$sp.AppId] = $sp
}

# One row per credential. App and SP credentials are paired by position so every
# credential is reported, even when an app has several (e.g. expired + replacement).
foreach ($app in $applicationArray) {
    $appCreds = @($app.PasswordCredentials)
    $spCreds = @($servicePrincipalByAppId[$app.AppId].PasswordCredentials)
    $rowCount = [Math]::Max([Math]::Max($appCreds.Count, $spCreds.Count), 1)

    for ($i = 0; $i -lt $rowCount; $i++) {
        [PSCustomObject] @{
            DisplayName     = $app.DisplayName
            AppID           = $app.AppId
            AppCredentialID = $appCreds[$i].KeyId
            AppCreated      = $appCreds[$i].StartDateTime
            AppExpires      = $appCreds[$i].EndDateTime
            SPCredentialID  = $spCreds[$i].KeyId
            SPCreated       = $spCreds[$i].StartDateTime
            SPExpires       = $spCreds[$i].EndDateTime
        }
    }
}
