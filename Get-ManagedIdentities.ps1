#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Applications
<#
.SYNOPSIS
Lists managed identity service principals with their appOwnerOrganizationId.
.NOTES
Read-only. Uses your current Connect-MgGraph session if there is one, otherwise signs in and requests Application.Read.All.
.EXAMPLE
./Get-ManagedIdentities.ps1 -TenantId <tenant-guid> | Export-Csv ManagedIdentities.csv
#>
[CmdletBinding()]
param([string]$TenantId)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Reuse an existing Graph connection unless -TenantId asks for another tenant
$context = Get-MgContext
if ($context -and (-not $TenantId -or $context.TenantId -eq $TenantId)) {
    Write-Information "Using existing Graph session: $($context.Account ?? $context.AppName) ($($context.AuthType))" -InformationAction Continue
}
else {
    $connectParams = @{ Scopes = 'Application.Read.All'; NoWelcome = $true }
    if ($TenantId) { $connectParams.TenantId = $TenantId }
    Connect-MgGraph @connectParams
}

Get-MgServicePrincipal -All -Filter "servicePrincipalType eq 'ManagedIdentity'" -Property DisplayName, AppOwnerOrganizationId |
    Select-Object DisplayName, AppOwnerOrganizationId
