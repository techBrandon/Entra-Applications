#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Applications
<#
.SYNOPSIS
Lists service principals that hold privileged application permissions.
.EXAMPLE
./Get-PrivilegedApps.ps1 -TenantId <tenant-guid> | Export-Csv PrivilegedApps.csv -NoTypeInformation
#>
[CmdletBinding()]
param([string]$TenantId)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# EDIT PER TENANT: each key is the AppId of an API (resource); values are permission names to flag.
# Permission names: https://graphpermissions.merill.net/ (AppIds below are the same in every tenant)
$PrivilegedPermissions = @{
    # Microsoft Graph
    '00000003-0000-0000-c000-000000000000' = @(
        'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'Calendars.ReadWrite',
        'Directory.ReadWrite.All', 'Directory.Read.All', 'Files.ReadWrite.All',
        'GroupMember.ReadWrite.All', 'Group.ReadWrite.All', 'Mail.ReadWrite', 'Mail.Send',
        'RoleManagement.ReadWrite.Directory', 'ServicePrincipalEndpoint.ReadWrite.All',
        'Sites.ReadWrite.All', 'User.Export.All', 'User.ReadWrite.All', 'User.Read.All'
    )
    # Windows Azure Active Directory (Azure AD Graph)
    '00000002-0000-0000-c000-000000000000' = @(
        'Application.ReadWrite.All', 'Directory.ReadWrite.All', 'Directory.Read.All'
    )
    # Office 365 Exchange Online
    '00000002-0000-0ff1-ce00-000000000000' = @('Exchange.ManageAsApp')
}

$connectParams = @{ Scopes = 'Application.Read.All'; NoWelcome = $true }
if ($TenantId) { $connectParams.TenantId = $TenantId }
Connect-MgGraph @connectParams

$appCache = @{}   # principal object Id -> service principal, so each app is fetched once

foreach ($resourceAppId in $PrivilegedPermissions.Keys) {
    $resource = Get-MgServicePrincipal -Filter "appId eq '$resourceAppId'"
    if (-not $resource) {
        Write-Warning "API $resourceAppId is not present in this tenant. Skipping."
        continue
    }

    # Translate permission names to the IDs Graph uses in assignments
    $privilegedIds = @{}
    foreach ($name in $PrivilegedPermissions[$resourceAppId]) {
        $appRole = $resource.AppRoles | Where-Object { $_.Value -eq $name }
        if (-not $appRole) { throw "Permission '$name' not found on '$($resource.DisplayName)'." }
        $privilegedIds["$($appRole.Id)"] = $name
    }

    # One call returns every app that was granted a permission on this API
    $grants = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $resource.Id -All
    foreach ($grant in $grants) {
        $permission = $privilegedIds["$($grant.AppRoleId)"]
        if ($grant.PrincipalType -ne 'ServicePrincipal' -or -not $permission) { continue }

        if (-not $appCache.ContainsKey($grant.PrincipalId)) {
            $appCache[$grant.PrincipalId] = Get-MgServicePrincipal -ServicePrincipalId $grant.PrincipalId
        }
        $app = $appCache[$grant.PrincipalId]
        [PSCustomObject]@{
            DisplayName    = $app.DisplayName
            AppId          = $app.AppId
            AccountEnabled = $app.AccountEnabled
            AppOwnerTenant = $app.AppOwnerOrganizationId   # raw ID for now; calculated in a later phase
            Resource       = $resource.DisplayName
            Permission     = $permission
        }
    }
}
