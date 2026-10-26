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

# EDIT PER TENANT: tenants whose apps should be labelled 'Microsoft'
$MicrosoftTenantIds = @(
    'f8cdef31-a31e-4b4a-93e4-5f571e91255a'  # Microsoft Services
    '72f988bf-86f1-41af-91ab-2d7cd011db47'  # Microsoft
)

$connectParams = @{ Scopes = 'Application.Read.All'; NoWelcome = $true }
if ($TenantId) { $connectParams.TenantId = $TenantId }
Connect-MgGraph @connectParams
$HomeTenantId = "$((Get-MgContext).TenantId)"

# Says who published the app. Third Party apps are the ones to review first.
function Get-AppOwnerTenant {
    param([string]$OwnerId)   # [string] because Graph may return a Guid or a string
    if (-not $OwnerId) { return 'Unknown' }
    if ($OwnerId -eq $HomeTenantId) { return 'Home Tenant' }
    if ($OwnerId -in $MicrosoftTenantIds) { return 'Microsoft' }
    'Third Party'
}

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
            AppOwnerTenant = Get-AppOwnerTenant $app.AppOwnerOrganizationId
            Resource       = $resource.DisplayName
            Permission     = $permission
        }
    }
}
