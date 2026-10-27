#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Applications
<#
.SYNOPSIS
Lists service principals that hold privileged application permissions.
.NOTES
Read-only. Uses your current Connect-MgGraph session if there is one, otherwise signs in and requests these Graph scopes: Application.Read.All.
Sign in as an account that can read applications (for example Global Reader or Application Administrator).
Checks application permissions only. Delegated permission grants are not included.
.EXAMPLE
./Get-PrivilegedApps.ps1 -TenantId <tenant-guid> | Export-Csv PrivilegedApps.csv
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
        # Apps, consent and role assignment
        'Application.ReadWrite.All', 'Application.ReadWrite.OwnedBy', 'AppRoleAssignment.ReadWrite.All',
        'DelegatedPermissionGrant.ReadWrite.All', 'ServicePrincipalEndpoint.ReadWrite.All',
        'RoleManagement.ReadWrite.Directory', 'RoleAssignmentSchedule.ReadWrite.Directory',
        'RoleEligibilitySchedule.ReadWrite.Directory', 'RoleManagementPolicy.ReadWrite.Directory',
        'EntitlementManagement.ReadWrite.All', 'ConsentRequest.ReadWrite.All',
        # PIM
        'PrivilegedAccess.ReadWrite.AzureAD', 'PrivilegedAccess.ReadWrite.AzureADGroup',
        'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup',
        'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup',
        # Directory objects, users and groups
        'Directory.ReadWrite.All', 'Group.ReadWrite.All', 'GroupMember.ReadWrite.All',
        'User.ReadWrite.All', 'User-PasswordProfile.ReadWrite.All',
        'UserAuthenticationMethod.ReadWrite.All', 'Domain.ReadWrite.All', 'Organization.ReadWrite.All',
        # Tenant policy and federation
        'Policy.ReadWrite.ConditionalAccess', 'Policy.ReadWrite.PermissionGrant',
        'Policy.ReadWrite.Authorization', 'Policy.ReadWrite.AuthenticationMethod',
        'Policy.ReadWrite.AuthenticationFlows', 'Policy.ReadWrite.CrossTenantAccess',
        'Policy.ReadWrite.ConsentRequest', 'Policy.ReadWrite.SecurityDefaults',
        'Policy.ReadWrite.ApplicationConfiguration', 'Policy.ReadWrite.TrustFramework',
        'IdentityProvider.ReadWrite.All', 'TrustFrameworkKeySet.ReadWrite.All',
        # Intune can run code on managed devices
        'DeviceManagementRBAC.ReadWrite.All', 'DeviceManagementConfiguration.ReadWrite.All',
        'DeviceManagementApps.ReadWrite.All', 'DeviceManagementManagedDevices.PrivilegedOperations.All',
        # Broad data access (not tenant takeover, kept from the original list)
        'Directory.Read.All', 'User.Read.All', 'User.Export.All', 'Calendars.ReadWrite',
        'Mail.ReadWrite', 'Mail.Send', 'Files.ReadWrite.All', 'Sites.ReadWrite.All', 'Sites.FullControl.All'
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
$HomeTenantId = "$((Get-MgContext).TenantId)"
Write-Information "Checking tenant $HomeTenantId" -InformationAction Continue

# Says who published the app. Third Party apps are the ones to review first.
function Get-AppOwnerTenant {
    param([string]$OwnerId)   # [string] because Graph may return a Guid or a string
    if (-not $OwnerId) { return 'Unknown' } # Null
    if ($OwnerId -eq $HomeTenantId) { return 'Home Tenant' } # Single-tenant app
    if ($OwnerId -in $MicrosoftTenantIds) { return 'Microsoft' }
    'Third Party' # Else assume tenant belongs to the vendor of the app
}

$appCache = @{}   # principal object Id -> service principal, so each app is fetched once
$found = 0

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
        if (-not $appRole) {
            Write-Warning "Permission '$name' not found on '$($resource.DisplayName)'. Skipping."
            continue
        }
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
        $found++
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
Write-Information "Done. Found $found privileged permission grant(s) held by apps." -InformationAction Continue
