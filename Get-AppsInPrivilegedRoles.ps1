#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Identity.Governance, Microsoft.Graph.Applications, Microsoft.Graph.Groups
<#
.SYNOPSIS
Lists service principals that hold a privileged Entra directory role.
.NOTES
Read-only. Requests these Graph scopes: RoleManagement.Read.Directory, Application.Read.All, GroupMember.Read.All.
Sign in as an account that can read applications and directory roles (for example Global Reader).
Checks active role assignments only. Roles that are PIM-eligible but not activated are not included.
.EXAMPLE
./Get-AppsInPrivilegedRoles.ps1 -TenantId <tenant-guid> | Format-Table
#>
[CmdletBinding()]
param([string]$TenantId)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# EDIT PER TENANT: role names to flag. Names must match the Entra role display name exactly.
# Lists every built-in role labelled PRIVILEGED on the page below (checked October 2026).
# Roles: https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference
$PrivilegedRoles = @(
    'Application Administrator', 'Application Developer', 'Attribute Provisioning Administrator',
    'Authentication Administrator', 'Authentication Extensibility Administrator',
    'B2C IEF Keyset Administrator', 'Cloud Application Administrator',
    'Cloud Device Administrator', 'Conditional Access Administrator', 'Directory Writers',
    'Domain Name Administrator', 'External Identity Provider Administrator',
    'Global Administrator', 'Global Reader', 'Helpdesk Administrator',
    'Hybrid Identity Administrator', 'Intune Administrator', 'Lifecycle Workflows Administrator',
    'Partner Tier1 Support', 'Partner Tier2 Support', 'Password Administrator',
    'Privileged Authentication Administrator', 'Privileged Role Administrator',
    'Security Administrator', 'Security Operator', 'Security Reader', 'User Administrator',
    'Agent ID Administrator', 'AI Administrator', 'AI Reader', 'Attribute Provisioning Reader',
    'Authentication Extensibility Password Administrator', 'Entra SOC Identity Responder',
    'Identity Governance Administrator', 'Tenant Governance Administrator'
)

# EDIT PER TENANT: tenants whose apps should be labelled 'Microsoft'
$MicrosoftTenantIds = @(
    'f8cdef31-a31e-4b4a-93e4-5f571e91255a'  # Microsoft Services
    '72f988bf-86f1-41af-91ab-2d7cd011db47'  # Microsoft
)

$connectParams = @{
    Scopes    = 'RoleManagement.Read.Directory', 'Application.Read.All', 'GroupMember.Read.All'
    NoWelcome = $true
}
if ($TenantId) { $connectParams.TenantId = $TenantId }
Connect-MgGraph @connectParams
$HomeTenantId = "$((Get-MgContext).TenantId)"
Write-Information "Checking tenant $HomeTenantId" -InformationAction Continue

# Says who published the app. Third Party apps are the ones to review first.
function Get-AppOwnerTenant {
    param([string]$OwnerId)   # [string] because Graph may return a Guid or a string
    if (-not $OwnerId) { return 'Unknown' }
    if ($OwnerId -eq $HomeTenantId) { return 'Home Tenant' }
    if ($OwnerId -in $MicrosoftTenantIds) { return 'Microsoft' }
    'Third Party'
}

# Translate role names to the IDs Graph uses in assignments
$roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All
$privilegedIds = @{}
foreach ($name in $PrivilegedRoles) {
    $definition = $roleDefinitions | Where-Object { $_.DisplayName -eq $name }
    if (-not $definition) {
        Write-Warning "Role '$name' not found in this tenant. Skipping."
        continue
    }
    $privilegedIds["$($definition.Id)"] = $name
}

# Principal is expanded so each assignment already says whether it is a user, group or app
$assignments = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal
$appCache = @{}   # principal Id -> apps, so an app or group holding several roles is fetched once
$found = 0

foreach ($assignment in $assignments) {
    $role = $privilegedIds["$($assignment.RoleDefinitionId)"]
    $principal = $assignment.Principal
    if (-not $role -or -not $principal) { continue }   # no principal means it was deleted

    # Graph normally sends '@odata.type'; fall back to the .NET type name if the SDK consumed it
    $type = $principal.AdditionalProperties['@odata.type']
    if (-not $type) { $type = "#microsoft.graph.$($principal.GetType().Name -replace '^MicrosoftGraph')" }
    $groupName = $null
    if ($type -eq '#microsoft.graph.group') {
        $groupName = $principal.AdditionalProperties['displayName']
        if (-not $groupName) { $groupName = $assignment.PrincipalId }
    }

    if (-not $appCache.ContainsKey($assignment.PrincipalId)) {
        $appCache[$assignment.PrincipalId] = switch ($type) {
            '#microsoft.graph.servicePrincipal' {
                Get-MgServicePrincipal -ServicePrincipalId $assignment.PrincipalId
            }
            '#microsoft.graph.group' {
                # Groups that can hold roles cannot be nested, so direct members are the full list
                Get-MgGroupMemberAsServicePrincipal -GroupId $assignment.PrincipalId -All
            }
        }
    }

    foreach ($app in $appCache[$assignment.PrincipalId]) {
        $found++
        [PSCustomObject]@{
            DisplayName      = $app.DisplayName
            AppId            = $app.AppId
            AccountEnabled   = $app.AccountEnabled
            AppOwnerTenant   = Get-AppOwnerTenant $app.AppOwnerOrganizationId
            Role             = $role
            Scope            = $assignment.DirectoryScopeId  # '/' means the whole tenant
            AssignedViaGroup = $groupName
        }
    }
}
Write-Information "Done. Found $found privileged role assignment(s) held by apps." -InformationAction Continue
