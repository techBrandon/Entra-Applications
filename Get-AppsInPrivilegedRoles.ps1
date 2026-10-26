#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Identity.Governance, Microsoft.Graph.Applications, Microsoft.Graph.Groups
<#
.SYNOPSIS
Lists service principals that hold a privileged Entra directory role.
.EXAMPLE
./Get-AppsInPrivilegedRoles.ps1 -TenantId <tenant-guid> | Format-Table
#>
[CmdletBinding()]
param([string]$TenantId)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# EDIT PER TENANT: role names to flag. Names must match the Entra role display name exactly.
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
    'Security Administrator', 'Security Operator', 'Security Reader', 'User Administrator'
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
    if (-not $definition) { throw "Role '$name' not found in this tenant." }
    $privilegedIds[$definition.Id] = $name
}

# Principal is expanded so each assignment already says whether it is a user, group or app
$assignments = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal
foreach ($assignment in $assignments) {
    $role = $privilegedIds[$assignment.RoleDefinitionId]
    if (-not $role) { continue }

    $groupName = $null
    $apps = @()   # users and other principal types stay empty
    switch ($assignment.Principal.AdditionalProperties['@odata.type']) {
        '#microsoft.graph.servicePrincipal' {
            $apps = Get-MgServicePrincipal -ServicePrincipalId $assignment.PrincipalId
        }
        '#microsoft.graph.group' {
            # Groups that can hold roles cannot be nested, so direct members are the full list
            $groupName = $assignment.Principal.AdditionalProperties['displayName']
            $apps = Get-MgGroupMemberAsServicePrincipal -GroupId $assignment.PrincipalId -All
        }
    }

    foreach ($app in $apps) {
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
