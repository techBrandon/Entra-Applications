
<#
.SYNOPSIS
Invokes Entra Application Checks in support of a Zero Trust approach to application security.
.DESCRIPTION
Inspired by https://learn.microsoft.com/en-us/entra/fundamentals/zero-trust-protect-engineering-systems
This script is intended to invoke various Entra Application checks in support of a Zero Trust approach to application security.
Each check is intended to identify potentially risky configurations that may lead to privilege escalation or other security concerns.
The checks focus on application owners, credentials (certificates & secrets), and permissions.
.NOTES
Version: 1.0
Updated: 20251211
Author: Brandon Colley
Email: ColleyBrandon@pm.me
#>

# Connect to Microsoft Graph with required scopes
$tenantID = '' #Tenant ID GUID (Optional)
Connect-MgGraph -TenantId $tenantID -Scopes 'Application.Read.All','Directory.Read.All'

# Section 1: Creating new applications and service principals is restricted to privileged users
# https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/delegate-app-roles

# Users can register applications: True or False
if ((Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions.AllowedToCreateApps) {
    "Users can register applications"
} 
else {
    "Users cannot register applications"
}

# Users can consent to apps accessing company data on their behalf: True or False
$userConsent = (Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions.PermissionGrantPoliciesAssigned
if ($userConsent -eq 'ManagePermissionGrantsForSelf.microsoft-user-default-recommended') {
    "Let Microsoft manage your consent settings (Recommended)"
} 
elseif ($userConsent -eq 'ManagePermissionGrantsForSelf.microsoft-user-default-low') {
    "Allow user consent for apps from verified publishers, for selected permissions"
}
elseif ($userConsent -notlike 'ManagePermissionGrantsForSelf.*') {
    "Do not allow user consent"
}
else {
    "Unknown user consent settings detected: $userConsent"
}

# Members of the Application Developer role can override the above settings.
# TODO: This should be a function to be reused based on role definition ID & considerations for nonPIM, eligible, permanent, etc
$roleMembers = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq 'cf1c38e5-3621-4004-a7cb-879624dced7c'"
#(Get-MgDirectoryObject -DirectoryObjectId PRINCIPALID).AdditionalProperties # This will return data if there are members but returns principalid as well as scope information (which might be relevant). This can be used to gather more information and will work for all object types
foreach ($member in $roleMembers) {
    $assignedObject = Get-MgDirectoryObject -DirectoryObjectId $member.PrincipalId
    [PSCustomObject]@{
        RoleDisplayName = "Application Developer"
        AssignedTo = $assignedObject.AdditionalProperties.displayName
        AssignedToId = $member.PrincipalId
        AssignedToUPN = $assignedObject.AdditionalProperties.userPrincipalName
    }
}

# Identify applications with owners configured
Get-MgApplication -All -ExpandProperty Owners | Where-Object Owners | Select-Object DisplayName, Owners
Get-MgServicePrincipal -All -ExpandProperty Owners | Where-Object Owners | Select-Object DisplayName, Owners

# Assign built-in (Cloud) Application Administrator roles
# TODO: Same as above, use function
Get-MgRoleManagementDirectoryRoleAssignment | Where-Object roleDefinitionId -in @('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3','158c047a-c907-4556-b7ef-446551a6b5f7')

# TODO: Use of Owners and App Admin roles can be good or bad depending on context.
# Further analysis is needed to determine if the configuration is appropriate.
# Zero trust framework seems to recommend the use of owners, which can be good, but only if tiered properly. I think this should be it's own control. Something like "Application Management is properly configured according to zero trust". This is hard. If, apps with elevated privs,.... Role = Tier 0, Owner = Tier 0, etc etc.
# This is going to require functions similar to the standalone scripts I have for permissions and roles. The roles script may be simplified to just include ALL roles, but if we're going this deep, then we might as well do it right with tiering.

# Use of custom role(s) to manage applications
#TODO: detect custom role based on permissions on role. can be "organization-wide scope" or "assigned at the scope of a single Microsoft Entra object".
##### The below is vibe code. No idea what it actually does yet.
Get-MgRoleManagementDirectoryRoleDefinition | Where-Object {$_.IsBuiltIn -eq $false} | ForEach-Object {
    $roleDef = $_
    $hasAppMgmtPerms = $false
    foreach ($perm in $roleDef.Permissions) {
        if ($perm.ResourceActions -contains "microsoft.directory/applications/*" -or $perm.ResourceActions -contains "microsoft.directory/servicePrincipals/*") {
            $hasAppMgmtPerms = $true
        }
    }
    if ($hasAppMgmtPerms) {
        # Output role definition and assignments
        $roleDef | Select-Object DisplayName, Id
        Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($roleDef.Id)'" | ForEach-Object {
            $assignment = $_
            $assignedObject = Get-MgDirectoryObject -DirectoryObjectId $assignment.PrincipalId
            [PSCustomObject]@{
                RoleDisplayName = $roleDef.DisplayName
                AssignedTo = $assignedObject.DisplayName
                AssignedToId = $assignedObject.Id
                AssignmentScope = $assignment.Scope
            }
        }
    }
}

# Section 2: Inactive applications don't have highly privileged Microsoft Graph API permissions

# Inactive is the keyword for this section. What is inactive? No sign-ins in 30/60/90/180 days? No activity at all? This needs to be defined.

# No sign-in logs (how long do they go back?) This might not scale well in large tenants.
Get-MgAuditLogSignIn -Filter "appId eq 'APPID'"
# or
$tmpAll = Get-MgAuditLogSignIn -All
$allApps | Where-Object { ($tmpAll.AppId -contains $_.AppId)}

# no valid credentials (all credentials expired)
# I don't like relying solely upon this because I see creds that are valid for 100 years.
$allApps | Where-Object PasswordCredentials.EndDateTime -lt $today

# No coorresponding service principal
###### The below is vibe code. No idea what it actually does yet.
$allApps = Get-MgApplication -All`
$allSPs = Get-MgServicePrincipal -All`
$allApps | Where-Object { -not ($allSPs.AppId -contains $_.appId)}

# Disabled service principal: part of the remediation guidance to "disable" apps before deleting
Get-MgServicePrincipal | Where-Object AccountEnabled -eq $False

# Section 3: Inactive applications don't have highly privileged built-in roles

    # Same as above, need to define inactive.

# Section 4: App registrations use safe redirect URIs

$apps = Get-MgApplication -All
$sps = Get-MgServicePrincipal -All

$results = @()

# --------------------
# Process Applications
# --------------------
foreach ($app in $apps) {

    $allUris = @()
    if ($app.Web.RedirectUris)       { $allUris += $app.Web.RedirectUris }
    if ($app.Spa.RedirectUris)       { $allUris += $app.Spa.RedirectUris }
    if ($app.PublicClient.RedirectUris) { $allUris += $app.PublicClient.RedirectUris }

    foreach ($uri in $allUris) {
        $results += [pscustomobject]@{
            ObjectType  = "Application"
            DisplayName = $app.DisplayName
            ObjectId    = $app.Id
            AppId       = $app.AppId
            RedirectUri = $uri
        }
    }
}

# ----------------------------
# Process Service Principals
# ----------------------------
foreach ($sp in $sps) {

    $allUris = @()
    if ($sp.Web.RedirectUris) { $allUris += $sp.Web.RedirectUris }
    if ($sp.ReplyUrls)        { $allUris += $sp.ReplyUrls }
    if ($sp.RedirectUris)     { $allUris += $sp.RedirectUris }

    foreach ($uri in $allUris) {
        $results += [pscustomobject]@{
            ObjectType  = "ServicePrincipal"
            DisplayName = $sp.DisplayName
            ObjectId    = $sp.Id
            AppId       = $sp.AppId
            RedirectUri = $uri
        }
    }
}

# ----------------------------
# Output / Export
# ----------------------------
#$results | Sort-Object ObjectType, DisplayName, RedirectUri

# Dangerous Redirect URIs:
$results | Where-Object { $_.RedirectUri -match "\*" } # Highly dangerous wildcard URI
$results | Where-Object { $_.RedirectUri -match "localhost" } # Localhost URIs (usually for dev/test))
$results | Where-Object {
    $_.RedirectUri -match "^http://" -and
    $_.RedirectUri -notmatch "^http://localhost(:\d+)?" # Non-localhost HTTP URIs
}


# Optional: Export to CSV
# $results | Export-Csv -Path ".\TenantRedirectURIReport.csv" -NoTypeInformation


# Section 5: Service principals use safe redirect URIs

    # Covered in Section 4

# Section 6: App registrations must not have dangling or abandoned domain redirect URIs

# Section 7: Resource-specific consent to application is restricted

# Section 8: Workload Identities are not assigned privileged roles

# Section 9: Enterprise applications must require explicit assignment or scoped provisioning


### Functions:

function Expand-EntraRoleGroupMembers {
    param(
        [Parameter(Mandatory)]
        [string]$GroupId,

        [Parameter(Mandatory)]
        [string]$RoleName,

        [Parameter(Mandatory)]
        [string]$RoleDefinitionId,

        [Parameter(Mandatory)]
        [string]$AssignmentType,

        [Parameter(Mandatory)]
        [string]$AssignmentState,

        [Parameter(Mandatory)]
        $RoleAssignment
    )

    $expanded = @()

    $members = Get-MgGroupMember -GroupId $GroupId -All

    foreach ($m in $members) {
        $expanded += [pscustomobject]@{
            RoleName         = $RoleName
            RoleDefinitionId = $RoleDefinitionId
            AssignmentType   = "$AssignmentType → GroupMember"
            AssignmentState  = $AssignmentState
            PrincipalId      = $m.Id
            PrincipalType    = $m.AdditionalProperties['@odata.type']
            PrincipalName    = $m.AdditionalProperties.displayName
            PrincipalUPN     = $m.AdditionalProperties.userPrincipalName
            ScopeId          = $RoleAssignment.DirectoryScopeId
            Expiration       = $null
            RawAssignment    = $RoleAssignment
        }
    }

    return $expanded
}

function Get-EntraRoleMembershipDeep {
    param(
        [Parameter(Mandatory)]
        [string]$RoleDefinitionId,

        # Whether to expand group membership (optional because it's expensive)
        [switch]$ExpandGroups
    )

    # ------------------------------------------------------------------------------------
    # 1. Resolve the role definition so we can output a clean role name
    # ------------------------------------------------------------------------------------
    $roleDef = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $RoleDefinitionId
    if (-not $roleDef) {
        throw "RoleDefinitionId $RoleDefinitionId not found."
    }

    $roleName = $roleDef.DisplayName

    $allAssignments = @()

    # ====================================================================================
    # SECTION 1 — Permanent (non-PIM) role assignments
    # WHY: These represent always-on admin assignments
    # API: /roleManagement/directory/roleAssignments
    # ====================================================================================
    $permAssignments = Get-MgRoleManagementDirectoryRoleAssignment -All -Filter "roleDefinitionId eq '$RoleDefinitionId'"

    foreach ($a in $permAssignments) {
        $principal = Get-MgDirectoryObject -DirectoryObjectId $a.PrincipalId

        $allAssignments += [pscustomobject]@{
            RoleName           = $roleName
            RoleDefinitionId   = $RoleDefinitionId
            AssignmentType     = "Permanent"
            AssignmentState    = "Active"
            PrincipalId        = $a.PrincipalId
            PrincipalType      = $principal.AdditionalProperties['@odata.type']
            PrincipalName      = $principal.AdditionalProperties.displayName
            PrincipalUPN       = $principal.AdditionalProperties.userPrincipalName
            ScopeId            = $a.DirectoryScopeId
            Expiration         = $null
            RawAssignment      = $a
        }

        # ---------------------------
        # Optional group expansion
        # ---------------------------
        if ($ExpandGroups -and $principal.AdditionalProperties['@odata.type'] -eq "#microsoft.graph.group") {
            $allAssignments += Expand-EntraRoleGroupMembers `
                -GroupId $a.PrincipalId `
                -RoleName $roleName `
                -RoleDefinitionId $RoleDefinitionId `
                -AssignmentType "Permanent" `
                -AssignmentState "Active" `
                -RoleAssignment $a 
        }
    }

    # ====================================================================================
    # SECTION 2 — PIM ACTIVE role assignments
    # WHY: These represent time-bound elevated roles currently active
    # API: /roleManagement/directory/roleAssignmentScheduleInstances
    # ====================================================================================
    $activeAssignments = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All `
        -Filter "roleDefinitionId eq '$RoleDefinitionId'"

    foreach ($a in $activeAssignments) {

        $principal = Get-MgDirectoryObject -DirectoryObjectId $a.PrincipalId

        $allAssignments += [pscustomobject]@{
            RoleName           = $roleName
            RoleDefinitionId   = $RoleDefinitionId
            AssignmentType     = "PIM-Active"
            AssignmentState    = $a.AssignmentType
            PrincipalId        = $a.PrincipalId
            PrincipalType      = $principal.AdditionalProperties['@odata.type']
            PrincipalName      = $principal.AdditionalProperties.displayName
            PrincipalUPN       = $principal.AdditionalProperties.userPrincipalName
            ScopeId            = $a.DirectoryScopeId
            Expiration         = $a.EndDateTime
            RawAssignment      = $a
        }

        # ---------------------------
        # Optional group expansion
        # ---------------------------
        if ($ExpandGroups -and $principal.AdditionalProperties['@odata.type'] -eq "#microsoft.graph.group") {
            $allAssignments += Expand-EntraRoleGroupMembers `
                -GroupId $a.PrincipalId `
                -RoleName $roleName `
                -RoleDefinitionId $RoleDefinitionId `
                -AssignmentType "PIM-Active" `
                -AssignmentState $a.AssignmentType `
                -RoleAssignment $a 
        }
    }

    # ====================================================================================
    # SECTION 3 — PIM ELIGIBLE role assignments
    # WHY: These users *could* activate the role but haven't yet
    # API: /roleManagement/directory/roleEligibilitySchedules
    # ====================================================================================
    $eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All `
        -Filter "roleDefinitionId eq '$RoleDefinitionId'"

    foreach ($a in $eligibleAssignments) {
        $principal = Get-MgDirectoryObject -DirectoryObjectId $a.PrincipalId

        $allAssignments += [pscustomobject]@{
            RoleName           = $roleName
            RoleDefinitionId   = $RoleDefinitionId
            AssignmentType     = "PIM-Eligible"
            AssignmentState    = $a.AssignmentType ### Does not exist. May not be needed
            PrincipalId        = $a.PrincipalId
            PrincipalType      = $principal.AdditionalProperties['@odata.type']
            PrincipalName      = $principal.AdditionalProperties.displayName
            PrincipalUPN       = $principal.AdditionalProperties.userPrincipalName
            ScopeId            = $a.DirectoryScopeId
            Expiration         = $a.ScheduleInfo.Expiration.EndDateTime
            RawAssignment      = $a
        }

        # ---------------------------
        # Optional group expansion
        # ---------------------------
        if ($ExpandGroups -and $principal.AdditionalProperties['@odata.type'] -eq "#microsoft.graph.group") {
            $allAssignments += Expand-EntraRoleGroupMembers `
                -GroupId $a.PrincipalId `
                -RoleName $roleName `
                -RoleDefinitionId $RoleDefinitionId `
                -AssignmentType "PIM-Eligible" `
                -AssignmentState $a.AssignmentType `
                -RoleAssignment $a 
        }
    }

    return $allAssignments
}


function Resolve-EntraEffectiveRoleMembers {
    param(
        [Parameter(Mandatory)]
        [array]$Assignments
    )

    # Group by the true identity of a role member
    $grouped = $Assignments | Group-Object `
        RoleDefinitionId, PrincipalId, ScopeId

    $effective = @()

    foreach ($g in $grouped) {

        $items = $g.Group

        # -----------------------------------
        # Determine effective assignment type
        # -----------------------------------
        $effectiveType = if ($items.AssignmentType -contains "PIM-Active") {
            "PIM-Active"
        }
        elseif ($items.AssignmentType -contains "Permanent") {
            "Permanent"
        }
        elseif ($items.AssignmentType -contains "PIM-Active → GroupMember") {
            "PIM-Active → GroupMember"
        }
        elseif ($items.AssignmentType -contains "Permanent → GroupMember") {
            "Permanent → GroupMember"
        }
        else {
            "PIM-Eligible"
        }

        # -----------------------------------
        # Resolve source precedence
        # -----------------------------------
        $source = if ($items.Source -contains "Direct") {
            "Direct"
        }
        elseif ($items.Source -contains "Group") {
            "Group"
        }
        else {
            "GroupMember"
        }

        # -----------------------------------
        # Expiration logic
        # -----------------------------------
        $expiration = ($items |
            Where-Object { $_.Expiration } |
            Sort-Object Expiration |
            Select-Object -First 1).Expiration

        # -----------------------------------
        # Build final effective record
        # -----------------------------------
        $effective += [pscustomobject]@{
            RoleName         = $items[0].RoleName
            RoleDefinitionId = $items[0].RoleDefinitionId
            PrincipalId      = $items[0].PrincipalId
            PrincipalType    = $items[0].PrincipalType
            PrincipalName    = $items[0].PrincipalName
            PrincipalUPN     = $items[0].PrincipalUPN
            ScopeId          = $items[0].ScopeId

            EffectiveAssignment = $effectiveType
            Source               = $source

            HasPermanent         = $items.AssignmentType -contains "Permanent"
            HasPIMActive         = $items.AssignmentType -contains "PIM-Active"
            HasPIMEligible       = $items.AssignmentType -contains "PIM-Eligible"

            Expiration           = $expiration
            RawAssignmentCount   = $items.Count
        }
    }

    return $effective
}


$deepMembers = Get-EntraRoleMembershipDeep -RoleDefinitionId $roledefinitionid -ExpandGroups
$effectiveMembers = Resolve-EntraEffectiveRoleMembers -Assignments $deepMembers