
<#
.SYNOPSIS
Invokes Entra Application Checks in support of a Zero Trust approach to application security.
.DESCRIPTION
Inspired by https://learn.microsoft.com/en-us/entra/fundamentals/zero-trust-protect-engineering-systems
This script is intended to invoke various Entra Application checks in support of a Zero Trust approach to application security.
Each check is intended to identify potentially risky configurations that may lead to privilege escalation or other security concerns.
The checks focus on tenant configurations, application owners, credentials (certificates & secrets), and permissions.
.NOTES
Version: 1.0
Updated: 20260119
Author: Brandon Colley
Email: ColleyBrandon@pm.me
#>

# ===========================================================================================
# CENTRAL DATA COLLECTOR
# ===========================================================================================

# Script-level cache for collected artifacts
$script:EntraCache = @{
    Timestamp = $null
    Data      = $null
}

<#
.SYNOPSIS
Collects all Entra application and role data required for Zero Trust checks.

.DESCRIPTION
Gathers applications, service principals, roles, groups, policies, and optionally sign-ins.
Results are cached in $script:EntraCache to avoid redundant API calls.

.PARAMETER TenantId
Optional tenant ID. If omitted, uses current connection.

.PARAMETER ForceRefresh
Skip cache and re-fetch all data from Graph.

.PARAMETER IncludeSignIns
Collect sign-in logs (optional, time-consuming on large tenants).

.OUTPUTS
[hashtable] with keys: Applications, ServicePrincipals, RoleDefinitions, RoleAssignments,
Groups, Policies, RedirectUriResults

.EXAMPLE
$data = Collect-EntraArtifacts -TenantId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
$data.Applications | Measure-Object
#>
function Collect-EntraArtifacts {
    param(
        [string]$TenantId,
        [switch]$ForceRefresh,
        [switch]$IncludeSignIns
    )

    # Check cache validity
    if (-not $ForceRefresh -and $script:EntraCache.Timestamp -and 
        ((Get-Date) - $script:EntraCache.Timestamp).TotalMinutes -lt 30) {
        Write-Verbose "Returning cached artifacts (collected at $($script:EntraCache.Timestamp))"
        return $script:EntraCache.Data
    }

    Write-Verbose "Collecting Entra artifacts..."

    # Ensure Graph connection
    $ctx = Get-MgContext
    if (-not $ctx) {
        Connect-MgGraph -TenantId $TenantId -Scopes 'Application.Read.All', 'Directory.Read.All'
    }

    try {
        $artifacts = @{
            Applications        = @()
            ServicePrincipals   = @()
            RoleDefinitions     = @()
            RoleAssignments     = @()
            Groups              = @()
            #AppRoleAssignments  = @()
            Policies            = @()
            SignIns             = @()
            Error               = $null
        }

        Write-Verbose "Fetching applications..."
        $artifacts.Applications = Get-MgApplication -All -Property * -ExpandProperty Owners -ErrorAction Stop

        Write-Verbose "Fetching service principals..."
        $artifacts.ServicePrincipals = Get-MgServicePrincipal -All -Property * -ExpandProperty Owners -ErrorAction Stop

        Write-Verbose "Fetching role definitions..."
        $artifacts.RoleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop

        Write-Verbose "Fetching role assignments..."
        $artifacts.RoleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction Stop

        Write-Verbose "Fetching groups with transitive members..."
        $artifacts.Groups = Get-MgGroup -All -ExpandProperty TransitiveMembers -ErrorAction Stop

        #Write-Verbose "Fetching app role assignments..."
        #$artifacts.AppRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -All -ErrorAction Stop

        Write-Verbose "Fetching authorization policies..."
        $artifacts.Policies = Get-MgPolicyAuthorizationPolicy -ErrorAction SilentlyContinue

        if ($IncludeSignIns) {
            Write-Verbose "Fetching sign-in logs (this may take a while)..."
            $artifacts.SignIns = Get-MgAuditLogSignIn -All -ErrorAction Stop
        }

        # Cache the results
        $script:EntraCache.Data = $artifacts
        $script:EntraCache.Timestamp = Get-Date

        Write-Verbose "Artifact collection complete. Cached until 30 minutes elapse."
        return $artifacts
    }
    catch {
        $artifacts.Error = $_
        Write-Error "Failed to collect artifacts: $_"
        return $artifacts
    }
}

# ===========================================================================================
# SECTION 1: Creating new applications and service principals is restricted to privileged users
# ===========================================================================================

<#
.SYNOPSIS
Tests Entra app registration and consent policies.

.DESCRIPTION
Validates:
- Whether users can register applications
- User consent policy settings
- Application Developer role members

.LINK
https://learn.microsoft.com/en-us/entra/fundamentals/zero-trust-protect-engineering-systems#creating-new-applications-and-service-principals-is-restricted-to-privileged-users

.PARAMETER Data
Collected artifacts (from Collect-EntraArtifacts). If omitted, collects on-demand.

.OUTPUTS
[PSCustomObject[]] with properties: Control, Setting, Status, Details

.EXAMPLE
Test-EntraAppRegistrationPolicy -Data $artifacts
#>
function Test-EntraAppRegistrationPolicy {
    param(
        [hashtable]$Data
    )

    if (-not $Data) {
        Write-Verbose "No data provided; collecting artifacts..."
        $Data = Collect-EntraArtifacts
    }

    # Initialize all 3 checks with defaults
    $check1 = [PSCustomObject]@{
        Control = "EA-101"
        Setting = "Users can register applications"
        Status  = "ERROR"
        Description = "Unable to evaluate"
        Details = @()
    }
    
    $check2 = [PSCustomObject]@{
        Control = "EA-102"
        Setting = "User consent policy"
        Status  = "ERROR"
        Description = "Unable to evaluate"
        Details = @()
    }
    
        $check3 = [PSCustomObject]@{
            Control = "EA-103"
            Setting = "Application Developer role members"
            Status  = "ERROR"
            Description = "Unable to evaluate"
            Details = @()
        }

    $check4 = [PSCustomObject]@{
        Control = "EA-104"
        Setting = "Application owners"
        Status  = "ERROR"
        Description = "Unable to evaluate"
        Details = @()
    }

    $check5 = [PSCustomObject]@{
        Control = "EA-105"
        Setting = "Service principal owners"
        Status  = "ERROR"
        Description = "Unable to evaluate"
        Details = @()
    }

    try {
        if ($Data.Policies) {
            $authPolicy = $Data.Policies

            # Check if users can register applications
            $canRegister = $authPolicy.DefaultUserRolePermissions.AllowedToCreateApps
            
            if ($canRegister -eq $true) {
                $check1.Status = "FINDING"
                $check1.Description = "Users can create app registrations"
            }
            elseif ($canRegister -eq $false) {
                $check1.Status = "PASS"
                $check1.Description = "Users cannot create app registrations"
            }
            else {
                $check1.Status = "UNKNOWN"
                $check1.Description = "Unable to determine if users can create app registrations"
            }

            # Check user consent policy
            $userConsent = $authPolicy.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned
            $consentStatus = switch -Regex ($userConsent) {
                'ManagePermissionGrantsForSelf.microsoft-user-default-recommended' { 
                    @("FINDING", "Let Microsoft manage consent settings (Recommended)")
                    break
                }
                'ManagePermissionGrantsForSelf.microsoft-user-default-low' { 
                    @("FINDING", "Allow user consent for verified publishers")
                    break
                }
                default {
                    if ($userConsent -and $userConsent -notcontains 'ManagePermissionGrantsForSelf') {
                        @("PASS", "Do not allow user consent")
                    }
                    else {
                        @("UNKNOWN", "Unknown consent setting: $($userConsent -join ', ')")
                    }
                }
            }

            $check2.Status = $consentStatus[0]
            $check2.Description = $consentStatus[1]
        }

        # Check Application Developer role members
        # TODO: Return WHO is assigned this role. Expand groups. Use Details property.
        if ($Data.RoleDefinitions -and $Data.RoleAssignments) {
            $appDevRole = $Data.RoleDefinitions | Where-Object { $_.DisplayName -eq "Application Developer" }
            if ($appDevRole) {
                $appDevAssignments = $Data.RoleAssignments | Where-Object { $_.RoleDefinitionId -eq $appDevRole.Id }
                if ($appDevAssignments.Count -gt 0) {
                    $check3.Status = "FINDING"
                    $check3.Description = "Count: $($appDevAssignments.Count); can override registration restrictions"
                    $check3.Details = $appDevAssignments
                }
                else {
                    $check3.Status = "PASS"
                    $check3.Description = "Count: 0; Application Developer role has no members"
                }
            }
            else {
                $check3.Status = "UNKNOWN"
                $check3.Description = "Application Developer role not found"
            }
        }

        # Check for application owners
        if ($Data.Applications) {
            $appsWithOwners = $Data.Applications | Where-Object { $_.Owners }
            $appsWithoutOwners = $Data.Applications | Where-Object { -not $_.Owners }
            if ($appsWithOwners.Count -gt 0) {
                $check4.Status = "FINDING"
                $check4.Description = "Count: $($appsWithOwners.Count); applications with owners exist. Count: $($appsWithoutOwners.Count); applications without owners."
                $check4.Details = $appsWithOwners
            }
            else {
                $check4.Status = "FINDING"
                $check4.Description = "No applications have assigned owners. Count: $($appsWithoutOwners.Count); applications without owners."
            }
        }
        # Check for service principal owners
        if ($Data.ServicePrincipals) {
            $spsWithOwners = $Data.ServicePrincipals | Where-Object { $_.Owners }
            $spsWithoutOwners = $Data.ServicePrincipals | Where-Object { -not $_.Owners }
            if ($spsWithOwners.Count -gt 0) {
                $check5.Status = "FINDING"
                $check5.Description = "Count: $($spsWithOwners.Count); service principals with owners exist. Count: $($spsWithoutOwners.Count); service principals without owners."
                $check5.Details = $spsWithOwners
            }
            else {
                $check5.Status = "FINDING"
                $check5.Description = "No service principals have assigned owners. Count: $($spsWithoutOwners.Count); service principals without owners."
                }
        }

        # TODO: Return WHO is assigned (cloud) application administrator roles . Write reusable code and replace appdev code above.
        # Get-MgRoleManagementDirectoryRoleAssignment | Where-Object roleDefinitionId -in @('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3','158c047a-c907-4556-b7ef-446551a6b5f7')

        # TODO: Return Custom Role(s) with permissions to create applications
    }
    catch {
        Write-Error "Error during Section 1 checks: $_"
    }

    return @($check1, $check2, $check3, $check4, $check5)
}

# ===========================================================================================
# SECTION 2: Inactive applications don't have highly privileged Microsoft Graph API permissions
# ===========================================================================================

<#
.SYNOPSIS
Identifies applications with highly privileged Microsoft Graph permissions.

.DESCRIPTION
Scans service principals for high-risk application role assignments (Graph permissions).
Use with Find-InactivePrivilegedApps to focus on unused high-privilege apps.

.LINK
https://learn.microsoft.com/en-us/entra/fundamentals/zero-trust-protect-engineering-systems#inactive-applications-dont-have-highly-privileged-microsoft-graph-api-permissions

.PARAMETER Data
Collected artifacts. If omitted, collects on-demand.

.PARAMETER PrivilegedPermissions
Optional list of permission IDs to search for. Defaults to built-in high-risk set.

.OUTPUTS
[PSCustomObject[]] with properties: ServicePrincipalDisplayName, ServicePrincipalId,
Permission, PermissionId, AssignmentType

.EXAMPLE
Find-EntraPrivilegedApps -Data $artifacts | Where-Object Permission -match "Directory"
#>
function Find-EntraPrivilegedApps {
    param(
        [hashtable]$Data,
        [array]$PrivilegedPermissions = @(
            [PSCustomObject]@{Permission = 'Application.ReadWrite.All'; Id = "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9" },
            [PSCustomObject]@{Permission = 'Application.ReadWrite.All'; Id = "1cda74f2-2616-4834-b122-5cb1b07f8a59" },
            [PSCustomObject]@{Permission = 'AppRoleAssignment.ReadWrite.All'; Id = "06b708a9-e830-4db3-a914-8e69da51d44f" },
            [PSCustomObject]@{Permission = 'Calendars.ReadWrite'; Id = "ef54d2bf-783f-4e0f-bca1-3210c0444d99" },
            [PSCustomObject]@{Permission = 'Directory.ReadWrite.All'; Id = "19dbc75e-c2e2-444c-a770-ec69d8559fc7" },
            [PSCustomObject]@{Permission = 'Directory.ReadWrite.All'; Id = "78c8a3c8-a07e-4b9e-af1b-b5ccab50a175" },
            [PSCustomObject]@{Permission = 'Directory.Read.All'; Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61" },
            [PSCustomObject]@{Permission = 'Directory.Read.All'; Id = "5778995a-e1bf-45b8-affa-663a9f3f4d04" },
            [PSCustomObject]@{Permission = 'Exchange.ManageAsApp'; Id = "dc50a0fb-09a3-484d-be87-e023b12c6440" },
            [PSCustomObject]@{Permission = 'Files.ReadWrite.All'; Id = "75359482-378d-4052-8f01-80520e7db3cd" },
            [PSCustomObject]@{Permission = 'GroupMember.ReadWrite.All'; Id = "dbaae8cf-10b5-4b86-a4a1-f871c94c6695" },
            [PSCustomObject]@{Permission = 'Group.ReadWrite.All'; Id = "62a82d76-70ea-41e2-9197-370581804d09" },
            [PSCustomObject]@{Permission = 'Mail.ReadWrite'; Id = "e2a3a72e-5f79-4c64-b1b1-878b674786c9" },
            [PSCustomObject]@{Permission = 'Mail.Send'; Id = "b633e1c5-b582-4048-a93e-9f11b44c7e96" },
            [PSCustomObject]@{Permission = 'RoleManagement.ReadWrite.Directory'; Id = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" },
            [PSCustomObject]@{Permission = 'ServicePrincipalEndPoint.ReadWrite.All'; Id = "89c8469c-83ad-45f7-8ff2-6e3d4285709e" },
            [PSCustomObject]@{Permission = 'Sites.ReadWrite.All'; Id = "9492366f-7969-46a4-8d15-ed1a20078fff" },
            [PSCustomObject]@{Permission = 'User.Export.All'; Id = "405a51b5-8d8d-430b-9842-8be4b0e9f324" },
            [PSCustomObject]@{Permission = 'User.ReadWrite.All'; Id = "741f803b-c850-494e-b5df-cde7c675a1ca" },
            [PSCustomObject]@{Permission = 'User.Read.All'; Id = "df021288-bdef-4463-88db-98f22de89214" }
        )
    )

    if (-not $Data) {
        Write-Verbose "No data provided; collecting artifacts..."
        $Data = Collect-EntraArtifacts
    }

    # Initialize check
    $check = [PSCustomObject]@{
        Control     = "EA-201"
        Setting     = "Applications with highly privileged Microsoft Graph permissions"
        Status  = "ERROR"
        Description = "Unable to evaluate"
        Details = @()
    }

    $privPermIds = $PrivilegedPermissions.Id

    try {
        if ($Data.ServicePrincipals) {
            foreach ($sp in $Data.ServicePrincipals) {
                $roleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction SilentlyContinue
                
                foreach ($roleAssignment in $roleAssignments) {
                    if ($privPermIds -contains $roleAssignment.AppRoleId) {
                        $permName = ($PrivilegedPermissions | Where-Object { $_.Id -eq $roleAssignment.AppRoleId }).Permission
                        $check.Details += [PSCustomObject]@{
                            ServicePrincipalDisplayName = $sp.DisplayName
                            ServicePrincipalId          = $sp.Id
                            ServicePrincipalType        = $sp.ServicePrincipalType
                            Enabled                     = $sp.AccountEnabled
                            Permission                  = $permName
                            PermissionId                = $roleAssignment.AppRoleId
                        }
                    }
                }
            }
        }
        
        if ($check.Details.Count -gt 0) {
            $check.Status = "FINDING"
            $check.Description = "Found $($check.Details.Count) application(s) with highly privileged permissions"
        }
        elseif ($check.Details.Count -eq 0) {
            $check.Status = "PASS"
            $check.Description = "No applications found with highly privileged permissions"
        }
        else {
            $check.Status = "UNKNOWN"
            $check.Description = "Unable to determine privileged applications"
        }
    }
    catch {
        Write-Error "Failed to find privileged apps: $_"
    }

    return @($check)
}

# ===========================================================================================
# SECTION 3: Inactive applications don't have highly privileged built-in roles
# ===========================================================================================

<#
.SYNOPSIS
Identifies service principals and groups assigned privileged Entra roles.

.DESCRIPTION
Expands role membership to show direct and group-based assignments. Includes permanent
and PIM-active assignments.

.LINK
https://learn.microsoft.com/en-us/entra/fundamentals/zero-trust-protect-engineering-systems#inactive-applications-dont-have-highly-privileged-built-in-roles

.PARAMETER Data
Collected artifacts. If omitted, collects on-demand.

.PARAMETER ExpandGroups
If set, expands group members to show individual identities (expensive).

.PARAMETER PrivilegedRoleIds
Optional list of role IDs to search for. Defaults to built-in privileged roles.

.OUTPUTS
[PSCustomObject[]] with properties: RoleName, PrincipalType, PrincipalName, AssignmentType

.EXAMPLE
Find-EntraPrivilegedRoleAssignments -Data $artifacts | Where-Object PrincipalType -eq 'Group'
#>
function Find-EntraPrivilegedRoleAssignments {
    param(
        [hashtable]$Data,
        [switch]$ExpandGroups,
        [array]$PrivilegedRoleIds = @(
            "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
            "cf1c38e5-3621-4004-a7cb-879624dced7c",  # Application Developer
            "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
            "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
            "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator
            "e8611ab8-c189-46e8-94e1-60213ab1f814"   # Privileged Role Administrator
        )
    )

    if (-not $Data) {
        Write-Verbose "No data provided; collecting artifacts..."
        $Data = Collect-EntraArtifacts
    }

    # Initialize check
    $check = [PSCustomObject]@{
        Control     = "EA-301"
        Setting     = "Service principals assigned to privileged roles"
        Status  = "ERROR"
        Description = "Unable to evaluate"
        Details = @()
    }

    try {
        if ($Data.RoleAssignments -and $Data.RoleDefinitions -and $Data.ServicePrincipals) {
            foreach ($assignment in $Data.RoleAssignments) {
                if ($PrivilegedRoleIds -contains $assignment.RoleDefinitionId) {
                    $role = $Data.RoleDefinitions | Where-Object { $_.Id -eq $assignment.RoleDefinitionId }
                    $principal = $Data.ServicePrincipals | Where-Object { $_.Id -eq $assignment.PrincipalId }
                    $group = $Data.Groups | Where-Object { $_.Id -eq $assignment.PrincipalId }

                    if ($principal) {
                        $check.Details += [PSCustomObject]@{
                            RoleName         = $role.DisplayName
                            RoleId           = $role.Id
                            PrincipalName    = $principal.DisplayName
                            PrincipalId      = $principal.Id
                            PrincipalType    = "ServicePrincipal"
                            Enabled          = $principal.AccountEnabled
                            IsManagedIdentity = $principal.ServicePrincipalType -eq "ManagedIdentity"
                            AssignmentType   = "Direct"
                            ScopeId          = $assignment.DirectoryScopeId
                        }
                    }
                    elseif ($group) {
                        $check.Details += [PSCustomObject]@{
                            RoleName       = $role.DisplayName
                            RoleId         = $role.Id
                            PrincipalName  = $group.DisplayName
                            PrincipalId    = $group.Id
                            PrincipalType  = "Group"
                            MemberCount    = if ($ExpandGroups) { ($group.TransitiveMembers | Measure-Object).Count } else { $null }
                            AssignmentType = "GroupMembership"
                            ScopeId        = $assignment.DirectoryScopeId
                        }

                        # Expand group members if requested
                        if ($ExpandGroups -and $group.TransitiveMembers) {
                            foreach ($member in $group.TransitiveMembers) {
                                $memberSP = $Data.ServicePrincipals | Where-Object { $_.Id -eq $member.Id }
                                if ($memberSP) {
                                    $check.Details += [PSCustomObject]@{
                                        RoleName         = $role.DisplayName
                                        RoleId           = $role.Id
                                        PrincipalName    = $memberSP.DisplayName
                                        PrincipalId      = $memberSP.Id
                                        PrincipalType    = "ServicePrincipal (via Group)"
                                        IsManagedIdentity = $memberSP.ServicePrincipalType -eq "ManagedIdentity"
                                        AssignmentType   = "GroupMembership"
                                        ParentGroup      = $group.DisplayName
                                        ScopeId          = $assignment.DirectoryScopeId
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if ($check.Details.Count -gt 0) {
                $check.Status = "FINDING"
                $check.Description = "Found $($check.Details.Count) assignment(s) to privileged roles"
            }
            elseif ($check.Details.Count -eq 0) {
                $check.Status = "PASS"
                $check.Description = "No service principals assigned to privileged roles"
            }
            else {
                $check.Status = "UNKNOWN"
                $check.Description = "Unable to determine privileged role assignments"
            }
        }
    }
    catch {
        Write-Error "Failed to find privileged role assignments: $_"
    }

    return @($check)
}

# ===========================================================================================
# SECTION 4 & 5: REDIRECT URI TESTS
# ===========================================================================================

<#
.SYNOPSIS
Collects redirect URIs from applications and service principals.

.DESCRIPTION
Extracts all redirect URIs (Web, Spa, PublicClient, ReplyUrls) and returns structured data
for further analysis (DNS validation, HTTP checks, reclaimable hosts).

.PARAMETER Data
Collected artifacts. If omitted, collects on-demand.

.OUTPUTS
[PSCustomObject[]] with properties: ObjectType, DisplayName, ObjectId, AppId, RedirectUri

.EXAMPLE
$uris = Test-EntraRedirectUris -Data $artifacts
$uris | Where-Object RedirectUri -match "localhost"
#>
function Test-EntraRedirectUris {
    param(
        [hashtable]$Data
    )

    if (-not $Data) {
        Write-Verbose "No data provided; collecting artifacts..."
        $Data = Collect-EntraArtifacts
    }

    $results = @()

    try {
        Write-Verbose "Processing applications..."
        foreach ($app in $Data.Applications) {
            $allUris = @()
            if ($app.Web.RedirectUris) { $allUris += $app.Web.RedirectUris }
            if ($app.Spa.RedirectUris) { $allUris += $app.Spa.RedirectUris }
            if ($app.PublicClient.RedirectUris) { $allUris += $app.PublicClient.RedirectUris }

            foreach ($uri in $allUris) {
                $results += [PSCustomObject]@{
                    ObjectType  = "Application"
                    DisplayName = $app.DisplayName
                    ObjectId    = $app.Id
                    AppId       = $app.AppId
                    RedirectUri = $uri
                }
            }
        }

        Write-Verbose "Processing service principals..."
        foreach ($sp in $Data.ServicePrincipals) {
            $allUris = @()
            if ($sp.Web.RedirectUris) { $allUris += $sp.Web.RedirectUris }
            if ($sp.ReplyUrls) { $allUris += $sp.ReplyUrls }
            if ($sp.RedirectUris) { $allUris += $sp.RedirectUris }

            foreach ($uri in $allUris) {
                $results += [PSCustomObject]@{
                    ObjectType  = "ServicePrincipal"
                    DisplayName = $sp.DisplayName
                    ObjectId    = $sp.Id
                    AppId       = $sp.AppId
                    RedirectUri = $uri
                }
            }
        }
    }
    catch {
        Write-Error "Failed to collect redirect URIs: $_"
    }

    return $results
}



# ===========================================================================================
# SECTION 7: RESOURCE SPECIFIC CONSENT
# ===========================================================================================

<#
.SYNOPSIS
Tests resource-specific consent (RSC) policy configuration.

.DESCRIPTION
Validates RSC policies for Teams and Chat to ensure elevated permissions are
appropriately restricted.

.PARAMETER Data
Collected artifacts. If omitted, collects on-demand.

.OUTPUTS
[PSCustomObject[]] with properties: Control, Setting, Status, Details

.EXAMPLE
Test-EntraResourceSpecificConsent -Data $artifacts
#>
function Test-EntraResourceSpecificConsent {
    param(
        [hashtable]$Data
    )

    if (-not $Data) {
        Write-Verbose "No data provided; collecting artifacts..."
        $Data = Collect-EntraArtifacts
    }

    $results = @()

    try {
        $authPolicy = $Data.Policies[0]
        $rscPolicy = $authPolicy.ResourceSpecificConsentPolicy

        $results += [PSCustomObject]@{
            Control = "EA-007"
            Setting = "Resource-Specific Consent Policy"
            Status  = if ($rscPolicy -eq "ManagedByMicrosoft") { "PASS" } else { "FINDING" }
            Details = "RSC Policy: $rscPolicy; should be 'ManagedByMicrosoft'"
        }
    }
    catch {
        $results += [PSCustomObject]@{
            Control = "EA-007"
            Setting = "Resource-Specific Consent"
            Status  = "ERROR"
            Details = "Error: $($_.Exception.Message)"
        }
    }

    return $results
}

# ===========================================================================================
# SECTION 8: WORKLOAD IDENTITY ROLES
# ===========================================================================================

<#
.SYNOPSIS
Identifies workload identities (managed identities) assigned to privileged roles.

.DESCRIPTION
Filters service principals with ServicePrincipalType = "ManagedIdentity" that hold
privileged role assignments. Often indicates misconfiguration if not intentional.

.PARAMETER Data
Collected artifacts. If omitted, collects on-demand.

.OUTPUTS
[PSCustomObject[]] with properties: ManagedIdentityName, RoleName, ScopeId

.EXAMPLE
Test-EntraWorkloadIdentityRoles -Data $artifacts
#>
function Test-EntraWorkloadIdentityRoles {
    param(
        [hashtable]$Data
    )

    if (-not $Data) {
        Write-Verbose "No data provided; collecting artifacts..."
        $Data = Collect-EntraArtifacts
    }

    $results = @()

    try {
        # Use privileged role assignments already found
        $privAssignments = Find-EntraPrivilegedRoleAssignments -Data $Data

        $managedIdentities = $privAssignments | Where-Object { $_.IsManagedIdentity -eq $true }

        if ($managedIdentities) {
            $results += $managedIdentities | ForEach-Object {
                [PSCustomObject]@{
                    Control              = "EA-008"
                    ManagedIdentityName  = $_.PrincipalName
                    ManagedIdentityId    = $_.PrincipalId
                    PrivilegedRole       = $_.RoleName
                    Status               = "FINDING"
                    Details              = "Workload identity assigned to privileged role"
                }
            }
        }
        else {
            $results += [PSCustomObject]@{
                Control = "EA-008"
                Setting = "Workload Identity Roles"
                Status  = "PASS"
                Details = "No workload identities found in privileged roles"
            }
        }
    }
    catch {
        $results += [PSCustomObject]@{
            Control = "EA-008"
            Setting = "Workload Identity Check"
            Status  = "ERROR"
            Details = "Error: $($_.Exception.Message)"
        }
    }

    return $results
}

# ===========================================================================================
# SECTION 9: ENTERPRISE APP ASSIGNMENT REQUIREMENTS
# ===========================================================================================

<#
.SYNOPSIS
Tests whether enterprise applications require explicit role assignment.

.DESCRIPTION
Validates AppRoleAssignmentRequired setting. Apps should require explicit assignment
to limit blast radius in case of compromise.

.PARAMETER Data
Collected artifacts. If omitted, collects on-demand.

.OUTPUTS
[PSCustomObject[]] with properties: ServicePrincipalName, AppRoleAssignmentRequired, Status

.EXAMPLE
Test-EntraEnterpriseAppAssignmentRequirements -Data $artifacts
#>
function Test-EntraEnterpriseAppAssignmentRequirements {
    param(
        [hashtable]$Data
    )

    if (-not $Data) {
        Write-Verbose "No data provided; collecting artifacts..."
        $Data = Collect-EntraArtifacts
    }

    $results = @()

    try {
        foreach ($sp in $Data.ServicePrincipals) {
            if (-not $sp.AppRoleAssignmentRequired) {
                $results += [PSCustomObject]@{
                    Control                   = "EA-009"
                    ServicePrincipalName      = $sp.DisplayName
                    ServicePrincipalId        = $sp.Id
                    AppRoleAssignmentRequired = $false
                    Status                    = "FINDING"
                    Details                   = "App does not require explicit role assignment"
                }
            }
        }

        if ($results.Count -eq 0) {
            $results += [PSCustomObject]@{
                Control = "EA-009"
                Setting = "Enterprise App Assignment"
                Status  = "PASS"
                Details = "All enterprise apps require explicit role assignment"
            }
        }
    }
    catch {
        $results += [PSCustomObject]@{
            Control = "EA-009"
            Setting = "Enterprise App Assignment"
            Status  = "ERROR"
            Details = "Error: $($_.Exception.Message)"
        }
    }

    return $results
}

# ===========================================================================================
# ORCHESTRATOR FUNCTION
# ===========================================================================================

<#
.SYNOPSIS
Orchestrates all Entra app Zero Trust security checks.

.DESCRIPTION
Coordinates artifact collection and runs all checks in proper order, with optional
filtering by check name and export capabilities.

.PARAMETER TenantId
Target tenant ID. If omitted, uses current Graph connection.

.PARAMETER Only
Run only specific checks (comma-separated names). Valid names:
  AppPolicy, PrivilegedApps, PrivilegedRoles, RedirectUris, ResourceConsent,
  WorkloadIdentity, EnterpriseAppAssignment

.PARAMETER ExportPath
Export results to CSV/JSON files in this directory.

.PARAMETER IncludeSignIns
Include sign-in logs (time-consuming on large tenants).

.PARAMETER PassThru
Return results object.

.OUTPUTS
[hashtable] with results per check name.

.EXAMPLE
$results = Invoke-EntraAppsZeroTrust -TenantId 'xxxxx' -ExportPath ./reports -PassThru
$results.AppPolicy | Where-Object Status -eq 'FINDING'
#>
function Invoke-EntraAppsZeroTrust {
    param(
        [string]$TenantId,
        [string[]]$Only,
        [string]$ExportPath,
        [switch]$IncludeSignIns,
        [switch]$PassThru
    )

    Write-Host "=== Entra Apps Zero Trust Assessment ===" -ForegroundColor Cyan
    Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host ""

    # Collect artifacts once
    Write-Host "Collecting Entra artifacts..." -ForegroundColor Yellow
    $data = Collect-EntraArtifacts -TenantId $TenantId -IncludeSignIns $IncludeSignIns
    
    if ($data.Error) {
        Write-Error "Failed to collect artifacts: $($data.Error)"
        return
    }

    # Define all available checks
    $allChecks = @(
        @{ Name = "AppPolicy"; Function = "Test-EntraAppRegistrationPolicy" },
        @{ Name = "PrivilegedApps"; Function = "Find-EntraPrivilegedApps" },
        @{ Name = "PrivilegedRoles"; Function = "Find-EntraPrivilegedRoleAssignments" },
        @{ Name = "RedirectUris"; Function = "Test-EntraRedirectUris" },
        @{ Name = "ResourceConsent"; Function = "Test-EntraResourceSpecificConsent" },
        @{ Name = "WorkloadIdentity"; Function = "Test-EntraWorkloadIdentityRoles" },
        @{ Name = "EnterpriseAppAssignment"; Function = "Test-EntraEnterpriseAppAssignmentRequirements" }
    )

    # Filter checks if -Only specified
    $checksToRun = if ($Only) {
        $allChecks | Where-Object { $_.Name -in $Only }
    }
    else {
        $allChecks
    }

    # Run checks
    $results = @{}
    foreach ($check in $checksToRun) {
        Write-Host "Running $($check.Name)..." -ForegroundColor Yellow
        try {
            $results[$check.Name] = & $check.Function -Data $data
            Write-Host "Complete" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed: $_" -ForegroundColor Red
            $results[$check.Name] = @()
        }
    }

    # Export if requested
    if ($ExportPath) {
        New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
        foreach ($name in $results.Keys) {
            $csvPath = Join-Path $ExportPath "$name.csv"
            $jsonPath = Join-Path $ExportPath "$name.json"
            $results[$name] | Export-Csv -Path $csvPath -NoTypeInformation
            $results[$name] | ConvertTo-Json | Out-File -Path $jsonPath
            Write-Host "Exported: $csvPath, $jsonPath" -ForegroundColor Green
        }
    }

    Write-Host ""
    Write-Host "=== Assessment Complete ===" -ForegroundColor Cyan

    if ($PassThru) {
        return $results
    }
}

# ===========================================================================================
# LEGACY INLINE SECTION CODE (To Be Refactored)
# ===========================================================================================

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

# Identify applications with highly privileged permissions - Code adapted from Get-PrivilegedApps.ps1
# List of highly privileged application permissions. Permissions can be added from: https://graphpermissions.merill.net/permission/
# or https://learn.microsoft.com/en-us/graph/migrate-azure-ad-graph-permissions-differences has the Id's for Azure AD Graph as well.
$highlyPrivilegedPermissions = @(
    [PSCustomObject]@{Permission = 'Application.ReadWrite.All'; Id = "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9" },
    [PSCustomObject]@{Permission = 'Application.ReadWrite.All'; Id = "1cda74f2-2616-4834-b122-5cb1b07f8a59" } # Windows Azure Active Directory,
    [PSCustomObject]@{Permission = 'AppRoleAssignment.ReadWrite.All'; Id = "06b708a9-e830-4db3-a914-8e69da51d44f" },
    [PSCustomObject]@{Permission = 'Calendars.ReadWrite'; Id = "ef54d2bf-783f-4e0f-bca1-3210c0444d99" },
    [PSCustomObject]@{Permission = 'Directory.ReadWrite.All'; Id = "19dbc75e-c2e2-444c-a770-ec69d8559fc7" },
    [PSCustomObject]@{Permission = 'Directory.ReadWrite.All'; Id = "78c8a3c8-a07e-4b9e-af1b-b5ccab50a175" } # Windows Azure Active Directory,
    [PSCustomObject]@{Permission = 'Directory.Read.All'; Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61" },
    [PSCustomObject]@{Permission = 'Directory.Read.All'; Id = "5778995a-e1bf-45b8-affa-663a9f3f4d04" } # Windows Azure Active Directory,
    [PSCustomObject]@{Permission = 'Exchange.ManageAsApp'; Id = "dc50a0fb-09a3-484d-be87-e023b12c6440" } # Exchange Online,
    [PSCustomObject]@{Permission = 'Files.ReadWrite.All'; Id = "75359482-378d-4052-8f01-80520e7db3cd" },
    [PSCustomObject]@{Permission = 'GroupMember.ReadWrite.All'; Id = "dbaae8cf-10b5-4b86-a4a1-f871c94c6695" },
    [PSCustomObject]@{Permission = 'Group.ReadWrite.All'; Id = "62a82d76-70ea-41e2-9197-370581804d09" },
    [PSCustomObject]@{Permission = 'Mail.ReadWrite'; Id = "e2a3a72e-5f79-4c64-b1b1-878b674786c9" },
    [PSCustomObject]@{Permission = 'Mail.Send'; Id = "b633e1c5-b582-4048-a93e-9f11b44c7e96" },
    [PSCustomObject]@{Permission = 'RoleManagement.ReadWrite.Directory'; Id = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" },
    [PSCustomObject]@{Permission = 'ServicePrincipalEndPoint.ReadWrite.All'; Id = "89c8469c-83ad-45f7-8ff2-6e3d4285709e" },
    [PSCustomObject]@{Permission = 'Sites.ReadWrite.All'; Id = "9492366f-7969-46a4-8d15-ed1a20078fff" },
    [PSCustomObject]@{Permission = 'User.Export.All'; Id = "405a51b5-8d8d-430b-9842-8be4b0e9f324" },
    [PSCustomObject]@{Permission = 'User.ReadWrite.All'; Id = "741f803b-c850-494e-b5df-cde7c675a1ca" },
    [PSCustomObject]@{Permission = 'User.Read.All'; Id = "df021288-bdef-4463-88db-98f22de89214" }
)
<# Options for searching servicePrincipals:
 1. Retrieves only Enterprise apps but won't include apps w/o Tags (ie: may be missing custom applications)
 2. Retrieves servicePrincipals with a cooresponding application in the tenant (ie: a more complete list of custom applications but may have issues with multi-tenant applications)
 3. Retrieves ALL servicePrincipals including Microsoft built-in apps (ie: this may include false positives and will take much longer to run in large tenants)
    *Note: Option 3 is the most secure method of searching for rogue applications that may utilize advanced evasion techniques
#>
$servicePrincipalArray = Get-MgServicePrincipal -All -Filter "tags/Any(x: x eq 'WindowsAzureActiveDirectoryIntegratedApp')" # Option 1
<# Option 2
$applicationArray = Get-MgApplication -All -Property AppId
$allServicePrincipals = Get-MgServicePrincipal -All
$servicePrincipalArray = $allServicePrincipals | Where-Object{$applicationArray.AppId -contains $_.AppId}
#>
#$servicePrincipalArray = Get-MgServicePrincipal -All # Option 3

foreach ($SP in $servicePrincipalArray) {
    [array]$roleAssignments = Get-MgServicePrincipalAppRoleAssignment -All -ServicePrincipalId $SP.Id
    ForEach ($roleAssignment in $roleAssignments) {
        if ($highlyPrivilegedPermissions.Id -contains $roleAssignment.AppRoleId) {
            Write-Host $SP.DisplayName "is privileged due to this permission:" ($highlyPrivilegedPermissions | Where-Object { $_.Id -eq $roleAssignment.AppRoleId }).Permission
        }
    }
}

# Inactive is the keyword for this section. What is inactive? No sign-ins in 30/60/90/180 days? No activity at all? This needs to be defined.
# TODO: Once inactive is defined, the below can be modified to identify inactive applications with results from highly privileged permissions code above. This is currently disconnected.

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

# Identity applications assigned to privileged built-in roles - Code adapted from Get-AppsInPrivilegedRoles.ps1
# List of highly privileged roles that are searched for membership. Roles can be added from: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
# This list includes all roles tagged as "PRIVILEGED" as of January 2025
$highlyPrivilegedRoles = @(
    [PSCustomObject]@{RoleName = "Application Administrator"; RoleID = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" },
    [PSCustomObject]@{RoleName = "Application Developer"; RoleID = "cf1c38e5-3621-4004-a7cb-879624dced7c" },
    [PSCustomObject]@{RoleName = "Attribute Provisioning Administrator"; RoleID = "ecb2c6bf-0ab6-418e-bd87-7986f8d63bbe" },
    [PSCustomObject]@{RoleName = "Authentication Administrator"; RoleID = "c4e39bd9-1100-46d3-8c65-fb160da0071f" },
    [PSCustomObject]@{RoleName = "Authentication Extensibility Administrator"; RoleID = "25a516ed-2fa0-40ea-a2d0-12923a21473a" },
    [PSCustomObject]@{RoleName = "B2C IEF Keyset Administrator"; RoleID = "aaf43236-0c0d-4d5f-883a-6955382ac081" },
    [PSCustomObject]@{RoleName = "Cloud Application Administrator"; RoleID = "158c047a-c907-4556-b7ef-446551a6b5f7" },
    [PSCustomObject]@{RoleName = "Cloud Device Administrator"; RoleID = "7698a772-787b-4ac8-901f-60d6b08affd2" },
    [PSCustomObject]@{RoleName = "Conditional Access Administrator"; RoleID = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9" },
    [PSCustomObject]@{RoleName = "Directory Writers"; RoleID = "9360feb5-f418-4baa-8175-e2a00bac4301" },
    [PSCustomObject]@{RoleName = "Domain Name Administrator"; RoleID = "8329153b-31d0-4727-b945-745eb3bc5f31" },
    [PSCustomObject]@{RoleName = "External Identity Provider Administrator"; RoleID = "be2f45a1-457d-42af-a067-6ec1fa63bc45" },
    [PSCustomObject]@{RoleName = "Global Administrator"; RoleID = "62e90394-69f5-4237-9190-012177145e10" },
    [PSCustomObject]@{RoleName = "Global Reader"; RoleID = "f2ef992c-3afb-46b9-b7cf-a126ee74c451" },
    [PSCustomObject]@{RoleName = "Helpdesk Administrator"; RoleID = "729827e3-9c14-49f7-bb1b-9608f156bbb8" },
    [PSCustomObject]@{RoleName = "Hybrid Identity Administrator"; RoleID = "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2" },
    [PSCustomObject]@{RoleName = "Intune Administrator"; RoleID = "3a2c62db-5318-420d-8d74-23affee5d9d5" },
    [PSCustomObject]@{RoleName = "Lifecycle Workflows Administrator"; RoleID = "59d46f88-662b-457b-bceb-5c3809e5908f" },
    [PSCustomObject]@{RoleName = "Partner Tier1 Support"; RoleID = "4ba39ca4-527c-499a-b93d-d9b492c50246" },
    [PSCustomObject]@{RoleName = "Partner Tier2 Support"; RoleID = "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8" },
    [PSCustomObject]@{RoleName = "Password Administrator"; RoleID = "966707d0-3269-4727-9be2-8c3a10f19b9d" },
    [PSCustomObject]@{RoleName = "Privileged Authentication Administrator"; RoleID = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" },
    [PSCustomObject]@{RoleName = "Privileged Role Administrator"; RoleID = "e8611ab8-c189-46e8-94e1-60213ab1f814" },
    [PSCustomObject]@{RoleName = "Security Administrator"; RoleID = "194ae4cb-b126-40b2-bd5b-6091b380977d" },
    [PSCustomObject]@{RoleName = "Security Operator"; RoleID = "5f2222b1-57c3-48ba-8ad5-d4759f1fde6f" },
    [PSCustomObject]@{RoleName = "Security Reader"; RoleID = "5d6b6bb7-de71-4623-b4af-96380a352509" },
    [PSCustomObject]@{RoleName = "User Administrator"; RoleID = "fe930be7-5e62-47db-91af-98c3a49a38b1" }
)
#}

# Get all servicePrincipals in the tenant
$servicePrincipalArray = Get-MgServicePrincipal -All

# Get all assigned roles in the tenant. Returns ID for the principal object and role
$roleArray = Get-MgRoleManagementDirectoryRoleAssignment -All

# Get all groups in the tenant. This is needed if role membership is granted via role-assignable group
$groupArray = Get-MgGroup -All -ExpandProperty TransitiveMembers

# Walks through all membership entries in the roleArray, checks to see if the role (RoleDefinitionId) is one of the highly privileged roles.
foreach ($entry in $roleArray) {
    foreach ($role in $highlyPrivilegedRoles) {
        if ($role.RoleId -eq $entry.RoleDefinitionId) {
            # Found membership in a highly privileged role
            if ($servicePrincipalArray.Id -contains $entry.PrincipalId) {
                # Found membership in a highly privileged role that is a servicePrincipal
                $privSP = $servicePrincipalArray | Where-Object { $_.Id -eq $entry.PrincipalId }
                Write-Host "$($privSP.DisplayName) is a member of this privileged role: $($role.RoleName)"
                if ($privSP.ServicePrincipalType -eq "ManagedIdentity") {
                    # Found Managed Identity servicePrincipal
                    Write-Host "$($privSP.DisplayName) is a Managed Identity"
                }
            }
            if ($groupArray.Id -contains $entry.PrincipalId) {
                # Found membership in a highly privileged role that is a group
                $privGroup = $groupArray | Where-Object { $_.Id -eq $entry.PrincipalId }
                $privGroupMembers = $privGroup.TransitiveMembers.Id
                foreach ($privMemberId in $privGroupMembers) {
                    if ($servicePrincipalArray.Id -contains $privMemberId) {
                        # Found group member that is a servicePrincipal
                        $privSP = $servicePrincipalArray | Where-Object { $_.Id -eq $privMemberId }
                        Write-Host "$($privSP.DisplayName) is a member of $($privGroup.DisplayName) which is a member of this privileged role: $($role.RoleName)"
                        if ($privSP.ServicePrincipalType -eq "ManagedIdentity") {
                            # Found Managed Identity servicePrincipal
                            Write-Host "$($privSP.DisplayName) is a Managed Identity"
                        }
                    }
                }
            }
        }
    }
}

# Same as above, need to define inactive & connect the two parts of this Section.

# Sections 4 & 5: App registrations and Service principals use safe redirect URIs

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



# Section 6: App registrations must not have dangling or abandoned domain redirect URIs

# Use the $results object from above

# Code in ChatGPT, broken into sections:
# 1. DNS does not resolve
foreach ($entry in $results) {
    try {
        $response = Resolve-DnsName -Name ($entry.RedirectUri -replace "^(https?://)?([^/]+)(/.*)?$",'$2') -ErrorAction Stop
        # If we get here, DNS resolved successfully
    }
    catch {
        Write-Host "DNS does not resolve for $($entry.RedirectUri) in $($entry.ObjectType) $($entry.DisplayName)"
    }
}
# 2. Reclaimable cloud hosting
$reclaimableHosts = @(
    "azurewebsites.net",
    "cloudapp.net",
    "herokuapp.com",
    "appspot.com",
    "ngrok.io",
    "azurefd.net",
    "azurestaticapps.net",
    "cloudfront.net",
    "elasticbeanstalk.com",
    "netlify.app",
    "vercel.app"
    # Add more as needed
)
foreach ($entry in $results) {
    $uriHost = ($entry.RedirectUri -replace "^(https?://)?([^/]+)(/.*)?$",'$2')
    foreach ($cloudHost in $reclaimableHosts) {
        if ($uriHost -like "*.$cloudHost" -or $uriHost -eq $cloudHost) {
            Write-Host "Reclaimable cloud hosting detected for $($entry.RedirectUri) in $($entry.ObjectType) $($entry.DisplayName)"
        }
    }
}
# 3. not in ChatGPT but, I want to check return codes (200, 301, etc) to see if the URL is active
foreach ($entry in $results) {
    try {
        $response = Invoke-WebRequest -Uri $entry.RedirectUri -Method Head -UseBasicParsing -ErrorAction Stop
        if ($response.StatusCode -ge 400) {
            Write-Host "Inactive redirect URI (status code $($response.StatusCode)) for $($entry.RedirectUri) in $($entry.ObjectType) $($entry.DisplayName)"
        }
    }
    catch {
        Write-Host "Error accessing $($entry.RedirectUri) in $($entry.ObjectType) $($entry.DisplayName): $($_.Exception.Message)"
    }
}

# Section 7: Resource-specific consent to application is restricted
# https://learn.microsoft.com/en-us/microsoftteams/platform/graph-api/rsc/preapproval-instruction-docs
Get-MgPolicyAuthorizationPolicy | Select-Object ResourceSpecificConsentPolicy
# Blanket policy configuration should be set to "ManagedByMicrosoft"
Get-MgBetaTeamsRscConfiguration -All
Get-MGBetaChatRscConfiguration -All
# Pre-approval policies should be checked for elevated permission sets
Get-MgBetaTeamAppPreApproval -All

# Section 8: Workload Identities are not assigned privileged roles

    # Workload identities are represented as service principals with ServicePrincipalType = "ManagedIdentity"
    # Therefore, section 3 code above already identifies workload identities in privileged roles.

# Section 9: Enterprise applications must require explicit assignment or scoped provisioning
# App role assignment required should be True
Get-MgServicePrincipal -All | Where-Object { $_.AppRoleAssignmentRequired -eq $false }

# Scoped provisioning should be used where possible
Get-MgServicePrincipal -All | Get-MgServicePrincipalSynchronizationJob -ServicePrincipalId $_.Id
    # more in chatgpt but needs to be fleshed out


# ----------------------------
# Functions
# ----------------------------

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