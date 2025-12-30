
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