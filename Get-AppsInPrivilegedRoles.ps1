# Identify applications in a privileged role

# Configure your tenant ID (Optional) and modify report file location. 
$tenantID = '' 
Connect-MgGraph -TenantId $tenantID -Scopes 'Directory.Read.All'

# If Beta cmdlets are available, the $highlyPrivilegedRoles variable can be automated. Otherwise, it can be manually populated.
#if (Get-Module Microsoft.Graph.Beta.Identity.Governance -ListAvailable) {
    # This needs a bit of work building the array in the same way
    #[array]$highlyPrivilegedRoles = Get-MgBetaRoleManagementDirectoryRoleDefinition -Filter "isPrivileged eq true"
#}
#else {
    # List of highly privileged roles that are searched for membership. Roles can be added from: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference 
    # This list includes all roles tagged as "PRIVILEGED" as of January 2025
    $highlyPrivilegedRoles = @()
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Application Administrator"; RoleID = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Application Developer"; RoleID = "cf1c38e5-3621-4004-a7cb-879624dced7c"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Attribute Provisioning Administrator"; RoleID = "ecb2c6bf-0ab6-418e-bd87-7986f8d63bbe"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Authentication Administrator"; RoleID = "c4e39bd9-1100-46d3-8c65-fb160da0071f"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Authentication Extensibility Administrator"; RoleID = "25a516ed-2fa0-40ea-a2d0-12923a21473a"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "B2C IEF Keyset Administrator"; RoleID = "aaf43236-0c0d-4d5f-883a-6955382ac081"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Cloud Application Administrator"; RoleID = "158c047a-c907-4556-b7ef-446551a6b5f7"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Cloud Device Administrator"; RoleID = "7698a772-787b-4ac8-901f-60d6b08affd2"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Conditional Access Administrator"; RoleID = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Directory Writers"; RoleID = "9360feb5-f418-4baa-8175-e2a00bac4301"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Domain Name Administrator"; RoleID = "8329153b-31d0-4727-b945-745eb3bc5f31"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "External Identity Provider Administrator"; RoleID = "be2f45a1-457d-42af-a067-6ec1fa63bc45"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Global Administrator"; RoleID = "62e90394-69f5-4237-9190-012177145e10"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Global Reader"; RoleID = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Helpdesk Administrator"; RoleID = "729827e3-9c14-49f7-bb1b-9608f156bbb8"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Hybrid Identity Administrator"; RoleID = "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Intune Administrator"; RoleID = "3a2c62db-5318-420d-8d74-23affee5d9d5"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Lifecycle Workflows Administrator"; RoleID = "59d46f88-662b-457b-bceb-5c3809e5908f"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Partner Tier1 Support"; RoleID = "4ba39ca4-527c-499a-b93d-d9b492c50246"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Partner Tier2 Support"; RoleID = "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Password Administrator"; RoleID = "966707d0-3269-4727-9be2-8c3a10f19b9d"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Privileged Authentication Administrator"; RoleID = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Privileged Role Administrator"; RoleID = "e8611ab8-c189-46e8-94e1-60213ab1f814"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Security Administrator"; RoleID = "194ae4cb-b126-40b2-bd5b-6091b380977d"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Security Operator"; RoleID = "5f2222b1-57c3-48ba-8ad5-d4759f1fde6f"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "Security Reader"; RoleID = "5d6b6bb7-de71-4623-b4af-96380a352509"}
    $highlyPrivilegedRoles += [PSCustomObject]@{RoleName = "User Administrator"; RoleID = "fe930be7-5e62-47db-91af-98c3a49a38b1"}
#}

# Get all servicePrincipals in the tenant
$servicePrincipalArray = Get-MgServicePrincipal -All

# Get all assigned roles in the tenant. Returns ID for the principal object and role
$roleArray = Get-MgRoleManagementDirectoryRoleAssignment -All

# Get all groups in the tenant. This is needed if role membership is granted via role-assignable group
$groupArray = Get-MgGroup -All -ExpandProperty TransitiveMembers

# Walks through all membership entries in the roleArray, checks to see if the role (RoleDefinitionId) is one of the highly privileged roles.
ForEach ($entry in $roleArray) {
    ForEach ($role in $highlyPrivilegedRoles) {
        if ($role.RoleId -eq $entry.RoleDefinitionId) { # Found membership in a highly privileged role
            if ($servicePrincipalArray.Id -contains $entry.PrincipalId) { # Found membership in a highly privileged role that is a servicePrincipal
                $privSP = $servicePrincipalArray | Where-Object {$_.Id -eq $entry.PrincipalId}
                Write-Host "$($privSP.DisplayName) is a member of this privileged role: $($role.RoleName)"
                if ($privSP.ServicePrincipalType -eq "ManagedIdentity") { # Found Managed Identity servicePrincipal 
                    Write-Host "$($privSP.DisplayName) is a Managed Identity"
                }
            }
            if ($groupArray.Id -contains $entry.PrincipalId) { # Found membership in a highly privileged role that is a group
                $privGroup = $groupArray | Where-Object {$_.Id -eq $entry.PrincipalId}
                $privGroupMembers = $privGroup.TransitiveMembers.Id
                ForEach ($privMemberId in $privGroupMembers) {
                    if ($servicePrincipalArray.Id -contains $privMemberId) { # Found group member that is a servicePrincipal 
                        $privSP = $servicePrincipalArray | Where-Object {$_.Id -eq $privMemberId}
                        Write-Host "$($privSP.DisplayName) is a member of $($privGroup.DisplayName) which is a member of this privileged role: $($role.RoleName)"
                        if ($privSP.ServicePrincipalType -eq "ManagedIdentity") { # Found Managed Identity servicePrincipal 
                            Write-Host "$($privSP.DisplayName) is a Managed Identity"
                        }
                    }
                }
            }
        }
    }   
}