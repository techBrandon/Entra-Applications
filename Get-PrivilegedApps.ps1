# Identify privileged applications in a tenant.

# Configure your tenant ID (Optional) and modify report file location. 
$tenantID = '' 
Connect-MgGraph -TenantId $tenantID -Scopes 'Directory.Read.All'

# List of highly privileged application permissions. Permissions can be added from: https://graphpermissions.merill.net/permission/
# or https://learn.microsoft.com/en-us/graph/migrate-azure-ad-graph-permissions-differences has the Id's for Azure AD Graph as well.
$highlyPrivilegedPermissions = @()
$highlyPrivilegedPermissions += [PSCustomObject]@{Permission = 'Application.ReadWrite.All'; Id = "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9"}
$highlyPrivilegedPermissions += [PSCustomObject]@{Permission = 'Application.ReadWrite.All'; Id = "1cda74f2-2616-4834-b122-5cb1b07f8a59"} # Windows Azure Active Directory
$highlyPrivilegedPermissions += [PSCustomObject]@{Permission = 'AppRoleAssignment.ReadWrite.All'; Id = "06b708a9-e830-4db3-a914-8e69da51d44f"}
$highlyPrivilegedPermissions += [PSCustomObject]@{Permission = 'Calendars.ReadWrite'; Id = "ef54d2bf-783f-4e0f-bca1-3210c0444d99"}	
$highlyPrivilegedPermissions += [PSCustomObject]@{Permission = 'Directory.ReadWrite.All'; Id = "19dbc75e-c2e2-444c-a770-ec69d8559fc7"}
$highlyPrivilegedPermissions += [PSCustomObject]@{Permission = 'Directory.ReadWrite.All'; Id = "78c8a3c8-a07e-4b9e-af1b-b5ccab50a175"} # Windows Azure Active Directory
$highlyPrivilegedPermissions += [PSCustomObject]@{Permission = 'Directory.Read.All'; Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"}
$highlyPrivilegedPermissions += [PSCustomObject]@{Permission = 'Directory.Read.All'; Id = "5778995a-e1bf-45b8-affa-663a9f3f4d04"} # Windows Azure Active Directory
$highlyPrivilegedPermissions += [PSCustomObject]@{Permission = 'Exchange.ManageAsApp'; Id = "dc50a0fb-09a3-484d-be87-e023b12c6440"} # Exchange Online
$highlyPrivilegedPermissions += [PSCustomObject]@{Permission = 'Files.ReadWrite.All'; Id = "75359482-378d-4052-8f01-80520e7db3cd"}	
$highlyPrivilegedPermissions += [PSCustomObject]@{Permission = 'GroupMember.ReadWrite.All'; Id = "dbaae8cf-10b5-4b86-a4a1-f871c94c6695"}
$highlyPrivilegedPermissions += [PSCustomObject]@{Permission = 'Group.ReadWrite.All'; Id = "62a82d76-70ea-41e2-9197-370581804d09"}	
$highlyPrivilegedPermissions += [PSCustomObject]@{Permission = 'Mail.ReadWrite'; Id = "e2a3a72e-5f79-4c64-b1b1-878b674786c9"}	
$highlyPrivilegedPermissions += [PSCustomObject]@{Permission = 'Mail.Send'; Id = "b633e1c5-b582-4048-a93e-9f11b44c7e96"}	
$highlyPrivilegedPermissions += [PSCustomObject]@{Permission = 'RoleManagement.ReadWrite.Directory'; Id = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"}
$highlyPrivilegedPermissions += [PSCustomObject]@{Permission = 'ServicePrincipalEndPoint.ReadWrite.All'; Id = "89c8469c-83ad-45f7-8ff2-6e3d4285709e"}	
$highlyPrivilegedPermissions += [PSCustomObject]@{Permission = 'Sites.ReadWrite.All'; Id = "9492366f-7969-46a4-8d15-ed1a20078fff"}	
$highlyPrivilegedPermissions += [PSCustomObject]@{Permission = 'User.Export.All'; Id = "405a51b5-8d8d-430b-9842-8be4b0e9f324"}	
$highlyPrivilegedPermissions += [PSCustomObject]@{Permission = 'User.ReadWrite.All'; Id = "741f803b-c850-494e-b5df-cde7c675a1ca"}	
$highlyPrivilegedPermissions += [PSCustomObject]@{Permission = 'User.Read.All'; Id = "df021288-bdef-4463-88db-98f22de89214"}

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
            Write-Host $SP.DisplayName "is privileged due to this permission:" ($highlyPrivilegedPermissions | Where-Object {$_.Id -eq $roleAssignment.AppRoleId}).Permission
        }
    }
}