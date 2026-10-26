#Requires Microsoft.Graph Module

Install-Module Microsoft.Graph
****
**Get-PrivilegedApps.ps1**

Reports apps (service principals) that hold privileged application permissions.
Edit the `$PrivilegedPermissions` list at the top of the script to match your tenant; permissions are listed by name under the API they belong to.
Returns one row per app and permission: DisplayName, AppId, AccountEnabled, AppOwnerTenant, Resource, Permission.

```powershell
./Get-PrivilegedApps.ps1 -TenantId <tenant-guid> | Export-Csv PrivilegedApps.csv
```

****
**Get-AppsInPrivilegedRoles.ps1**

Reports apps (service principals) that hold a privileged Entra directory role, directly or through a role-assignable group.
Edit the `$PrivilegedRoles` list at the top of the script to match your tenant; roles are listed by display name.
Returns one row per app and role: DisplayName, AppId, AccountEnabled, AppOwnerTenant, Role, Scope, AssignedViaGroup.

```powershell
./Get-AppsInPrivilegedRoles.ps1 -TenantId <tenant-guid> | Export-Csv AppsInPrivilegedRoles.csv
```

AppOwnerTenant is `Home Tenant`, `Microsoft` (IDs in `$MicrosoftTenantIds`), `Third Party` or `Unknown`.
Both scripts only read data. Sign in with an account that can read directory roles and applications (for example Global Reader).

****
**Get-ClientSecrets.ps1**

Reports on Applications and their client secrets.
Outputs a CSV of Applications and details for client secrets.

****
**Invoke-ApplicationChecks.ps1**

Checks for application owners and possibly dangerous Certificates & Secrets configured for all tenant applications.

Application owners can leverage their permissions to impersonate the tenant application, obtaining all rights delegated to the application. 
This is true of both app registrations (Applications) and Enterprise Applications (Service Principals).
Both of these objects can also posess credentials that are used to authenticate on behalf of the application. This is standard practice for applications but is also leveraged in attacks.
Identification of these settings isn't simple which is why I created this short PowerShell script.

The script will output a CSV that contains a list of all possibly dangerous configurations. The output looks like this:
![image](https://github.com/user-attachments/assets/c9a2bef3-ae6c-40e8-953f-53d57f41b404)

Risk is attempted to be generated based on the number of dangerous credential values (+1) for each entry over 1 year old or expiring over 1 year from now.
and the existence of an owner (+10)
Owner UPNs are displayed in the cooresponding column.
Password and Key values in the cooresponding column.

****
**New-MaliciousApp.ps1**

Creates new tenant Application & generates a client secret lasting for 100 years. By default, no permssions are granted to this application. To be used only for POC and testing purposes.

****
**Connect-ToGraphAsApplication.ps1**

Template for connecting to Graph PowerShell as an Application. Variables for tenantID, appID, and clearTestPassword must be populated. 
