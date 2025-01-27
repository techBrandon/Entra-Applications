#Requires Microsoft.Graph Module

Install-Module Microsoft.Graph
****
**Get-PrivilegedApps.ps1**

Reports on all Applications granted elevated permissions in the tenant. 
Compares a custom list of highly privileged permissions with all configured Application permissions in the environment.
Outputs a list of Applications and their privileged permissions.

****
**Get-AppsInPrivilegedRoles.ps1**

Reports on Applications with membership in highly privileged roles.
Compares a custom list of highly privileged roles with all role membership including an Application.
Outputs a list of Applications that are a member of a privileged role.
Identifies if the Application is considered a Managed Identity which would indicate a lower risk.

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
