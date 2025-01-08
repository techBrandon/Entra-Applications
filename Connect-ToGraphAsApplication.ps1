# Connect to Graph as Application
# Sample application created in New-MaliciousApp.ps1

# Tenant ID is required when connecting in this way.
$tenantID = ''

# Application ID for Application being used for authentication.
# This is not the same as the "id". The app registration and servicePrincipal objects share the same appID.
# Example appID GUID: "1fc417b8-09ef-4c9c-97a0-71a4f6055bc2"
$appID = ''

# Password or "Secret Text" Generated when creating an application client secret.
# Example 40 character random password: "dwc8Q~sDrFwLecsMdkS6FxAMi.aI.iUmwUvQ5eoS"
$clearTextPassword = 'xyz'
$securePassword = ConvertTo-SecureString -String $clearTextPassword -AsPlainText -Force

$loginCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $appID, $securePassword

Connect-MgGraph -TenantId $tenantID -ClientSecretCredential $loginCredential