# Identify applications utilizing client secrets in a tenant.

# Configure your tenant ID (Optional) and modify report file location.
$tenantID = ''
Connect-MgGraph -TenantId $tenantID -Scopes 'Directory.Read.All'

$reportFile = "C:\Temp\test.csv" #Expects CSV file format

# This script only checks Applications and their cooresponding Service Principal.
# For a more complete list of all Applications (including those without an "App Registration") run Invoke-ApplicationChecks-v10.ps1
$applicationArray = Get-MgApplication -All
$servicePrincipalArray = Get-MgServicePrincipal -All 
function Format-CredentialObject {
    param (
        $credObject
    )
    $returnString = ""
    foreach ($cred in $credObject) {
        $returnString = $returnString + " Credential ID: " + $cred.KeyId + " Created: " + $cred.StartDateTime + " Expires: " + $cred.EndDateTime
    }
    $returnString
}

$updatedObjects = foreach ($app in $applicationArray) {
    $singleAppInfo = [PSCustomObject] @{
        DisplayName = $app.DisplayName
        AppID = $app.AppId 
        AppPasswordCreds = Format-CredentialObject $app.PasswordCredentials
        SPPasswordCreds = Format-CredentialObject ($servicePrincipalArray | Where-Object {$_.AppId -eq $app.AppId}).PasswordCredentials
    }
    $singleAppInfo
}
$updatedObjects | Export-Csv $reportFile