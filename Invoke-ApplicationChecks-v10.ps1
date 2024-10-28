<#
.SYNOPSIS
Reports on Entra Applications and Service Principals with Owners, Certificates & Secrets 
.DESCRIPTION
This script generates a simple csv file including all applications or service principals that are configured with an owner or configured with a certificate or secret.
Application owners have the ability to elevate privilegs to that of the application or service principal via certificates & secrets.
These configurations may or may not present concern.
"Credentials" referenced in this script are NOT sensitive objects and do not contain actual application credentials.
.NOTES
Version: 1.0
Updated: 20241028
Author: Brandon Colley
Email: ColleyBrandon@pm.me

## Definitions ##
"Applications" and "Application Registrations" are synonymous and may be abbreviated as "app" or "app reg".
"Service Principals" and "Enterprise Applications" are synonymous and may be abbreviated as "SP"

## Future Development ##
Some commented code exists as a placeholder for future development efforts that attempt to automate the review of these possibly dangerous applications.
#>

# Configure your tenant ID (Optional) and modify report file location. 
$tenantID = '' #Tenant ID GUID
$reportFile = "C:\Temp\test.csv" #Expects CSV file format
Connect-MgGraph -TenantId $tenantID -Scopes 'Directory.Read.All'

# Variables for Applications, Service Principals, Users, Groups, and Roles.
$allApps = Get-MgApplication -All -ExpandProperty Owners
$allSPs = Get-MgServicePrincipal -All -ExpandProperty Owners
$userArray = Get-MgUser -All
#$groupArray = Get-MgGroup -All
#$roleArray = Get-

# Date Variables used to evaluate certificates and secrets
$today = Get-Date
$nextMonth = (Get-Date).AddMonths(1)
$lastYear = (Get-Date).AddYears(-1)
$nextYear = (Get-Date).AddYears(1)

###############
## Functions ##
###############

# Function accepts a list of GUIDs and object type of "User", "Group", or "Role"
# Returns a list of objects with matching GUIDs
function Convert-GUID 
{
    Param 
    (
        $ListOfGUIDs,
        [string]$ObjectType # User, Group, etc
    )
    switch ($ObjectType) {
        User {$searchArray = $userArray}
        Group {$searchArray = $groupArray}
        Role {$searchArray = $roleArray}
    }

    ForEach ($GUID in $ListOfGUIDs){
        $searchArray | Where-Object {$_.Id -eq $GUID}
    }
}

# Function Creates an array that combines all applications and service principals
# The array holds a list of "SingleAppInfo" objects that matches apps that share the same AppId
# The object consists of attributes for everything we might care about.
# Calls the Convert-GUID function to translate the ownership GUIDs into User Objects
# Calls the Format-CredentialObject function to translate the key and password credentials into strings
function New-CombinedApplicationList
{
    # Use case 1 - Collect all application information (Apps with no cooresponding SP)
    # Use case 2 - Collect all application information and combine with cooresponding SP
    $updatedObjects = foreach ($app in $allApps) {
        $matchingSP = $allSPs | Where-Object {$_.AppId -eq $app.AppId}
        $singleAppInfo = [PSCustomObject] @{
            DisplayName = $app.DisplayName
            AppID = $app.AppId #AppId attribute is shared between app & SP
            CreatedDateTime = $app.CreatedDateTime
            Risk = 0
            #AppPermissions = 
            AppOwnersId = $app.Owners.Id
            AppOwnersUsers = $null
            AppOwnersUsersFlatUPN = $null
            AppPasswordCreds = $app.PasswordCredentials
            AppPasswordCredsFlat = Format-CredentialObject $app.PasswordCredentials
            AppKeyCreds = $app.KeyCredentials
            AppKeyCredsFlat = Format-CredentialObject $app.KeyCredentials
            SPOwnersId = $matchingSP.Owners.Id
            SPOwnersUsers = $null
            SPOwnersUsersFlatUPN = $null
            SPPasswordCreds = $matchingSP.PasswordCredentials
            SPPasswordCredsFlat = Format-CredentialObject $matchingSP.PasswordCredentials
            SPKeyCreds = $matchingSP.KeyCredentials
            SPKeyCredsFlat = Format-CredentialObject $matchingSP.KeyCredentials
            #SPinRoles = 
        }
        if ($singleAppInfo.AppOwnersId -or $singleAppInfo.SPOwnersId) {
            $singleAppInfo.Risk = 10
            #Write-Host "Application Registration Owners: " $app.Owners.Id
            $singleAppInfo.AppOwnersUsers = Convert-GUID -ListOfGUIDs $singleAppInfo.AppOwnersId -ObjectType User
            $singleAppInfo.AppOwnersUsersFlatUPN = $singleAppInfo.AppOwnersUsers.UserPrincipalName -join ","
            #Write-Host "Enterprise Application Owners: " $matchingSP.Owners.Id
            $singleAppInfo.SpOwnersUsers = Convert-GUID -ListOfGUIDs $singleAppInfo.SPOwnersId -ObjectType User
            $singleAppInfo.SPOwnersUsersFlatUPN = $singleAppInfo.SPOwnersUsers.UserPrincipalName -join ","
        }
        $singleAppInfo
    }
    # Use case 3 - Collect all SP information (SPs with no cooresponding Application)
    $updatedObjects += foreach ($sp in $allSPs) {
        $matchingApp = $allApps | Where-Object {$_.AppId -eq $sp.AppId}
        if($null -eq $matchingApp) {
            $singleAppInfo = [PSCustomObject] @{
                DisplayName = $sp.DisplayName
                AppID = $sp.AppId #AppId attribute is shared between app & SP
                CreatedDateTime = $sp.AdditionalProperties.createdDateTime
                Risk = 0
                #AppPermissions = 
                AppOwnersId = $null
                AppOwnersUsers = $null
                AppOwnersUsersFlatUPN = $null
                AppPasswordCreds = $null
                AppPasswordCredsFlat = $null
                AppKeyCreds = $null
                AppKeyCredsFlat = $null
                SPOwnersId = $sp.Owners.Id
                SPOwnersUsers = $null
                SPOwnersUsersFlatUPN = $null
                SPPasswordCreds = $sp.PasswordCredentials
                SPPasswordCredsFlat = Format-CredentialObject $sp.PasswordCredentials
                SPKeyCreds = $sp.KeyCredentials
                SPKeyCredsFlat = Format-CredentialObject $sp.KeyCredentials
                #SPinRoles = 
            }
            if ($singleAppInfo.SPOwnersId) {
                $singleAppInfo.Risk = 10
                #Write-Host "Enterprise Application Owners: " $matchingSP.Owners.Id
                $singleAppInfo.SpOwnersUsers = Convert-GUID -ListOfGUIDs $singleAppInfo.SPOwnersId -ObjectType User
                $singleAppInfo.SPOwnersUsersFlatUPN = $singleAppInfo.SPOwnersUsers.UserPrincipalName -join ","
            }
            $singleAppInfo
        }   
    }
    # Return the array of custom objects
    $updatedObjects
}

# Function in Progress. Attempting to define risk of credentials.
function Set-CredentialRisk {
    param(
        $credObject,
        $objectType
    )
    #$returnedRisk = 0
    foreach ($cred in $credObject) {
        # Looking for old keys or keys that do not expire for over 1 year
        if (($cred.StartDateTime -lt $lastYear) -or ($cred.EndDateTime -gt $nextYear)) {
            $returnedRisk = $returnedRisk + 1
        }
    }
    $returnedRisk
}

# Function accepts credential object with 1 or more entries and flattens them for read-ability
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

########
# MAIN #
########

# Create array of custom application objects consisting of all application and SP objects in the tenant
$arrayOfCustomApps = New-CombinedApplicationList

# Output Application report
Write-Host -fore Cyan "Generating Full Application Report:" $reportFile

# Interesting applications are those with at least 1: owner, password credential, or certificate credential
$interestingApps = $arrayOfCustomApps | Where-Object {$_.AppOwnersId -or $_.SPOwnersId -or $_.AppPasswordCreds -or $_.SPPasswordCreds -or $_.AppKeyCreds -or $_.SPKeyCreds} 

# Loop to update credential risk for each application.
foreach ($appObject in $interestingApps) {
    $appObject.Risk += Set-CredentialRisk $appObject.AppPasswordCreds
    $appObject.Risk += Set-CredentialRisk $appObject.AppKeyCreds
    $appObject.Risk += Set-CredentialRisk $appObject.SPPasswordCreds
    $appObject.Risk += Set-CredentialRisk $appObject.SPKeyCreds
}

# Exports to CSV "Flat" attributes contain strings for their cooresponding attributes.
$interestingApps | Select-Object DisplayName, AppID, CreatedDateTime, Risk, AppOwnersUsersFlatUPN, SPOwnersUsersFlatUPN, AppPasswordCredsFlat, AppKeyCredsFlat, SPPasswordCredsFlat, SPKeyCredsFlat| Export-Csv -Path $reportFile