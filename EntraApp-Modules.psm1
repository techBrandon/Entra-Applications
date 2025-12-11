<#
Module Approach for Entra Applications and Service Principals Checks
Author: Brandon Colley
Email: colleybrandon@pm.me
version: 1.0
Updated: 20241028
.DESCRIPTION
This module contains functions to retrieve and analyze Entra Applications and Service Principals with Owners, Certificates & Secrets.
add more later.
#>

function New-FullApplicationList {
    $AllApps = Get-MgApplication -All -ExpandProperty Owners
    $AllSPs = Get-MgServicePrincipal -All -ExpandProperty Owners

    # Use case 1 - Collect all application information (Apps with no cooresponding SP)
    # Use case 2 - Collect all application information and combine with cooresponding SP
    $CombinedApps = foreach ($App in $AllApps) {
        # Find matching SP, if one exists
        $MatchingSP = $AllSPs | Where-Object {$_.AppId -eq $App.AppId}
        # Build instance of combined application object
        $SingleAppInfo = [PSCustomObject] @{
            DisplayName = $App.DisplayName
            AppID = $App.AppId #AppId attribute is shared between app & SP
            CreatedDateTime = $App.CreatedDateTime
            Risk = 0 #TODO
            AppPermissions = $null #TODO
            AppOwnersId = $App.Owners.Id
            AppOwnersUsers = $null
            AppOwnersUsersFlatUPN = $null
            AppPasswordCreds = $App.PasswordCredentials
            AppPasswordCredsFlat = Format-CredentialObject $App.PasswordCredentials #TODO
            AppKeyCreds = $App.KeyCredentials
            AppKeyCredsFlat = Format-CredentialObject $App.KeyCredentials #TODO
            SPOwnersId = $MatchingSP.Owners.Id
            SPOwnersUsers = $null
            SPOwnersUsersFlatUPN = $null
            SPPasswordCreds = $MatchingSP.PasswordCredentials
            SPPasswordCredsFlat = Format-CredentialObject $MatchingSP.PasswordCredentials #TODO
            SPKeyCreds = $MatchingSP.KeyCredentials
            SPKeyCredsFlat = Format-CredentialObject $MatchingSP.KeyCredentials #TODO
            SPinRoles = $null #TODO
        }
        $singleAppInfo
    }
    # Use case 3 - Collect all SP information (SPs with no cooresponding Application)
    $CombinedApps += foreach ($SP in $AllSPs) {
        $MatchingApp = $AllApps | Where-Object {$_.AppId -eq $SP.AppId}
        if($null -eq $MatchingApp) {
            $singleAppInfo = [PSCustomObject] @{
                DisplayName = $SP.DisplayName
                AppID = $SP.AppId #AppId attribute is shared between app & SP
                CreatedDateTime = $sp.AdditionalProperties.createdDateTime
                Risk = 0
                AppPermissions = $null #TODO
                AppOwnersId = $null
                AppOwnersUsers = $null
                AppOwnersUsersFlatUPN = $null
                AppPasswordCreds = $null
                AppPasswordCredsFlat = $null
                AppKeyCreds = $null
                AppKeyCredsFlat = $null
                SPOwnersId = $SP.Owners.Id
                SPOwnersUsers = $null
                SPOwnersUsersFlatUPN = $null
                SPPasswordCreds = $SP.PasswordCredentials
                SPPasswordCredsFlat = Format-CredentialObject $sp.PasswordCredentials #TODO
                SPKeyCreds = $SP.KeyCredentials
                SPKeyCredsFlat = Format-CredentialObject $sp.KeyCredentials #TODO
                SPinRoles = $null #TODO
            }
            $singleAppInfo
        }   
    }
    return $CombinedApps
}

function Find-ApplicationOwners {
    Param (
        [PSCustomObject]$SingleAppInfo
    )
        if ($SingleAppInfo.AppOwnersId) {
            $singleAppInfo.AppOwnersUsers = Convert-GUID -ListOfGUIDs $singleAppInfo.AppOwnersId -ObjectType User
            $singleAppInfo.AppOwnersUsersFlatUPN = $singleAppInfo.AppOwnersUsers.UserPrincipalName -join ","
        }
        if ($singleAppInfo.SPOwnersId) {
            $singleAppInfo.SpOwnersUsers = Convert-GUID -ListOfGUIDs $singleAppInfo.SPOwnersId -ObjectType User
            $singleAppInfo.SPOwnersUsersFlatUPN = $singleAppInfo.SPOwnersUsers.UserPrincipalName -join ","
        }
}

function Measure-ApplicationRisk {
    Param (
        [PSCustomObject]$SingleAppInfo
    )
    #TODO - Implement risk measurement logic
    $singleAppInfo.Risk = 10
}

# Function accepts a list of GUIDs and object type of "User", "Group", or "Role"
# Returns a list of objects with matching GUIDs
function Convert-GUID 
{
    Param 
    (
        $ListOfGUIDs,
        [string]$ObjectType # User, Group, etc
    )
    $userArray = Get-MgUser -All
    $groupArray = Get-MgGroup -All
    $roleArray = Get-MgDirectoryRole -All
    switch ($ObjectType) {
        User {$searchArray = $userArray}
        Group {$searchArray = $groupArray}
        Role {$searchArray = $roleArray}
    }

    ForEach ($GUID in $ListOfGUIDs){
        $searchArray | Where-Object {$_.Id -eq $GUID}
    }
}