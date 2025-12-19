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