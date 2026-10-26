#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are read inside Pester mock blocks')]
param()

BeforeAll {
    $ScriptPath = Join-Path $PSScriptRoot 'Get-AppsInPrivilegedRoles.ps1'

    # Every name in the script's editable list becomes a role definition, so edits to the list keep tests valid
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$null, [ref]$null)
    $assignment = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left.Extent.Text -eq '$PrivilegedRoles' }, $true)
    $names = $assignment.Right.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true).Value
    $RoleIds = @{}
    foreach ($name in $names + 'Reports Reader') { $RoleIds[$name] = (New-Guid).Guid }

    $App = [PSCustomObject]@{
        DisplayName = 'Contoso App'; AppId = 'app-1'; AccountEnabled = $false; AppOwnerOrganizationId = 'tenant-1'
    }

    function Get-FakeAssignment {
        param([string]$Role, [string]$ODataType = '#microsoft.graph.servicePrincipal', [string]$Scope = '/')
        [PSCustomObject]@{
            PrincipalId       = 'principal-1'
            RoleDefinitionId  = $RoleIds[$Role]
            DirectoryScopeId  = $Scope
            Principal         = [PSCustomObject]@{
                AdditionalProperties = @{ '@odata.type' = $ODataType; 'displayName' = 'Admins Group' }
            }
        }
    }
}

Describe 'Get-AppsInPrivilegedRoles' {
    BeforeEach {
        Mock Connect-MgGraph {}
        Mock Get-MgRoleManagementDirectoryRoleDefinition {
            $RoleIds.GetEnumerator() | ForEach-Object { [PSCustomObject]@{ Id = $_.Value; DisplayName = $_.Key } }
        }
        Mock Get-MgServicePrincipal { $App }
    }

    It 'returns a row for a service principal in a privileged role' {
        Mock Get-MgRoleManagementDirectoryRoleAssignment { Get-FakeAssignment -Role 'Global Administrator' -Scope '/administrativeUnits/au-1' }
        $rows = & $ScriptPath
        $rows | Should -HaveCount 1
        $rows[0].DisplayName | Should -Be 'Contoso App'
        $rows[0].AppId | Should -Be 'app-1'
        $rows[0].AccountEnabled | Should -BeFalse
        $rows[0].AppOwnerTenant | Should -Be 'tenant-1'
        $rows[0].Role | Should -Be 'Global Administrator'
        $rows[0].Scope | Should -Be '/administrativeUnits/au-1'
        $rows[0].AssignedViaGroup | Should -BeNullOrEmpty
    }

    It 'returns a row for each service principal in a group assigned a privileged role' {
        Mock Get-MgRoleManagementDirectoryRoleAssignment { Get-FakeAssignment -Role 'Global Administrator' -ODataType '#microsoft.graph.group' }
        Mock Get-MgGroupMemberAsServicePrincipal { $App, $App }
        $rows = & $ScriptPath
        $rows | Should -HaveCount 2
        $rows[0].DisplayName | Should -Be 'Contoso App'
        $rows[0].Role | Should -Be 'Global Administrator'
        $rows[0].AssignedViaGroup | Should -Be 'Admins Group'
        Should -Invoke Get-MgGroupMemberAsServicePrincipal -Times 1 -ParameterFilter { $GroupId -eq 'principal-1' }
    }

    It 'returns nothing for a privileged group with no service principal members' {
        Mock Get-MgRoleManagementDirectoryRoleAssignment { Get-FakeAssignment -Role 'Global Administrator' -ODataType '#microsoft.graph.group' }
        Mock Get-MgGroupMemberAsServicePrincipal { @() }
        & $ScriptPath | Should -BeNullOrEmpty
    }

    It 'does not expand groups holding roles that are not on the privileged list' {
        Mock Get-MgRoleManagementDirectoryRoleAssignment { Get-FakeAssignment -Role 'Reports Reader' -ODataType '#microsoft.graph.group' }
        Mock Get-MgGroupMemberAsServicePrincipal { $App }
        & $ScriptPath | Should -BeNullOrEmpty
        Should -Invoke Get-MgGroupMemberAsServicePrincipal -Times 0
    }

    It 'excludes roles that are not on the privileged list' {
        Mock Get-MgRoleManagementDirectoryRoleAssignment { Get-FakeAssignment -Role 'Reports Reader' }
        & $ScriptPath | Should -BeNullOrEmpty
    }

    It 'excludes users and does not look them up as apps' {
        Mock Get-MgRoleManagementDirectoryRoleAssignment { Get-FakeAssignment -Role 'Global Administrator' -ODataType '#microsoft.graph.user' }
        & $ScriptPath | Should -BeNullOrEmpty
        Should -Invoke Get-MgServicePrincipal -Times 0
    }

    It 'throws when a listed role does not exist in the tenant' {
        Mock Get-MgRoleManagementDirectoryRoleDefinition {
            $RoleIds.GetEnumerator() | Where-Object Key -ne 'Global Administrator' |
                ForEach-Object { [PSCustomObject]@{ Id = $_.Value; DisplayName = $_.Key } }
        }
        Mock Get-MgRoleManagementDirectoryRoleAssignment { @() }
        { & $ScriptPath } | Should -Throw "*Role 'Global Administrator' not found*"
    }
}
