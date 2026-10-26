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
        Mock Get-MgContext { [PSCustomObject]@{ TenantId = 'home-tenant'; AuthType = 'Delegated'; Scopes = 'Application.Read.All', 'RoleManagement.Read.Directory', 'GroupMember.Read.All' } }
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
        $rows[0].AppOwnerTenant | Should -Be 'Third Party'
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

    It 'warns and keeps going when a listed role does not exist in the tenant' {
        Mock Get-MgRoleManagementDirectoryRoleDefinition {
            $RoleIds.GetEnumerator() | Where-Object Key -ne 'Global Reader' |
                ForEach-Object { [PSCustomObject]@{ Id = $_.Value; DisplayName = $_.Key } }
        }
        Mock Get-MgRoleManagementDirectoryRoleAssignment { Get-FakeAssignment -Role 'Global Administrator' }
        $rows = & $ScriptPath -WarningVariable warnings -WarningAction SilentlyContinue
        $rows.Role | Should -Be 'Global Administrator'
        $warnings -join ' ' | Should -BeLike "*Role 'Global Reader' not found*"
    }

    It 'skips role assignments whose principal was deleted' {
        Mock Get-MgRoleManagementDirectoryRoleAssignment {
            [PSCustomObject]@{
                PrincipalId = 'gone'; RoleDefinitionId = $RoleIds['Global Administrator']
                DirectoryScopeId = '/'; Principal = $null
            }
            Get-FakeAssignment -Role 'Global Administrator'
        }
        $rows = & $ScriptPath
        $rows | Should -HaveCount 1
        $rows[0].DisplayName | Should -Be 'Contoso App'
    }

    It 'recognises a service principal by its .NET type when @odata.type is missing' {
        class MicrosoftGraphServicePrincipal { [hashtable]$AdditionalProperties = @{} }
        Mock Get-MgRoleManagementDirectoryRoleAssignment {
            [PSCustomObject]@{
                PrincipalId = 'principal-1'; RoleDefinitionId = $RoleIds['Global Administrator']
                DirectoryScopeId = '/'; Principal = [MicrosoftGraphServicePrincipal]::new()
            }
        }
        (& $ScriptPath).DisplayName | Should -Be 'Contoso App'
    }

    It 'looks up an app once when it holds several privileged roles' {
        Mock Get-MgRoleManagementDirectoryRoleAssignment {
            Get-FakeAssignment -Role 'Global Administrator'
            Get-FakeAssignment -Role 'Security Reader'
        }
        $rows = & $ScriptPath
        $rows.Role | Should -Be 'Global Administrator', 'Security Reader'
        Should -Invoke Get-MgServicePrincipal -Times 1 -Exactly
    }
}

Describe 'Get-AppsInPrivilegedRoles AppOwnerTenant' {
    BeforeEach {
        Mock Connect-MgGraph {}
        Mock Get-MgContext { [PSCustomObject]@{ TenantId = 'home-tenant'; AuthType = 'Delegated'; Scopes = 'Application.Read.All', 'RoleManagement.Read.Directory', 'GroupMember.Read.All' } }
        Mock Get-MgRoleManagementDirectoryRoleDefinition {
            $RoleIds.GetEnumerator() | ForEach-Object { [PSCustomObject]@{ Id = $_.Value; DisplayName = $_.Key } }
        }
        Mock Get-MgRoleManagementDirectoryRoleAssignment { Get-FakeAssignment -Role 'Global Administrator' }
    }

    It 'labels owner <OwnerId> as <Expected>' -ForEach @(
        @{ OwnerId = 'home-tenant'; Expected = 'Home Tenant' }
        @{ OwnerId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'; Expected = 'Microsoft' }
        @{ OwnerId = '72f988bf-86f1-41af-91ab-2d7cd011db47'; Expected = 'Microsoft' }
        @{ OwnerId = 'other-tenant'; Expected = 'Third Party' }
        @{ OwnerId = $null; Expected = 'Unknown' }
    ) {
        $owned = [PSCustomObject]@{ DisplayName = 'X'; AppId = 'x'; AccountEnabled = $true; AppOwnerOrganizationId = $OwnerId }
        Mock Get-MgServicePrincipal { $owned }
        (& $ScriptPath).AppOwnerTenant | Should -Be $Expected
    }
}

Describe 'Get-AppsInPrivilegedRoles connection' {
    BeforeEach {
        $state = @{ Existing = $false; Connected = $false }
        Mock Connect-MgGraph { $state.Connected = $true }
        Mock Get-MgContext {
            if ($state.Existing -or $state.Connected) {
                [PSCustomObject]@{ TenantId = 'home-tenant'; AuthType = 'Delegated'; Scopes = 'Application.Read.All', 'RoleManagement.Read.Directory', 'GroupMember.Read.All' }
            }
        }
        Mock Get-MgRoleManagementDirectoryRoleDefinition { @() }
        Mock Get-MgRoleManagementDirectoryRoleAssignment { @() }
    }

    It 'connects when there is no existing connection' {
        & $ScriptPath -WarningAction SilentlyContinue
        Should -Invoke Connect-MgGraph -Times 1 -Exactly
    }

    It 'reuses an existing connection' {
        $state.Existing = $true
        & $ScriptPath -WarningAction SilentlyContinue
        Should -Invoke Connect-MgGraph -Times 0 -Exactly
    }

    It 'reuses an existing connection when -TenantId matches it' {
        $state.Existing = $true
        & $ScriptPath -TenantId 'home-tenant' -WarningAction SilentlyContinue
        Should -Invoke Connect-MgGraph -Times 0 -Exactly
    }

    It 'reconnects when -TenantId names a different tenant' {
        $state.Existing = $true
        & $ScriptPath -TenantId 'other-tenant' -WarningAction SilentlyContinue
        Should -Invoke Connect-MgGraph -Times 1 -Exactly -ParameterFilter { $TenantId -eq 'other-tenant' }
    }

    It 'warns when a delegated connection lacks a required scope' {
        $state.Existing = $true
        Mock Get-MgContext { [PSCustomObject]@{ TenantId = 'home-tenant'; AuthType = 'Delegated'; Scopes = @('User.Read') } }
        & $ScriptPath -WarningVariable warnings -WarningAction SilentlyContinue
        $warnings -join ' ' | Should -BeLike '*RoleManagement.Read.Directory**'
    }

    It 'does not check scopes on an app-only connection' {
        $state.Existing = $true
        Mock Get-MgContext { [PSCustomObject]@{ TenantId = 'home-tenant'; AuthType = 'AppOnly'; Scopes = @() } }
        & $ScriptPath -WarningVariable warnings -WarningAction SilentlyContinue
        $warnings -join ' ' | Should -Not -BeLike '*scope*'
    }
}
