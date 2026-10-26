#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are read inside Pester mock blocks')]
param()

BeforeAll {
    $ScriptPath = Join-Path $PSScriptRoot 'Get-PrivilegedApps.ps1'
    $GraphAppId = '00000003-0000-0000-c000-000000000000'

    # Every string in the script's editable list becomes a Graph permission, so edits to the list keep tests valid
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$null, [ref]$null)
    $assignment = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left.Extent.Text -eq '$PrivilegedPermissions' }, $true)
    $names = $assignment.Right.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true).Value
    $Roles = @{}
    foreach ($name in $names + 'Reports.Read.All') { $Roles[$name] = (New-Guid).Guid }
    $App = [PSCustomObject]@{
        DisplayName = 'Contoso App'; AppId = 'app-1'; AccountEnabled = $true; AppOwnerOrganizationId = 'tenant-1'
    }
}

Describe 'Get-PrivilegedApps' {
    BeforeEach {
        # Rebuilt per test so a test that edits AppRoles can't affect the next one
        $appRoles = $Roles.GetEnumerator() | ForEach-Object { [PSCustomObject]@{ Id = $_.Value; Value = $_.Key } }
        $GraphResource = [PSCustomObject]@{ Id = 'res-1'; DisplayName = 'Microsoft Graph'; AppRoles = $appRoles }
        Mock Connect-MgGraph {}
        Mock Get-MgContext { [PSCustomObject]@{ TenantId = 'home-tenant' } }
        Mock Get-MgServicePrincipal { $GraphResource } -ParameterFilter { $Filter -like "*$GraphAppId*" }
        Mock Get-MgServicePrincipal { $null } -ParameterFilter { $Filter -and $Filter -notlike "*$GraphAppId*" }
        Mock Get-MgServicePrincipal { $App } -ParameterFilter { $ServicePrincipalId }
    }

    It 'returns one row per privileged permission with app details' {
        Mock Get-MgServicePrincipalAppRoleAssignedTo {
            [PSCustomObject]@{ PrincipalId = 'app-obj'; PrincipalType = 'ServicePrincipal'; AppRoleId = $Roles['Mail.Send'] }
        }
        $rows = & $ScriptPath -WarningAction SilentlyContinue
        $rows | Should -HaveCount 1
        $rows[0].DisplayName | Should -Be 'Contoso App'
        $rows[0].AppId | Should -Be 'app-1'
        $rows[0].AccountEnabled | Should -BeTrue
        $rows[0].AppOwnerTenant | Should -Be 'Third Party'
        $rows[0].Resource | Should -Be 'Microsoft Graph'
        $rows[0].Permission | Should -Be 'Mail.Send'
    }

    It 'excludes permissions that are not on the privileged list' {
        Mock Get-MgServicePrincipalAppRoleAssignedTo {
            [PSCustomObject]@{ PrincipalId = 'app-obj'; PrincipalType = 'ServicePrincipal'; AppRoleId = $Roles['Reports.Read.All'] }
        }
        & $ScriptPath -WarningAction SilentlyContinue | Should -BeNullOrEmpty
    }

    It 'excludes assignments to users' {
        Mock Get-MgServicePrincipalAppRoleAssignedTo {
            [PSCustomObject]@{ PrincipalId = 'user-obj'; PrincipalType = 'User'; AppRoleId = $Roles['Mail.Send'] }
        }
        & $ScriptPath -WarningAction SilentlyContinue | Should -BeNullOrEmpty
    }

    It 'warns instead of failing when an API is not in the tenant' {
        Mock Get-MgServicePrincipalAppRoleAssignedTo { @() }
        & $ScriptPath -WarningVariable warnings -WarningAction SilentlyContinue | Should -BeNullOrEmpty
        $warnings | Should -Not -BeNullOrEmpty
    }

    It 'throws when a listed permission does not exist on the API' {
        $GraphResource.AppRoles = @()
        { & $ScriptPath -WarningAction SilentlyContinue } | Should -Throw "*not found on 'Microsoft Graph'*"
    }
}

Describe 'Get-PrivilegedApps AppOwnerTenant' {
    BeforeEach {
        Mock Connect-MgGraph {}
        Mock Get-MgContext { [PSCustomObject]@{ TenantId = 'home-tenant' } }
        $graphRoles = $Roles.GetEnumerator() | ForEach-Object { [PSCustomObject]@{ Id = $_.Value; Value = $_.Key } }
        $graph = [PSCustomObject]@{ Id = 'res-1'; DisplayName = 'Microsoft Graph'; AppRoles = $graphRoles }
        Mock Get-MgServicePrincipal { $graph } -ParameterFilter { $Filter -like "*$GraphAppId*" }
        Mock Get-MgServicePrincipal { $null } -ParameterFilter { $Filter -and $Filter -notlike "*$GraphAppId*" }
        Mock Get-MgServicePrincipalAppRoleAssignedTo {
            [PSCustomObject]@{ PrincipalId = 'app-obj'; PrincipalType = 'ServicePrincipal'; AppRoleId = $Roles['Mail.Send'] }
        }
    }

    It 'labels owner <OwnerId> as <Expected>' -ForEach @(
        @{ OwnerId = 'home-tenant'; Expected = 'Home Tenant' }
        @{ OwnerId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'; Expected = 'Microsoft' }
        @{ OwnerId = '72f988bf-86f1-41af-91ab-2d7cd011db47'; Expected = 'Microsoft' }
        @{ OwnerId = 'other-tenant'; Expected = 'Third Party' }
        @{ OwnerId = $null; Expected = 'Unknown' }
    ) {
        $owned = [PSCustomObject]@{ DisplayName = 'X'; AppId = 'x'; AccountEnabled = $true; AppOwnerOrganizationId = $OwnerId }
        Mock Get-MgServicePrincipal { $owned } -ParameterFilter { $ServicePrincipalId }
        (& $ScriptPath -WarningAction SilentlyContinue).AppOwnerTenant | Should -Be $Expected
    }
}
