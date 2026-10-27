#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are read inside Pester mock blocks')]
param()

BeforeAll {
    $ScriptPath = Join-Path $PSScriptRoot 'Get-ManagedIdentities.ps1'
}

Describe 'Get-ManagedIdentities' {
    BeforeEach {
        Mock Connect-MgGraph {}
        Mock Get-MgContext {
            [PSCustomObject]@{ TenantId = 'home-tenant'; AuthType = 'Delegated'; Account = 'admin@contoso.com'; AppName = $null }
        }
        Mock Get-MgServicePrincipal {
            [PSCustomObject]@{ DisplayName = 'vm-web-01'; AppOwnerOrganizationId = 'home-tenant'; Id = 'ignored' }
        }
    }

    It 'returns the name and appOwnerOrganizationId of each managed identity' {
        $rows = & $ScriptPath
        $rows | Should -HaveCount 1
        $rows[0].DisplayName | Should -Be 'vm-web-01'
        $rows[0].AppOwnerOrganizationId | Should -Be 'home-tenant'
        $rows[0].PSObject.Properties.Name | Should -Be 'DisplayName', 'AppOwnerOrganizationId'
    }

    It 'asks Graph for managed identities only' {
        & $ScriptPath | Out-Null
        Should -Invoke Get-MgServicePrincipal -Times 1 -Exactly -ParameterFilter {
            $Filter -eq "servicePrincipalType eq 'ManagedIdentity'" -and $All
        }
    }

    It 'returns nothing when the tenant has no managed identities' {
        Mock Get-MgServicePrincipal { @() }
        & $ScriptPath | Should -BeNullOrEmpty
    }

    It 'reuses an existing session instead of signing in' {
        & $ScriptPath | Out-Null
        Should -Invoke Connect-MgGraph -Times 0 -Exactly
    }

    It 'signs in when there is no session' {
        Mock Get-MgContext { $null }
        & $ScriptPath | Out-Null
        Should -Invoke Connect-MgGraph -Times 1 -Exactly
    }
}
