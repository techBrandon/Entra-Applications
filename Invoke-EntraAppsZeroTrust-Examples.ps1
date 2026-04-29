<#
.SYNOPSIS
Examples and usage patterns for refactored Invoke-EntraAppsZeroTrust functions.

.DESCRIPTION
Demonstrates standalone function usage, data reuse, filtering, and orchestration patterns.
Use these examples to validate the refactored module and as a starting point for automation.

.NOTES
Author: Brandon Colley
Updated: 2025-12-05
#>

# ===========================================================================================
# EXAMPLE 1: Run Full Assessment with Orchestrator
# ===========================================================================================

# Simple one-liner for complete assessment with export
Invoke-EntraAppsZeroTrust -TenantId 'your-tenant-id' -ExportPath './ZeroTrustReports' -PassThru | ForEach-Object {
    Write-Host "Check: $_"
}

# ===========================================================================================
# EXAMPLE 2: Collect Artifacts Once, Reuse for Multiple Checks
# ===========================================================================================

# Collect all data once
$artifacts = Collect-EntraArtifacts -TenantId 'your-tenant-id' -Verbose

# Run multiple checks reusing same data (efficient)
$appPolicyResults = Test-EntraAppRegistrationPolicy -Data $artifacts
$privilegedAppsResults = Find-EntraPrivilegedApps -Data $artifacts
$roleAssignmentResults = Find-EntraPrivilegedRoleAssignments -Data $artifacts

# View findings
$appPolicyResults | Where-Object Status -eq 'FINDING'
$privilegedAppsResults | Format-Table ServicePrincipalDisplayName, Permission
$roleAssignmentResults | Where-Object PrincipalType -eq 'Group'

# ===========================================================================================
# EXAMPLE 3: Focus on Specific Risk Areas
# ===========================================================================================

# Example 3a: Find all privileged role assignments, expanded
$data = Collect-EntraArtifacts
$privilegedRoles = Find-EntraPrivilegedRoleAssignments -Data $data -ExpandGroups
$privilegedRoles | Group-Object RoleName | ForEach-Object {
    Write-Host "[$($_.Name)]: $($_.Count) assignments"
}

# Example 3b: Find workload identities in privileged roles (dangerous)
$workloadIdentities = $privilegedRoles | Where-Object IsManagedIdentity -eq $true
if ($workloadIdentities) {
    Write-Warning "Found $($workloadIdentities.Count) workload identities with privileged roles"
    $workloadIdentities
}

# ===========================================================================================
# EXAMPLE 4: Redirect URI Risk Assessment
# ===========================================================================================

$data = Collect-EntraArtifacts
$uris = Test-EntraRedirectUris -Data $data

# Find dangerous redirect URIs
$wildcardUris = $uris | Where-Object { $_.RedirectUri -match "\*" }
$localhostUris = $uris | Where-Object { $_.RedirectUri -match "localhost" }
$httpUris = $uris | Where-Object {
    $_.RedirectUri -match "^http://" -and 
    $_.RedirectUri -notmatch "^http://localhost(:\d+)?"
}

Write-Host "Wildcard URIs: $($wildcardUris.Count)"
Write-Host "Localhost URIs: $($localhostUris.Count)"
Write-Host "Non-localhost HTTP: $($httpUris.Count)"

# ===========================================================================================
# EXAMPLE 5: Run Only Specific Checks
# ===========================================================================================

# Run just role and privilege checks
$results = Invoke-EntraAppsZeroTrust `
    -TenantId 'your-tenant-id' `
    -Only 'AppPolicy', 'PrivilegedRoles', 'WorkloadIdentity' `
    -PassThru

$results.PrivilegedRoles | Where-Object IsManagedIdentity -eq $true

# ===========================================================================================
# EXAMPLE 6: Export Results for Further Analysis
# ===========================================================================================

$data = Collect-EntraArtifacts
$privilegedApps = Find-EntraPrivilegedApps -Data $data
$roleAssignments = Find-EntraPrivilegedRoleAssignments -Data $data

# Export to CSV for Excel analysis
$privilegedApps | Export-Csv -Path './privileged-apps.csv' -NoTypeInformation
$roleAssignments | Export-Csv -Path './privileged-roles.csv' -NoTypeInformation

# Export to JSON for structured data processing
$privilegedApps | ConvertTo-Json | Out-File -Path './privileged-apps.json'

# ===========================================================================================
# EXAMPLE 7: Programmatic Filtering and Reporting
# ===========================================================================================

$data = Collect-EntraArtifacts

# Get all policy check results
$policyChecks = Test-EntraAppRegistrationPolicy -Data $data

# Summary report
Write-Host "=== Policy Check Summary ===" -ForegroundColor Cyan
$policyChecks | Group-Object Status | ForEach-Object {
    Write-Host "  $($_.Name): $($_.Count)"
}

# Find all findings
$findings = @()
$findings += $policyChecks | Where-Object Status -eq 'FINDING'
$findings += Find-EntraPrivilegedApps -Data $data
$findings += Find-EntraPrivilegedRoleAssignments -Data $data | Where-Object IsManagedIdentity -eq $true
$findings += Test-EntraEnterpriseAppAssignmentRequirements -Data $data | Where-Object Status -eq 'FINDING'

Write-Host "Total findings: $($findings.Count)" -ForegroundColor Yellow
$findings | Group-Object Control | ForEach-Object {
    Write-Host "  $($_.Name): $($_.Count)"
}

# ===========================================================================================
# EXAMPLE 8: Conditional Logic - Act on Results
# ===========================================================================================

$data = Collect-EntraArtifacts

# Check if users can create apps
$canUsersCreateApps = (Test-EntraAppRegistrationPolicy -Data $data | 
    Where-Object Control -eq 'TS-EA-001').Status -eq 'FINDING'

if ($canUsersCreateApps) {
    Write-Warning "Users can register applications - consider restricting this"
    # Trigger notification, escalation, or remediation
}

# Check if any privileged roles are assigned to groups
$rolesOnGroups = Find-EntraPrivilegedRoleAssignments -Data $data | Where-Object PrincipalType -eq 'Group'
if ($rolesOnGroups) {
    Write-Warning "Found $($rolesOnGroups.Count) privileged roles assigned to groups"
    # Log for review, create ticket, etc.
}

# ===========================================================================================
# EXAMPLE 9: Caching and Refresh Patterns
# ===========================================================================================

# Initial collection and cache
$data1 = Collect-EntraArtifacts -TenantId 'your-tenant-id'
Write-Host "First collection timestamp: $($script:EntraCache.Timestamp)"

# Subsequent calls use cache (within 30 minutes)
$data2 = Collect-EntraArtifacts
Write-Host "Cache still valid: $($script:EntraCache.Timestamp)"

# Force refresh if needed (e.g., after known change)
$data3 = Collect-EntraArtifacts -ForceRefresh
Write-Host "Force-refreshed: $($script:EntraCache.Timestamp)"

# ===========================================================================================
# EXAMPLE 10: Error Handling
# ===========================================================================================

try {
    $data = Collect-EntraArtifacts -TenantId 'invalid-tenant' -ErrorAction Stop
}
catch {
    Write-Error "Collection failed: $_"
    Write-Host "Check Graph permissions and connection status"
}

# Check for errors in data collection
$data = Collect-EntraArtifacts
if ($data.Error) {
    Write-Error "Artifact collection had errors: $($data.Error)"
    exit 1
}

# Wrap function calls for graceful failure
try {
    $privilegedApps = Find-EntraPrivilegedApps -Data $data
    Write-Host "Found $($privilegedApps.Count) apps with privileged permissions"
}
catch {
    Write-Warning "Privileged apps check failed, continuing with others..."
}

# ===========================================================================================
# EXAMPLE 11: Orchestrator with Selective Execution and Reporting
# ===========================================================================================

# Run assessment, export results, and display summary
$results = Invoke-EntraAppsZeroTrust `
    -TenantId 'your-tenant-id' `
    -ExportPath './reports' `
    -PassThru

# Post-processing: summarize findings per check
foreach ($checkName in $results.Keys) {
    $checkResults = $results[$checkName]
    $findingCount = ($checkResults | Where-Object Status -eq 'FINDING' | Measure-Object).Count
    $passCount = ($checkResults | Where-Object Status -eq 'PASS' | Measure-Object).Count
    
    Write-Host "$checkName" -ForegroundColor Cyan
    Write-Host "  Findings: $findingCount"
    Write-Host "  Passed: $passCount"
}

# ===========================================================================================
# VALIDATION TESTS
# ===========================================================================================

# Quick smoke tests to validate function behavior

Write-Host "=== Running Validation Tests ===" -ForegroundColor Magenta

try {
    # Test 1: Collect artifacts
    Write-Host "Test 1: Collect-EntraArtifacts..." -NoNewline
    $data = Collect-EntraArtifacts -Verbose:$false
    if ($data -and $data.Applications) {
        Write-Host " ✓" -ForegroundColor Green
    } else {
        Write-Host " ✗ (Empty data)" -ForegroundColor Red
    }

    # Test 2: App registration policy check
    Write-Host "Test 2: Test-EntraAppRegistrationPolicy..." -NoNewline
    $result = Test-EntraAppRegistrationPolicy -Data $data
    if ($result -and $result.Count -gt 0) {
        Write-Host " ✓" -ForegroundColor Green
    } else {
        Write-Host " ✗ (No results)" -ForegroundColor Red
    }

    # Test 3: Redirect URIs
    Write-Host "Test 3: Test-EntraRedirectUris..." -NoNewline
    $result = Test-EntraRedirectUris -Data $data
    if ($result -is [array] -or $result) {
        Write-Host " ✓" -ForegroundColor Green
    } else {
        Write-Host " ✗ (No results)" -ForegroundColor Red
    }

    # Test 4: Privileged apps
    Write-Host "Test 4: Find-EntraPrivilegedApps..." -NoNewline
    $result = Find-EntraPrivilegedApps -Data $data
    if ($result) {
        Write-Host " ✓" -ForegroundColor Green
    } else {
        Write-Host " ✓ (No privileged apps - expected)" -ForegroundColor Green
    }

    # Test 5: Privileged roles
    Write-Host "Test 5: Find-EntraPrivilegedRoleAssignments..." -NoNewline
    $result = Find-EntraPrivilegedRoleAssignments -Data $data
    if ($result) {
        Write-Host " ✓" -ForegroundColor Green
    } else {
        Write-Host " ✓ (No privileged roles - possible)" -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "=== Validation Complete ===" -ForegroundColor Magenta
}
catch {
    Write-Host " ✗" -ForegroundColor Red
    Write-Error $_
}
