# Checks the claims .github/copilot-instructions.md makes about what does NOT exist.
#
# This checks the named legacy symbols, not whether replacement features are built.
# In particular, absence of DerivedStore does not mean the Stage2aRun derive stage is absent.
# Older instructions and this script's display label incorrectly conflated those claims.
#
# Stage status is checked separately by check-stage-status.ps1. This is the legacy-name check.
#
# Exit code 0 when every named symbol is absent, 1 when any has come back.

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

$claims = [ordered]@{
    'Scoped (OU-level) capture was removed on 2026-07-30' = @(
        'RunSnapshotAsync'
        'RunConfigurationAuditAsync'
        'CaptureService'
        'ConfigurationModeRunner'
        'ForConfigurationMode'
    )
    'Legacy compare, derive and assessment symbols were removed' = @(
        'AssessmentMode'
        'DerivedStoreSchema'
        'DerivedStore'
        'StructuralCompareEngine'
        'SecurityCompareEngine'
    )
}

$failed = $false

foreach ($claim in $claims.Keys) {
    Write-Output ''
    Write-Output $claim

    foreach ($symbol in $claims[$claim]) {
        $hits = @(git grep -l -- $symbol 'next/src' 2>$null)

        if ($hits.Count -gt 0) {
            $failed = $true
            '  PRESENT  {0,-28} {1}' -f $symbol, ($hits -join ', ')
        }
        else {
            '  absent   {0}' -f $symbol
        }
    }
}

Write-Output ''

if ($failed) {
    Write-Output 'FAILED - a symbol the instructions say is gone is back in next/src.'
    Write-Output 'Either it was reintroduced, or the instruction claiming it is gone is now wrong.'
    exit 1
}

Write-Output 'PASS - every symbol the instructions call absent is absent from next/src.'
exit 0
