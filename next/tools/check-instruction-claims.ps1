# Checks the claims .github/copilot-instructions.md makes about what does NOT exist.
#
# Why this file exists at all: the instructions cite it by name as the evidence for two
# claims - that scoped capture was removed, and that compare/derive/assessment are not
# built. It was zero bytes from the day it was named until 2026-09, so both citations
# pointed at a script that had never run. The claims were true; the proof was not.
#
# A claim that something is ABSENT is the one kind of statement no gate in this
# repository checks, because there is no name to look up. This is that gate.
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
    'Compare, derive and assessment modes are not built' = @(
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
