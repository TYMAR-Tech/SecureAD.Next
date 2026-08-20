$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Checks the checkable claims in .github/copilot-instructions.md against this repository. That
# file is the first thing every session reads, so a wrong statement in it costs more than a wrong
# statement anywhere else - and nothing has ever checked it.
#
# Only claims with a yes/no answer are here. Judgement and guidance are not testable and are not
# the point; what is testable is "this file exists", "this type is gone", "this project is here".

function Say($claim, $ok, $detail) {
    "{0,-6} {1}{2}" -f $(if ($ok) { 'OK' } else { 'WRONG' }), $claim, $(if ($detail) { "  [$detail]" } else { '' })
}

"DOCUMENTS THE INSTRUCTIONS POINT AT"
foreach ($d in @(
    'docs/next/README.md', 'docs/decisions', 'docs/areas', 'docs/history',
    'docs/next/sessions', 'docs/review/README.md', 'docs/review/00a-product-identity.md',
    'docs/next/WHAT-THE-OLD-APP-HAD.md')) {
    Say "$d exists" (Test-Path $d) ''
}

""
"TYPES THE INSTRUCTIONS SAY WERE REMOVED"
foreach ($t in @('RunSnapshotAsync', 'RunConfigurationAuditAsync', 'CaptureService',
                 'ConfigurationModeRunner', 'ForConfigurationMode', 'FromComponents')) {
    $hits = @(git grep -l -w $t -- 'next/src')
    Say "$t is gone from next/src" ($hits.Count -eq 0) $(if ($hits.Count) { "found in $($hits.Count) file(s)" })
}

""
"THINGS THE INSTRUCTIONS SAY DELIBERATELY SURVIVE"
foreach ($t in @('AssessmentMode', 'DerivedStoreSchema', 'StructuralCompareEngine',
                 'SecurityCompareEngine', 'ForSecurityModeFromForestFqdn')) {
    $hits = @(git grep -l -w $t -- 'next/src')
    Say "$t is present" ($hits.Count -gt 0) $(if (-not $hits.Count) { 'not found' })
}

""
"OTHER CHECKABLE CLAIMS"
$projects = @(git ls-files 'next/tests/*.csproj')
Say 'SecureAD.Infrastructure.Tests is a project' ($projects -match 'Infrastructure') "test projects: $($projects.Count)"
$rules = @(git ls-files 'docs/rules/SEC-*.md')
Say 'there are 62 rule cards' ($rules.Count -eq 62) "actual: $($rules.Count)"
Say 'next/tools holds measure-findings scripts' ((@(git ls-files 'next/tools/measure-findings*')).Count -gt 0) ''
