$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')
$refs = git grep -oh -E 'docs/[A-Za-z0-9_./-]+\.md' -- 'next/tests/**/*.cs' 'next/src/**/*.cs'
$grouped = $refs | Group-Object | Sort-Object Count -Descending
"Distinct documents referenced from code or tests: $($grouped.Count)"
""
"TOP 25 BY REFERENCE COUNT"
$grouped | Select-Object -First 25 | ForEach-Object { "{0,4}  {1}" -f $_.Count, $_.Name }
""
"BY FOLDER"
$grouped | ForEach-Object {
    $parts = $_.Name -split '/'
    if ($parts.Count -gt 2) { $parts[0..1] -join '/' } else { 'docs/(root)' }
} | Group-Object | Sort-Object Count -Descending | ForEach-Object { "{0,4}  {1}" -f $_.Count, $_.Name }
