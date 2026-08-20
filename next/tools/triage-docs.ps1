$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

# 1. Documents named in test code. Removing one of these breaks the suite.
$testFiles = Get-ChildItem (Join-Path $repo 'next\tests') -Recurse -Filter *.cs -File |
    Where-Object { $_.FullName -notmatch '\\(obj|bin)\\' }

$cited = $testFiles |
    Select-String -Pattern '([A-Za-z0-9\-\._]+\.md)' -AllMatches |
    ForEach-Object { $_.Matches } |
    ForEach-Object { $_.Groups[1].Value } |
    Sort-Object -Unique

# 2. Every document on disk.
$all = Get-ChildItem (Join-Path $repo 'docs') -Recurse -Filter *.md -File

Write-Host "=== DOCUMENTS CITED BY TESTS (load-bearing) ==="
foreach ($c in $cited) {
    $hits = $all | Where-Object { $_.Name -eq $c }
    if ($hits) {
        foreach ($h in $hits) {
            Write-Host ("  {0}" -f ($h.FullName -replace [regex]::Escape($repo), '').TrimStart('\'))
        }
    }
    else {
        Write-Host ("  !! CITED BUT ABSENT: {0}" -f $c)
    }
}

Write-Host ""
Write-Host "=== CITED COUNT BY FOLDER ==="
$citedPaths = @()
foreach ($c in $cited) { $citedPaths += ($all | Where-Object { $_.Name -eq $c }) }
$citedPaths | Group-Object { $_.Directory.Name } | Sort-Object Count -Descending |
    ForEach-Object { "  {0,-14} {1,3} of {2,3} cited" -f $_.Name, $_.Count, ($all | Where-Object { $_.Directory.Name -eq $_.Name }).Count }

Write-Host ""
Write-Host "=== FOLDER TOTALS ==="
$all | Group-Object { $_.Directory.Name } | Sort-Object Count -Descending | ForEach-Object {
    $words = ($_.Group | ForEach-Object { (Get-Content $_.FullName -Raw) -split '\s+' }).Count
    "  {0,-14} {1,3} files  {2,9:N0} words" -f $_.Name, $_.Count, $words
}
