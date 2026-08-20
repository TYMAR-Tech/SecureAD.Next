$ErrorActionPreference = 'Continue'
$repo = 'C:\Users\jistrand\source\repos\razamus\SecureAD'
$wt = Join-Path $env:TEMP 'securead-nodocs'

if (Test-Path $wt) { & git -C $repo worktree remove --force $wt 2>&1 | Out-Null }

Write-Host '=== creating isolated worktree at HEAD ==='
& git -C $repo worktree add --detach $wt HEAD 2>&1 | Select-Object -Last 2

try {
    Write-Host ''
    Write-Host "docs/ in worktree: $((Get-ChildItem (Join-Path $wt 'docs') -Recurse -Filter *.md -File).Count) files"

    Remove-Item -LiteralPath (Join-Path $wt 'docs') -Recurse -Force
    Write-Host "docs/ removed. Present: $(Test-Path (Join-Path $wt 'docs'))"

    Write-Host ''
    Write-Host '=== BUILD ==='
    & dotnet build (Join-Path $wt 'next\SecureAD.Next.sln') --nologo -v q 2>&1 |
        Select-String -Pattern 'error|Build succeeded|Build FAILED' | Select-Object -First 8

    Write-Host ''
    Write-Host '=== TEST ==='
    $out = & dotnet test (Join-Path $wt 'next\SecureAD.Next.sln') --nologo 2>&1
    $out | Select-String -Pattern 'Passed!|Failed!' | Select-Object -First 3

    Write-Host ''
    Write-Host '=== FAILURES BY TEST CLASS ==='
    $out | Select-String -Pattern 'Failed\s+([A-Za-z0-9_\.]+)\.[A-Za-z0-9_]+' |
        ForEach-Object { (($_.Matches[0].Groups[1].Value) -split '\.')[-1] } |
        Group-Object | Sort-Object Count -Descending |
        ForEach-Object { "  {0,-50} {1,4}" -f $_.Name, $_.Count }
}
finally {
    Write-Host ''
    & git -C $repo worktree remove --force $wt 2>&1 | Out-Null
    Write-Host "worktree removed: $(-not (Test-Path $wt))"
    Write-Host "main docs/ intact: $((Get-ChildItem (Join-Path $repo 'docs') -Recurse -Filter *.md -File).Count) files"
}
