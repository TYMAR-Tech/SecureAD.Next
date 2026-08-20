$ErrorActionPreference = 'Continue'
$repo = 'C:\Users\jistrand\source\repos\razamus\SecureAD'
$wt = Join-Path $env:TEMP 'securead-export'
$standalone = Join-Path $env:TEMP 'securead-next-standalone'

if (Test-Path $wt) { & git -C $repo worktree remove --force $wt 2>&1 | Out-Null }
if (Test-Path $standalone) { Remove-Item $standalone -Recurse -Force }

Write-Host '=== clean export of HEAD ==='
& git -C $repo worktree add --detach $wt HEAD 2>&1 | Select-Object -Last 1

try {
    New-Item -ItemType Directory -Path $standalone -Force | Out-Null

    # The four inherited build files. next/ has none of its own.
    foreach ($f in @('Directory.Build.props', 'Directory.Packages.props', 'global.json', '.editorconfig')) {
        Copy-Item (Join-Path $wt $f) (Join-Path $standalone $f) -Force
        Write-Host "  copied $f"
    }

    # The rebuild and the documentation, keeping the <root>/next + <root>/docs shape.
    & robocopy (Join-Path $wt 'next') (Join-Path $standalone 'next') /E /NFL /NDL /NJH /NJS /NP | Out-Null
    & robocopy (Join-Path $wt 'docs') (Join-Path $standalone 'docs') /E /NFL /NDL /NJH /NJS /NP | Out-Null

    Write-Host ''
    Write-Host "standalone next/ files: $((Get-ChildItem (Join-Path $standalone 'next') -Recurse -File).Count)"
    Write-Host "standalone docs/ files: $((Get-ChildItem (Join-Path $standalone 'docs') -Recurse -File).Count)"
    Write-Host "old app present:        $(Test-Path (Join-Path $standalone 'src'))"

    Write-Host ''
    Write-Host '=== BUILD ==='
    & dotnet build (Join-Path $standalone 'next\SecureAD.Next.sln') --nologo -v q 2>&1 |
        Select-String -Pattern 'error|Build succeeded|Build FAILED' | Select-Object -First 10

    Write-Host ''
    Write-Host '=== TEST ==='
    $out = & dotnet test (Join-Path $standalone 'next\SecureAD.Next.sln') --nologo 2>&1
    $out | Select-String -Pattern 'Passed!|Failed!' | Select-Object -First 3

    Write-Host ''
    Write-Host '=== FAILURES BY CLASS (if any) ==='
    $out | Select-String -Pattern 'Failed\s+([A-Za-z0-9_\.]+)\.[A-Za-z0-9_]+' |
        ForEach-Object { (($_.Matches[0].Groups[1].Value) -split '\.')[-1] } |
        Group-Object | Sort-Object Count -Descending |
        ForEach-Object { "  {0,-50} {1,4}" -f $_.Name, $_.Count }
}
finally {
    & git -C $repo worktree remove --force $wt 2>&1 | Out-Null
    Write-Host ''
    Write-Host "export worktree removed: $(-not (Test-Path $wt))"
    Write-Host "standalone left at: $standalone"
}
