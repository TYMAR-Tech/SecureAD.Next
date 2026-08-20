$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# The solution lists documentation as solution items. Archiving a document without pruning the
# solution leaves Visual Studio showing an entry that opens nothing. Reports every solution item
# whose file is no longer on disk.
$sln = (Resolve-Path 'next/SecureAD.Next.sln').Path
$dir = Split-Path $sln -Parent
$missing = @()
foreach ($line in [System.IO.File]::ReadAllLines($sln, [System.Text.Encoding]::UTF8)) {
    $m = [regex]::Match($line, '^\s*(\.\.\\[^=]+?\.md)\s*=')
    if (-not $m.Success) { continue }
    $rel = $m.Groups[1].Value.Trim()
    if (-not (Test-Path -LiteralPath (Join-Path $dir $rel))) { $missing += $rel }
}
"Solution items pointing at files that are not there: $($missing.Count)"
$missing | Select-Object -First 10 | ForEach-Object { "   $_" }
if ($missing.Count -gt 10) { "   ... and $($missing.Count - 10) more" }
