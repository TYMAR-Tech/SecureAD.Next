$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Removes solution items whose file is no longer on disk. Writes UTF-8 WITH a byte-order mark,
# because the solution file has one and Visual Studio expects it; writing without would be a
# silent corruption of the kind that hit 29 documents earlier in this work.
$sln = (Resolve-Path 'next/SecureAD.Next.sln').Path
$dir = Split-Path $sln -Parent
$lines = [System.IO.File]::ReadAllLines($sln, [System.Text.Encoding]::UTF8)
$kept = @(); $dropped = 0
foreach ($line in $lines) {
    $m = [regex]::Match($line, '^\s*(\.\.\\[^=]+?\.md)\s*=')
    if ($m.Success -and -not (Test-Path -LiteralPath (Join-Path $dir $m.Groups[1].Value.Trim()))) {
        $dropped++
        continue
    }
    $kept += $line
}
[System.IO.File]::WriteAllLines($sln, $kept, (New-Object System.Text.UTF8Encoding $true))
"Dropped $dropped solution item(s) pointing at files that are not there."
