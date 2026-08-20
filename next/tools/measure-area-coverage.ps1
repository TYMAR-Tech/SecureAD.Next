$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# How much of the product do the area files actually claim? Each "What is built" row names a
# test, and AreaFileGateTests proves by reflection that the test exists - so the count of rows
# is the count of capabilities the documentation vouches for. Comparing it against the size of
# the suite says how much of what is built is tracked.
$total = 0
"{0,-40} {1,10} {2,10}" -f 'AREA', 'DECIDED', 'BUILT'
foreach ($f in (git ls-files 'docs/areas/*.md')) {
    if ((Split-Path $f -Leaf) -eq 'README.md') { continue }
    $text = [System.IO.File]::ReadAllText((Resolve-Path $f).Path, [System.Text.Encoding]::UTF8)
    $decided = ([regex]::Matches($text, '(?m)^\|.*\|\s*\[?`?\d{4}`?')).Count
    $built = ([regex]::Matches($text, '(?m)^\|.*\|\s*`[A-Za-z0-9_]+\.[A-Za-z0-9_]+`\s*\|')).Count
    $total += $built
    "{0,-40} {1,10} {2,10}" -f (Split-Path $f -Leaf), $decided, $built
}
""
"Capabilities the area files vouch for: $total"
