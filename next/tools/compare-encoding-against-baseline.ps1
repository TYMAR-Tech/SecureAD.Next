$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Did my delink run introduce double-encoding, or was it already here? Compares the count of
# the "a-circumflex euro" signature in each document at the pre-session commit against HEAD.
# Only a rise is my doing.
$before = 'bbc9d23'
foreach ($f in @(
    'docs/evidence/what-a-bundle-holds.md',
    'docs/evidence/the-bundle-on-disk.md',
    'docs/next/README.md',
    'docs/rules/SEC-022.md',
    'docs/decisions/0058-a-run-may-be-stopped-and-stopping-it-keeps-nothing.md')) {
    $old = git show "${before}:$f" 2>$null | Out-String
    if ($LASTEXITCODE -ne 0) { $old = '' }
    $new = [System.IO.File]::ReadAllText((Resolve-Path $f).Path, [System.Text.Encoding]::UTF8)
    $o = ([regex]::Matches($old, "\u00E2\u20AC")).Count
    $n = ([regex]::Matches($new, "\u00E2\u20AC")).Count
    "{0,-70} before={1,4}  now={2,4}" -f $f, $o, $n
}
