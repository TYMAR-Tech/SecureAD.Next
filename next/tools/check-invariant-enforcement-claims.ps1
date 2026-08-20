$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Every invariant in docs/INVARIANTS.md that names an enforcing test, checked against whether
# that test actually exists in this repository. A document claiming enforcement by a test that
# is not here is worse than an unenforced one: it reads as verified.
$doc = Get-Content 'docs/INVARIANTS.md' -Raw
$invariants = [regex]::Matches($doc, '(?m)^## (I-\d+[^\r\n]*)')
"Invariants stated: $($invariants.Count)"

$claims = [regex]::Matches($doc, '(?m)^\*\*Enforced by:\*\*\s*`?([A-Za-z0-9_]+)')
"Claiming an enforcing test: $($claims.Count)"
""
"{0,-42} {1}" -f 'TEST NAMED BY THE DOCUMENT', 'DECLARED HERE'
foreach ($c in $claims) {
    $name = $c.Groups[1].Value
    # Looks for the class DECLARATION, not any mention. Searching for the bare name counts a
    # comment saying "this test exists in the old tree" as the test existing - a check that
    # passes while measuring nothing, which is the thing this script is meant to detect.
    $hits = (git grep -l -E "(class|record)\s+$name\b" -- 'next/tests' | Measure-Object).Count
    "{0,-42} {1}" -f $name, $(if ($hits -gt 0) { 'yes' } else { 'NO - not in this repository' })
}
