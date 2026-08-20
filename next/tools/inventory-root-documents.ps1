$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Matches on the FULL path, never the leaf name. Two files are called ARCHITECTURE.md
# (docs/ and docs/next/) and every folder has a README.md, so a leaf-name match reports
# one document's references against another's - which is how a previous session counted
# seven citations that were not there.
$root = git ls-files 'docs/*.md' | Where-Object { ($_ -split '/').Count -eq 2 }
"{0,-30} {1,6} {2,7} {3,6}" -f 'FILE', 'LINES', 'CODEREF', 'DOCREF'
foreach ($f in $root) {
    $lines = (Get-Content $f).Count
    $codeRef = (git grep -l -F $f -- 'next/src' 'next/tests' | Measure-Object).Count
    $docRef = (git grep -l -F $f -- 'docs' | Where-Object { $_ -ne $f } | Measure-Object).Count
    "{0,-30} {1,6} {2,7} {3,6}" -f (Split-Path $f -Leaf), $lines, $codeRef, $docRef
}
