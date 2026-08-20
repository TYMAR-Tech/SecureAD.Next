$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Where do the component documents in docs/next overlap the area files in docs/areas, and how
# much of their shape is left over from the old application's inventory? "Row" and "Rebuild"
# were dispositions in that inventory, which was archived on 2026-09-XX.
"{0,-46} {1,9} {2,9} {3,9}" -f 'DOCUMENT', 'FINDINGS', 'OPENQ', 'OLD-APP'
foreach ($f in (git ls-files 'docs/next/S-*.md')) {
    $text = [System.IO.File]::ReadAllText((Resolve-Path $f).Path, [System.Text.Encoding]::UTF8)
    $findings = if ($text -match '(?m)^##\s+Findings') { 'yes' } else { '' }
    $openq = if ($text -match '(?m)^##\s+Open questions') { 'yes' } else { '' }
    $old = ([regex]::Matches($text, '(?i)\bthis row\b|\bRebuild row\b|\bthe map\b|inventory row')).Count
    "{0,-46} {1,9} {2,9} {3,9}" -f (Split-Path $f -Leaf), $findings, $openq, $(if ($old) { $old } else { '' })
}
