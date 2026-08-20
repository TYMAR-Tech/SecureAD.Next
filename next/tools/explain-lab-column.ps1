$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Adds one sentence to the standard "What is built" paragraph explaining what the lab column
# means, so a reader meeting a blank cell knows it is honest rather than neglected.
$old = 'here can claim something the product does not do.'
$new = @'
here can claim something the product does not do.

**Confirmed in lab** is the date the owner saw this working against a real forest. Blank is the
honest answer for most rows and means unit-tested but not yet exercised against Active Directory -
a test with a synthetic descriptor proves the parser handles those bytes, not that a domain
controller sends them.
'@

$utf8 = New-Object System.Text.UTF8Encoding $false
$changed = 0
foreach ($file in (git ls-files 'docs/areas/*.md')) {
    $full = (Resolve-Path $file).Path
    $text = [System.IO.File]::ReadAllText($full, [System.Text.Encoding]::UTF8)
    if ($text -notmatch 'Confirmed in lab \|') { continue }
    if ($text.Contains('**Confirmed in lab** is the date')) { continue }
    if (-not $text.Contains($old)) { "  no standard paragraph: $(Split-Path $file -Leaf)"; continue }
    [System.IO.File]::WriteAllText($full, $text.Replace($old, $new.TrimEnd()), $utf8)
    $changed++
}
"$changed area file(s) given the explanation."
