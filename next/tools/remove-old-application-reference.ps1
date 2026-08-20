$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Removes the "Reference - the old application" section from every area file. It made sense
# while the predecessor's component map was in the tree; the map was archived on 2026-09-XX, and
# nineteen sections describing a product the owner deliberately walked away from pull every
# future session backwards.
#
# Reads and writes UTF-8 explicitly - Get-Content -Raw would decode with the system codepage and
# double-encode every em dash, which happened to 29 documents earlier in this work.
$utf8 = New-Object System.Text.UTF8Encoding $false
$changed = 0
foreach ($file in (git ls-files 'docs/areas/*.md')) {
    $full = (Resolve-Path $file).Path
    $lines = [System.IO.File]::ReadAllLines($full, [System.Text.Encoding]::UTF8)

    $start = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^##\s+Reference\b') { $start = $i; break }
    }
    if ($start -lt 0) { continue }

    $end = $lines.Count
    for ($i = $start + 1; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^##\s') { $end = $i; break }
    }

    # Drop any '---' rule and blank lines immediately above the heading too.
    $cut = $start
    while ($cut -gt 0 -and ($lines[$cut - 1].Trim() -eq '' -or $lines[$cut - 1].Trim() -eq '---')) { $cut-- }

    $kept = @()
    if ($cut -gt 0) { $kept += $lines[0..($cut - 1)] }
    if ($end -lt $lines.Count) { $kept += $lines[$end..($lines.Count - 1)] }

    [System.IO.File]::WriteAllLines($full, $kept, $utf8)
    $changed++
    "{0,-36} removed {1} line(s)" -f (Split-Path $file -Leaf), ($end - $cut)
}
"$changed area file(s) rewritten."
