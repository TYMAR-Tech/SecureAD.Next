$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# A markdown table whose rows do not all have the same number of cells renders wrong and parses
# worse. add-lab-confirmation-column.ps1 was run twice; its skip guard only looked at the header
# row, so the separator and data rows gained a second empty column while the header did not.
#
# LabConfirmationColumnTests did not catch it: it reads the second-to-last cell, which after the
# double run is the spurious column - so it was checking an empty cell that no one writes in.
$bad = 0
foreach ($f in (git ls-files 'docs/areas/*.md')) {
    $lines = [System.IO.File]::ReadAllLines((Resolve-Path $f).Path, [System.Text.Encoding]::UTF8)
    $width = 0
    $line = 0
    foreach ($l in $lines) {
        $line++
        # A blank or prose line ends the table, so each contiguous block is measured against its
        # own header. Counting across the whole file calls a document ragged for having two
        # tables of different widths, which is not a fault.
        if ($l -notmatch '^\|') { $width = 0; continue }
        $n = ($l.TrimEnd().TrimEnd('|') -split '\|').Count
        if ($width -eq 0) { $width = $n; continue }
        if ($n -ne $width) {
            $bad++
            "{0} line {1}: {2} cells, header has {3}" -f (Split-Path $f -Leaf), $line, $n, $width
        }
    }
}
"Ragged table rows: $bad"
