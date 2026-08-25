#Requires -Version 7.0
# Windows PowerShell 5.1 reads UTF-8 files as Windows-1252, turning every em dash into three
# characters. This script writes documents, so running it under 5.1 would corrupt them silently.

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Normalises every table row to its header's column count by trimming trailing empty cells.
# add-lab-confirmation-column.ps1 was run twice and its skip guard only inspected the header
# row, so separator and data rows gained a second empty column that the header never got.
$utf8 = New-Object System.Text.UTF8Encoding $false
$fixed = 0
foreach ($file in (git ls-files 'docs/areas/*.md')) {
    $full = (Resolve-Path $file).Path
    $lines = [System.IO.File]::ReadAllLines($full, [System.Text.Encoding]::UTF8)
    $width = 0
    $touched = $false

    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -notmatch '^\|') { $width = 0; continue }

        $cells = [System.Collections.Generic.List[string]]($lines[$i].TrimEnd().TrimEnd('|') -split '\|')
        if ($width -eq 0) { $width = $cells.Count; continue }   # header sets the width

        while ($cells.Count -gt $width -and $cells[$cells.Count - 1].Trim() -in @('', '---')) {
            $cells.RemoveAt($cells.Count - 1)
            $touched = $true
        }
        if ($cells.Count -ne ($lines[$i].TrimEnd().TrimEnd('|') -split '\|').Count) {
            $lines[$i] = ($cells -join '|') + '|'
        }
    }

    if ($touched) { [System.IO.File]::WriteAllLines($full, $lines, $utf8); $fixed++ }
}
"$fixed area file(s) repaired."
