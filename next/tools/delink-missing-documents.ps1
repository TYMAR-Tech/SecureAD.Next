param([switch]$Apply)

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Turns [text](path/to/missing.md) into plain text, so archiving a document never deletes a
# sentence - only the clickable target. Keyed on whether the target EXISTS rather than on a
# list of archived paths, which means it works after the files are already gone and cannot be
# fooled by two documents sharing a file name.
#
# Reads and writes with an explicit UTF-8 encoder. Get-Content -Raw uses the system codepage
# on Windows PowerShell 5.1, so every em dash returns as three wrong characters and is written
# back as UTF-8 - silent double-encoding across every file touched. That happened once.
$utf8 = New-Object System.Text.UTF8Encoding $false
$changed = 0
foreach ($file in (git ls-files 'docs/*.md')) {
    $full = (Resolve-Path $file).Path
    $dir = Split-Path $full -Parent
    $orig = [System.IO.File]::ReadAllText($full, [System.Text.Encoding]::UTF8)
    $new = [regex]::Replace($orig, '\[([^\]]+)\]\(([^)#]+\.md)[^)]*\)', {
        param($m)
        $t = [System.IO.Path]::GetFullPath((Join-Path $dir $m.Groups[2].Value))
        if (Test-Path -LiteralPath $t) { $m.Value } else { $m.Groups[1].Value }
    })
    if ($new -ne $orig) {
        $changed++
        "$file"
        if ($Apply) { [System.IO.File]::WriteAllText($full, $new, $utf8) }
    }
}
"$changed document(s) " + $(if ($Apply) { 'rewritten' } else { 'would change - rerun with -Apply' })
