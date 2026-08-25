#Requires -Version 7.0
# Windows PowerShell 5.1 reads UTF-8 files as Windows-1252, turning every em dash into three
# characters. This script writes documents, so running it under 5.1 would corrupt them silently.

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Adds a "Confirmed in lab" column to every "What is built" table. A unit test proves the code
# does what the test says; it says nothing about whether the product works against a real
# Active Directory. Only the owner can answer that, and until now there was nowhere to write
# the answer down, so it lived in his head and was periodically redone.
#
# Blank is the honest default and means "unit-tested, not yet seen against a real forest".
$utf8 = New-Object System.Text.UTF8Encoding $false
$changed = 0
foreach ($file in (git ls-files 'docs/areas/*.md')) {
    $full = (Resolve-Path $file).Path
    $lines = [System.IO.File]::ReadAllLines($full, [System.Text.Encoding]::UTF8)
    $inBuilt = $false
    $touched = $false

    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^##\s') { $inBuilt = $lines[$i] -match '^##\s+What is built' }
        if (-not $inBuilt -or $lines[$i] -notmatch '^\|') { continue }
        if ($lines[$i] -match '\|\s*Confirmed in lab\s*\|') { continue }

        if ($lines[$i] -match '^\|\s*An operator can') { $lines[$i] = $lines[$i].TrimEnd() + ' Confirmed in lab |'; $touched = $true }
        elseif ($lines[$i] -match '^\|\s*-{2,}') { $lines[$i] = $lines[$i].TrimEnd() + '---|'; $touched = $true }
        else { $lines[$i] = $lines[$i].TrimEnd() + '  |'; $touched = $true }
    }

    if ($touched) {
        [System.IO.File]::WriteAllLines($full, $lines, $utf8)
        $changed++
    }
}
"$changed area file(s) given a lab column."
