#Requires -Version 7.0
# Windows PowerShell 5.1 reads UTF-8 files as Windows-1252, turning every em dash into three
# characters. This script writes documents, so running it under 5.1 would corrupt them silently.

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Removes the index rows for decision records that no longer exist. DecisionIndexTests binds
# docs/DECISIONS.md to docs/decisions/ in both directions, so a row for a removed record fails
# the build - as it should.
#
# Reads and writes UTF-8 explicitly; Get-Content -Raw would decode with the system codepage
# and silently double-encode every em dash in the file.
$path = (Resolve-Path 'docs/DECISIONS.md').Path
$text = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
$kept = @()
$dropped = 0
foreach ($line in ($text -split "`r?`n")) {
    $m = [regex]::Match($line, '^\|\s*\[\d+\]\(decisions/([^)]+\.md)\)')
    if ($m.Success -and -not (Test-Path -LiteralPath (Join-Path 'docs/decisions' $m.Groups[1].Value))) {
        $dropped++
        continue
    }
    $kept += $line
}
[System.IO.File]::WriteAllText($path, ($kept -join "`r`n"), (New-Object System.Text.UTF8Encoding $false))
"Dropped $dropped index row(s) for records that no longer exist."
