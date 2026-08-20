$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Replaces the 2026-09-XX placeholders written during the documentation clean with the real
# date. They were placed because the session did not know the date and would not guess; the
# guess would have been wrong by three weeks and in the future.
#
# DocumentationDateGateTests already refuses a date that has not happened, but an unparseable
# placeholder slipped straight through it - the gate is strengthened alongside this.
$today = (Get-Date -Format 'yyyy-MM-dd')
$utf8 = New-Object System.Text.UTF8Encoding $false
$changed = 0
foreach ($file in @(git ls-files 'docs/*.md') + @('.github/copilot-instructions.md')) {
    $full = (Resolve-Path $file).Path
    $text = [System.IO.File]::ReadAllText($full, [System.Text.Encoding]::UTF8)
    if ($text -notmatch '\d{4}-\d{2}-XX') { continue }
    [System.IO.File]::WriteAllText($full, ([regex]::Replace($text, '\d{4}-\d{2}-XX', $today)), $utf8)
    $changed++
    "  $file"
}
"$changed file(s) given the real date, $today."
