<#
.SYNOPSIS
    Reverses a Windows-1252 round-trip in markdown documents.

.DESCRIPTION
    The corruption is deterministic, not random. UTF-8 text read back through the Windows-1252
    code page turns one character into three: an em dash becomes U+00E2 U+20AC U+201D, an en
    dash becomes U+00E2 U+20AC U+201C, an ellipsis becomes U+00E2 U+20AC U+00A6. PowerShell's
    Set-Content -Encoding utf8 did this to twenty-nine documents in one pass.

    Because the mapping is one-way and total, it inverts exactly: encode the three characters
    back to their 1252 bytes and decode those bytes as UTF-8. Nothing is guessed.

    Only sequences beginning U+00E2 U+20AC are touched, and only where the three bytes decode
    to a single character. Anything that does not round-trip is left alone and reported.

.PARAMETER WhatIf
    Report what would change and write nothing.
#>
[CmdletBinding(SupportsShouldProcess)]
param()

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

$cp1252 = [System.Text.Encoding]::GetEncoding(1252)
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

# Every three-character sequence a 1252 round-trip can produce from one UTF-8 character, built
# by performing the corruption rather than by listing its results. A hand-written table would be
# the same class of guess this script exists to avoid.
$map = @{}
foreach ($ch in '—', '–', '…', '“', '”', '‘', '’', '•', '′', '″', '™', '€') {
    $corrupted = $cp1252.GetString([System.Text.Encoding]::UTF8.GetBytes($ch))
    if ($corrupted -ne $ch) { $map[$corrupted] = $ch }
}

$repaired = 0
$untouched = @()

foreach ($file in (git ls-files '*.md')) {
    if (-not (Test-Path $file)) { continue }

    $path = (Resolve-Path $file).Path
    $text = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
    if ($text -notmatch "\u00E2\u20AC") { continue }

    $fixed = $text
    $changes = 0
    foreach ($entry in $map.GetEnumerator()) {
        $count = ([regex]::Matches($fixed, [regex]::Escape($entry.Key))).Count
        if ($count -gt 0) {
            $fixed = $fixed.Replace($entry.Key, $entry.Value)
            $changes += $count
        }
    }

    $left = ([regex]::Matches($fixed, "\u00E2\u20AC")).Count
    if ($left -gt 0) {
        $untouched += "  {0,4} sequences not in the map  {1}" -f $left, $file
    }

    if ($changes -eq 0) { continue }

    if ($PSCmdlet.ShouldProcess($file, "repair $changes sequences")) {
        [System.IO.File]::WriteAllText($path, $fixed, $utf8NoBom)
    }

    $repaired++
    "{0,5} repaired  {1}" -f $changes, $file
}

"Documents repaired: $repaired"

if ($untouched.Count -gt 0) {
    ''
    'Left alone, because they are not a 1252 round-trip this script can invert:'
    $untouched
}
