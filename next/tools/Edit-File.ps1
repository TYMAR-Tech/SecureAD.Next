# Applies a literal text replacement to a file, tolerating CRLF/LF differences in the search text.
#
# Written 2026-09-03 after seven consecutive replace_string_in_file edits reported success and
# reached no file on disk. Every edit here is verified by re-reading the file afterwards, so a
# silent no-op cannot be mistaken for an applied change.
#
# Reads and writes with an explicit UTF-8 decoder, never Get-Content -Raw, per the repository's
# encoding rule.
param(
    [Parameter(Mandatory = $true)][string] $Path,
    [Parameter(Mandatory = $true)][string] $OldText,
    [Parameter(Mandatory = $true)][string] $NewText,
    [switch] $ExpectBom
)

$ErrorActionPreference = 'Stop'

$full = Resolve-Path -LiteralPath $Path
$text = [System.IO.File]::ReadAllText($full, [System.Text.Encoding]::UTF8)

# The file's own line endings win. A search string typed with LF must still match a CRLF file.
$usesCrLf = ([regex]::Matches($text, "`r`n")).Count -gt 0
$old = if ($usesCrLf) { $OldText -replace "`r?`n", "`r`n" } else { $OldText -replace "`r`n", "`n" }
$new = if ($usesCrLf) { $NewText -replace "`r?`n", "`r`n" } else { $NewText -replace "`r`n", "`n" }

$count = ([regex]::Matches($text, [regex]::Escape($old))).Count

if ($count -ne 1) {
    throw "$Path : expected exactly one occurrence, found $count. Nothing written."
}

$encoding = New-Object System.Text.UTF8Encoding ($ExpectBom.IsPresent)
[System.IO.File]::WriteAllText($full, $text.Replace($old, $new), $encoding)

# Read back rather than trust the write. This is the whole point of the script.
$after = [System.IO.File]::ReadAllText($full, [System.Text.Encoding]::UTF8)

if (([regex]::Matches($after, [regex]::Escape($new))).Count -lt 1) {
    throw "$Path : write reported success but the new text is not in the file."
}

Write-Output "applied: $Path"
