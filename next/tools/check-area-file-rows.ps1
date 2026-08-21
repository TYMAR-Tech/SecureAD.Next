# Finds findings rows in docs/areas/*.md whose identifier cell has been lost.
#
# Why this exists. Editing a markdown table row of a thousand-odd characters with a text-
# replacement tool silently dropped the leading cells three times on 2026-08-21, turning
# "| `F-0079-8` | ... | **closed.** ... |" into "| **closed.** ... |". Nothing caught it:
# the line count is unchanged, so `git diff --numstat` reconciles, and no gate reads the
# shape of these tables. The damage is invisible until somebody looks for a finding by its
# identifier and does not find it.
#
# A findings row states a status. If it states one and its first cell carries neither a
# backticked identifier nor the em dash used for findings that never got one, its opener
# was lost.

$ErrorActionPreference = 'Stop'

$areas = Join-Path $PSScriptRoot '..\..\docs\areas'
$status = '\*\*(open|closed|half closed|believed closed|moved, still open|did not reproduce)'
$damaged = 0

foreach ($file in Get-ChildItem $areas -Filter *.md | Sort-Object Name) {
    $lines = [System.IO.File]::ReadAllLines($file.FullName, [System.Text.Encoding]::UTF8)

    for ($i = 0; $i -lt $lines.Length; $i++) {
        $line = $lines[$i]

        if (-not $line.StartsWith('|') -or $line -notmatch $status) { continue }

        $first = ($line -split '\|')[1].Trim()

        if ($first -match '^`[A-Z]+-[0-9A-Za-z-]+`$' -or $first -eq [char]0x2014) { continue }

        $damaged++
        '{0}:{1}  {2}' -f $file.Name, ($i + 1), $line.Substring(0, [Math]::Min(70, $line.Length))
    }
}

"Findings rows with a lost identifier: $damaged"
if ($damaged -gt 0) { exit 1 }
