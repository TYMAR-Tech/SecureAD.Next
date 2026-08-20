# Replaces one WHAT-THE-OLD-APP-HAD.md row whole, by index, guarded by the component id.
# Written as a script rather than done with the file editor: a partial-line edit has destroyed a
# row four times, most recently C10 on 2026-08-23 (F-S17-6). Rows are single lines of two thousand
# characters or more and the editor does not handle a targeted replacement inside one reliably.
param(
    [Parameter(Mandatory = $true)][string] $ComponentId,
    [Parameter(Mandatory = $true)][string] $NewRowPath
)

$ErrorActionPreference = 'Stop'

$inventory = Join-Path $PSScriptRoot '..\..\docs\next\WHAT-THE-OLD-APP-HAD.md' | Resolve-Path
$lines = [System.IO.File]::ReadAllLines($inventory)

$prefix = '| ' + $ComponentId + ' |'
$matches = @(0..($lines.Length - 1) | Where-Object { $lines[$_].StartsWith($prefix, [StringComparison]::Ordinal) })

if ($matches.Count -ne 1) {
    throw "Expected exactly one row starting '$prefix'; found $($matches.Count)."
}

$index = $matches[0]
$new = [System.IO.File]::ReadAllText($NewRowPath).TrimEnd("`r", "`n")

$oldCells = ($lines[$index] -split '\|').Count
$newCells = ($new -split '\|').Count

if (-not $new.StartsWith($prefix, [StringComparison]::Ordinal)) {
    throw "Replacement row does not start '$prefix'."
}

if ($oldCells -ne $newCells) {
    throw "Cell count changed for $ComponentId : $oldCells -> $newCells. A row that loses a cell is the failure this script exists to prevent."
}

$lines[$index] = $new
[System.IO.File]::WriteAllLines($inventory, $lines)

Write-Output "$ComponentId replaced at line $($index + 1). Cells: $newCells (unchanged)."
