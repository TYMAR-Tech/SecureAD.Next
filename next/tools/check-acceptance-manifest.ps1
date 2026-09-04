<#
.SYNOPSIS
    Reconciles the acceptance-criteria manifest against the spec it was extracted from.

.DESCRIPTION
    JUDGEMENT-HALF-ACCEPTANCE.md restates 100 criteria from JUDGEMENT-HALF.md so each can carry the
    kind of external anchor it will need. A restatement is a second copy, and a second copy drifts -
    which is the fault this repository has already paid for twice in this very document, where one
    fact was corrected in one place and left stale in others.

    So the manifest is not trusted to be right, it is checked. Ids are extracted by regex from both
    documents and differenced in both directions; the criterion text is compared character for
    character. Either direction failing is a failure: a criterion in the spec with no row means an
    anchor nobody chose, and a row with no criterion means an anchor for something the spec no
    longer says.

    WHAT THIS CANNOT TELL YOU, AND MUST NOT BE READ AS TELLING YOU. This compares two documents. It
    reads no code and says nothing about whether anything is built, tested or correct. That
    distinction is not pedantry: until 2026-09-04 the manifest also carried a Test name and a
    Status, this check passed against them for months, and not one of the hundred named tests had
    ever existed. See P-135. Whether a stage is built is answered by check-stage-status.ps1, which
    reads the code.

    This is not a prose check. It derives everything it expects from the source document, and the
    change that makes it fail is an edit to a criterion - not a heading, a status line or a format.

    Reads with an explicit UTF-8 decoder. Get-Content -Raw uses the system codepage on Windows
    PowerShell 5.1 and has silently double-encoded documents in this repository before.

.NOTES
    Exit code 0 when the two agree, 1 otherwise.
#>
[CmdletBinding()]
param(
    [string] $Spec,
    [string] $Manifest
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not $Spec)     { $Spec     = Join-Path $repoRoot 'docs\layers\specs\JUDGEMENT-HALF.md' }
if (-not $Manifest) { $Manifest = Join-Path $repoRoot 'docs\layers\specs\JUDGEMENT-HALF-ACCEPTANCE.md' }

function Read-Utf8([string] $path) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Not found: $path" }
    return [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
}

# A table row is split on unescaped pipes and its cell count asserted, because an edit that
# silently drops a cell has truncated a sentence in this document before while reporting a no-op.
function Get-Rows([string] $text, [int] $expectedCells, [string] $label) {
    $rows = [ordered]@{}
    foreach ($line in ($text -split "`r?`n")) {
        if ($line -notmatch '^\|\s*(AC-\d+)\s*\|') { continue }

        $cells = $line.Trim().Trim('|') -split '(?<!\\)\|'
        if ($cells.Count -ne $expectedCells) {
            throw "$label row $($cells[0].Trim()) has $($cells.Count) cells, expected $expectedCells"
        }

        $id = $cells[0].Trim()
        if ($rows.Contains($id)) { throw "$label lists $id more than once" }

        $rows[$id] = $cells[1].Trim()
    }
    return $rows
}

$specRows     = Get-Rows (Read-Utf8 $Spec)     2 'Spec'
$manifestRows = Get-Rows (Read-Utf8 $Manifest) 3 'Manifest'

Write-Host "Method: ids matched by regex '^\|\s*(AC-\d+)\s*\|' in both documents, differenced each way."
Write-Host "Spec     $Spec : $($specRows.Count) criteria"
Write-Host "Manifest $Manifest : $($manifestRows.Count) rows"

$failed = $false

$missingFromManifest = @($specRows.Keys | Where-Object { -not $manifestRows.Contains($_) })
$extraInManifest     = @($manifestRows.Keys | Where-Object { -not $specRows.Contains($_) })

Write-Host "In spec but not manifest: $($missingFromManifest.Count) $($missingFromManifest -join ', ')"
Write-Host "In manifest but not spec: $($extraInManifest.Count) $($extraInManifest -join ', ')"

if ($missingFromManifest.Count -or $extraInManifest.Count) { $failed = $true }

# The manifest exists to make drift visible, so a reworded criterion is the whole point.
$reworded = @()
foreach ($id in $specRows.Keys) {
    if (-not $manifestRows.Contains($id)) { continue }
    if ($manifestRows[$id] -cne $specRows[$id]) { $reworded += $id }
}

Write-Host "Criteria whose text differs: $($reworded.Count) $($reworded -join ', ')"
if ($reworded.Count) {
    $failed = $true
    foreach ($id in $reworded) {
        Write-Host "  $id"
        Write-Host "    spec:     $($specRows[$id])"
        Write-Host "    manifest: $($manifestRows[$id])"
    }
}

# Source order is preserved deliberately - AC-100 sits between AC-98 and AC-99 - so the two tables
# can be read line against line. Normalising it here would hide a reordering of either.
$specOrder     = @($specRows.Keys) -join ','
$manifestOrder = @($manifestRows.Keys) -join ','
if ($specOrder -cne $manifestOrder) {
    $failed = $true
    Write-Host 'Row order differs between the two documents.'
}
else {
    Write-Host 'Row order matches source order.'
}

if ($failed) {
    Write-Host 'FAILED'
    exit 1
}

Write-Host 'OK'
exit 0
