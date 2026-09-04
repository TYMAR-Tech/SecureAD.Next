<#
.SYNOPSIS
    Checks the roadmap's stage statuses, and the rule count, against the code.

.DESCRIPTION
    A status is the one documentation claim that goes false without anyone editing the document. A
    wrong sentence needs somebody to write it; a wrong status needs only for the product to improve
    while the file sits still. That is why proof-reading never catches one, and why a check
    comparing two documents cannot either - both copies stay perfectly consistent with each other
    and go quietly false together.

    Measured on 2026-09-04 and recorded as P-135: six of the eight check-*.ps1 gates compared
    documents against documents. In that gap, ROADMAP.md carried Stage 5 as "not started" while
    group expansion had been built and had two consumers, WHAT-THE-PRODUCT-IS.md said judging was
    built with "two rules" while fourteen existed, and the acceptance manifest reported ninety-eight
    criteria "not started" while naming a hundred tests that had never been written.

    So this gate reads the code.

    HOW A STAGE IS DECIDED. Each row of the roadmap's "Where we are" table names a Witness: a type
    that exists if and only if the stage is built. The check runs BOTH WAYS.

      - a row claiming built or started whose witness is absent  -> failure
      - a row claiming not started whose witness is PRESENT      -> failure

    The second direction is the one that matters and the one nothing had before. A stage does not
    get quietly finished; the day its witness appears, this fails until somebody updates the row.

    A WITNESS IS A TYPE DECLARATION, NOT A STRING. It is matched as (class|record|struct|interface|
    enum) followed by the name, because a plain search counts prose. Both "Chokepoint" and
    "Reachability" appear in this repository today, in comments describing things that do not exist,
    and either would have made a false witness for an unbuilt stage.

    A WITNESS IS A PROXY AND THIS GATE IS A TRIPWIRE, NOT A PROOF. It can show that the named type
    is there or not there. It cannot show that a stage is finished, and a witness chosen badly - one
    naming a type that exists but that nothing calls - would pass while the stage was hollow. That
    is why Stage 2's witness is DashboardViewModel and not Dashboard: a Dashboard member already
    exists in ShellSection as a deliberately empty navigation tab, and the obvious witness would
    have reported the stage built while the screen showed nothing.

    THE RULE COUNT is checked the same way and for the same reason: it is a number in a sentence,
    and numbers in sentences rot. It is counted from the rule identifiers declared in
    SecureAD.Judgement and compared against the claim in WHAT-THE-PRODUCT-IS.md.

    Reads with an explicit UTF-8 decoder. Get-Content -Raw uses the system codepage on Windows
    PowerShell 5.1 and has silently double-encoded documents in this repository before.

.PARAMETER SelfTest
    Proves the gate can fail, rather than trusting that it would. Runs the checks against fabricated
    inputs whose answers are known: a stage marked not started whose witness exists, a stage marked
    built whose witness does not, and a wrong rule count. Every gate in this repository carries one,
    because a gate that cannot be shown to fail is indistinguishable from a gate that measures
    nothing - which this repository has now produced three times.

.NOTES
    Exit code 0 when the documents and the code agree, 1 otherwise.
#>
[CmdletBinding()]
param(
    [string] $Roadmap,
    [string] $Product,
    [string] $Source,
    [switch] $SelfTest
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not $Roadmap) { $Roadmap = Join-Path $repoRoot 'docs\ROADMAP.md' }
if (-not $Product) { $Product = Join-Path $repoRoot 'docs\WHAT-THE-PRODUCT-IS.md' }
if (-not $Source)  { $Source  = Join-Path $repoRoot 'next\src' }

function Read-Utf8Lines([string] $path) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Not found: $path" }
    return [System.IO.File]::ReadAllLines($path, [System.Text.UTF8Encoding]::new($false))
}

# Statuses that assert the thing exists. Anything else asserts it does not.
$BuiltStatuses = @('built', 'started')

<#
.SYNOPSIS
    Every stage row of the roadmap's "Where we are" table, as id, status and witness.
#>
function Get-StageRows([string[]] $lines) {
    $rows = @()

    foreach ($line in $lines) {
        # Four cells, the last a backticked type name. The separator row and the prose around the
        # table both fail this, so the table is found by its shape rather than by counting lines
        # from a heading - which would break the first time a paragraph was added above it.
        if ($line -notmatch '^\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*`([A-Za-z0-9_]+)`\s*\|\s*$') {
            continue
        }

        $rows += [pscustomobject]@{
            Stage   = $Matches[1]
            What    = $Matches[2]
            Status  = ($Matches[3] -replace '\*', '').Trim().ToLowerInvariant()
            Witness = $Matches[4]
        }
    }

    return $rows
}

<#
.SYNOPSIS
    Whether a type of this name is declared anywhere under the source tree.
#>
function Test-Witness([string] $name, [System.IO.FileInfo[]] $files) {
    $pattern = '(class|record|struct|interface|enum)\s+' + [regex]::Escape($name) + '\b'

    foreach ($file in $files) {
        $text = [System.IO.File]::ReadAllText($file.FullName, [System.Text.UTF8Encoding]::new($false))
        if ($text -match $pattern) { return $true }
    }

    return $false
}

<#
.SYNOPSIS
    The distinct rule identifiers declared in the judgement assembly.
#>
function Get-RuleIds([System.IO.FileInfo[]] $files) {
    $ids = @()

    foreach ($file in $files) {
        if ($file.FullName -notmatch 'SecureAD\.Judgement') { continue }

        $text = [System.IO.File]::ReadAllText($file.FullName, [System.Text.UTF8Encoding]::new($false))
        foreach ($m in [regex]::Matches($text, '"(SEC-\d+)"')) { $ids += $m.Groups[1].Value }
    }

    return ($ids | Sort-Object -Unique)
}

<#
.SYNOPSIS
    Compares stage rows and the rule count against the code, returning the failures found.
#>
function Get-Failures($rows, [int] $ruleCount, [string[]] $productLines, [scriptblock] $witnessTest) {
    $failures = @()

    foreach ($row in $rows) {
        $present = & $witnessTest $row.Witness
        $claimsBuilt = $BuiltStatuses -contains $row.Status

        if ($claimsBuilt -and -not $present) {
            $failures += "Stage $($row.Stage) says '$($row.Status)' but its witness ``$($row.Witness)`` is declared nowhere in the source. Either the stage is not built, or the witness names the wrong type."
        }

        if (-not $claimsBuilt -and $present) {
            $failures += "Stage $($row.Stage) says '$($row.Status)' but its witness ``$($row.Witness)`` IS declared in the source. The stage looks finished and the roadmap has not caught up - which is exactly how Stage 5 went unnoticed."
        }
    }

    # The claim reads "built, N rules". Matched loosely on the number so a reworded sentence does
    # not silently stop being checked.
    $claimed = $null
    foreach ($line in $productLines) {
        if ($line -match 'built,\s*(\d+)\s*rules') { $claimed = [int]$Matches[1]; break }
    }

    if ($null -eq $claimed) {
        $failures += "No 'built, N rules' claim found in the product document. It was there to be checked and now is not, so either the wording changed or the claim was dropped."
    }
    elseif ($claimed -ne $ruleCount) {
        $failures += "The product document claims $claimed rules; $ruleCount rule identifiers are declared in SecureAD.Judgement."
    }

    return $failures
}

if ($SelfTest) {
    Write-Host 'Self-test: proving this gate fails when it should.'

    $fakeRows = @(
        [pscustomobject]@{ Stage = '5'; What = 'x'; Status = 'not started'; Witness = 'PresentType' },
        [pscustomobject]@{ Stage = '6'; What = 'y'; Status = 'built';       Witness = 'AbsentType'  }
    )

    $fakeWitness = { param($n) return $n -eq 'PresentType' }
    $fakeProduct = @('| Judge | ... | built, 99 rules |')

    $found = Get-Failures $fakeRows 14 $fakeProduct $fakeWitness

    $expected = @(
        @{ Name = 'not-started stage whose witness exists'; Match = "Stage 5 says 'not started'" },
        @{ Name = 'built stage whose witness is absent';    Match = "Stage 6 says 'built'"       },
        @{ Name = 'rule count disagreeing with the code';   Match = 'claims 99 rules'            }
    )

    $missed = @()
    foreach ($case in $expected) {
        if (-not ($found | Where-Object { $_ -like "*$($case.Match)*" })) { $missed += $case.Name }
    }

    foreach ($case in $expected) {
        $ok = if ($missed -contains $case.Name) { 'NOT CAUGHT' } else { 'caught' }
        Write-Host ("  {0,-42} {1}" -f $case.Name, $ok)
    }

    # A clean input must produce nothing. Without this the self-test would pass against a checker
    # that returned a failure for every row it was handed.
    $cleanRows = @([pscustomobject]@{ Stage = '1'; What = 'x'; Status = 'built'; Witness = 'PresentType' })
    $clean = Get-Failures $cleanRows 14 @('built, 14 rules') $fakeWitness

    if ($clean.Count -ne 0) {
        Write-Host '  clean input produced failures        NOT CLEAN'
        $missed += 'clean input'
    }
    else {
        Write-Host ("  {0,-42} {1}" -f 'clean input produces no failures', 'clean')
    }

    if ($missed.Count -gt 0) {
        Write-Host ''
        Write-Host "SELF-TEST FAILED: $($missed -join '; ')"
        exit 1
    }

    Write-Host ''
    Write-Host 'Self-test OK: the gate catches all three, and stays quiet on clean input.'
    exit 0
}

$roadmapLines = Read-Utf8Lines $Roadmap
$productLines = Read-Utf8Lines $Product
$sourceFiles  = @(Get-ChildItem $Source -Recurse -Filter *.cs -File)

$rows = Get-StageRows $roadmapLines

if ($rows.Count -eq 0) {
    Write-Host "No stage rows found in $Roadmap. The table shape changed, so this gate is measuring nothing."
    exit 1
}

$ruleIds = @(Get-RuleIds $sourceFiles)

$failures = Get-Failures $rows $ruleIds.Count $productLines { param($n) Test-Witness $n $sourceFiles }

Write-Host "Method: each stage's witness is looked for as a type declaration under $Source, both directions asserted."
Write-Host "Roadmap $Roadmap : $($rows.Count) stage rows"
Write-Host "Rules declared in SecureAD.Judgement: $($ruleIds.Count) ($($ruleIds -join ', '))"

foreach ($row in $rows) {
    $present = Test-Witness $row.Witness $sourceFiles
    Write-Host ("  {0,-4} {1,-12} {2,-34} {3}" -f $row.Stage, $row.Status, $row.Witness, $(if ($present) { 'present' } else { 'absent' }))
}

if ($failures.Count -gt 0) {
    Write-Host ''
    foreach ($failure in $failures) { Write-Host "FAIL: $failure" }
    exit 1
}

Write-Host ''
Write-Host 'OK'
exit 0
