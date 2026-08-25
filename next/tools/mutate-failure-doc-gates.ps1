#Requires -Version 7.0
# Windows PowerShell 5.1 reads UTF-8 files as Windows-1252, turning every em dash into three
# characters. This script writes documents, so running it under 5.1 would corrupt them silently.

# Mutation harness for the two gates written when docs/areas/how-failures-are-reported.md was
# deleted: FailureReportingDocumentationTests over the new Kernel page, and the TYPES checks added
# to BundleOnDiskDocumentationTests.
#
# Six mutations, three per gate, covering both directions of each ownership table plus the enum
# tables on the Kernel page. Every replacement is asserted to have changed something: the pages are
# stored with CRLF endings, so a harness matching an anchor plus "`n" mutates nothing and reports a
# gate as passing while measuring nothing at all.

$ErrorActionPreference = 'Stop'

$root       = 'C:\Users\jistrand\source\repos\razamus\SecureAD.Next'
$kernelPage = Join-Path $root 'docs\layers\kernel\how-failure-is-reported.md'
$bundlePage = Join-Path $root 'docs\layers\evidence\the-bundle-on-disk.md'
$errorSrc   = Join-Path $root 'next\src\SecureAD.Kernel\AuditError.cs'
$outcomeSrc = Join-Path $root 'next\src\SecureAD.Evidence\Run\RunOutcomeFile.cs'
$sln        = Join-Path $root 'next\SecureAD.Next.sln'

$filter = 'FullyQualifiedName~FailureReportingDocumentationTests|FullyQualifiedName~BundleOnDiskDocumentationTests'

function Invoke-Suite {
    Push-Location (Join-Path $root 'next')
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $out = & dotnet test $sln --nologo --filter $filter 2>&1
    $ErrorActionPreference = $previous
    Pop-Location
    $line  = ($out | Select-String -Pattern 'Failed:\s+\d+, Passed:\s+\d+' | Select-Object -First 1)
    $names = ($out | Select-String -Pattern '\[FAIL\]' | ForEach-Object { $_.ToString().Trim() })
    $build = ($out | Select-String -Pattern 'error CS' | Select-Object -First 1)
    if ($build) { return "BUILD ERROR: $build" }
    if (-not $line) { return 'NO SUMMARY LINE' }
    return ($line.ToString().Trim() + "`n      " + ($names -join "`n      "))
}

function Set-Mutation([string]$path, [string]$original, [string]$mutated, [string]$what) {
    if ($mutated -eq $original) { throw "Mutation '$what' changed nothing; the harness is not mutating." }
    [System.IO.File]::WriteAllText($path, $mutated)
}

$results = @()

$kernelOriginal  = [System.IO.File]::ReadAllText($kernelPage)
$bundleOriginal  = [System.IO.File]::ReadAllText($bundlePage)
$errorOriginal   = [System.IO.File]::ReadAllText($errorSrc)
$outcomeOriginal = [System.IO.File]::ReadAllText($outcomeSrc)

# --- Baseline -------------------------------------------------------------------
$results += "BASELINE (no mutation)`n      " + (Invoke-Suite)

# --- A: the Kernel page drops a type it owns ------------------------------------
$anchorA = '| `ErrorSeverity` | Whether a result survived the failure |'
Set-Mutation $kernelPage $kernelOriginal $kernelOriginal.Replace($anchorA, '') 'A'
$results += "A. kernel page drops the ErrorSeverity row`n      " + (Invoke-Suite)
[System.IO.File]::WriteAllText($kernelPage, $kernelOriginal)

# --- B: the Kernel component grows a type the page does not claim ---------------
Set-Mutation $errorSrc $errorOriginal `
    ($errorOriginal + "`npublic sealed record MutationProbe(string Value);`n") 'B'
$results += "B. AuditError.cs adds public MutationProbe`n      " + (Invoke-Suite)
[System.IO.File]::WriteAllText($errorSrc, $errorOriginal)

# --- C: the Kernel page invents a category the enum does not declare ------------
$anchorC = '| `Shell` |'
Set-Mutation $kernelPage $kernelOriginal `
    $kernelOriginal.Replace($anchorC, "| ``Invented`` | not a real category |`r`n" + $anchorC) 'C'
$results += "C. kernel page invents an error category`n      " + (Invoke-Suite)
[System.IO.File]::WriteAllText($kernelPage, $kernelOriginal)

# --- D: the bundle page drops a type it owns ------------------------------------
$anchorD = '| `RunOutcome` | Which bad ending it was |'
Set-Mutation $bundlePage $bundleOriginal $bundleOriginal.Replace($anchorD, '') 'D'
$results += "D. bundle page drops the RunOutcome row`n      " + (Invoke-Suite)
[System.IO.File]::WriteAllText($bundlePage, $bundleOriginal)

# --- E: the bundle component grows a type the page does not claim ---------------
Set-Mutation $outcomeSrc $outcomeOriginal `
    ($outcomeOriginal + "`npublic sealed record MutationProbe(string Value);`n") 'E'
$results += "E. RunOutcomeFile.cs adds public MutationProbe`n      " + (Invoke-Suite)
[System.IO.File]::WriteAllText($outcomeSrc, $outcomeOriginal)

# --- F: the bundle page claims a type its files do not declare ------------------
$anchorF = '| `RunOutcomeFile` |'
Set-Mutation $bundlePage $bundleOriginal `
    $bundleOriginal.Replace($anchorF, "| ``RunState`` | claimed here as well as elsewhere |`r`n" + $anchorF) 'F'
$results += "F. bundle page claims RunState, which its files do not declare`n      " + (Invoke-Suite)
[System.IO.File]::WriteAllText($bundlePage, $bundleOriginal)

# --- Confirm the tree is back ---------------------------------------------------
$results += 'REVERTED kernel page identical  : ' + ([System.IO.File]::ReadAllText($kernelPage) -eq $kernelOriginal)
$results += 'REVERTED bundle page identical  : ' + ([System.IO.File]::ReadAllText($bundlePage) -eq $bundleOriginal)
$results += 'REVERTED AuditError.cs identical: ' + ([System.IO.File]::ReadAllText($errorSrc) -eq $errorOriginal)
$results += 'REVERTED RunOutcomeFile identical: ' + ([System.IO.File]::ReadAllText($outcomeSrc) -eq $outcomeOriginal)

$results | ForEach-Object { Write-Output $_; Write-Output '' }
