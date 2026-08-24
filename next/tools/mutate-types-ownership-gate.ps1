# Mutation harness for TypesTableOwnershipTests, the gate that binds a layer page's TYPES table to
# the surface register.
#
# The gate was first observed failing on two real defects rather than on a mutation - IDirectoryChannel
# and IDirectoryChannelFactory were claimed by how-a-controller-is-read.md while the register assigned
# both to an area file. That is stronger evidence than anything below, but it is not repeatable once
# fixed, so these four mutations stand in for it.
#
# Every replacement is asserted to have changed something. The pages are stored with CRLF endings, so
# a harness that matches an anchor plus "`n" mutates nothing and reports the gate as passing while
# measuring nothing at all.

$ErrorActionPreference = 'Stop'

$root     = 'C:\Users\jistrand\source\repos\razamus\SecureAD.Next'
$register = Join-Path $root 'docs\next\SURFACE-REGISTER.md'
$bundle   = Join-Path $root 'docs\layers\evidence\the-bundle-on-disk.md'
$kernel   = Join-Path $root 'docs\layers\kernel\how-failure-is-reported.md'
$sln      = Join-Path $root 'next\SecureAD.Next.sln'

$filter = 'FullyQualifiedName~TypesTableOwnershipTests'

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

$registerOriginal = [System.IO.File]::ReadAllText($register)
$bundleOriginal   = [System.IO.File]::ReadAllText($bundle)
$kernelOriginal   = [System.IO.File]::ReadAllText($kernel)

# --- Baseline -------------------------------------------------------------------
$results += "BASELINE (no mutation)`n      " + (Invoke-Suite)

# --- A: the register gives a claimed type to somebody else -----------------------
$anchorA = '| RunOutcome | SecureAD.Evidence | [the-bundle-on-disk](../layers/evidence/the-bundle-on-disk.md) |'
$replaceA = '| RunOutcome | SecureAD.Evidence | [how-a-bundle-is-read](../layers/evidence/how-a-bundle-is-read.md) |'
Set-Mutation $register $registerOriginal $registerOriginal.Replace($anchorA, $replaceA) 'A'
$results += "A. register moves RunOutcome to a page that does not claim it`n      " + (Invoke-Suite)
[System.IO.File]::WriteAllText($register, $registerOriginal)

# --- B: a page claims a type with no register row --------------------------------
$anchorB = '| `RunOutcome` | Which bad ending it was |'
Set-Mutation $bundle $bundleOriginal `
    $bundleOriginal.Replace($anchorB, "| ``NotAPublicTypeAnywhere`` | invented |`r`n" + $anchorB) 'B'
$results += "B. bundle page claims a type the register has never heard of`n      " + (Invoke-Suite)
[System.IO.File]::WriteAllText($bundle, $bundleOriginal)

# --- C: two pages claim one type -------------------------------------------------
$anchorC = '| `AuditError` |'
Set-Mutation $kernel $kernelOriginal `
    $kernelOriginal.Replace($anchorC, "| ``RunOutcome`` | claimed here as well |`r`n" + $anchorC) 'C'
$results += "C. kernel page also claims RunOutcome`n      " + (Invoke-Suite)
[System.IO.File]::WriteAllText($kernel, $kernelOriginal)

# --- D: a page opens a TYPES block and claims nothing ----------------------------
$startD = $kernelOriginal.IndexOf('<!-- TYPES:BEGIN -->')
$endD   = $kernelOriginal.IndexOf('<!-- TYPES:END -->')
if ($startD -lt 0 -or $endD -le $startD) { throw 'Refusing to mutate: no TYPES block on the kernel page.' }
$emptied = $kernelOriginal.Substring(0, $startD) + '<!-- TYPES:BEGIN -->' + "`r`n`r`n" + $kernelOriginal.Substring($endD)
Set-Mutation $kernel $kernelOriginal $emptied 'D'
$results += "D. kernel page opens a TYPES block and fills it with nothing`n      " + (Invoke-Suite)
[System.IO.File]::WriteAllText($kernel, $kernelOriginal)

# --- Confirm the tree is back ---------------------------------------------------
$results += 'REVERTED register identical    : ' + ([System.IO.File]::ReadAllText($register) -eq $registerOriginal)
$results += 'REVERTED bundle page identical : ' + ([System.IO.File]::ReadAllText($bundle) -eq $bundleOriginal)
$results += 'REVERTED kernel page identical : ' + ([System.IO.File]::ReadAllText($kernel) -eq $kernelOriginal)

$results | ForEach-Object { Write-Output $_; Write-Output '' }
