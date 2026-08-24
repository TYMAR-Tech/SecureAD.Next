$ErrorActionPreference = 'Stop'

$root = 'C:\Users\jistrand\source\repos\razamus\SecureAD.Next'
$page = Join-Path $root 'docs\layers\evidence\what-an-objects-permissions-hold.md'
$src  = Join-Path $root 'next\src\SecureAD.Evidence\ObjectPermissions.cs'
$sln  = Join-Path $root 'next\SecureAD.Next.sln'

function Invoke-Suite {
    Push-Location (Join-Path $root 'next')
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $out = & dotnet test $sln --nologo --filter 'FullyQualifiedName~ObjectPermissionsDocumentationTests' 2>&1
    $ErrorActionPreference = $previous
    Pop-Location
    $line = ($out | Select-String -Pattern 'Failed:\s+\d+, Passed:\s+\d+' | Select-Object -First 1)
    $names = ($out | Select-String -Pattern '\[FAIL\]' | ForEach-Object { $_.ToString().Trim() })
    $build = ($out | Select-String -Pattern 'error CS' | Select-Object -First 1)
    if ($build) { return "BUILD ERROR: $build" }
    if (-not $line) { return 'NO SUMMARY LINE' }
    return ($line.ToString().Trim() + "`n      " + ($names -join "`n      "))
}

function Assert-Contains([string]$text, [string]$needle, [string]$what) {
    if ($text -notmatch [regex]::Escape($needle)) {
        throw "Refusing to mutate: $what did not contain the expected anchor."
    }
}

$results = @()

# --- Baseline -------------------------------------------------------------------
$results += "BASELINE (no mutation)`n      " + (Invoke-Suite)

# --- Mutation A: page drops a type it owns --------------------------------------
$original = [System.IO.File]::ReadAllText($page)
$anchor = '| `PermissionTrustee` | The principal an entry names, and what this bundle knows about it |'
Assert-Contains $original $anchor 'the page'
$mutatedA = $original.Replace($anchor, '')
if ($mutatedA -eq $original) { throw 'Mutation A changed nothing; the harness is not mutating.' }
[System.IO.File]::WriteAllText($page, $mutatedA)
$results += "A. page drops the PermissionTrustee row`n      " + (Invoke-Suite)
[System.IO.File]::WriteAllText($page, $original)

# --- Mutation B: code grows a type the page does not claim ----------------------
$originalSrc = [System.IO.File]::ReadAllText($src)
[System.IO.File]::WriteAllText(
    $src, $originalSrc + "`npublic sealed record MutationProbe(string Value);`n")
$results += "B. code adds public MutationProbe`n      " + (Invoke-Suite)
[System.IO.File]::WriteAllText($src, $originalSrc)

# --- Mutation C: enum grows a state the page does not name ----------------------
$anchorC = '    /// <summary>The descriptor was read and is in this bundle.</summary>
    Read,'
Assert-Contains $originalSrc $anchorC 'the enum'
[System.IO.File]::WriteAllText(
    $src, $originalSrc.Replace($anchorC, $anchorC + "`n`n    MutationProbeState,"))
$results += "C. enum adds MutationProbeState`n      " + (Invoke-Suite)
[System.IO.File]::WriteAllText($src, $originalSrc)

# --- Mutation D: page invents a state the enum does not declare -----------------
$anchorD = '| `NotAttempted` |'
Assert-Contains $original $anchorD 'the availability table'
[System.IO.File]::WriteAllText(
    $page, $original.Replace($anchorD, "| ``Invented`` | not a real state |`n" + $anchorD))
$results += "D. page invents an availability state`n      " + (Invoke-Suite)
[System.IO.File]::WriteAllText($page, $original)

# --- Confirm the tree is back ---------------------------------------------------
$results += 'REVERTED page identical : ' + ([System.IO.File]::ReadAllText($page) -eq $original)
$results += 'REVERTED src identical  : ' + ([System.IO.File]::ReadAllText($src) -eq $originalSrc)

$results | ForEach-Object { Write-Output $_; Write-Output '' }
