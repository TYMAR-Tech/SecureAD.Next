#Requires -Version 7.0
# Windows PowerShell 5.1 reads UTF-8 files as Windows-1252, turning every em dash into three
# characters. This script writes documents, so running it under 5.1 would corrupt them silently.

$ErrorActionPreference = 'Stop'

$root = 'C:\Users\jistrand\source\repos\razamus\SecureAD.Next'
$scan = Join-Path $root 'next\tests\SecureAD.Next.Tests\Architecture\SurfaceRegister.cs'
$sln  = Join-Path $root 'next\SecureAD.Next.sln'

function Invoke-Suite {
    Push-Location (Join-Path $root 'next')
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $out = & dotnet test $sln --nologo --filter 'FullyQualifiedName~SurfaceRegisterTests' 2>&1
    $ErrorActionPreference = $previous
    Pop-Location
    $build = ($out | Select-String -Pattern 'error CS' | Select-Object -First 1)
    if ($build) { return "BUILD ERROR: $build" }
    $line = ($out | Select-String -Pattern 'Failed:\s+\d+, Passed:\s+\d+' | Select-Object -First 1)
    $names = ($out | Select-String -Pattern '\[FAIL\]' | ForEach-Object { $_.ToString().Trim() })
    if (-not $line) { return 'NO SUMMARY LINE' }
    return ($line.ToString().Trim() + "`n      " + ($names -join "`n      "))
}

function Mutate([string]$anchor, [string]$replacement, [string]$label) {
    $original = [System.IO.File]::ReadAllText($scan)
    if ($original -notmatch [regex]::Escape($anchor)) {
        throw "Anchor not found for $label."
    }
    $mutated = $original.Replace($anchor, $replacement)
    if ($mutated -eq $original) { throw "Mutation $label changed nothing." }
    [System.IO.File]::WriteAllText($scan, $mutated)
    $result = Invoke-Suite
    [System.IO.File]::WriteAllText($scan, $original)
    if ([System.IO.File]::ReadAllText($scan) -ne $original) { throw "Revert of $label failed." }
    return "$label`n      $result"
}

$results = @()
$results += "BASELINE`n      " + (Invoke-Suite)

$results += Mutate `
    'Add(System.IO.Path.Combine(RepositoryLocation.Root(), "docs", "areas"), "areas");' `
    '' `
    'E. docs scan stops walking docs/areas'

$results += Mutate `
    'Add(System.IO.Path.Combine(LayerDocuments.Root(), subsystem), "layers/" + subsystem);' `
    '{ }' `
    'F. docs scan stops walking docs/layers'

$results | ForEach-Object { Write-Output $_; Write-Output '' }
