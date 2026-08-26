# Measures how fast a sealed bundle can be streamed for judging.
#
# WHAT THIS ANSWERS. Judging reads every object in a bundle once. This walks exactly the path a
# judging run walks - BundleReader.StreamObjects - and reports how long it takes and how many
# objects a second that is. It runs no rules, so the number is the floor: the I/O cost that every
# rule catalogue shares, before any rule does any work.
#
# WHY IT IS A TOOL AND NOT A TEST. The answer depends on the machine, the disk and the size of the
# forest, so it is not something a build can assert. Run it against a real bundle on the machine
# that will do the judging.
#
# USAGE
#   pwsh -File next/tools/measure-judging-throughput.ps1 -BundlePath 'D:\audits\contoso-2026-08-25'

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $BundlePath,

    # Where the built assemblies are. See judge-bundle.ps1 for why this exists.
    [string] $BinPath
)

$ErrorActionPreference = 'Stop'

$candidates = @()
if ($BinPath) { $candidates += $BinPath }
$candidates += $PSScriptRoot
$candidates += (Join-Path $PSScriptRoot '..\tests\SecureAD.Next.Tests\bin\Debug\net10.0-windows')

$bin = $null
foreach ($candidate in $candidates) {
    $full = [System.IO.Path]::GetFullPath($candidate)
    if (Test-Path (Join-Path $full 'SecureAD.Evidence.dll')) { $bin = $full; break }
}

if (-not $bin) {
    $looked = ($candidates | ForEach-Object { '  ' + [System.IO.Path]::GetFullPath($_) }) -join [Environment]::NewLine
    throw "Could not find SecureAD.Evidence.dll. Looked in:$([Environment]::NewLine)$looked"
}

$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SecureAD.Kernel.dll'))
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SecureAD.Evidence.dll'))

# SQLite's managed provider needs its native library, which sits under a runtime identifier folder
# that only the .NET host resolves - PowerShell's loader does not. So the native directory goes on
# PATH and the batteries are initialised by hand. Without this the first connection fails with a
# type initialiser error that says nothing about the real cause.
$architecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString().ToLowerInvariant()
$native = Join-Path $bin "runtimes\win-$architecture\native\e_sqlite3.dll"

if (-not (Test-Path $native)) {
    throw "The native SQLite library is missing. This process is $architecture, so it needs '$native'. Copy the build output folder across whole, including runtimes\."
}

$null = [System.Runtime.InteropServices.NativeLibrary]::Load($native)

$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SQLitePCLRaw.core.dll'))
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SQLitePCLRaw.provider.e_sqlite3.dll'))
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SQLitePCLRaw.batteries_v2.dll'))
[SQLitePCL.Batteries_V2]::Init()

# The bundle path is made absolute before anything changes directory under our feet.
$BundlePath = [System.IO.Path]::GetFullPath($BundlePath)
Push-Location $bin

try {

$opened = [SecureAD.Evidence.BundleReader]::Open($BundlePath)

if (-not $opened.IsSuccess) {
    throw "Could not open '$BundlePath': $($opened.Error.Code) - $($opened.Error.Description)"
}

$reader = $opened.Value

try {
    $description = $reader.Description

    Write-Host ''
    Write-Host "Forest              $($description.ForestFqdn)"
    Write-Host "Captured            $($description.CaptureCompletedUtc)"
    Write-Host ("Evidence            {0:N0} bytes" -f (Get-Item (Join-Path $BundlePath 'evidence.db')).Length)

    # The whole point of the measurement: one pass, counting, holding nothing.
    $objects = $reader.StreamObjects()

    $count = 0
    $withGuid = 0
    $watch = [System.Diagnostics.Stopwatch]::StartNew()

    foreach ($o in $objects.Objects) {
        $count++
        if ($null -ne $o.ObjectGuid) { $withGuid++ }
    }

    $watch.Stop()

    $seconds = $watch.Elapsed.TotalSeconds
    $rate = if ($seconds -gt 0) { $count / $seconds } else { 0 }

    Write-Host ''
    Write-Host ("Objects streamed    {0:N0}" -f $count)
    Write-Host ("With an objectGUID  {0:N0}" -f $withGuid)
    Write-Host "Every declared unit read  $($objects.IsComplete)"
    Write-Host ''
    Write-Host ("Elapsed             {0:N2} s" -f $seconds)
    Write-Host ("Rate                {0:N0} objects/second" -f $rate)

    if ($rate -gt 0) {
        Write-Host ''
        Write-Host 'At this rate:'
        foreach ($size in 100000, 1000000, 5000000) {
            Write-Host ("  {0,-12:N0} objects would take {1,8:N1} s" -f $size, ($size / $rate))
        }
    }

    Write-Host ''
    Write-Host 'This is the read cost only. The two delegation rules add a handful of'
    Write-Host 'comparisons per object, which is expected to be small beside the I/O.'
    Write-Host ''
}
finally {
    $reader.Dispose()
}

}
finally {
    Pop-Location
}
