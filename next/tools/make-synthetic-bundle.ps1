# Builds a synthetic sealed bundle of a given size, so judging can be measured before a real
# capture exists.
#
# WHAT IT IS AND IS NOT. The objects are plausible in shape - a distinguished name, an
# objectGUID, the attributes the delegation rules read - but they are invented. The number this
# supports is the I/O cost of streaming a bundle of a given size on this machine. It is not a
# statement about anybody's forest.
#
# One object in every two hundred is given the unconstrained delegation flag, so a judging run
# over the result has something to find.
#
# USAGE
#   pwsh -File next/tools/make-synthetic-bundle.ps1 -Objects 50000 -Path 'C:\temp\synthetic'

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [int] $Objects,

    [Parameter(Mandatory = $true)]
    [string] $Path
)

$ErrorActionPreference = 'Stop'

$bin = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\tests\SecureAD.Next.Tests\bin\Debug\net10.0-windows'))
if (-not (Test-Path $bin)) { throw "Build the solution first - no assemblies at '$bin'." }

$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SecureAD.Kernel.dll'))
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SecureAD.Evidence.dll'))

$native = Join-Path $bin 'runtimes\win-x64\native'
if (Test-Path $native) { $env:PATH = $native + [System.IO.Path]::PathSeparator + $env:PATH }

$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SQLitePCLRaw.core.dll'))
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SQLitePCLRaw.provider.e_sqlite3.dll'))
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SQLitePCLRaw.batteries_v2.dll'))
[SQLitePCL.Batteries_V2]::Init()

$Path = [System.IO.Path]::GetFullPath($Path)
if (Test-Path $Path) { Remove-Item $Path -Recurse -Force }
$null = New-Item -ItemType Directory -Path $Path -Force

Push-Location $bin
try {
    $started  = [DateTimeOffset]::new(2026, 8, 26, 9, 0, 0, [TimeSpan]::Zero)
    $finished = $started.AddHours(2)

    $coverage = [SecureAD.Evidence.PartitionCoverage]::new(
        'DC=contoso,DC=com',
        [SecureAD.Evidence.NamingContextKind]::Domain,
        'dc01.contoso.com',
        [SecureAD.Evidence.ConnectionSecurityLevel]::SignedAndSealed,
        12, $Objects, 3, [System.Collections.Generic.List[string]]::new(), $false)

    $writer = [SecureAD.Evidence.BundleWriter]::Create($Path, $started)

    $complete = [SecureAD.Evidence.StoredAttributeCompleteness]::Complete
    $watch = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        $null = $writer.WriteCoverage($coverage)

        for ($i = 0; $i -lt $Objects; $i++) {
            # Most accounts are ordinary; one in two hundred carries TRUSTED_FOR_DELEGATION so the
            # rules have something to fire on.
            $uac = if ($i % 200 -eq 0) { '524288' } else { '512' }

            $attributes = [System.Collections.Generic.List[SecureAD.Evidence.EvidenceAttribute]]::new()

            foreach ($pair in @(
                @('sAMAccountName',     "user$i"),
                @('userAccountControl', $uac),
                @('primaryGroupID',     '513'))) {

                $values = [System.Collections.Generic.List[SecureAD.Evidence.EvidenceValue]]::new()
                $values.Add([SecureAD.Evidence.EvidenceValue]::OfText($pair[1]))
                $attributes.Add([SecureAD.Evidence.EvidenceAttribute]::new($pair[0], $complete, $values))
            }

            $classes = [System.Collections.Generic.List[SecureAD.Evidence.EvidenceValue]]::new()
            $classes.Add([SecureAD.Evidence.EvidenceValue]::OfText('top'))
            $classes.Add([SecureAD.Evidence.EvidenceValue]::OfText('person'))
            $classes.Add([SecureAD.Evidence.EvidenceValue]::OfText('user'))
            $attributes.Add([SecureAD.Evidence.EvidenceAttribute]::new('objectClass', $complete, $classes))

            $object = [SecureAD.Evidence.EvidenceObject]::new(
                $coverage,
                "CN=user$i,OU=People,DC=contoso,DC=com",
                [Guid]::NewGuid(),
                $attributes,
                $started)

            $null = $writer.WriteObject($object)

            if (($i % 10000) -eq 0 -and $i -gt 0) {
                Write-Host ("  written {0:N0} of {1:N0} ({2:N0} s)" -f $i, $Objects, $watch.Elapsed.TotalSeconds)
            }
        }

        $domains = [System.Collections.Generic.List[SecureAD.Evidence.Run.DomainCoverage]]::new()
        $domains.Add([SecureAD.Evidence.Run.DomainCoverage]::Read('contoso.com'))

        $partitions = [System.Collections.Generic.List[SecureAD.Evidence.Run.ForestPartitionCoverage]]::new()
        $partitions.Add([SecureAD.Evidence.Run.ForestPartitionCoverage]::Read(
            'CN=Configuration,DC=contoso,DC=com', [SecureAD.Evidence.NamingContextKind]::Configuration))
        $partitions.Add([SecureAD.Evidence.Run.ForestPartitionCoverage]::Read(
            'CN=Schema,CN=Configuration,DC=contoso,DC=com', [SecureAD.Evidence.NamingContextKind]::Schema))

        $declared = [System.Collections.Generic.List[string]]::new()
        $declared.Add('contoso.com')

        $runCoverage = [SecureAD.Evidence.Run.RunCoverage]::Of(
            [SecureAD.Evidence.Run.CoverageId]::ForDomains('contoso.com', $declared),
            $domains,
            $partitions,
            [SecureAD.Evidence.Run.SysvolCoverage]::Of(
                [System.Collections.Generic.List[SecureAD.Evidence.Run.GpoCoverage]]::new()))

        $writer.Complete($runCoverage, $finished)
    }
    finally {
        $writer.Dispose()
    }

    $watch.Stop()

    Write-Host ''
    Write-Host ("Wrote {0:N0} objects in {1:N1} s" -f $Objects, $watch.Elapsed.TotalSeconds)
    Write-Host ("Bundle at {0}" -f $Path)
    Write-Host ("Evidence  {0:N0} bytes" -f (Get-Item (Join-Path $Path 'evidence.db')).Length)
    Write-Host ''
}
finally {
    Pop-Location
}
