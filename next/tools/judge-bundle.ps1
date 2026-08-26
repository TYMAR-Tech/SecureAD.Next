# Judges a sealed bundle and reports what the rules concluded.
#
# WHAT THIS IS FOR. Judging has no entry point in the product yet - no command, no button. This is
# the way to run it against a real bundle on a real machine, which is the only place the rules meet
# objects nobody invented.
#
# It writes judgement.db and judgement.db.seal beside the evidence and never touches evidence.db.
# Running it again replaces the judgement.
#
# USAGE
#   pwsh -File next/tools/judge-bundle.ps1 -BundlePath 'D:\audits\contoso-2026-08-25'

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $BundlePath,

    # Where the built assemblies are. Only needed when this script is not sitting in the
    # repository - on a lab machine, copy the whole build output folder across and either put this
    # script inside it or point -BinPath at it.
    [string] $BinPath
)

$ErrorActionPreference = 'Stop'

# Three places to look, in order: where the caller said, beside this script (a copied deployment),
# and the repository layout. The lab machine has no repository, so the second is what makes this
# runnable there at all.
$candidates = @()
if ($BinPath) { $candidates += $BinPath }
$candidates += $PSScriptRoot
$candidates += (Join-Path $PSScriptRoot '..\tests\SecureAD.Next.Tests\bin\Debug\net10.0-windows')

$bin = $null
foreach ($candidate in $candidates) {
    $full = [System.IO.Path]::GetFullPath($candidate)
    if (Test-Path (Join-Path $full 'SecureAD.Judgement.dll')) { $bin = $full; break }
}

if (-not $bin) {
    $looked = ($candidates | ForEach-Object { '  ' + [System.IO.Path]::GetFullPath($_) }) -join [Environment]::NewLine
    throw @"
Could not find SecureAD.Judgement.dll. Looked in:
$looked

On a development machine, build the solution.

On any other machine, copy the whole build output folder across - that is
next\tests\SecureAD.Next.Tests\bin\Debug\net10.0-windows, including its runtimes\ subfolder -
and either put this script inside it or pass -BinPath pointing at it.
"@
}

$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SecureAD.Kernel.dll'))
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SecureAD.Evidence.dll'))
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SecureAD.Judgement.dll'))

$native = Join-Path $bin 'runtimes\win-x64\native'
if (Test-Path $native) { $env:PATH = $native + [System.IO.Path]::PathSeparator + $env:PATH }

$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SQLitePCLRaw.core.dll'))
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SQLitePCLRaw.provider.e_sqlite3.dll'))
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SQLitePCLRaw.batteries_v2.dll'))
[SQLitePCL.Batteries_V2]::Init()

$BundlePath = [System.IO.Path]::GetFullPath($BundlePath)
Push-Location $bin

try {
    $rules = [System.Collections.Generic.List[SecureAD.Evidence.Findings.IRule]]::new()
    $rules.Add([SecureAD.Evidence.Findings.UnconstrainedDelegationOnAccount]::new())
    $rules.Add([SecureAD.Evidence.Findings.UnconstrainedDelegationOnNonDomainController]::new())

    $now = [DateTimeOffset]::UtcNow
    $watch = [System.Diagnostics.Stopwatch]::StartNew()

    $judged = [SecureAD.Judgement.JudgingRun]::Judge($BundlePath, $rules, $now, $now)

    $watch.Stop()

    if (-not $judged.IsSuccess) {
        throw "Could not judge '$BundlePath': $($judged.Error.Code) - $($judged.Error.Description)"
    }

    Write-Host ''
    Write-Host ("Judging finished    {0}" -f $judged.Value)
    Write-Host ("Elapsed             {0:N2} s" -f $watch.Elapsed.TotalSeconds)

    $opened = [SecureAD.Judgement.JudgementReader]::Open($BundlePath)
    if (-not $opened.IsSuccess) {
        throw "Judged, and the judgement could not be read back: $($opened.Error.Code) - $($opened.Error.Description)"
    }

    $reader = $opened.Value
    try {
        $stored = $reader.Read()

        Write-Host ''
        Write-Host 'Rules run'
        Write-Host '---------'

        foreach ($rule in $stored.RulesRun) {
            Write-Host ("  {0,-10} {1,-14} judged {2,9:N0}   could not judge {3,9:N0}" -f
                $rule.RuleId, $rule.Outcome, $rule.ObjectsJudged, $rule.ObjectsNotJudged)

            foreach ($missing in $rule.MissingInputs) {
                Write-Host ("      not captured: {0} on {1:N0} objects" -f
                    $missing.Attribute, $missing.ObjectsAffected)
            }

            if ($rule.Error) {
                Write-Host ("      ERROR: {0}" -f ($rule.Error -split "`n")[0])
            }
        }

        Write-Host ''
        Write-Host ("Findings            {0:N0}" -f $stored.Findings.Count)
        Write-Host ("Nobody judged this  {0}" -f $stored.DidNotRun)
        Write-Host ("Every verdict reached  {0}" -f $stored.EveryRuleReachedEveryVerdict)

        if ($stored.Findings.Count -gt 0) {
            Write-Host ''
            Write-Host 'First findings'
            Write-Host '--------------'
            foreach ($finding in ($stored.Findings | Select-Object -First 10)) {
                Write-Host ("  {0,-9} {1,-8} {2}" -f
                    $finding.RuleId, $finding.Severity, $finding.DistinguishedName)
            }
        }

        Write-Host ''
        Write-Host 'If "Every verdict reached" is False, the findings are a floor and not a total:'
        Write-Host 'somewhere a rule could not read what it declared, and the lines above say which.'
        Write-Host ''
    }
    finally {
        $reader.Dispose()
    }
}
finally {
    Pop-Location
}
