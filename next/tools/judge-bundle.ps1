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

    # Where the built assemblies are - the FOLDER holding them, not one of the files. Only needed
    # when this script is not sitting in the repository: on a lab machine, copy the whole build
    # output folder across and either put this script inside it or point -BinPath at it.
    [string] $BinPath
)

$ErrorActionPreference = 'Stop'

# Everything this script needs in one folder. Checked up front rather than discovered one
# LoadFrom at a time, because a half-populated folder otherwise fails with a loader error naming
# a single file and no clue that the other eleven are missing too.
$required = @(
    'SecureAD.Kernel.dll',
    'SecureAD.Evidence.dll',
    'SecureAD.Judgement.dll',
    'Microsoft.Data.Sqlite.dll',
    'SQLitePCLRaw.core.dll',
    'SQLitePCLRaw.provider.e_sqlite3.dll',
    'SQLitePCLRaw.batteries_v2.dll')

$candidates = @()

if ($BinPath) {
    $given = [System.IO.Path]::GetFullPath($BinPath)

    # A folder is wanted and a file is easy to give - tab completion offers files. Take the
    # folder it is in rather than failing on something that says plainly enough what was meant.
    if (Test-Path $given -PathType Leaf) { $given = Split-Path $given -Parent }

    $candidates += $given
}

$candidates += $PSScriptRoot
$candidates += (Join-Path $PSScriptRoot '..\tests\SecureAD.Next.Tests\bin\Debug\net10.0-windows')
$candidates += (Join-Path $PSScriptRoot 'net10.0-windows')

$bin = $null
foreach ($candidate in $candidates) {
    $full = [System.IO.Path]::GetFullPath($candidate)
    if (-not (Test-Path $full -PathType Container)) { continue }

    $absent = @($required | Where-Object { -not (Test-Path (Join-Path $full $_)) })
    if ($absent.Count -eq 0) { $bin = $full; break }
}

if (-not $bin) {
    $report = foreach ($candidate in $candidates) {
        $full = [System.IO.Path]::GetFullPath($candidate)

        if (-not (Test-Path $full -PathType Container)) {
            "  $full" + [Environment]::NewLine + '      no such folder'
        }
        else {
            $absent = @($required | Where-Object { -not (Test-Path (Join-Path $full $_)) })
            "  $full" + [Environment]::NewLine + '      missing: ' + ($absent -join ', ')
        }
    }

    throw @"
Could not find a folder holding all the assemblies this needs. Looked in:
$($report -join [Environment]::NewLine)

-BinPath wants the FOLDER, not a file inside it.

On a development machine, build the solution.

On any other machine, copy the whole build output folder across - that is
next\tests\SecureAD.Next.Tests\bin\Debug\net10.0-windows, including its runtimes\ subfolder,
which holds the native SQLite library - and either put this script inside it or pass -BinPath
pointing at it.
"@
}

$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SecureAD.Kernel.dll'))
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SecureAD.Evidence.dll'))
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SecureAD.Judgement.dll'))

# The native SQLite library, loaded by absolute path rather than left to PATH.
#
# SQLite ships one native binary per processor architecture under runtimes\, and only the .NET
# host does that selection - a PowerShell process does not, so the DllImport for 'e_sqlite3'
# fails with "Unable to load DLL" and names nothing useful. Loading it here by full path means the
# module is already in the process when the provider asks for it.
#
# The architecture is read from the running process rather than assumed, because an arm64 machine
# with an x64 folder present would otherwise load a library it cannot execute.
$architecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString().ToLowerInvariant()

$nativeCandidates = @(
    (Join-Path $bin "runtimes\win-$architecture\native\e_sqlite3.dll"),
    (Join-Path $bin 'e_sqlite3.dll'))

$native = $nativeCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $native) {
    $found = Get-ChildItem $bin -Recurse -Filter 'e_sqlite3.dll' -ErrorAction SilentlyContinue |
        ForEach-Object { '  ' + $_.FullName }

    $detail = if ($found) {
        'Copies that are present, none of them for this machine:' + [Environment]::NewLine + ($found -join [Environment]::NewLine)
    }
    else {
        'No copy of e_sqlite3.dll anywhere under that folder - the runtimes\ subfolder was not copied.'
    }

    throw @"
The native SQLite library is missing. This process is $architecture, so it needs:

  $(Join-Path $bin "runtimes\win-$architecture\native\e_sqlite3.dll")

$detail

Copy the build output folder across whole, including runtimes\. The managed assemblies alone are
not enough - nothing can open a bundle without this file.
"@
}

$null = [System.Runtime.InteropServices.NativeLibrary]::Load($native)

# Resolve every other assembly out of the same folder, rather than naming them one at a time.
#
# A LoadFrom'd assembly's own dependencies are not resolved from the folder it came from, so each
# one has to be found somehow. Listing them was a mistake that cost three round trips to the lab:
# the list was short by Microsoft.Data.Sqlite, and it would have been short by the next one too.
# This handler answers for anything the runtime asks for, so the folder is either complete or the
# failure names the assembly that is actually missing.
[System.Runtime.Loader.AssemblyLoadContext]::Default.add_Resolving({
    param($context, $name)

    $candidate = Join-Path $bin ($name.Name + '.dll')
    if (Test-Path $candidate) { return $context.LoadFromAssemblyPath($candidate) }

    return $null
}.GetNewClosure())

$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SQLitePCLRaw.core.dll'))
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SQLitePCLRaw.provider.e_sqlite3.dll'))
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SQLitePCLRaw.batteries_v2.dll'))
[SQLitePCL.Batteries_V2]::Init()

# The assemblies and this script travel separately between machines, so they can disagree - and a
# script newer than its assemblies fails silently rather than loudly: a column this script prints
# but the older type does not have comes out blank, and the run looks like a result rather than a
# mismatch. That cost a lab round trip on 2026-08-26. Checked here instead.
$expectedSchema = 2
$actualSchema = [SecureAD.Judgement.JudgementSchema]::Version

if ($actualSchema -lt $expectedSchema) {
    throw @"
These assemblies are older than this script.

  judgement schema this script expects   $expectedSchema
  judgement schema the assemblies have   $actualSchema
  assemblies loaded from                 $bin

Copy the build output folder across again - the whole of
next\tests\SecureAD.Next.Tests\bin\Debug\net10.0-windows, including runtimes\. Copying the script
alone leaves the behaviour unchanged and the output misleading.
"@
}

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
            Write-Host ("  {0,-10} {1,-14} judged {2,9:N0}   not about {3,9:N0}   could not judge {4,9:N0}" -f
                $rule.RuleId, $rule.Outcome, $rule.ObjectsJudged, $rule.ObjectsNotApplicable,
                $rule.ObjectsNotJudged)

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
