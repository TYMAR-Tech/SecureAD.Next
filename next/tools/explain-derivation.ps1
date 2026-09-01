# Reports what a bundle's derivation concluded, and why.
#
# WHAT THIS IS FOR. `securead --derive` runs the derivation and says whether it succeeded. Nothing
# reads derivation.db back, so there is no way to ask what a stored product concluded about a
# principal without writing code - Wave 5's real-forest check was done with a throwaway test class
# for exactly this reason, and it was deleted afterwards. This is the reusable version. It retires
# when the shared CLI workflow provides an equivalent derive-side explain diagnostic. See P-106.
#
# It opens derivation.db read-only and never writes anything, unless -Derive is given, in which case
# it derives first and replaces any earlier derivation. Evidence is never written to either way.
#
# USAGE
#   pwsh -File next/tools/explain-derivation.ps1 -BundlePath 'D:\audits\contoso-2026-08-25'
#   pwsh -File next/tools/explain-derivation.ps1 -BundlePath '...' -Sid 'S-1-5-21-...-1108'
#   pwsh -File next/tools/explain-derivation.ps1 -BundlePath '...' -Derive

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $BundlePath,

    # A security identifier to explain instead of summarising the whole forest. Reports whether the
    # principal is in the derivation at all, what the product concluded, and the membership path
    # that decided it - which is the question asked when something is protected and nobody expected
    # it to be, and the question a count on its own cannot answer.
    [string] $Sid,

    # Derive before reporting, rather than reading whatever derivation is already there. Needed for
    # a bundle that has only been captured, and for re-deriving after this tool has learned
    # something new. Replaces any earlier derivation; never writes to evidence.db.
    [switch] $Derive,

    # How many protected principals to list. The whole point of a forest-wide summary is that the
    # counts are small enough to read, but a forest with a large protected population should not
    # scroll a terminal for a minute before the reasons appear at the bottom.
    [int] $Limit = 40,

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
    'SecureAD.Derivation.dll',
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
$candidates += (Join-Path $PSScriptRoot '..\tests\SecureAD.Next.Tests\bin\Debug\net10.0-windows\win-x64')
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
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SecureAD.Derivation.dll'))

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
#
# Checked against the schema the STORE reports rather than a constant on the assembly, because
# DerivationSchema is internal - and against the store rather than the reader for the better
# reason too: an old bundle read by new assemblies is the common case on a lab machine, and it is
# the bundle that lacks the rows, not the code.
$expectedSchema = 4

$BundlePath = [System.IO.Path]::GetFullPath($BundlePath)

if (-not (Test-Path $BundlePath -PathType Container)) {
    throw "There is no bundle at '$BundlePath'."
}

Push-Location $bin

try {
    if ($Derive) {
        $now = [DateTimeOffset]::UtcNow
        $watch = [System.Diagnostics.Stopwatch]::StartNew()

        $derived = [SecureAD.Derivation.Stage2aRun]::Derive(
            $BundlePath,
            [SecureAD.Derivation.ExpansionBudget]::Bulk,
            $now,
            [SecureAD.Derivation.Stage2aRun]::Unwatched,
            [SecureAD.Kernel.RunLog]::Discarded,
            [System.Threading.CancellationToken]::None)

        $watch.Stop()

        if (-not $derived.IsSuccess) {
            throw "Could not derive '$BundlePath': $($derived.Error.Code) - $($derived.Error.Description)"
        }

        Write-Host ''
        Write-Host ("Deriving finished   {0}" -f $derived.Value)
        Write-Host ("Elapsed             {0:N2} s" -f $watch.Elapsed.TotalSeconds)
    }

    $opened = [SecureAD.Derivation.DerivationReader]::Open($BundlePath)
    if (-not $opened.IsSuccess) {
        throw @"
Could not open the derivation at '$BundlePath': $($opened.Error.Code) - $($opened.Error.Description)

If this bundle has only been captured, there is no derivation to read yet. Run this again with
-Derive, or run: securead --derive '$BundlePath'
"@
    }

    $reader = $opened.Value
    try {
        $stored = $reader.Read()
        $product = $stored.ProtectedPrincipals

        if ($stored.Description.SchemaVersion -lt $expectedSchema) {
            throw @"
This derivation is older than this script.

  derivation schema this script expects   $expectedSchema
  derivation schema this store has        $($stored.Description.SchemaVersion)

A store written before schema $expectedSchema has no protected-principal rows at all, and reporting
"nothing protected" from it would be false. Derive it again with -Derive.
"@
        }

        Write-Host ''
        Write-Host ("Derivation state    {0}" -f $stored.Description.State)
        Write-Host ("Schema              {0}" -f $stored.Description.SchemaVersion)
        Write-Host ("Principals          {0:N0}" -f $stored.Size.Principals)
        Write-Host ("Protected product   {0}" -f $product.Availability)

        # Availability is reported before anything is read out of Value, because the three ways of
        # not having a product mean different things and only one of them is a fault. A phase that
        # did not run is not a phase that failed, and neither is an answer of "nothing protected".
        if ($product.Availability -ne [SecureAD.Derivation.ProtectedPrincipalProductAvailability]::Available) {
            Write-Host ''
            switch ($product.Availability.ToString()) {
                'DidNotRun' {
                    Write-Host 'The protected-principal phase never ran, so this bundle says nothing'
                    Write-Host 'about who is protected. That is not the same as nobody being protected.'
                }
                'Failed' {
                    Write-Host 'The protected-principal phase ran and failed. Any protection question'
                    Write-Host 'asked of this bundle is unanswered, not answered No.'
                }
                default {
                    Write-Host 'This derivation predates the protected-principal product, or its rows'
                    Write-Host 'are absent. Derive again with -Derive to produce it.'
                }
            }
            Write-Host ''
            return
        }

        $derivation = $product.Value

        Write-Host ('Catalogue version   {0}   ({1:N0} entries)' -f
            $derivation.CatalogueVersion, $derivation.Catalogue.Count)
        Write-Host ('Forest mask         {0}   character {1}   excluding {2:N0}' -f
            $derivation.Mask.Outcome,
            $(if ($derivation.Mask.Character) { "'" + $derivation.Mask.Character + "'" } else { '(none)' }),
            $derivation.Mask.Excluded.Count)

        # Sid id to text, so a stored path can be printed as principals rather than as row numbers.
        $sidById = @{}
        foreach ($fact in $derivation.Principals) { $sidById[$fact.SidId] = $fact.Sid }

        function Format-Path([object] $fact) {
            if ($fact.Path.Count -eq 0) { return '' }
            return (($fact.Path | ForEach-Object { $sidById[$_] }) -join ' -> ')
        }

        if ($Sid) {
            # Scope is part of the key, and a caller asking about one SID does not know it - so
            # every match is shown rather than one guessed at. A principal present under a scope
            # the caller did not expect is itself worth seeing.
            $matches = @($derivation.Principals | Where-Object { $_.Sid -eq $Sid })

            Write-Host ''
            Write-Host $Sid
            Write-Host ('-' * $Sid.Length)

            if ($matches.Count -eq 0) {
                Write-Host ''
                Write-Host 'NOT IN THIS DERIVATION.'
                Write-Host 'No protection question was ever asked about it, so its absence from the'
                Write-Host 'protected principals says nothing about whether it is protected.'
                Write-Host ''
                return
            }

            foreach ($fact in $matches) {
                Write-Host ''
                Write-Host ("  scope           {0}" -f $(if ($fact.Scope) { $fact.Scope } else { '(none)' }))
                Write-Host ("  evaluation      {0}" -f $fact.Evaluation)

                if ($fact.Basis) {
                    Write-Host ("  because         {0}   catalogue entry {1} (RID {2})" -f
                        $fact.Basis.Kind, $fact.Basis.CatalogueEntryId, $fact.Basis.CatalogueRid)

                    $entry = $derivation.Catalogue | Where-Object { $_.Id -eq $fact.Basis.CatalogueEntryId }
                    if ($entry) {
                        Write-Host ("  that entry is   {0}" -f $entry.Name)
                        Write-Host ("  principal       {0} ({1}, {2})" -f
                            $entry.PrincipalStatus, $entry.PrincipalProvenance, $entry.PrincipalSourceId)
                        Write-Host ("  propagation     {0} ({1}, {2})" -f
                            $entry.PropagationStatus, $entry.PropagationProvenance, $entry.PropagationSourceId)
                    }
                }
                else {
                    Write-Host '  because         nothing established it'
                }

                if ($fact.Path.Count -gt 0) {
                    Write-Host ("  path            {0}" -f (Format-Path $fact))
                    Write-Host '                  (one path of possibly several; see P-105 on which root wins)'
                }

                if ($fact.UnknownReasons -ne [SecureAD.Derivation.ProtectionUnknownReason]::None) {
                    Write-Host ("  not settled     {0}" -f $fact.UnknownReasons)
                }
            }

            Write-Host ''
            return
        }

        $protected = @($derivation.Principals | Where-Object {
            $_.Evaluation -eq [SecureAD.Derivation.ProtectedPrincipalEvaluation]::Protected })
        $unknown = @($derivation.Principals | Where-Object {
            $_.Evaluation -eq [SecureAD.Derivation.ProtectedPrincipalEvaluation]::Unknown })
        $notProtected = @($derivation.Principals | Where-Object {
            $_.Evaluation -eq [SecureAD.Derivation.ProtectedPrincipalEvaluation]::NotProtected })

        Write-Host ''
        Write-Host ("Protected           {0:N0}" -f $protected.Count)
        Write-Host ("Not protected       {0:N0}" -f $notProtected.Count)
        Write-Host ("Unknown             {0:N0}" -f $unknown.Count)

        $direct = @($protected | Where-Object {
            $_.Basis -and $_.Basis.Kind -eq [SecureAD.Derivation.ProtectedPrincipalBasisKind]::DirectPrincipalClaim })
        $viaMembership = @($protected | Where-Object {
            $_.Basis -and $_.Basis.Kind -eq [SecureAD.Derivation.ProtectedPrincipalBasisKind]::MembershipRoot })

        Write-Host ''
        Write-Host 'Why each protected principal is protected'
        Write-Host '----------------------------------------'
        Write-Host ("  protected in its own right   {0,9:N0}" -f $direct.Count)
        Write-Host ("  protected through membership {0,9:N0}" -f $viaMembership.Count)

        if ($viaMembership.Count -gt 0) {
            Write-Host ''
            Write-Host 'Protected through membership'
            Write-Host '----------------------------'
            foreach ($fact in ($viaMembership | Select-Object -First $Limit)) {
                Write-Host ("  {0}" -f $fact.Sid)
                Write-Host ("      root RID {0}   {1}" -f $fact.Basis.CatalogueRid, (Format-Path $fact))
            }

            if ($viaMembership.Count -gt $Limit) {
                Write-Host ("  ... and {0:N0} more; raise -Limit to see them" -f ($viaMembership.Count - $Limit))
            }
        }

        if ($unknown.Count -gt 0) {
            Write-Host ''
            Write-Host 'Why the unknowns are unknown'
            Write-Host '----------------------------'
            $unknown |
                Group-Object { $_.UnknownReasons.ToString() } |
                Sort-Object Count -Descending |
                ForEach-Object { Write-Host ("  {0,9:N0}   {1}" -f $_.Count, $_.Name) }
        }

        Write-Host ''
        Write-Host ("Stated limits       {0}" -f $derivation.StatedLimits)
        Write-Host ("Whole forest        {0}" -f $derivation.IsComplete)

        Write-Host ''
        Write-Host 'An Unknown is a principal this product declined to call safe, not one it found'
        Write-Host 'a problem with. If "Whole forest" is False, every count above is a floor: the'
        Write-Host 'reasons named above say what stopped it, and nothing here means "nothing found".'
        Write-Host ''
    }
    finally {
        $reader.Dispose()
    }
}
finally {
    Pop-Location
}
