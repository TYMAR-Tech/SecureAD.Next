# Judges a sealed bundle and reports what the rules concluded.
#
# WHAT THIS IS FOR. The Shell runs judging as part of an audit. This remains a developer-only way to
# judge or explain an existing bundle without opening the application. It retires when the shared CLI
# workflow provides equivalent judge-existing and explain diagnostics.
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

    # A distinguished name to explain instead of judging the bundle. Reports whether the object is
    # in the bundle at all, what the rules make of it, and why - which is the question an operator
    # asks when something they expected to see is not in the findings, and the question an absence
    # cannot answer on its own.
    [string] $Explain,

    # Read the persisted initial control slice without re-judging. This is diagnostic measurement,
    # not acceptance of the unfinished stage-6 catalogue or P-145.
    [switch] $ControlEdges,

    # Judge the way the application does, with Tier-0 discovery deciding which objects receive
    # detailed control assessment. REQUIRED FOR THE P-145 TIER-0 ANALYSIS: an ungated judgement
    # records no Tier-0 seeds, and the report would then have nothing to measure unexpected control
    # against - which reads as "nothing controls Tier 0" rather than as "this run cannot tell you".
    [switch] $Gated,

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
$candidates += (Join-Path $PSScriptRoot '..\tests\SecureAD.Next.Tests\bin\Debug\net10.0-windows\win-x64')
$candidates += (Join-Path $PSScriptRoot '..\tests\SecureAD.Next.Tests\bin\Debug\net10.0-windows')
$candidates += (Join-Path $PSScriptRoot '..\tests\SecureAD.Next.Tests\bin\Release\net10.0-windows\win-x64')
$candidates += (Join-Path $PSScriptRoot '..\tests\SecureAD.Next.Tests\bin\Release\net10.0-windows')
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

# WHICH BUILD THIS IS MEASURING, said out loud rather than assumed.
#
# The candidate list holds both Debug and Release, and a developer who builds one while an older
# copy of the other is still on disk would otherwise get a report from whichever the list reached
# first. That failed loudly on 2026-09-12 only because a signature had changed; a behavioural change
# would have produced numbers from a month-old binary with nothing on screen saying so. A
# measurement that cannot name its own provenance is not evidence.
$stamp = (Get-Item (Join-Path $bin 'SecureAD.Judgement.dll')).LastWriteTime
Write-Output "Assemblies: $bin"
Write-Output "SecureAD.Judgement.dll built: $($stamp.ToString('yyyy-MM-dd HH:mm:ss'))"

$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SecureAD.Kernel.dll'))
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SecureAD.Evidence.dll'))
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SecureAD.Derivation.dll'))
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
$expectedSchema = if ($ControlEdges) { 15 } else { 2 }
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
    if ($ControlEdges) {
        if ($Explain) { throw 'Choose -ControlEdges or -Explain, not both.' }
        $opened = [SecureAD.Judgement.JudgementReader]::Open($BundlePath)
        if (-not $opened.IsSuccess) { throw $opened.Error.Description }
        $reader = $opened.Value
        try {
            $all = [System.Collections.Generic.List[object]]::new()
            $after = 0L
            $supporting = 0L
            do {
                $unset = [System.Management.Automation.Language.NullString]::Value
                $page = $reader.ReadControlEdges($unset, $unset, $unset, $true, $after)
                if (-not $page.ProductWasDerived) { throw 'The control product was not derived.' }
                foreach ($edge in $page.Edges) {
                    if ($edge.IsCounted) { $all.Add($edge) } else { $supporting++ }
                }
                $after = $page.LastId
            } while ($page.HasMore)
            Write-Output ([SecureAD.Judgement.ControlEdgePage]::SupportedScope)
            Write-Output "Evidence: $($reader.Description.EvidenceSeal)"
            Write-Output "Generation: $($reader.Description.GenerationId); derivation: $($reader.Description.DerivationGenerationId)"
            $path = [SecureAD.Evidence.BundleLayout]::AnalysisGenerationDataPath($BundlePath, [SecureAD.Evidence.AnalysisStoreKind]::Judgement, $reader.Description.GenerationId)
            $connection = [Microsoft.Data.Sqlite.SqliteConnection]::new("Data Source=$path;Mode=ReadOnly;Pooling=False")
            try {
                $connection.Open()
                $query = $connection.CreateCommand()
                $query.CommandText = 'SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY type,name'
                $schema = $query.ExecuteReader()
                $layout = [System.Text.StringBuilder]::new()
                try {
                    while ($schema.Read()) {
                        for ($column = 0; $column -lt 4; $column++) { $null = $layout.Append($schema.GetString($column).Replace("`r`n", "`n")).Append("`n") }
                    }
                } finally { $schema.Dispose(); $query.Dispose() }
                Write-Output ('Stored layout SHA256: ' + [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($layout.ToString()))))
            } finally { $connection.Dispose() }
            Write-Output "Counted primitives: $($all.Count); uncounted supporting compounds: $supporting"
            Write-Output "Expected: $($page.ExpectedCount); unexpected: $($page.UnexpectedCount); expectedness unknown: $($page.UnknownCount)"
            Write-Output "Unanswered objects: $($page.UnansweredObjects); capture complete: $($page.CaptureIsComplete)"
            foreach ($property in @('EvaluationState', 'Uncertainty', 'ExpectednessReason', 'Capability', 'TargetClass', 'HolderSid')) {
                Write-Output "Grouped by $property (top 20):"
                $all | Group-Object -Property $property | Sort-Object @{Expression='Count';Descending=$true},Name |
                    Select-Object -First 20 Count,Name | Format-Table -AutoSize | Out-String -Width 220 | Write-Output
            }
            Write-Output 'Unexpected contributors:'
            $all | Where-Object Expectedness -eq Unexpected | Group-Object HolderSid,HolderName,TargetClass |
                Sort-Object @{Expression='Count';Descending=$true},Name | Select-Object -First 30 Count,Name |
                Format-Table -AutoSize | Out-String -Width 220 | Write-Output
            foreach ($sid in @('S-1-5-18','S-1-5-32-548','S-1-5-32-549','S-1-5-32-550','S-1-5-32-551','S-1-5-32-552')) {
                $held = @($all | Where-Object HolderSid -eq $sid)
                Write-Output "$sid : $($held.Count) counted primitives"
            }
            $evidence = [SecureAD.Evidence.BundleReader]::Open($BundlePath)
            if (-not $evidence.IsSuccess) { throw $evidence.Error.Description }
            try {
                foreach ($subject in $evidence.Value.StreamObjects().Objects) {
                    if ($subject.Find('objectClass').Values.Text -notcontains 'computer') { continue }
                    if (-not [SecureAD.Evidence.Findings.DomainControllerSignals]::Of($subject).IsDomainController) { continue }
                    $value = $subject.Find('objectSid').OnlyValue
                    $sid = if ($value.Bytes) { [System.Security.Principal.SecurityIdentifier]::new([byte[]]$value.Bytes, 0).Value } else { $value.Text }
                    $held = @($all | Where-Object HolderSid -eq $sid)
                    Write-Output "DC $($subject.DistinguishedName) [$sid]: $($held.Count) counted primitives"
                }
            } finally { $evidence.Value.Dispose() }

            # UNEXPECTED CONTROL AGAINST TIER 0, which is the measurement P-145 names and the one
            # this report lacked. The seeds come from the judgement's own ownership_seed table rather
            # than a list written here: a hand-kept list of privileged groups would disagree with the
            # product about what Tier 0 is, and would do so silently.
            #
            # Reported as a count AND grouped, because the acceptance question is about dominance. A
            # single total cannot distinguish one overdelegated group from a platform principal
            # holding the same permission on a thousand objects.
            $seeds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $connection = [Microsoft.Data.Sqlite.SqliteConnection]::new("Data Source=$path;Mode=ReadOnly;Pooling=False")
            try {
                $connection.Open()
                $seedQuery = $connection.CreateCommand()
                $seedQuery.CommandText = 'SELECT target FROM ownership_seed'
                $seedReader = $seedQuery.ExecuteReader()
                try { while ($seedReader.Read()) { $null = $seeds.Add($seedReader.GetString(0)) } }
                finally { $seedReader.Dispose(); $seedQuery.Dispose() }
            } catch {
                Write-Output "Tier-0 seeds unavailable: $($_.Exception.Message)"
            } finally { $connection.Dispose() }

            Write-Output "Tier-0 seeds recorded: $($seeds.Count)"
            if ($seeds.Count -eq 0) {
                # Said plainly rather than reported as zero unexpected edges. A judgement with no
                # recorded seeds was not scoped, and "none against Tier 0" would read as reassurance.
                Write-Output 'No Tier-0 seeds are recorded in this judgement, so no Tier-0 target analysis is possible. This is not a statement that nothing controls Tier 0.'
            } else {
                $againstTier0 = @($all | Where-Object { $seeds.Contains($_.Target) })
                $unexpectedAgainstTier0 = @($againstTier0 | Where-Object Expectedness -eq Unexpected)
                Write-Output "Counted primitives against Tier-0 seeds: $($againstTier0.Count); of those unexpected: $($unexpectedAgainstTier0.Count)"
                Write-Output 'Unexpected against Tier 0, by holder and capability:'
                $unexpectedAgainstTier0 | Group-Object HolderSid,HolderName,Capability |
                    Sort-Object @{Expression='Count';Descending=$true},Name | Select-Object -First 30 Count,Name |
                    Format-Table -AutoSize | Out-String -Width 220 | Write-Output
                Write-Output 'Unexpected against Tier 0, by target:'
                $unexpectedAgainstTier0 | Group-Object Target |
                    Sort-Object @{Expression='Count';Descending=$true},Name | Select-Object -First 30 Count,Name |
                    Format-Table -AutoSize | Out-String -Width 220 | Write-Output
            }

            # THE DOMINANCE RATIO, which is the acceptance question stated as a number. P-145 says a
            # large unexpected count is not by itself a failure; the failure is a count dominated by
            # behaviour already established as necessary platform operation. These five operator
            # groups are the 0099 exclusions - present and privileged in every forest Microsoft ships
            # - so the share of unexpected edges they account for is the thing to look at.
            #
            # READ FROM THE STORE'S OWN BASIS, not recomputed here. The headline counts come from one
            # query, and nothing else reproduces it by accident: counted primitives that a full-control
            # summary has absorbed are excluded, established summaries are unioned in, and duplicates
            # across capabilities are NOT collapsed. Four attempts at counting it in this script gave
            # four different answers - 46 by counting every primitive, 29, 20 by adding a DISTINCT the
            # store does not have - before this query, which is the reader's own with the grouping
            # changed from expectedness to holder. A measurement that disagrees with the screen it is
            # measuring is worse than no measurement. Anyone changing this must change it to match
            # ControlEdgeStorage, not to produce a number that looks more reasonable.
            $share = $null
            $connection = [Microsoft.Data.Sqlite.SqliteConnection]::new("Data Source=$path;Mode=ReadOnly;Pooling=False")
            try {
                $connection.Open()
                $byHolder = $connection.CreateCommand()
                $byHolder.CommandText = @'
SELECT holder_sid, COUNT(*) AS rows_held FROM (
    SELECT target,holder_sid,holder_scope,expectedness FROM control_edge e
    WHERE counted=1 AND NOT EXISTS (SELECT 1 FROM full_control_support s WHERE s.edge_id=e.id)
    UNION ALL
    SELECT target,holder_sid,holder_scope,expectedness FROM full_control_assessment WHERE evaluation='Established'
) WHERE expectedness='Unexpected' GROUP BY holder_sid ORDER BY rows_held DESC
'@
                $holderRows = @()
                $read = $byHolder.ExecuteReader()
                try { while ($read.Read()) { $holderRows += [pscustomobject]@{ Sid = $read.GetString(0); Rows = $read.GetInt64(1) } } }
                finally { $read.Dispose(); $byHolder.Dispose() }

                $totalRows = ($holderRows | Measure-Object -Property Rows -Sum).Sum
                $operators = @('S-1-5-32-548','S-1-5-32-549','S-1-5-32-550','S-1-5-32-551','S-1-5-32-552')
                $operatorRows = ($holderRows | Where-Object { $operators -contains $_.Sid } | Measure-Object -Property Rows -Sum).Sum
                if (-not $totalRows) { $totalRows = 0 }
                if (-not $operatorRows) { $operatorRows = 0 }

                Write-Output ''
                Write-Output "Unexpected, on the store's own basis (the same count the reader is shown): $totalRows"
                if ($totalRows -gt 0) {
                    $share = '{0:P1}' -f ($operatorRows / $totalRows)
                    Write-Output "  held by the five 0099-excluded operator groups: $operatorRows ($share)"
                    foreach ($row in ($holderRows | Select-Object -First 10)) {
                        $name = @($all | Where-Object HolderSid -eq $row.Sid | Select-Object -First 1).HolderName
                        Write-Output ("    {0,5}  {1,-7}  {2} {3}" -f $row.Rows, ('{0:P1}' -f ($row.Rows / $totalRows)), $row.Sid, $name)
                    }
                }
            } catch {
                Write-Output "Dominance analysis unavailable: $($_.Exception.Message)"
            } finally { $connection.Dispose() }

            Write-Output ''
            Write-Output 'P-145: MEASURED, NOT ACCEPTED. This report now carries the exploratory half of the gate,'
            Write-Output 'including Tier-0 target analysis and the platform-dominance ratio. The planted half lives in'
            Write-Output 'ControlEdgeExpectednessGateTests. Whether these numbers show the catalogue exposing real'
            Write-Output 'permissions understandably, or a platform principal dominating the default screen, is the'
            Write-Output 'owner''s acceptance decision and is not asserted here. A laboratory forest cannot establish'
            Write-Output 'production volumes either way.'
        } finally { $reader.Dispose() }
        return
    }

    # The product's own list, rather than one written out here.
    #
    # This script used to construct two rules by name, which went stale twice: once when IRule moved
    # from SecureAD.Evidence.Findings to SecureAD.Judgement, and again when a third rule was added
    # that this would not have run. A hand-written list makes the script quietly disagree with the
    # product about what an audit is, which is worse than failing - it reports a clean bundle that
    # the application would have found something in.
    $rules = [SecureAD.Judgement.RuleCatalogue]::All

    if ($Explain) {
        $opened = [SecureAD.Evidence.BundleReader]::Open($BundlePath)
        if (-not $opened.IsSuccess) {
            throw "Could not open '$BundlePath': $($opened.Error.Code) - $($opened.Error.Description)"
        }

        $bundle = $opened.Value
        try {
            $subject = $bundle.ReadObjectAttributes($Explain)

            Write-Host ''
            Write-Host $Explain
            Write-Host ('-' * $Explain.Length)

            if ($null -eq $subject) {
                Write-Host ''
                Write-Host 'NOT IN THIS BUNDLE.'
                Write-Host 'No rule was ever offered it, so its absence from the findings says'
                Write-Host 'nothing about any rule.'
                Write-Host ''
                return
            }

            $classes = ($subject.Attributes | Where-Object { $_.LdapDisplayName -eq 'objectClass' }).Values.Text
            $control = ($subject.Attributes | Where-Object { $_.LdapDisplayName -eq 'userAccountControl' }).Values.Text

            Write-Host ''
            Write-Host ("objectClass          {0}" -f ($classes -join ', '))
            Write-Host ("userAccountControl   {0}" -f $(if ($control) { $control } else { '(not captured)' }))

            # BOTH LAPS TIMESTAMPS, RAW AND DECODED. Added 2026-09-03 because a question about
            # SEC-092 could not be settled without them: whether a machine carries one timestamp or
            # two decides what its overdue span even means, and no other tool prints it. A rule's
            # own finding text shows the value it chose, which is the one thing that cannot be used
            # to check whether it chose correctly.
            foreach ($laps in @('msLAPS-PasswordExpirationTime', 'ms-Mcs-AdmPwdExpirationTime')) {
                $raw = ($subject.Attributes | Where-Object { $_.LdapDisplayName -eq $laps }).Values.Text

                if (-not $raw) {
                    Write-Host ("{0,-32} (absent)" -f $laps)
                    continue
                }

                $decoded = [SecureAD.Evidence.Findings.LapsTimestamp]::Of($raw).ExpiresUtc

                Write-Host ("{0,-32} {1}  =>  {2}" -f
                    $laps, $raw, $(if ($null -ne $decoded) { $decoded.ToString('u') } else { '(undecodable)' }))
            }

            $signals = [SecureAD.Evidence.Findings.DomainControllerSignals]::Of($subject)

            Write-Host ''
            Write-Host 'Is this a domain controller?'
            Write-Host ("  SERVER_TRUST_ACCOUNT bit      {0}" -f $signals.ServerTrustAccountBit)
            Write-Host ("  primary group is 516 or 521   {0}" -f $signals.PrimaryGroupIsDomainController)
            Write-Host ("  under Domain Controllers OU   {0}" -f $signals.UnderDomainControllersOu)
            Write-Host ("  => treated as a controller    {0}" -f $signals.IsDomainController)
            Write-Host ("  => the signals disagree       {0}" -f $signals.SignalsDisagree)

            Write-Host ''
            Write-Host 'What each rule makes of it'
            Write-Host '--------------------------'

            # A rule that reads derived facts has to be offered them, and refuses the bare
            # overload rather than answering without them - so this reads the bundle's derivation
            # and hands it over. If there is none, that rule says so instead of being skipped
            # quietly, because silence from a rule reads as nothing found.
            #
            # The reference time is the clock HERE and not in the judging, because this path
            # explains one object rather than writing a judgement. Nothing records it, so nothing
            # can later disagree with it. A rule judged through the -BundlePath path above takes
            # its reference time from the run and is reproducible; this one is a diagnostic.
            $asOf = [DateTimeOffset]::UtcNow
            $protectedPrincipals = $null
            $permissions = $null
            $attributeVisibility = $null

            $openedDerivation = [SecureAD.Derivation.DerivationReader]::Open($BundlePath)

            if ($openedDerivation.IsSuccess) {
                $storedDerivation = $openedDerivation.Value.Read()
                $product = $storedDerivation.ProtectedPrincipals

                if ($product.Availability -eq 'Available') {
                    $protectedPrincipals = $product.Value
                    $permissions = [Func[string, SecureAD.Evidence.ObjectPermissions]] {
                        param($dn) $bundle.ReadPermissions($dn) }
                }

                # Carried too, or every LAPS rule reports that it was handed nothing. This was
                # missing until 2026-09-03 and made -Explain useless for SEC-091, SEC-092 and
                # SEC-094 - the three rules whose whole question is what the schema permits.
                $visibility = $storedDerivation.AttributeVisibility

                if ($visibility.Availability -eq 'Available') {
                    $attributeVisibility = $visibility.Value
                }
            }

            # Built in one call rather than with a `with` expression, which PowerShell cannot use.
            $members = $null
            if ($openedDerivation.IsSuccess -and $openedDerivation.Value.NestingWasDerived()) {
                $members = [Func[string, string, SecureAD.Derivation.PrincipalExpansion]] {
                    param($sid, $scope) $openedDerivation.Value.MembersOf($sid, $scope) }
            }
            $names = [Func[string, string]] { param($sid) $bundle.PrincipalNameFor($sid) }
            $context = [SecureAD.Judgement.JudgingContext]::new(
                $asOf, $protectedPrincipals, $permissions, $attributeVisibility,
                $members, $bundle.ReadSchemaGuids(), $names, $null,
                [SecureAD.Kernel.Security.DirectoryHeuristics]::OwnerImplicitRights($bundle.ReadForestHeuristics()))
            $context.ForestFqdn = $bundle.Description.ForestFqdn

            foreach ($rule in $rules) {
                $definition = $rule.Definition

                if (-not $definition.IsAbout($subject)) {
                    Write-Host ("  {0,-10} not about objects of this class" -f $definition.Id)
                    continue
                }

                # Checked against what this rule actually declared. Testing only the protected
                # principals said "not derived" for a LAPS rule on a bundle that had everything
                # that rule needed, and said nothing for a protected-principals rule on a bundle
                # that had only the visibility.
                $missing = @($definition.RequiredDerivedFacts | Where-Object {
                    ($_ -eq 'ProtectedPrincipals' -and $null -eq $context.ProtectedPrincipals) -or
                    ($_ -eq 'AttributeVisibility' -and $null -eq $context.AttributeVisibility) -or
                    ($_ -eq 'PrincipalExpansion' -and $null -eq $context.MembersOfPrincipal) })

                if ($missing.Count -gt 0) {
                    Write-Host ("  {0,-10} needs {1}, which this bundle has not derived" -f
                        $definition.Id, ($missing -join ', '))
                    continue
                }

                # Invoked through the interface method by reflection, because PowerShell will not
                # dispatch a default interface method - neither on the concrete type nor through a
                # cast. Judge(subject, context) is defaulted so a rule reading only captured
                # attributes need not implement it, which is most of them, so this is the ordinary
                # case rather than the exception.
                $method = [SecureAD.Judgement.IRule].GetMethod(
                    'Judge',
                    [Type[]] @(
                        [SecureAD.Evidence.ObjectAttributes],
                        [SecureAD.Judgement.JudgingContext]))

                $verdict = $method.Invoke($rule, @($subject, $context))

                if ($verdict.Unresolved.Count -gt 0) {
                    Write-Host ("  {0,-10} could not decide - {1}" -f
                        $definition.Id, (($verdict.Unresolved | ForEach-Object { $_.Token }) -join ', '))
                }
                elseif (-not $verdict.IsComplete) {
                    Write-Host ("  {0,-10} could not judge - not captured: {1}" -f
                        $definition.Id, ($verdict.InputsNotCaptured -join ', '))
                }
                elseif ($verdict.Findings.Count -gt 0) {
                    Write-Host ("  {0,-10} FINDING: {1}" -f $definition.Id, $verdict.Findings[0].Detail)
                }
                else {
                    Write-Host ("  {0,-10} judged, nothing to report" -f $definition.Id)
                }
            }

            if ($openedDerivation.IsSuccess) { $openedDerivation.Value.Dispose() }

            Write-Host ''
            return
        }
        finally {
            $bundle.Dispose()
        }
    }

    $now = [DateTimeOffset]::UtcNow
    $watch = [System.Diagnostics.Stopwatch]::StartNew()

    $judged = if ($Gated) {
        [SecureAD.Judgement.JudgingRun]::JudgeWithTier0Discovery(
            $BundlePath,
            $rules,
            $now,
            $now,
            [SecureAD.Judgement.JudgingRun]::NobodyIsWatching,
            [SecureAD.Kernel.RunLog]::Discarded,
            [System.Threading.CancellationToken]::None,
            $null)
    } else {
        [SecureAD.Judgement.JudgingRun]::Judge(
            $BundlePath,
            $rules,
            $now,
            $now,
            [SecureAD.Judgement.JudgingRun]::NobodyIsWatching,
            [SecureAD.Kernel.RunLog]::Discarded,
            [System.Threading.CancellationToken]::None)
    }

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
