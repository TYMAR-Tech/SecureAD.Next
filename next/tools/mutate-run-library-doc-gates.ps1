# Mutation harness for the gates written when docs/areas/the-run-library.md was deleted.
#
# Each mutation is a single replacement in one tracked file. Every replacement asserts that it
# changed something: a harness whose anchor does not match mutates nothing and reports the gate as
# passing, which is the failure this repository has already been bitten by (CRLF against an anchor
# ending in "\n"). Every touched file is restored from git and verified byte-identical afterwards.

$ErrorActionPreference = 'Stop'
$root = 'C:\Users\jistrand\source\repos\razamus\SecureAD.Next'
Set-Location $root

$doc  = 'docs/layers/evidence/how-a-bundle-is-read.md'
$cmp  = 'docs/layers/evidence/whether-two-runs-compare.md'
$ann  = 'docs/layers/evidence/what-an-operator-writes-on-a-run.md'
$reg  = 'docs/next/SURFACE-REGISTER.md'
$src  = 'next/src/SecureAD.Evidence/Run/RunMoment.cs'

$mutations = @(
    @{ Name = 'bundle-read page drops the RunScope row';
       File = $doc;
       From = '| `RunScope` | Which domains a sealed run covered';
       To   = '| `RunScopeXX` | Which domains a sealed run covered' }

    @{ Name = 'comparability page drops the RunSummary row';
       File = $cmp;
       From = '| `RunSummary` | What a caller needs to know';
       To   = '| `RunSummaryXX` | What a caller needs to know' }

    @{ Name = 'annotations page drops the RunAnnotations row';
       File = $ann;
       From = '| `RunAnnotations` | Reads and writes that record';
       To   = '| `RunAnnotationsXX` | Reads and writes that record' }

    @{ Name = 'annotations page drops a door';
       File = $ann;
       From = '| `Save` | Records what he wrote';
       To   = '| `SaveXX` | Records what he wrote' }

    @{ Name = 'annotations page stops saying an annotation is not evidence';
       File = $ann;
       From = 'This is annotation and it is not evidence';
       To   = 'This is annotation and it is a fact about the run' }

    @{ Name = 'annotations page opens its TYPES table and fills it with nothing';
       File = $ann;
       From = @"
| Type | What it is |
|---|---|
| ``RunAnnotation`` | What an operator called a run, what he wrote about it, and whether he marked it as his baseline |
| ``RunAnnotations`` | Reads and writes that record, in a sidecar beside the evidence and outside the seal |
"@;
       To   = '' }

    @{ Name = 'bundle-read page stops naming one of the files it claims from';
       File = $doc;
       From = '`RunCompletionReader.cs`, `RunListing.cs`, `RunState.cs`, `RunMoment.cs`, `RunScope.cs`';
       To   = '`RunCompletionReader.cs`, `RunListing.cs`, `RunState.cs`, `RunMoment.cs`' }

    @{ Name = "comparability test's hand-written component list goes stale";
       File = 'next/tests/SecureAD.Next.Tests/Documentation/RunComparabilityDocumentationTests.cs';
       From = '        typeof(RunSummary),';
       To   = '' }

    @{ Name = 'register moves RunScope to a page that does not claim it';
       File = $reg;
       From = '| RunScope | SecureAD.Evidence | [how-a-bundle-is-read](../layers/evidence/how-a-bundle-is-read.md) |';
       To   = '| RunScope | SecureAD.Evidence | [the-bundle-on-disk](../layers/evidence/the-bundle-on-disk.md) |' }

    @{ Name = 'register moves RunAnnotation to the page that already owns RunAnnotations';
       File = $reg;
       From = '| RunAnnotation | SecureAD.Evidence | [what-an-operator-writes-on-a-run](../layers/evidence/what-an-operator-writes-on-a-run.md) |';
       To   = '| RunAnnotation | SecureAD.Evidence | [how-a-bundle-is-read](../layers/evidence/how-a-bundle-is-read.md) |' }

    @{ Name = 'code gains a public type no page claims';
       File = $src;
       From = 'public sealed record RunMoment(DateTimeOffset Utc, bool Recorded);';
       To   = "public sealed record RunMoment(DateTimeOffset Utc, bool Recorded);`r`n`r`n/// <summary>A type nobody documented.</summary>`r`npublic sealed record RunMomentSurprise(int Value);" }
)

$touched = $mutations | ForEach-Object { $_.File } | Sort-Object -Unique

# Byte-identity is verified against a hash taken now, never by restoring from git: at the time this
# was first run the work was still uncommitted, so a `git checkout --` restore would have silently
# reverted the very edits under test to HEAD.
$before = @{}
foreach ($f in $touched) {
    $before[$f] = (Get-FileHash (Join-Path $root $f) -Algorithm SHA256).Hash
}

$results = @()

foreach ($m in $mutations) {
    $path = Join-Path $root $m.File
    $original = [System.IO.File]::ReadAllText($path)

    if (-not $original.Contains($m.From)) {
        throw "ANCHOR MISS for '$($m.Name)': the text to replace is not in $($m.File). Nothing was mutated, so a pass here would mean nothing."
    }

    $mutated = $original.Replace($m.From, $m.To)
    if ($mutated -eq $original) {
        throw "NO-OP for '$($m.Name)': replacement produced identical text."
    }

    [System.IO.File]::WriteAllText($path, $mutated)

    $out = & cmd /c "cd /d `"$root\next`" && dotnet test SecureAD.Next.sln --nologo 2>&1"
    $summary = ($out | Select-String 'Failed:\s+\d+, Passed:' | Select-Object -First 1).ToString().Trim()

    $killedBy = @()
    foreach ($line in ($out | Select-String '^\s*(Failed|X)\s+SecureAD')) {
        $killedBy += ($line.ToString().Trim() -replace '\s+\[.*$', '' -replace '^(Failed|X)\s+', '')
    }

    [System.IO.File]::WriteAllText($path, $original)

    $results += [pscustomobject]@{
        Mutation = $m.Name
        Killed   = ($summary -notmatch 'Failed:\s+0,')
        Summary  = $summary
        KilledBy = ($killedBy | Sort-Object -Unique) -join '; '
    }

    "[$(if ($results[-1].Killed) { 'KILLED ' } else { 'SURVIVED' })] $($m.Name)"
    "           $summary"
    if ($killedBy.Count -gt 0) { "           by: $(($killedBy | Sort-Object -Unique) -join '; ')" }
}

''
'--- verifying every touched file is byte-identical ---'
$drifted = @()
foreach ($f in $touched) {
    $after = (Get-FileHash (Join-Path $root $f) -Algorithm SHA256).Hash
    if ($after -ne $before[$f]) { $drifted += $f }
    "$(if ($after -eq $before[$f]) { 'identical' } else { 'DRIFTED  ' })  $f"
}
if ($drifted.Count -gt 0) { throw "these files did not return to their original bytes: $($drifted -join ', ')" }

''
"mutations: $($results.Count), killed: $(($results | Where-Object Killed).Count), survived: $(($results | Where-Object { -not $_.Killed }).Count)"

$results | Format-Table Mutation, Killed, KilledBy -AutoSize -Wrap
