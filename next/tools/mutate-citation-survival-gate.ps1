#Requires -Version 7.0
# Windows PowerShell 5.1 reads UTF-8 files as Windows-1252, turning every em dash into three
# characters. This script writes documents, so running it under 5.1 would corrupt them silently.

# Mutation harness for AreaFileCitationSurvivalTests.
#
# Every replacement asserts it changed something: an anchor that misses mutates nothing and reports
# the gate as passing, which is the failure this repository has been bitten by before. Touched files
# are restored from the text captured here and verified byte-identical by hash, never by
# `git checkout`, which would revert uncommitted work under test.

$ErrorActionPreference = 'Stop'
$root = 'C:\Users\jistrand\source\repos\razamus\SecureAD.Next'
Set-Location $root

$gate  = 'next/tests/SecureAD.Next.Tests/Architecture/AreaFileCitationSurvivalTests.cs'
$cmp   = 'docs/layers/evidence/whether-two-runs-compare.md'
$punch = 'docs/PUNCH-LIST.md'

$mutations = @(
    @{ Name = 'a restored capability row is deleted from its new home';
       File = $cmp;
       From = '| be certain a refused comparison never reports that it may proceed | `RunComparabilityTests.NoRefusedComparisonEverReportsThatItMayProceed` |  |';
       To   = '' }

    @{ Name = 'the only record of an unplaced row is removed from the punch list';
       File = $punch;
       From = '`SysvolCaptureTests`';
       To   = 'that capture test' }

    @{ Name = 'git cannot be reached, so the scan reads nothing';
       File = $gate;
       From = '            if (process is null)
                return [];';
       To   = '            if (process is not null)
                return [];';
       Note = 'stands in for a machine with no git binary' }

    @{ Name = 'the superseded rule is widened to accept any citation';
       File = $gate;
       From = '        return !citation.Contains(''.'', StringComparison.Ordinal) && classes.Contains(citation);';
       To   = '        return true;' }

    @{ Name = 'the survivor scan reads only one document';
       File = $gate;
       From = '        foreach (var file in Directory.EnumerateFiles(docs, "*.md", SearchOption.AllDirectories))';
       To   = '        foreach (var file in Directory.EnumerateFiles(docs, "*.md", SearchOption.AllDirectories).Take(1))' }
)

$touched = $mutations | ForEach-Object { $_.File } | Sort-Object -Unique
$before = @{}
foreach ($f in $touched) { $before[$f] = (Get-FileHash (Join-Path $root $f) -Algorithm SHA256).Hash }

$results = @()

foreach ($m in $mutations) {
    $path = Join-Path $root $m.File
    $original = [System.IO.File]::ReadAllText($path)

    if (-not $original.Contains($m.From)) {
        throw "ANCHOR MISS for '$($m.Name)': the text to replace is not in $($m.File). Nothing was mutated, so a pass here would mean nothing."
    }

    $mutated = $original.Replace($m.From, $m.To)
    if ($mutated -eq $original) { throw "NO-OP for '$($m.Name)'." }

    [System.IO.File]::WriteAllText($path, $mutated)

    $out = & cmd /c "cd /d `"$root\next`" && dotnet test SecureAD.Next.sln --nologo --filter FullyQualifiedName~AreaFileCitationSurvivalTests 2>&1"
    $summary = ($out | Select-String 'Failed:\s+\d+, Passed:|error CS' | Select-Object -First 1)
    $summary = if ($summary) { $summary.ToString().Trim() } else { '(no summary)' }

    $killedBy = @()
    foreach ($line in ($out | Select-String '^\s*(Failed|X)\s+SecureAD')) {
        $killedBy += ($line.ToString().Trim() -replace '\s+\[.*$', '' -replace '^(Failed|X)\s+', '' -replace '^SecureAD\.Next\.Tests\.Architecture\.AreaFileCitationSurvivalTests\.', '')
    }

    [System.IO.File]::WriteAllText($path, $original)

    $killed = ($summary -notmatch 'Failed:\s+0,')
    $results += [pscustomobject]@{ Mutation = $m.Name; Killed = $killed; KilledBy = ($killedBy | Sort-Object -Unique) -join '; ' }

    "[$(if ($killed) { 'KILLED ' } else { 'SURVIVED' })] $($m.Name)"
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
if ($drifted.Count -gt 0) { throw "did not return to original bytes: $($drifted -join ', ')" }

''
"mutations: $($results.Count), killed: $(($results | Where-Object Killed).Count), survived: $(($results | Where-Object { -not $_.Killed }).Count)"
