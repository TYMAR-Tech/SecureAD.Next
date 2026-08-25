#Requires -Version 7.0
# Windows PowerShell 5.1 reads UTF-8 files as Windows-1252, turning every em dash into three
# characters. This script writes documents, so running it under 5.1 would corrupt them silently.

# Mutation harness for the gates written when the-new-audit-wizard.md was consumed to its screen.
#
# Every replacement asserts it changed something: an anchor that misses mutates nothing and reports
# a gate as passing. Touched files are restored from the text captured here and verified
# byte-identical by hash, never by `git checkout`, which would revert uncommitted work under test.

$ErrorActionPreference = 'Stop'
$root = 'C:\Users\jistrand\source\repos\razamus\SecureAD.Next'
Set-Location $root

$forest = 'docs/layers/connect/how-the-forest-is-found.md'
$pre    = 'docs/layers/connect/what-preflight-proves.md'
$excl   = 'docs/layers/evidence/a-domain-left-out-on-purpose.md'
$reg    = 'docs/next/SURFACE-REGISTER.md'
$src    = 'next/src/SecureAD.Audit/Connect/ForestPartitions.cs'

$mutations = @(
    @{ Name = 'forest page drops the DomainSelection row';
       File = $forest;
       From = '| `DomainSelection` | Why a controller was chosen';
       To   = '| `DomainSelectionXX` | Why a controller was chosen' }

    @{ Name = 'preflight page drops the NamedControllerAnswer row';
       File = $pre;
       From = '| `NamedControllerAnswer` | What that check found';
       To   = '| `NamedControllerAnswerXX` | What that check found' }

    @{ Name = 'exclusion page drops a kind the enum declares';
       File = $excl;
       From = '| `ForWantOfCandidates` | The forest named no writable controller for it, so nothing could read it |';
       To   = '' }

    @{ Name = 'exclusion page stops saying the authorising name is unvalidated';
       File = $excl;
       From = 'not validated';
       To   = 'checked against the directory' }

    @{ Name = 'a file that declared nothing public gains a type';
       File = $src;
       From = 'namespace SecureAD.Audit.Connect;';
       To   = "namespace SecureAD.Audit.Connect;`r`n`r`n/// <summary>A type nobody documented.</summary>`r`npublic sealed record ForestPartitionsSurprise(int Value);" }

    @{ Name = 'register moves a claimed type to a page that does not claim it';
       File = $reg;
       From = '| ForestPlan | SecureAD.Audit | [how-the-forest-is-found](../layers/connect/how-the-forest-is-found.md) |';
       To   = '| ForestPlan | SecureAD.Audit | [what-preflight-proves](../layers/connect/what-preflight-proves.md) |' }
)

$touched = $mutations | ForEach-Object { $_.File } | Sort-Object -Unique
$before = @{}
foreach ($f in $touched) { $before[$f] = (Get-FileHash (Join-Path $root $f) -Algorithm SHA256).Hash }

$results = @()

foreach ($m in $mutations) {
    $path = Join-Path $root $m.File
    $original = [System.IO.File]::ReadAllText($path)

    if (-not $original.Contains($m.From)) {
        throw "ANCHOR MISS for '$($m.Name)': text not found in $($m.File). Nothing mutated, so a pass would mean nothing."
    }

    $mutated = $original.Replace($m.From, $m.To)
    if ($mutated -eq $original) { throw "NO-OP for '$($m.Name)'." }

    [System.IO.File]::WriteAllText($path, $mutated)

    $out = & cmd /c "cd /d `"$root\next`" && dotnet test SecureAD.Next.sln --nologo 2>&1"
    $line = ($out | Select-String 'Failed:\s+\d+, Passed:' | Select-Object -First 1)
    $summary = if ($line) { $line.ToString().Trim() } else { '(no summary - build failure?)' }

    $killedBy = @()
    foreach ($l in ($out | Select-String '^\s*(Failed|X)\s+SecureAD')) {
        $killedBy += ($l.ToString().Trim() -replace '\s+\[.*$', '' -replace '^(Failed|X)\s+', '' -replace '^SecureAD\.Next\.Tests\.(Documentation|Architecture)\.', '')
    }

    [System.IO.File]::WriteAllText($path, $original)

    $killed = ($summary -notmatch 'Failed:\s+0,')
    $results += [pscustomobject]@{ Mutation = $m.Name; Killed = $killed }

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
