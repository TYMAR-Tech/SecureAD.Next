# Mutation harness for the two gates written to stop the documentation rotting:
# ProsePathCitationTests, and DocumentationLinkGateTests once widened past docs/.
#
# Every replacement asserts it changed something: an anchor that misses mutates nothing and reports
# a gate as passing. Touched files are restored from the text captured here and verified
# byte-identical by hash, never by `git checkout`, which would revert uncommitted work under test.

$ErrorActionPreference = 'Stop'
$root = 'C:\Users\jistrand\source\repos\razamus\SecureAD.Next'
Set-Location $root

$authority = 'docs/next/README.md'
$rootReadme = 'README.md'
$reading = 'docs/next/READING-ORDER.md'

$mutations = @(
    @{ Name = 'a document names an in-repo path in backticks that does not exist';
       File = $authority;
       From = '**The documentation is consolidated, and staying that way is the job.**';
       To   = '**The documentation is consolidated, and staying that way is the job.** See `docs/no-such-document.md`.' }

    @{ Name = 'the root README links to something absent (outside the old docs/ scope)';
       File = $rootReadme;
       From = '## Documentation';
       To   = "## Documentation`r`n`r`nSee [the missing guide](docs/no-such-guide.md)." }

    @{ Name = 'a document under docs/ links to something absent (the original scope still holds)';
       File = $reading;
       From = '# ';
       To   = "See [nothing](no-such-target.md).`r`n`r`n# " }
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

    $index = $original.IndexOf($m.From)
    $mutated = $original.Remove($index, $m.From.Length).Insert($index, $m.To)
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

    $killed = ($summary -notmatch 'Failed:\s+0,') -or ($summary -match 'build failure')
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
