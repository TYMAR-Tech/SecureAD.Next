# Mutation harness for the gates written when which-controller-we-read.md was deleted.
#
# Every replacement asserts it changed something: an anchor that misses mutates nothing and reports
# a gate as passing. Touched files are restored from the text captured here and verified
# byte-identical by hash, never by `git checkout`, which would revert uncommitted work under test.

$ErrorActionPreference = 'Stop'
$root = 'C:\Users\jistrand\source\repos\razamus\SecureAD.Next'
Set-Location $root

$ladder  = 'docs/layers/connect/the-connection-ladder.md'
$channel = 'docs/layers/connect/how-a-connection-is-opened.md'
$reg     = 'docs/next/SURFACE-REGISTER.md'
$src     = 'next/src/SecureAD.Audit/Connect/ConnectionFailureReason.cs'

$mutations = @(
    @{ Name = 'ladder page drops the ConnectionSecurityLevel row';
       File = $ladder;
       From = '| `ConnectionSecurityLevel` | How well protected a connection turned out to be.';
       To   = '| `ConnectionSecurityLevelXX` | How well protected a connection turned out to be.' }

    @{ Name = 'channel page drops the LdapDirectoryChannel row';
       File = $channel;
       From = '| `LdapDirectoryChannel` | A live connection to one controller';
       To   = '| `LdapDirectoryChannelXX` | A live connection to one controller' }

    @{ Name = 'register moves a claimed type to the other connect page';
       File = $reg;
       From = '| ConnectionSecurityLog | SecureAD.Audit | [the-connection-ladder](../layers/connect/the-connection-ladder.md) |';
       To   = '| ConnectionSecurityLog | SecureAD.Audit | [how-a-connection-is-opened](../layers/connect/how-a-connection-is-opened.md) |' }

    @{ Name = 'a file both the page and the gate say declares nothing gains a public type';
       File = $src;
       From = 'internal static class ConnectionFailureReason';
       To   = "public sealed record ConnectionFailureSurprise(int Value);`r`n`r`ninternal static class ConnectionFailureReason" }

    @{ Name = 'ladder page stops naming the evidence file its component is scoped from';
       File = $ladder;
       From = 'and [`ConnectionSecurityLevel`](../../../next/src/SecureAD.Evidence/ConnectionSecurityLevel.cs).';
       To   = 'and the level the evidence library records.' }
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
