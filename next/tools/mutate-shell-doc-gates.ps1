# Mutation harness for the gates written when docs/layers/shell/ was created and
# the-new-audit-wizard.md was deleted.
#
# Every replacement asserts it changed something: an anchor that misses mutates nothing and reports
# a gate as passing. Touched files are restored from the text captured here and verified
# byte-identical by hash, never by `git checkout`, which would revert uncommitted work under test.

$ErrorActionPreference = 'Stop'
$root = 'C:\Users\jistrand\source\repos\razamus\SecureAD.Next'
Set-Location $root

$audit = 'docs/layers/shell/the-new-audit-screen.md'
$homePage  = 'docs/layers/shell/the-home-screen.md'
$src   = 'next/src/SecureAD.Shell/ViewModels/NewAuditViewModel.cs'

$mutations = @(
    @{ Name = 'New Audit page drops the NewAuditViewModel row';
       File = $audit;
       From = '| `NewAuditViewModel` | The New Audit window';
       To   = '| `NewAuditViewModelXX` | The New Audit window' }

    @{ Name = 'Home page drops the HomeViewModel row';
       File = $homePage;
       From = '| `HomeViewModel` | The first screen';
       To   = '| `HomeViewModelXX` | The first screen' }

    @{ Name = 'Home page header stops naming a file its component is scoped from';
       File = $homePage;
       From = '`RunLibraryLocation.cs`, `ShellSettings.cs`';
       To   = '`RunLibraryLocation.cs`' }

    @{ Name = 'a shell view model becomes public, so the window grows a surface';
       File = $src;
       From = 'internal sealed partial class NewAuditViewModel';
       To   = 'public sealed partial class NewAuditViewModel' }

    @{ Name = 'a shell page claims a type the surface register already holds';
       File = $homePage;
       From = '| `HomeViewModel` | The first screen: where the run library is |';
       To   = "| ``HomeViewModel`` | The first screen: where the run library is |`r`n| ``RunLibrary`` | A type the register holds and the shell must not |" }
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
