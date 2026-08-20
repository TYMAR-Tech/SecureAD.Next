param([Parameter(Mandatory)][string[]]$Target)

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Resolves every markdown link in docs/ relative to the file that contains it, then reports
# only those that land inside -Target and come from outside it. Matching the link TEXT instead
# is wrong: "../README.md" written inside docs/next/sessions/ points at docs/next/README.md,
# and reading it as docs/README.md invents inbound links that do not exist.
#
# -Target accepts files or folders, e.g.  -Target docs/history
$targets = $Target | ForEach-Object { (Resolve-Path $_).Path }
function Inside($path) { foreach ($t in $targets) { if ($path -eq $t -or $path.StartsWith($t + [IO.Path]::DirectorySeparatorChar)) { return $true } } $false }

$found = @{}
foreach ($file in (git ls-files 'docs/*.md')) {
    $full = (Resolve-Path $file).Path
    if (Inside $full) { continue }
    $dir = Split-Path $full -Parent
    foreach ($m in [regex]::Matches((Get-Content $file -Raw), '\]\(([^)#]+\.md)[^)]*\)')) {
        $t = [System.IO.Path]::GetFullPath((Join-Path $dir $m.Groups[1].Value))
        if (Inside $t) {
            $key = $t.Substring((Get-Location).Path.Length + 1).Replace('\', '/')
            if (-not $found[$key]) { $found[$key] = @() }
            $found[$key] += $file
        }
    }
}

if ($found.Count -eq 0) { "No document outside the target links into it." }
foreach ($k in $found.Keys | Sort-Object) {
    "== $k  ($($found[$k].Count) inbound)"
    $found[$k] | Sort-Object -Unique | ForEach-Object { "   $_" }
}
