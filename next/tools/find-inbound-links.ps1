$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Resolves every markdown link in docs/ relative to the file that contains it, then reports
# only those that land on one of the named targets. Matching the link TEXT instead is wrong:
# "../README.md" written inside docs/next/sessions/ points at docs/next/README.md, and reading
# it as docs/README.md invents inbound links that do not exist.
$doomed = @(
    'docs/ARCHITECTURE.md', 'docs/CAPTURE-PIPELINE.md', 'docs/CONFIGURATION.md',
    'docs/CONTROL-EDGES-AND-PATHS.md', 'docs/DATA-MODEL.md', 'docs/GROUP-POLICY-CAPTURE.md',
    'docs/INVARIANTS.md', 'docs/README.md'
) | ForEach-Object { (Resolve-Path $_).Path }

$found = @{}
foreach ($file in (git ls-files 'docs/*.md')) {
    $dir = Split-Path (Resolve-Path $file).Path -Parent
    foreach ($m in [regex]::Matches((Get-Content $file -Raw), '\]\(([^)#]+\.md)[^)]*\)')) {
        $target = [System.IO.Path]::GetFullPath((Join-Path $dir $m.Groups[1].Value))
        if ($doomed -contains $target) {
            $key = (Resolve-Path $target -Relative).Replace('\', '/')
            if (-not $found[$key]) { $found[$key] = @() }
            $found[$key] += $file
        }
    }
}

if ($found.Count -eq 0) { "No document links to any of the eight." }
foreach ($k in $found.Keys | Sort-Object) {
    "== $k  ($($found[$k].Count) inbound)"
    $found[$k] | Sort-Object -Unique | ForEach-Object { "   $_" }
}
