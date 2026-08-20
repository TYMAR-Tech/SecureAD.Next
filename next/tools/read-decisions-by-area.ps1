$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# A reading order for the decision records that surfaces contradictions. Two records that
# disagree almost always govern the same subject, so they are grouped by the area that cites
# them and printed with their titles. Reading one area's decisions together is the smallest
# unit in which a contradiction is visible; reading them by number never puts the pair
# side by side.
$titles = @{}
foreach ($f in (git ls-files 'docs/decisions/0*.md')) {
    $id = (Split-Path $f -Leaf).Substring(0, 4)
    $titles[$id] = ((Get-Content $f -TotalCount 1) -replace '^#\s*\d+\s*-\s*', '')
}

foreach ($f in (git ls-files 'docs/areas/*.md')) {
    $name = (Split-Path $f -Leaf) -replace '\.md$', ''
    if ($name -eq 'README') { continue }
    $text = [System.IO.File]::ReadAllText((Resolve-Path $f).Path, [System.Text.Encoding]::UTF8)
    $ids = [regex]::Matches($text, '\b(\d{4})\b') | ForEach-Object { $_.Groups[1].Value } |
        Where-Object { $titles.ContainsKey($_) } | Sort-Object -Unique
    if (-not $ids) { continue }
    ""
    "== $name  ($($ids.Count) records)"
    foreach ($id in $ids) { "   {0}  {1}" -f $id, $titles[$id] }
}
