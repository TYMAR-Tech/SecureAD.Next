$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Could the component documents fold into the area files? Only if each belongs to exactly one
# area. One cited by two areas would have to be duplicated, and a fact in two places is a fact
# that can disagree with itself. This is the same test that settled the decision records:
# 51 of 69 were shared, so they stayed separate.
$byDoc = @{}
foreach ($f in (git ls-files 'docs/areas/*.md')) {
    $area = (Split-Path $f -Leaf) -replace '\.md$', ''
    if ($area -eq 'README') { continue }
    $text = [System.IO.File]::ReadAllText((Resolve-Path $f).Path, [System.Text.Encoding]::UTF8)
    foreach ($m in [regex]::Matches($text, '\bS-\d+\b')) {
        $id = $m.Value
        if (-not $byDoc[$id]) { $byDoc[$id] = @() }
        if ($byDoc[$id] -notcontains $area) { $byDoc[$id] += $area }
    }
}
$one = @($byDoc.Keys | Where-Object { $byDoc[$_].Count -eq 1 })
$many = @($byDoc.Keys | Where-Object { $byDoc[$_].Count -gt 1 })
"Component documents cited by exactly one area : $($one.Count)"
"Component documents cited by more than one    : $($many.Count)"
""
foreach ($id in ($many | Sort-Object)) { "  {0,-6} ({1})  {2}" -f $id, $byDoc[$id].Count, ($byDoc[$id] -join ', ') }
