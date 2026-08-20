$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Could the decision records simply live inside the area files? Only if each record belongs to
# exactly one area. A record cited by two areas would have to be duplicated, and a fact written
# in two places is a fact that can disagree with itself - which is what produced the
# documentation this project has spent a session clearing out.
$byRecord = @{}
foreach ($f in (git ls-files 'docs/areas/*.md')) {
    $area = (Split-Path $f -Leaf) -replace '\.md$', ''
    $text = [System.IO.File]::ReadAllText((Resolve-Path $f).Path, [System.Text.Encoding]::UTF8)
    foreach ($m in [regex]::Matches($text, '\b(\d{4})\b')) {
        $id = $m.Groups[1].Value
        if ([int]$id -lt 1 -or [int]$id -gt 76) { continue }
        if (-not $byRecord[$id]) { $byRecord[$id] = @() }
        if ($byRecord[$id] -notcontains $area) { $byRecord[$id] += $area }
    }
}
$shared = $byRecord.Keys | Where-Object { $byRecord[$_].Count -gt 1 } | Sort-Object
"Records cited by exactly one area : $(($byRecord.Keys | Where-Object { $byRecord[$_].Count -eq 1 }).Count)"
"Records cited by more than one    : $($shared.Count)"
""
"SHARED RECORDS - these would have to be duplicated if decisions moved into areas"
foreach ($id in $shared) { "  {0}  ({1})  {2}" -f $id, $byRecord[$id].Count, ($byRecord[$id] -join ', ') }
