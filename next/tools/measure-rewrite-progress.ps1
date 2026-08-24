$root = 'C:\Users\jistrand\source\repos\razamus\SecureAD.Next'
$reg = [System.IO.File]::ReadAllLines((Join-Path $root 'docs\next\SURFACE-REGISTER.md'))
$docs = Get-ChildItem -Path (Join-Path $root 'docs\layers') -Recurse -Filter *.md

$layerText = ''
$declared = @{}
foreach ($d in $docs) {
    $text = [System.IO.File]::ReadAllText($d.FullName)
    $layerText += $text
    $begin = $text.IndexOf('<!-- TYPES:BEGIN -->')
    $end = $text.IndexOf('<!-- TYPES:END -->')
    if ($begin -ge 0 -and $end -gt $begin) {
        foreach ($row in $text.Substring($begin, $end - $begin).Split("`n")) {
            $r = $row.Trim()
            if ($r.StartsWith('|') -and -not $r.Contains('---')) {
                $declared[$r.Trim('|').Split('|')[0].Trim().Trim('`')] = $true
            }
        }
    }
}

# area -> types it still governs
$byArea = @{}
foreach ($line in $reg) {
    if ($line -notmatch '^\| ' -or $line -match '^\|---' -or $line -match '^\| Type ') { continue }
    $cells = $line -split '\|'
    $type = $cells[1].Trim()
    $target = $cells[3].Trim()
    if ($target -notmatch '\.\./areas/([a-z0-9-]+)\.md') { continue }
    $area = $Matches[1]
    if (-not $byArea.ContainsKey($area)) { $byArea[$area] = @() }
    $byArea[$area] += $type
}

'{0,-28} {1,7} {2,12} {3,10}' -f 'AREA FILE', 'GOVERNS', 'UNNAMED', 'UNDECLARED'
'-' * 62
$rows = @()
foreach ($area in $byArea.Keys) {
    $types = $byArea[$area]
    $unnamed = @($types | Where-Object { -not $layerText.Contains('`' + $_ + '`') }).Count
    $undeclared = @($types | Where-Object { -not $declared.ContainsKey($_) }).Count
    $rows += [pscustomobject]@{ Area = $area; Governs = $types.Count; Unnamed = $unnamed; Undeclared = $undeclared }
}
foreach ($r in $rows | Sort-Object Unnamed, Governs) {
    '{0,-28} {1,7} {2,12} {3,10}' -f $r.Area, $r.Governs, $r.Unnamed, $r.Undeclared
}
''
"area files with register rows: $($byArea.Keys.Count)"
"area files on disk:            " + (Get-ChildItem (Join-Path $root 'docs\areas') -Filter *.md | Where-Object { $_.Name -ne 'README.md' }).Count
"layer documents:               $($docs.Count)"
"layer documents with a TYPES table: " + @($docs | Where-Object { [System.IO.File]::ReadAllText($_.FullName).Contains('<!-- TYPES:BEGIN -->') }).Count
