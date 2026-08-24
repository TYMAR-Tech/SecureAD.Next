$root = 'C:\Users\jistrand\source\repos\razamus\SecureAD.Next'
$reg = [System.IO.File]::ReadAllLines((Join-Path $root 'docs\next\SURFACE-REGISTER.md'))

$types = @()
foreach ($line in $reg) {
    if ($line -match 'what-we-capture') { $types += ($line -split '\|')[1].Trim() }
}

$docs = Get-ChildItem -Path (Join-Path $root 'docs\layers') -Recurse -Filter *.md

# For each layer document, the set of types it declares as rows of its TYPES table.
$declared = @{}
foreach ($d in $docs) {
    $text = [System.IO.File]::ReadAllText($d.FullName)
    $begin = $text.IndexOf('<!-- TYPES:BEGIN -->')
    $end = $text.IndexOf('<!-- TYPES:END -->')
    $page = $d.Directory.Name + '/' + $d.Name
    $owned = @()
    if ($begin -ge 0 -and $end -gt $begin) {
        foreach ($row in $text.Substring($begin, $end - $begin).Split("`n")) {
            $r = $row.Trim()
            if ($r.StartsWith('|') -and -not $r.Contains('---')) {
                $owned += $r.Trim('|').Split('|')[0].Trim().Trim('`')
            }
        }
    }
    $declared[$page] = $owned
}

'{0,-38} {1}' -f 'TYPE', 'DECLARED BY (TYPES table row)'
$unowned = 0
$multi = 0
foreach ($t in $types) {
    $owners = @()
    foreach ($page in $declared.Keys) {
        if ($declared[$page] -ccontains $t) { $owners += $page }
    }
    if ($owners.Count -eq 0) { $unowned++ }
    if ($owners.Count -gt 1) { $multi++ }
    '{0,-38} {1}  {2}' -f $t, $owners.Count, ($owners -join ' ; ')
}
''
"types with no declaring page: $unowned"
"types declared by more than one page: $multi"
