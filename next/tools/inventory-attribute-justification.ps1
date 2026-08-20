$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Which captured attributes are justified by a rule card, and which only by a component of the
# old application? The catalogue's table is
#   | Attribute | Cardinality | Storage | Read by | Why |
# and only the "Read by" column counts. Scanning the whole row also reads the "Why" prose, which
# invents readers out of ordinary words and numbers.
$legacyOnly = @{}; $mixed = @{}; $ruleOnly = @{}
foreach ($line in [System.IO.File]::ReadAllLines((Resolve-Path 'docs/next/S-8-captured-attribute-catalogue.md').Path, [System.Text.Encoding]::UTF8)) {
    if ($line -notmatch '^\|') { continue }
    $cells = $line -split '\|'
    if ($cells.Count -lt 6) { continue }
    $name = $cells[1].Trim().Trim('`')
    $readBy = $cells[4]
    if ($name -in @('Attribute', '---') -or $name -match '^-+$') { continue }

    $ids = @([regex]::Matches($readBy, '\b[A-K][0-9]{1,2}\b') | ForEach-Object { $_.Value })
    $rules = @([regex]::Matches($readBy, '\bSEC-\d+\b') | ForEach-Object { $_.Value })
    if ($ids.Count -eq 0 -and $rules.Count -eq 0) { continue }

    if ($rules.Count -eq 0) { $legacyOnly[$name] = ($ids | Sort-Object -Unique) -join ', ' }
    elseif ($ids.Count -gt 0) { $mixed[$name] = $readBy.Trim() }
    else { $ruleOnly[$name] = $readBy.Trim() }
}
"NO RULE CARD - justified only by an old-application component: $($legacyOnly.Count) attributes"
$legacyOnly.Keys | Sort-Object | ForEach-Object { "   {0,-26} {1}" -f $_, $legacyOnly[$_] }
""
"A RULE CARD AND ALSO A COMPONENT: $($mixed.Count)"
$mixed.Keys | Sort-Object | ForEach-Object { "   {0,-26} {1}" -f $_, $mixed[$_] }
""
"A RULE CARD ALONE: $($ruleOnly.Count)"
$ruleOnly.Keys | Sort-Object | ForEach-Object { "   {0,-26} {1}" -f $_, $ruleOnly[$_] }
