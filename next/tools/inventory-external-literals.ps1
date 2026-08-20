$ErrorActionPreference = 'Stop'

# Finds every literal in the product that originates OUTSIDE the codebase and could therefore be
# silently wrong: GUIDs, hex bit constants, LDAP OIDs, well-known SIDs, LDAP result codes.
# Scanned mechanically because reading 183 files is the step that produced the defects.

$root = Join-Path $PSScriptRoot '..\src'

$files = Get-ChildItem $root -Recurse -Filter *.cs -File |
    Where-Object { $_.FullName -notmatch '\\(obj|bin)\\' }

$patterns = [ordered]@{
    'GUID'    = '"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"'
    'Hex'     = '0x[0-9a-fA-F]{1,8}'
    'OID'     = '"1\.[0-9]+(\.[0-9]+)+"'
    'SID'     = '"S-1-[0-9\-]+"'
}

$rows = @()
foreach ($f in $files) {
    $text = Get-Content $f.FullName -Raw
    if ([string]::IsNullOrEmpty($text)) { continue }
    $counts = [ordered]@{}
    $any = $false
    foreach ($k in $patterns.Keys) {
        $n = ([regex]::Matches($text, $patterns[$k])).Count
        $counts[$k] = $n
        if ($n -gt 0) { $any = $true }
    }
    if (-not $any) { continue }

    $project = ($f.FullName -replace [regex]::Escape($root), '').TrimStart('\') -split '\\' | Select-Object -First 1

    $rows += [pscustomobject]@{
        Project = $project
        File    = $f.Name
        GUID    = $counts['GUID']
        Hex     = $counts['Hex']
        OID     = $counts['OID']
        SID     = $counts['SID']
        Total   = $counts['GUID'] + $counts['Hex'] + $counts['OID'] + $counts['SID']
        Path    = ($f.FullName -replace [regex]::Escape((Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path), '').TrimStart('\')
    }
}

$rows | Sort-Object Total -Descending |
    Format-Table Project, File, GUID, Hex, OID, SID, Total -AutoSize |
    Out-String -Width 200

"FILES WITH EXTERNAL LITERALS: $($rows.Count)"
"TOTAL LITERALS: $((($rows | Measure-Object Total -Sum).Sum))"
""
"BY PROJECT:"
$rows | Group-Object Project | Sort-Object { ($_.Group | Measure-Object Total -Sum).Sum } -Descending |
    ForEach-Object { "{0,-28} {1,4} files {2,5} literals" -f $_.Name, $_.Count, ($_.Group | Measure-Object Total -Sum).Sum }

$rows | Sort-Object Total -Descending | Export-Csv -LiteralPath (Join-Path $PSScriptRoot 'external-literals.csv') -NoTypeInformation
