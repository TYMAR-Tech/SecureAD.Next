$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Prints everything capture requests, read from CapturedAttributeCatalog.cs rather than from any
# document. The code is what the directory is actually asked for, so a list taken from anywhere
# else can be wrong without anything failing.
$src = [System.IO.File]::ReadAllText((Resolve-Path 'next/src/SecureAD.Kernel/Capture/CapturedAttributeCatalog.cs').Path, [System.Text.Encoding]::UTF8)

$sets = [regex]::Matches($src, '(?s)IReadOnlyList<CapturedAttribute>\s+(\w+)\s*\{\s*get;\s*\}\s*=\s*\[(.*?)\n    \];')
foreach ($s in $sets) {
    $name = $s.Groups[1].Value
    if ($name -in @('All', 'RangeLiable')) { continue }   # unions of the sets above
    $rows = [regex]::Matches($s.Groups[2].Value, 'new\("([^"]+)",\s*AttributeCardinality\.(\w+),\s*AttributeStorage\.(\w+)\)')
    ""
    "== $name  ($($rows.Count) attributes)"
    "{0,-38} {1,-14} {2}" -f 'ATTRIBUTE', 'CARDINALITY', 'STORED AS'
    foreach ($r in $rows) { "{0,-38} {1,-14} {2}" -f $r.Groups[1].Value, $r.Groups[2].Value, $r.Groups[3].Value }
}

$map = [regex]::Match($src, '(?s)ClassSpecific\s*=.*?\{(.*?)\n        \};')
if ($map.Success) {
    $pairs = [regex]::Matches($map.Groups[1].Value, '\["([^"]+)"\]\s*=\s*(\w+)')
    ""
    "== Object classes read, and which set each gets  ($($pairs.Count))"
    "{0,-36} {1}" -f 'OBJECT CLASS', 'ATTRIBUTE SET'
    foreach ($p in $pairs) { "{0,-36} {1}" -f $p.Groups[1].Value, $p.Groups[2].Value }
    "" ; "Every class above also gets the Universal set."
}

$unread = [regex]::Match($src, 'UnreadObjectClasses\s*\{\s*get;\s*\}\s*=\s*\[([^\]]+)\]')
if ($unread.Success) {
    ""
    "== Object classes deliberately NOT read"
    ([regex]::Matches($unread.Groups[1].Value, '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value }) -join ', '
}

$not = [regex]::Match($src, '(?s)NotCaptured\s*\{\s*get;\s*\}\s*=(.*?)\n        \};')
if ($not.Success) {
    # Reasons are written as several quoted strings joined with +, so the pattern has to allow
    # the operator between them or only the first line of each reason is read.
    $pairs = [regex]::Matches($not.Groups[1].Value, '(?s)\["([^"]+)"\]\s*=\s*((?:\s*\+?\s*"[^"]*")+)')
    ""
    "== Attributes deliberately NOT captured  ($($pairs.Count))"
    foreach ($p in $pairs) {
        $why = (([regex]::Matches($p.Groups[2].Value, '"([^"]*)"') | ForEach-Object { $_.Groups[1].Value }) -join '')
        ""
        "$($p.Groups[1].Value)"
        "    $why"
    }
}
