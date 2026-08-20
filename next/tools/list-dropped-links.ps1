$ErrorActionPreference = 'Stop'
$repo = 'C:\Users\jistrand\source\repos\razamus\SecureAD'
$docs = Join-Path $repo 'docs'
$drop = @('review', 'work')

$all = Get-ChildItem $docs -Recurse -Filter *.md -File
$carried = $all | Where-Object {
    $rel = ($_.FullName -replace [regex]::Escape($docs), '').TrimStart('\')
    if ($rel -notmatch '\\') { $true } else { $drop -notcontains ($rel -split '\\')[0] }
}

$linkPattern = '\]\(([^)#]+?)(?:#[^)]*)?\)'
$broken = @()

foreach ($f in $carried) {
    $text = Get-Content $f.FullName -Raw
    if ([string]::IsNullOrEmpty($text)) { continue }
    $lines = $text -split "`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        foreach ($m in [regex]::Matches($lines[$i], $linkPattern)) {
            $target = $m.Groups[1].Value.Trim()
            if ($target -match '^(https?:|mailto:)') { continue }
            $resolved = [System.IO.Path]::GetFullPath((Join-Path $f.Directory.FullName $target))
            if (-not $resolved.StartsWith($docs, 'OrdinalIgnoreCase')) { continue }
            $rel = ($resolved -replace [regex]::Escape($docs), '').TrimStart('\')
            if ($rel -notmatch '\\') { continue }
            if ($drop -contains ($rel -split '\\')[0]) {
                $broken += [pscustomobject]@{
                    From   = ($f.FullName -replace [regex]::Escape($docs), 'docs').Replace('\', '/')
                    Line   = $i + 1
                    Target = $target
                    Text   = $lines[$i].Trim()
                }
            }
        }
    }
}

Write-Host "=== LINKS INTO review/ OR work/ FROM CARRIED DOCS: $($broken.Count) ==="
Write-Host ''
$broken | Sort-Object From, Line | ForEach-Object {
    $t = $_.Text; if ($t.Length -gt 110) { $t = $t.Substring(0, 110) + '...' }
    "{0}:{1}" -f $_.From, $_.Line
    "    -> {0}" -f $_.Target
    "    {0}" -f $t
    ''
}
