$ErrorActionPreference = 'Continue'
$repo = 'C:\Users\jistrand\source\repos\razamus\SecureAD'
$docs = Join-Path $repo 'docs'

# Folders proposed to travel to the new repository.
$carry = @('rules', 'decisions', 'areas', 'next')      # docs/next EXCLUDING docs/next/sessions
$carryRootFiles = $true

function IsCarried([string]$fullPath) {
    $rel = ($fullPath -replace [regex]::Escape($docs), '').TrimStart('\')
    if ($rel -notmatch '\\') { return $carryRootFiles }          # docs/*.md
    $top = ($rel -split '\\')[0]
    if ($top -eq 'next' -and $rel -match '^next\\sessions\\') { return $false }
    return $carry -contains $top
}

$all = Get-ChildItem $docs -Recurse -Filter *.md -File
$carried = $all | Where-Object { IsCarried $_.FullName }

Write-Host "documents carried:     $($carried.Count)"
Write-Host "documents left behind: $($all.Count - $carried.Count)"
Write-Host ''

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

            $survives = $false
            if ($resolved.StartsWith($docs, 'OrdinalIgnoreCase')) {
                if (Test-Path $resolved) { $survives = IsCarried $resolved }
            }
            elseif ($resolved.StartsWith((Join-Path $repo 'next'), 'OrdinalIgnoreCase')) { $survives = $true }
            elseif ($resolved -eq (Join-Path $repo 'README.md')) { $survives = $true }
            elseif ($resolved.StartsWith((Join-Path $repo '.github'), 'OrdinalIgnoreCase')) { $survives = $true }

            if (-not $survives) {
                $broken += [pscustomobject]@{
                    From   = ($f.FullName -replace [regex]::Escape($docs), 'docs').Replace('\', '/')
                    Line   = $i + 1
                    Target = $target
                }
            }
        }
    }
}

Write-Host "=== LINKS FROM CARRIED DOCS THAT WOULD BREAK: $($broken.Count) ==="
Write-Host ''
$broken | Group-Object Target | Sort-Object Count -Descending | ForEach-Object {
    "  {0,3}x  {1}" -f $_.Count, $_.Name
}
Write-Host ''
Write-Host '=== BY SOURCE FOLDER ==='
$broken | Group-Object { ($_.From -split '/')[1] } | Sort-Object Count -Descending | ForEach-Object {
    "  {0,-14} {1,4} broken links" -f $_.Name, $_.Count
}
