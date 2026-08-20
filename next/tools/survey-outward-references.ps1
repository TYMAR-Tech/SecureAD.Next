$ErrorActionPreference = 'Continue'
$repo = 'C:\Users\jistrand\source\repos\razamus\SecureAD'

# Everything outside next/ that mentions next/, so the move does not silently break a workflow,
# a script or a benchmark that nobody thought to look at.

$exclude = '\\(\.git|\.vs|next|obj|bin|node_modules)\\'

$files = Get-ChildItem $repo -Recurse -File -Force -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -notmatch $exclude -and
        $_.FullName -notmatch '\\\.git\\' -and
        $_.Extension -in '.yml', '.yaml', '.ps1', '.props', '.json', '.sln', '.csproj', '.md', '.cmd', '.bat', '.editorconfig', '.txt'
    }

Write-Host "scanning $($files.Count) files outside next/"
Write-Host ''

$hits = @()
foreach ($f in $files) {
    $text = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrEmpty($text)) { continue }
    $lines = $text -split "`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '(^|[^A-Za-z])next[/\\]' -or $lines[$i] -match 'SecureAD\.Next') {
            $hits += [pscustomobject]@{
                File = ($f.FullName -replace [regex]::Escape($repo), '').TrimStart('\')
                Line = $i + 1
                Text = $lines[$i].Trim()
            }
        }
    }
}

Write-Host "=== REFERENCES TO next/ FROM OUTSIDE IT: $($hits.Count) ==="
$hits | Group-Object File | Sort-Object Count -Descending | ForEach-Object {
    Write-Host ''
    Write-Host ("  {0}  ({1} references)" -f $_.Name, $_.Count)
    $_.Group | Select-Object -First 6 | ForEach-Object {
        $t = $_.Text; if ($t.Length -gt 120) { $t = $t.Substring(0, 120) + '...' }
        Write-Host ("      line {0}: {1}" -f $_.Line, $t)
    }
    if ($_.Count -gt 6) { Write-Host ("      ... and {0} more" -f ($_.Count - 6)) }
}
