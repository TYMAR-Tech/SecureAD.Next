param([Parameter(Mandatory)][string[]]$Archived, [switch]$Apply)

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Turns [text](path/into/an/archived/doc.md) into plain text in the documents that are STAYING,
# so archiving a folder never deletes a sentence - only the clickable target. Resolves each
# link against its containing directory; matching link text instead would rewrite links that
# merely share a file name with an archived one.
$targets = $Archived | ForEach-Object { (Resolve-Path $_).Path }
function Inside($p) { foreach ($t in $targets) { if ($p.StartsWith($t)) { return $true } } $false }

$changed = 0
foreach ($file in (git ls-files 'docs/*.md')) {
    $full = (Resolve-Path $file).Path
    if (Inside $full) { continue }
    $dir = Split-Path $full -Parent
    $orig = Get-Content $file -Raw
    $new = [regex]::Replace($orig, '\[([^\]]+)\]\(([^)#]+\.md)[^)]*\)', {
        param($m)
        $t = [System.IO.Path]::GetFullPath((Join-Path $dir $m.Groups[2].Value))
        if (Inside $t) { $m.Groups[1].Value } else { $m.Value }
    })
    if ($new -ne $orig) {
        $changed++
        "$file"
        if ($Apply) { [System.IO.File]::WriteAllText($full, $new, (New-Object Text.UTF8Encoding $false)) }
    }
}
"$changed document(s) " + $(if ($Apply) { 'rewritten' } else { 'would change - rerun with -Apply' })
