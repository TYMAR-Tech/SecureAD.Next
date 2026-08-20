param([Parameter(Mandatory)][string]$Destination)

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Extracts every document deleted from docs/ during the documentation clean into $Destination,
# keeping its original folder structure. For each file, takes the version from the commit
# immediately BEFORE the one that deleted it, which is its last real content.
#
# Redirects through cmd rather than piping into PowerShell: a pipe would decode the blob as
# text using the system codepage and re-encode it, which is exactly how 29 documents were
# double-encoded earlier in this work. cmd passes bytes straight through.
$deleted = git log --diff-filter=D --name-only --pretty=format: -- docs |
    Where-Object { $_ } | Sort-Object -Unique

$n = 0
foreach ($path in $deleted) {
    $killer = git rev-list -n 1 HEAD -- $path
    if (-not $killer) { continue }
    $out = Join-Path $Destination ($path -replace '/', '\')
    New-Item -ItemType Directory -Force -Path (Split-Path $out -Parent) | Out-Null
    cmd /c "git show `"$killer^:$path`" > `"$out`"" 2>$null
    if (Test-Path -LiteralPath $out) { $n++ }
}
"Extracted $n of $($deleted.Count) deleted document(s) to $Destination"
