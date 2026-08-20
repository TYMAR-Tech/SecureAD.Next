$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Splits a folder's documents into those a test opens (specification) and those none does
# (prose). "Opens" means the file name appears in a quoted string literal in test source,
# not in an XML doc comment - a citation in a comment is not enforcement.
$literals = @{}
foreach ($cs in (git ls-files 'next/tests/*.cs')) {
    foreach ($m in [regex]::Matches((Get-Content $cs -Raw), '"([^"\r\n]*\.md)"')) {
        $literals[(Split-Path $m.Groups[1].Value -Leaf)] = $true
    }
}

$folder = 'docs/next'
$files = git ls-files "$folder/*.md" | Where-Object { (Split-Path $_ -Parent).Replace('\','/') -eq $folder }
"ENFORCED (a test opens it):"
$files | Where-Object { $literals[(Split-Path $_ -Leaf)] } | ForEach-Object { "   $_" }
""
"NOT ENFORCED (prose):"
$files | Where-Object { -not $literals[(Split-Path $_ -Leaf)] } | ForEach-Object {
    "{0,6} lines  {1}" -f (Get-Content $_).Count, $_
}
