$ErrorActionPreference = 'Stop'
$root = 'C:\Users\jistrand\source\repos\SecureAD.Next'

$owners = Get-ChildItem -Path (Join-Path $root 'docs\layers') -Recurse -Filter '*.md' |
    Where-Object { (Get-Content $_.FullName -Raw) -match 'TYPES:BEGIN' }

$map = @{}

foreach ($file in $owners) {
    $lines = [System.IO.File]::ReadAllLines($file.FullName)
    $inTable = $false
    foreach ($line in $lines) {
        if ($line -match 'TYPES:BEGIN') { $inTable = $true; continue }
        if ($line -match 'TYPES:END')   { $inTable = $false; continue }
        if (-not $inTable) { continue }
        if ($line -notmatch '^\|') { continue }
        $cells = $line.Trim('|').Split('|')
        $name = $cells[0].Trim().Trim('`')
        if ($name -eq 'Type' -or $name -match '^-+$' -or [string]::IsNullOrWhiteSpace($name)) { continue }

        $relative = $file.FullName.Substring($root.Length + 1).Replace('\', '/')
        if ($map.ContainsKey($name)) {
            Write-Output ("DUPLICATE OWNER: {0} in {1} and {2}" -f $name, $map[$name], $relative)
        }
        $map[$name] = $relative
    }
}

$targets = @(
    'GenericRightsExpander','AceNormalizer','AceNormalizationResult','CanonicalAce',
    'AceCanonicalization','SchemaGuidCatalog','SchemaGuidEntry','SchemaGuidKind','SchemaGuidSource',
    'DangerousPermissionClassifier','PermissionAssessment','PermissionVerdict','EntryReach',
    'EntryReachReader','AceSetHash','PermissionWordingWriter','PermissionWording','PermissionRight',
    'PermissionScopeWriter','PermissionScope')

foreach ($name in $targets) {
    if ($map.ContainsKey($name)) {
        Write-Output ("{0,-32} {1}" -f $name, $map[$name])
    } else {
        Write-Output ("{0,-32} *** NO OWNER ***" -f $name)
    }
}
