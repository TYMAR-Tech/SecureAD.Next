$ErrorActionPreference = 'Stop'
$root = 'C:\Users\jistrand\source\repos\razamus\SecureAD.Next'

# Which types does each TYPES table already own?
$owned = @{}
Get-ChildItem -Path (Join-Path $root 'docs\layers') -Recurse -Filter '*.md' |
    Where-Object { (Get-Content $_.FullName -Raw) -match 'TYPES:BEGIN' } |
    ForEach-Object {
        $inTable = $false
        foreach ($line in [System.IO.File]::ReadAllLines($_.FullName)) {
            if ($line -match 'TYPES:BEGIN') { $inTable = $true; continue }
            if ($line -match 'TYPES:END')   { $inTable = $false; continue }
            if (-not $inTable -or $line -notmatch '^\|') { continue }
            $name = $line.Trim('|').Split('|')[0].Trim().Trim('`')
            if ($name -and $name -ne 'Type' -and $name -notmatch '^-+$') {
                $owned[$name] = $_.FullName.Substring($root.Length + 1).Replace('\', '/')
            }
        }
    }

$target = $args[0]
if (-not $target) { throw 'Pass an area file stem, e.g. how-failures-are-reported' }

$register = Join-Path $root 'docs\next\SURFACE-REGISTER.md'
Write-Output "AREA FILE: $target"
Write-Output ''
Write-Output 'TYPE                             ASSEMBLY              OWNED BY'
Write-Output ('-' * 100)

foreach ($line in [System.IO.File]::ReadAllLines($register)) {
    if ($line -notmatch [regex]::Escape("areas/$target.md")) { continue }
    $cells = $line.Trim('|').Split('|')
    $type = $cells[0].Trim()
    $assembly = $cells[1].Trim()
    $by = if ($owned.ContainsKey($type)) { $owned[$type] } else { '*** UNOWNED ***' }
    Write-Output ('{0,-32} {1,-21} {2}' -f $type, $assembly, $by)
}
