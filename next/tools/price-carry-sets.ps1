$ErrorActionPreference = 'Stop'
$repo = 'C:\Users\jistrand\source\repos\razamus\SecureAD'
$docs = Join-Path $repo 'docs'
$all = Get-ChildItem $docs -Recurse -Filter *.md -File
$linkPattern = '\]\(([^)#]+?)(?:#[^)]*)?\)'

function Measure-CarrySet {
    param([string]$Name, [string[]]$CarryFolders, [bool]$CarrySessions)

    function IsCarried([string]$fullPath) {
        $rel = ($fullPath -replace [regex]::Escape($docs), '').TrimStart('\')
        if ($rel -notmatch '\\') { return $true }
        $top = ($rel -split '\\')[0]
        if ($top -eq 'next' -and $rel -match '^next\\sessions\\') { return $CarrySessions }
        return $CarryFolders -contains $top
    }

    $carried = $all | Where-Object { IsCarried $_.FullName }
    $broken = 0
    $words = 0

    foreach ($f in $carried) {
        $text = Get-Content $f.FullName -Raw
        if ([string]::IsNullOrEmpty($text)) { continue }
        $words += ($text -split '\s+').Count
        foreach ($m in [regex]::Matches($text, $linkPattern)) {
            $target = $m.Groups[1].Value.Trim()
            if ($target -match '^(https?:|mailto:)') { continue }
            $resolved = [System.IO.Path]::GetFullPath((Join-Path $f.Directory.FullName $target))
            $ok = $false
            if ($resolved.StartsWith($docs, 'OrdinalIgnoreCase')) {
                if (Test-Path $resolved) { $ok = IsCarried $resolved }
            }
            elseif ($resolved.StartsWith((Join-Path $repo 'next'), 'OrdinalIgnoreCase')) { $ok = $true }
            elseif ($resolved -eq (Join-Path $repo 'README.md')) { $ok = $true }
            elseif ($resolved.StartsWith((Join-Path $repo '.github'), 'OrdinalIgnoreCase')) { $ok = $true }
            if (-not $ok) { $broken++ }
        }
    }

    "{0,-46} {1,4} files  {2,8:N0} words  {3,4} broken links" -f $Name, $carried.Count, $words, $broken
}

Measure-CarrySet 'A1  rules+decisions+areas+next(-sessions)+map' @('rules', 'decisions', 'areas', 'next', 'map') $false
Measure-CarrySet 'A2  ...+sessions'                              @('rules', 'decisions', 'areas', 'next', 'map') $true
Measure-CarrySet 'A3  ...+sessions+history'                      @('rules', 'decisions', 'areas', 'next', 'map', 'history') $true
Measure-CarrySet 'A4  everything except review+work'             @('rules', 'decisions', 'areas', 'next', 'map', 'history') $true
Measure-CarrySet 'A5  everything'                                @('rules', 'decisions', 'areas', 'next', 'map', 'history', 'review', 'work') $true
