$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# How much of an area file could a script produce, and how much only a human knows?
#   What is decided        - links to records. Derivable from the records themselves.
#   What is built          - names tests. Derivable from the test assembly.
#   What has not discussed - open questions. NOT derivable. Nobody has answered them.
#   Open findings          - NOT derivable until a finding is recorded somewhere machine-readable.
#   Confirmed in lab       - NOT derivable. Only the owner can supply it.
$derivable = 0; $human = 0
foreach ($f in (git ls-files 'docs/areas/*.md')) {
    if ((Split-Path $f -Leaf) -eq 'README.md') { continue }
    $section = ''
    foreach ($line in [System.IO.File]::ReadAllLines((Resolve-Path $f).Path, [System.Text.Encoding]::UTF8)) {
        if ($line -match '^##\s+(.*)') { $section = $Matches[1]; continue }
        if ($line.Trim() -eq '') { continue }
        if ($section -match 'not been discussed|Open findings') { $human++ } else { $derivable++ }
    }
}
$total = $derivable + $human
"Lines a script could produce      : {0,5}  ({1:P0})" -f $derivable, ($derivable / $total)
"Lines only a human can supply     : {0,5}  ({1:P0})" -f $human, ($human / $total)
"Total non-blank lines in areas    : {0,5}" -f $total
