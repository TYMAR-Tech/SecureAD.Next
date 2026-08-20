$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Double-encoded UTF-8 shows up as the byte sequence for U+00E2 U+20AC (the "a-circumflex
# euro" pair) where an em dash or curly quote should be. Reading with an explicit UTF-8
# decoder is the only reliable check; the terminal re-mangles anything it prints.
$bad = 0
foreach ($f in (git ls-files 'docs/*.md')) {
    $text = [System.IO.File]::ReadAllText((Resolve-Path $f).Path, [System.Text.Encoding]::UTF8)
    $hits = ([regex]::Matches($text, "\u00E2\u20AC")).Count
    if ($hits -gt 0) { $bad++; "{0,5} suspect sequences  {1}" -f $hits, $f }
}
"Documents with double-encoded text: $bad"
