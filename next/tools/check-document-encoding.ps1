$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Double-encoded UTF-8: text that was UTF-8, read as if it were a single-byte codepage, and
# written back out as UTF-8. Every byte above 0x7F becomes its own character, so one non-ASCII
# character becomes two or three - and the FIRST of those is always U+00C2, U+00C3 or U+00E2,
# because those are what the UTF-8 lead bytes 0xC2, 0xC3 and 0xE2 decode to in cp1252.
#
# THIS CHECK USED TO LOOK FOR ONE PAIR AND MISSED REAL DAMAGE. It matched only "\u00E2\u20AC" -
# the a-circumflex/euro sequence an em dash or curly quote turns into - and reported zero while
# two rows of PUNCH-LIST.md carried "\u00C2\u2556", which is what a MIDDLE DOT turns into. That
# corruption was committed twice with the check passing over it (37f7359, 829170f) and was found
# by eye on 2026-09-01. A check that passes while measuring nothing is worse than no check,
# because everything downstream of it looks verified.
#
# So the lead character is what is matched, followed by anything in the range a mangled
# continuation byte lands in. Reading with an explicit UTF-8 decoder is still the only reliable
# way to see it; the terminal re-mangles anything it prints.
$pattern = '[\u00C2\u00C3\u00E2][\u0080-\u00FF\u2000-\u27BF\u0152-\u0178]'

$bad = 0

foreach ($f in (git ls-files 'docs/*.md')) {
    # git lists a deleted file until the deletion is staged, so a missing path here is
    # expected rather than an error. Dying on one would stop the scan part way through.
    if (-not (Test-Path $f)) { continue }

    $text = [System.IO.File]::ReadAllText((Resolve-Path $f).Path, [System.Text.Encoding]::UTF8)
    $hits = [regex]::Matches($text, $pattern)

    if ($hits.Count -gt 0) {
        $bad++
        '{0,5} suspect sequences  {1}' -f $hits.Count, $f

        # What was found, so a reader can tell a real fault from a false one without opening the
        # file and hunting. Reporting only a count leaves the next person where this check left
        # the last one: told something is wrong and not what.
        foreach ($sequence in ($hits | ForEach-Object { $_.Value } | Sort-Object -Unique)) {
            $codes = ($sequence.ToCharArray() | ForEach-Object { 'U+{0:X4}' -f [int] $_ }) -join ' '
            "        '$sequence'  ($codes)"
        }
    }
}

# THE SELF-TEST. A gate that has never been observed failing is not evidence, so this feeds the
# pattern text that is known to be damaged and text that is known to be clean, and refuses to
# report a result if either comes out wrong. Without it, a future edit that breaks the pattern
# would leave this printing "0" forever and nobody would know.
$mustMatch = @(
    ([char] 0x00C2 + [char] 0x2556),   # middle dot, the sequence this check used to miss
    ([char] 0x00E2 + [char] 0x20AC),   # em dash or curly quote, the sequence it did catch
    ([char] 0x00C3 + [char] 0x00A9))   # e-acute

$mustNotMatch = @(
    'plain ascii',
    'an em dash - like this',
    ([string] [char] 0x00B7),          # a correct middle dot
    ([string] [char] 0x2014))          # a correct em dash

foreach ($sample in $mustMatch) {
    if ([regex]::Matches($sample, $pattern).Count -eq 0) {
        throw 'The encoding check no longer detects known-corrupt text, so its result means nothing.'
    }
}

foreach ($sample in $mustNotMatch) {
    if ([regex]::Matches($sample, $pattern).Count -gt 0) {
        throw 'The encoding check now flags correct text, so it would be worked around rather than trusted.'
    }
}

"Documents with double-encoded text: $bad"
