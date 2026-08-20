$ErrorActionPreference = 'Stop'
$doc = 'C:\Users\jistrand\Downloads\SecureAD Archive\docs\next\S-56-what-a-permission-grants.md'
$text = [System.IO.File]::ReadAllText($doc, [System.Text.Encoding]::UTF8)

# Every Microsoft source S-56 cites. The document claimed these had been read; a later session
# said they had not. Nobody can now establish which. What this produces is the denominator - the
# set of claims that would have to be re-verified for the document's subject matter to be trusted.
$urls = [regex]::Matches($text, 'learn\.microsoft\.com/[^\s)\]]+') |
    ForEach-Object { $_.Value -replace '[.,;]$', '' } |
    Sort-Object -Unique

"Distinct Microsoft pages cited: $($urls.Count)"
""
$urls | ForEach-Object { "  $_" }

$adts = [regex]::Matches($text, 'MS-ADTS[^0-9]{0,20}([0-9]+(?:\.[0-9]+)+)') |
    ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
""
"MS-ADTS sections named: $($adts.Count)"
$adts | ForEach-Object { "  $_" }
