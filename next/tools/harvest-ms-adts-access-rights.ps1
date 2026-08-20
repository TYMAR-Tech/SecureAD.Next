# Re-checks the AD access-right bit values and the four generic-right mappings against
# MS-ADTS 5.1.3.2, which states both in its own prose: each right as "CC (RIGHT_DS_CREATE_CHILD,
# 0x00000001)" and each mapping as "GR = (RC | LC | RP | LO)". Both are extracted and joined
# here, so the printed mapping values are computed from Microsoft's own bit table rather than
# read off by eye.
#
# GenericRightsExpanderMicrosoftAnchorTests is the gate; this is how its rows were sourced.
#
# NOTE - this is a weaker harvest than harvest-schema-guids.ps1, and knowing why matters.
# That one reads Microsoft's own markdown from MicrosoftDocs/win32. The Open Specifications
# (MS-ADTS, MS-DTYP) are not published as markdown anywhere public - only as rendered pages -
# so this strips HTML tags before matching. The text read is the same specification text; what
# is fragile is the extraction, which a change to Microsoft's page rendering could break. A run
# that suddenly parses zero rights means the page changed, not that the rights did.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$url = 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/990fb975-ab31-4bc1-8b75-5da132cd4584'
$html = (Invoke-WebRequest -UseBasicParsing -Uri $url).Content
$text = [System.Net.WebUtility]::HtmlDecode([regex]::Replace($html, '<[^>]+>', ' '))
$text = [regex]::Replace($text, '\s+', ' ')

$bits = [ordered]@{}
foreach ($m in [regex]::Matches($text, '([A-Z]{2}) \(RIGHT_[A-Z_]+, (0x[0-9A-Fa-f]{8})\)')) {
    $bits[$m.Groups[1].Value] = [uint32]$m.Groups[2].Value
}

Write-Host "Access right bits parsed: $($bits.Count)"
$bits.GetEnumerator() | ForEach-Object { "  {0} = 0x{1:X8}" -f $_.Key, $_.Value }

Write-Host "`nGeneric mappings (value computed from the bits above):"
foreach ($m in [regex]::Matches($text, '(G[RWXA]) = \(([A-Z |]+)\)')) {
    $parts = $m.Groups[2].Value -split '\|' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $value = 0
    foreach ($p in $parts) { $value = $value -bor $bits[$p] }
    "  {0} = 0x{1:X8}  = {2}" -f $m.Groups[1].Value, $value, ($parts -join ' | ')
}
