# Re-checks the ACE type and ACE flag values against MS-DTYP 2.4.4.1, which states each as a
# constant name followed by its hex value.
#
# AceTypeMicrosoftAnchorTests is the gate; this is how its rows were sourced.
#
# NOTE - the Open Specifications are not published as markdown anywhere public, only as rendered
# pages, so this strips HTML tags before matching. The text read is the same specification text;
# what is fragile is the extraction. A run that parses zero types means Microsoft changed the
# page, not that the values changed.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$url = 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586'
$html = (Invoke-WebRequest -UseBasicParsing -Uri $url).Content
$text = [System.Net.WebUtility]::HtmlDecode([regex]::Replace($html, '<[^>]+>', ' '))
$text = [regex]::Replace($text, '\s+', ' ')

Write-Host 'ACE TYPES (MS-DTYP 2.4.4.1)'
$types = [regex]::Matches($text, '([A-Z][A-Z_]*_ACE_TYPE) (0x[0-9A-Fa-f]{2})')
$seen = [ordered]@{}
foreach ($m in $types) { $seen[$m.Groups[1].Value] = $m.Groups[2].Value }
$seen.GetEnumerator() | ForEach-Object { "  {0,-45} {1}" -f $_.Key, $_.Value }
Write-Host "  parsed: $($seen.Count)"

Write-Host "`nACE FLAGS (same section)"
$flags = [ordered]@{}
foreach ($m in [regex]::Matches($text, '([A-Z][A-Z_]*(?:_ACE|_ACE_FLAG)) (0x[0-9A-Fa-f]{2}) ')) {
    if ($m.Groups[1].Value -notmatch '_ACE_TYPE$') { $flags[$m.Groups[1].Value] = $m.Groups[2].Value }
}
$flags.GetEnumerator() | ForEach-Object { "  {0,-45} {1}" -f $_.Key, $_.Value }
Write-Host "  parsed: $($flags.Count)"
