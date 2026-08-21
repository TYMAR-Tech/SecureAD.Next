# Re-checks the well-known SID values against MS-DTYP 2.4.2.4, which states each as a constant
# name followed by its SID, in a two-column table of constant/value against description.
#
# WellKnownSidCatalogMicrosoftAnchorTests is the gate; this is how its rows were sourced.
#
# NOTE - the Open Specifications are not published as markdown anywhere public, only as rendered
# pages, so this strips HTML tags before matching. The text read is the same specification text;
# what is fragile is the extraction. A run that parses zero SIDs means Microsoft changed the
# page, not that the values changed.
#
# Two shapes are extracted separately because they are different kinds of fact:
#   absolute       S-1-5-10          - the same SID in every forest
#   domain-relative S-1-5-21-<domain>-512 - a RID under some domain's own SID
# Conflating them is how a product reports a domain group as though it were universal.
#
# KNOWN EXCLUSION - COMPOUNDED_AUTHENTICATION (S-1-5-21-0-0-0-496) and CLAIMS_VALID
# (S-1-5-21-0-0-0-497) match neither pattern: they begin S-1-5-21 so the absolute pass skips them,
# and they carry a literal 0-0-0 rather than an italicised domain so the relative pass misses them.
# Both are Kerberos claims assertions that never appear as a DACL trustee. Named here so the lists
# are not mistaken for the whole table.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$url = 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab'
$html = (Invoke-WebRequest -UseBasicParsing -Uri $url).Content
$text = [System.Net.WebUtility]::HtmlDecode([regex]::Replace($html, '<[^>]+>', ' '))
$text = [regex]::Replace($text, '\s+', ' ')

Write-Host 'ABSOLUTE WELL-KNOWN SIDS (MS-DTYP 2.4.2.4)'
$absolute = [ordered]@{}
foreach ($m in [regex]::Matches($text, '([A-Z][A-Z0-9_\\ ]*[A-Z0-9_]) (S-1-(?:\d+-)*\d+) ')) {
    $sid = $m.Groups[2].Value
    if ($sid -match '^S-1-5-21-') { continue }   # domain-relative, handled below
    $absolute[$m.Groups[1].Value.Trim()] = $sid
}
$absolute.GetEnumerator() | ForEach-Object { "  {0,-52} {1}" -f $_.Key, $_.Value }
Write-Host "  parsed: $($absolute.Count)"

# The domain part is rendered in italics, so tag-stripping leaves spaces around it and the text
# reads "S-1-5-21- <domain> -512". Matching that literally is what the self-test below caught:
# a pattern requiring no spaces parsed only the two SIDs Microsoft writes with a literal 0-0-0.
Write-Host "`nDOMAIN-RELATIVE WELL-KNOWN SIDS (same section)"
$relative = [ordered]@{}
foreach ($m in [regex]::Matches($text, '([A-Z][A-Z0-9_ ]*[A-Z0-9_])\s+S-1-5-21-\s*<([^>]+)>\s*-\s*(\d{3})')) {
    $relative[$m.Groups[1].Value.Trim()] = '{0} (under {1})' -f $m.Groups[3].Value, $m.Groups[2].Value.Trim()
}
$relative.GetEnumerator() | ForEach-Object { "  {0,-52} RID {1}" -f $_.Key, $_.Value }
Write-Host "  parsed: $($relative.Count)"

# SCANNER SELF-TEST. Without it a page change that breaks every pattern reports two empty lists
# and looks like a clean run. These four are named individually because each carries a different
# kind of meaning the catalogue depends on: a placeholder, a qualifier, a universal group, and a
# domain-relative group.
Write-Host "`nSELF-TEST"
$expected = @{
    'CREATOR_OWNER' = 'S-1-3-0'; 'OWNER_RIGHTS' = 'S-1-3-4'
    'PRINCIPAL_SELF' = 'S-1-5-10'; 'AUTHENTICATED_USERS' = 'S-1-5-11'
}
$failed = $false
foreach ($k in $expected.Keys) {
    $got = $absolute[$k]
    if ($got -ne $expected[$k]) { Write-Host "  FAIL $k expected $($expected[$k]) got '$got'"; $failed = $true }
    else { Write-Host "  ok   $k $got" }
}
if (-not $relative.Contains('DOMAIN_ADMINS')) { Write-Host '  FAIL DOMAIN_ADMINS not parsed'; $failed = $true }
elseif ($relative['DOMAIN_ADMINS'] -notmatch '^512 ') { Write-Host "  FAIL DOMAIN_ADMINS RID $($relative['DOMAIN_ADMINS'])"; $failed = $true }
else { Write-Host "  ok   DOMAIN_ADMINS RID $($relative['DOMAIN_ADMINS'])" }
if ($failed) { Write-Host "`nEXTRACTION IS BROKEN - do not trust the lists above"; exit 1 }
Write-Host '  extraction verified'
