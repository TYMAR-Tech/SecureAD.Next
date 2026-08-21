# Re-checks every UserAccountControlWording.Documented row against the two pages Microsoft
# publishes these flags on, and against each other.
#
# UserAccountControlWordingMicrosoftAnchorTests is the gate; this is how its rows were sourced.
#
# THREE PAGES, AND THE THIRD IS THE POINT. adschema a-useraccountcontrol gives the bits as a table;
# the iads ADS_USER_FLAG_ENUM page gives the same constants as a C enum. Those two agree because
# both descend from iads.h - one lineage read twice, which reads like corroboration and is not.
# KB 305144 is maintained separately and publishes a bit neither of the others has,
# PARTIAL_SECRETS_ACCOUNT 0x04000000, which marks a read-only domain controller. That flag was
# missing from the product until this script read outside the family. A run reporting zero parsed
# flags for any page means Microsoft changed it, not that the values changed.
#
# Wording is deliberately NOT checked here. A script can pin a number; it cannot judge whether a
# sentence is fair to an administrator reading a report. See docs/MICROSOFT-VERIFICATION.md.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Get-PageText($url) {
    $html = (Invoke-WebRequest -UseBasicParsing -Uri $url).Content
    $text = [System.Net.WebUtility]::HtmlDecode([regex]::Replace($html, '<[^>]+>', ' '))
    return [regex]::Replace($text, '\s+', ' ')
}

function Add-Flag($map, $name, $hex) {
    $map[$name] = '0x{0:X8}' -f [Convert]::ToUInt32($hex, 16)
}

$source = Join-Path $PSScriptRoot '..\src\SecureAD.Kernel\Security\UserAccountControlWording.cs'
$code = [System.IO.File]::ReadAllText($source, [System.Text.Encoding]::UTF8)

$inCode = [ordered]@{}
foreach ($m in [regex]::Matches($code, 'new\(\s*(0x[0-9A-Fa-f]{8})\s*,\s*"([A-Z][A-Z_]+)"')) {
    Add-Flag $inCode $m.Groups[2].Value $m.Groups[1].Value
}

$schema = [ordered]@{}
$text = Get-PageText 'https://learn.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol'
foreach ($m in [regex]::Matches($text, '(0x[0-9A-Fa-f]{8})\s+\**\s*(ADS_UF_[A-Z_]+)')) {
    Add-Flag $schema $m.Groups[2].Value $m.Groups[1].Value
}

$iads = [ordered]@{}
$text = Get-PageText 'https://learn.microsoft.com/en-us/windows/win32/api/iads/ne-iads-ads_user_flag_enum'
foreach ($m in [regex]::Matches($text, '(ADS_UF_[A-Z_]+)\s*=\s*(0x[0-9A-Fa-f]+)')) {
    Add-Flag $iads $m.Groups[1].Value $m.Groups[2].Value
}

$kb = [ordered]@{}
$text = Get-PageText 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties'
foreach ($m in [regex]::Matches($text, '([A-Z][A-Z_]{4,})\s*\|?\s*(0x[0-9A-Fa-f]{4,8})\s*\|?\s*([0-9]+)')) {
    Add-Flag $kb $m.Groups[1].Value $m.Groups[2].Value
}

Write-Host "parsed: code $($inCode.Count), adschema $($schema.Count), iads $($iads.Count), kb $($kb.Count)"
if ($schema.Count -eq 0 -or $iads.Count -eq 0 -or $kb.Count -eq 0) {
    throw 'A Microsoft page parsed to zero flags. The page changed; fix the extraction before believing anything below.'
}

if ($kb.Count -lt 21) {
    throw "KB 305144 parsed only $($kb.Count) flags. It publishes 22 rows; the extraction is dropping some, so nothing below can be trusted."
}

# Names are compared only across the iads.h family, because only that family uses them. A flag
# published solely by KB 305144 is absent here by design and is checked by bit below.
$names = @($schema.Keys) + @($iads.Keys) | Sort-Object -Unique
$disagreed = 0
foreach ($name in $names) {
    $c = $inCode[$name]; $s = $schema[$name]; $i = $iads[$name]
    $agree = ($c -eq $s) -and ($s -eq $i)
    if (-not $agree) {
        $disagreed++
        "  {0,-46} code={1} adschema={2} iads={3}" -f $name, $c, $s, $i
    }
}

# KB 305144 is compared by BIT, not by name. It spells several flags differently
# (DONT_REQ_PREAUTH, ENCRYPTED_TEXT_PWD_ALLOWED) and matching on names would manufacture
# disagreements. It is the only source outside the iads.h family, and the only one that publishes
# PARTIAL_SECRETS_ACCOUNT - so a bit it holds and the code does not is the failure that matters.
$codeBits = @($inCode.Values) | Sort-Object -Unique
$published = (@($kb.Values) + @($schema.Values) + @($iads.Values)) | Sort-Object -Unique
foreach ($bit in ($published | Where-Object { $_ -notin $codeBits })) {
    $disagreed++
    "  {0,-46} Microsoft publishes this bit and the code has no flag for it" -f $bit
}
foreach ($bit in ($codeBits | Where-Object { $_ -notin $published })) {
    $disagreed++
    "  {0,-46} the code carries this bit and no Microsoft page publishes it" -f $bit
}

Write-Host "disagreements: $disagreed across $($names.Count) named flags and $($published.Count) published bits"
if ($disagreed -ne 0) { throw 'Code and Microsoft disagree. Independent reads of one specification; find out which is wrong.' }
