$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Values Microsoft defines that the hex/GUID/OID/SID scanner cannot see. The session brief named
# this blind spot: a value written 26 rather than 0x1A is invisible to it. So are names, which are
# just as much Microsoft's to define as numbers - an attribute spelled wrong finds nothing and
# reports nothing wrong.
$src = @(git ls-files 'next/src/*.cs')

function Report($title, $pattern, $note) {
    $hits = @()
    foreach ($f in $src) {
        $text = [System.IO.File]::ReadAllText((Resolve-Path $f).Path, [System.Text.Encoding]::UTF8)
        foreach ($m in [regex]::Matches($text, $pattern)) {
            $hits += "{0,-40} {1}" -f (Split-Path $f -Leaf), $m.Value.Trim()
        }
    }
    ""
    "== $title  ($($hits.Count))"
    if ($note) { "   $note" }
    $hits | Sort-Object -Unique | Select-Object -First 14 | ForEach-Object { "   $_" }
}

# Well-known relative identifiers: 512 Domain Admins, 519 Enterprise Admins, 544 Administrators.
Report 'Decimal well-known RIDs' '(?m)=\s*(51[0-9]|52[0-9]|54[0-9]|498|500|501|502)\b[^0-9]' `
    'MS-DTYP 2.4.2.4. A wrong RID names the wrong group as Tier 0.'

# LDAP control and matching-rule OIDs.
Report 'LDAP OIDs' '"1\.2\.840\.113556[0-9.]*"' `
    'MS-ADTS 3.1.1.3.4. A wrong OID is refused by the controller, so this fails loudly.'

# Attribute and class names are Microsoft''s to spell.
Report 'ldapDisplayName spellings' '"(?:ms-?DS-[A-Za-z-]+|ms-Mcs-[A-Za-z]+|msLAPS-[A-Za-z]+)"' `
    'A misspelt attribute is simply never returned, and nothing reports that it was missing.'

# searchFlags bits are decimal in Microsoft''s own table.
Report 'searchFlags / systemFlags bit tests' '(?m)(searchFlags|systemFlags)[^;\r\n]{0,60}' `
    'adschema a-searchflags. Bit 7 (128) is the confidential flag.'
