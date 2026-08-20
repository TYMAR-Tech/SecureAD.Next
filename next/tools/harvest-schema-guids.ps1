# Re-checks every SchemaGuidCatalog.EmbeddedEntries() row against the value Microsoft publishes
# for it, reading the GUID field that belongs to the row's kind: Rights-GUID for extended rights,
# validated writes and property sets, System-Id-Guid for attributes, Schema-Id-Guid for classes.
# Reading the wrong field makes a correct entry look wrong, which is the easiest way to
# manufacture a false finding here.
#
# SchemaGuidCatalogMicrosoftAnchorTests is the gate; this is how its rows were sourced and how to
# re-source them when Microsoft moves a page. Entries with no published value - the LAPS pair and
# msDS-KeyCredentialLink - report as fetch failures and are expected to.
#
# Source: MicrosoftDocs/win32, desktop-src/ADSchema, which is what learn.microsoft.com renders.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$source = Join-Path $PSScriptRoot '..\src\SecureAD.Kernel\Schema\SchemaGuidCatalog.cs'
$lines = Get-Content -LiteralPath $source

$entries = @()
foreach ($line in $lines) {
    if ($line -match '^\s*(ExtendedRight|ValidatedWrite|PropertySet|Attribute|ObjectClass)\("([0-9a-fA-F-]+)",\s*"([^"]+)"\),\s*$') {
        $entries += [pscustomobject]@{
            Kind     = $Matches[1]
            Guid     = $Matches[2]
            LdapName = $Matches[3]
        }
    }
}

Write-Host "Parsed $($entries.Count) entries"
$entries | Group-Object Kind | ForEach-Object { Write-Host "  $($_.Name): $($_.Count)" }

function Get-Slug($kind, $name) {
    $lower = $name.ToLowerInvariant()
    switch ($kind) {
        'ExtendedRight'  { "r-$lower" }
        'ValidatedWrite' { "r-$lower" }
        'PropertySet'    { "r-$lower" }
        'Attribute'      { "a-$lower" }
        'ObjectClass'    { "c-$lower" }
    }
}

function Get-Field($content, $field) {
    foreach ($l in ($content -split "`n")) {
        if ($l -match "^\|\s*$([regex]::Escape($field))\s*\|\s*([^|]*?)\s*\|") {
            return $Matches[1].Trim()
        }
    }
    return $null
}

$results = @()
foreach ($e in $entries) {
    $slug = Get-Slug $e.Kind $e.LdapName
    $url = "https://raw.githubusercontent.com/MicrosoftDocs/win32/docs/desktop-src/ADSchema/$slug.md"
    $content = $null
    $status = 'ok'
    try {
        $content = (Invoke-WebRequest -UseBasicParsing -Uri $url).Content
    }
    catch {
        $status = "fetch-failed: $($_.Exception.Message)"
    }

    $guidField = switch ($e.Kind) {
        'ExtendedRight'  { 'Rights-GUID' }
        'ValidatedWrite' { 'Rights-GUID' }
        'PropertySet'    { 'Rights-GUID' }
        'Attribute'      { 'System-Id-Guid' }
        'ObjectClass'    { 'Schema-Id-Guid' }
    }

    $results += [pscustomobject]@{
        Kind      = $e.Kind
        LdapName  = $e.LdapName
        Guid      = $e.Guid
        Slug      = $slug
        Status    = $status
        MsCn      = if ($content) { Get-Field $content 'CN' } else { $null }
        MsLdap    = if ($content) { Get-Field $content 'Ldap-Display-Name' } else { $null }
        GuidField = $guidField
        MsGuid    = if ($content) { Get-Field $content $guidField } else { $null }
    }
}

$out = Join-Path $PSScriptRoot 'schema-guid-harvest.csv'
$results | Export-Csv -LiteralPath $out -NoTypeInformation
Write-Host "Wrote $out"

Write-Host "`n=== FETCH FAILURES ==="
$results | Where-Object { $_.Status -ne 'ok' } | ForEach-Object { Write-Host "$($_.Kind) $($_.LdapName) -> $($_.Slug)" }

Write-Host "`n=== GUID MISMATCHES ==="
$results | Where-Object { $_.MsGuid -and ($_.MsGuid.ToLowerInvariant() -ne $_.Guid.ToLowerInvariant()) } |
    ForEach-Object { Write-Host "$($_.Kind) $($_.LdapName): catalogue=$($_.Guid) ms($($_.GuidField))=$($_.MsGuid)" }

Write-Host "`n=== MISSING GUID FIELD ==="
$results | Where-Object { $_.Status -eq 'ok' -and -not $_.MsGuid } | ForEach-Object { Write-Host "$($_.Kind) $($_.LdapName) -> $($_.Slug)" }
