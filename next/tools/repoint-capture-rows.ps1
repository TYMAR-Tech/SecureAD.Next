#Requires -Version 7.0
# Windows PowerShell 5.1 reads UTF-8 files as Windows-1252, turning every em dash into three
# characters. This script writes documents, so running it under 5.1 would corrupt them silently.

$path = 'C:\Users\jistrand\source\repos\razamus\SecureAD.Next\docs\next\SURFACE-REGISTER.md'

# The owner of each type, as measured by measure-declared-owners.ps1: the page whose TYPES
# table carries the type as a row. NamingContextKind is the one ruling not settled that way -
# the-search-capture-issues.md disowns it in writing, and the coverage page describes the
# member it types.
$owner = @{
    'SecurityDescriptorParser'            = 'kernel/security-descriptors'
    'ParsedSecurityDescriptor'            = 'kernel/security-descriptors'
    'ParsedAce'                           = 'kernel/security-descriptors'
    'AceType'                             = 'kernel/security-descriptors'
    'DaclState'                           = 'kernel/security-descriptors'
    'DaclCompleteness'                    = 'kernel/security-descriptors'
    'CapturedAttributeCatalog'            = 'audit/the-attribute-catalogue'
    'CapturedAttribute'                   = 'audit/the-attribute-catalogue'
    'AttributeCardinality'                = 'audit/the-attribute-catalogue'
    'AttributeStorage'                    = 'audit/the-attribute-catalogue'
    'CaptureUnit'                         = 'audit/the-search-capture-issues'
    'CaptureSearchRequestFactory'         = 'audit/the-search-capture-issues'
    'ContinuationReferenceReconciliation' = 'audit/how-a-controller-is-read'
    'LdapEntryReader'                     = 'audit/how-a-controller-is-read'
    'AttributeValues'                     = 'audit/how-a-controller-is-read'
    'AttributeCompleteness'               = 'audit/how-a-controller-is-read'
    'AttributeRange'                      = 'audit/how-a-controller-is-read'
    'DirectoryPage'                       = 'audit/how-a-controller-is-read'
    'PageCompleteness'                    = 'audit/how-a-controller-is-read'
    'CapturedObject'                      = 'audit/how-a-controller-is-read'
    'ObjectCompleteness'                  = 'audit/how-a-controller-is-read'
    'ICapturedObjectSink'                 = 'audit/how-a-controller-is-read'
    'UserAccountControlWording'           = 'kernel/naming'
    'UserAccountControlFlag'              = 'kernel/naming'
    'DirectoryTime'                       = 'kernel/naming'
    'DirectoryTimeWording'                = 'kernel/naming'
    'DirectoryTimeFormat'                 = 'kernel/naming'
    'NamingContextKind'                   = 'evidence/run-identity-and-coverage'
}

$lines = [System.IO.File]::ReadAllLines($path)
$before = ($lines | Select-String 'what-we-capture').Count
$changed = 0
$unmapped = @()

for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -notmatch 'what-we-capture') { continue }

    $type = ($lines[$i] -split '\|')[1].Trim()
    if (-not $owner.ContainsKey($type)) { $unmapped += "$i $type"; continue }

    $page = $owner[$type]
    $label = $page.Split('/')[1]
    $lines[$i] = $lines[$i].Replace(
        '[what-we-capture](../areas/what-we-capture.md)',
        "[$label](../layers/$page.md)")
    $changed++
}

if ($unmapped.Count -gt 0) {
    "!! no owner ruled for:"
    $unmapped
    throw 'Refusing to write a partial repointing.'
}

[System.IO.File]::WriteAllLines($path, $lines, (New-Object System.Text.UTF8Encoding $false))

$after = [System.IO.File]::ReadAllLines($path)
"rows citing what-we-capture before: $before"
"rows repointed:                     $changed"
"rows citing what-we-capture after:  " + (($after | Select-String 'what-we-capture').Count)
"total lines:                        $($after.Count)"
