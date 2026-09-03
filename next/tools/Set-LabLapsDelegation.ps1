# Plants the delegation SEC-090 exists to find, so its deep path runs against a real directory.
#
# WHY THIS EXISTS. SEC-090's first run against ad.lab produced two findings and both said
# "reached directly": Everyone was named in the access control entry itself. The part of the rule
# that matters most - walking a delegated group down through nested membership to a principal that
# is broad in every organisation - has only ever run in unit tests. building-a-rule.md is explicit
# that a code path which has only ever produced one kind of answer proves nothing.
#
# WHAT IT MAKES. Two Global groups, nested, with Domain Users at the bottom:
#
#     SecureADLapsReaders  ->  SecureADLapsMid  ->  Domain Users
#
# and grants SecureADLapsReaders permission to read the LAPS password attributes on one
# organisational unit, using Microsoft's own cmdlet rather than a hand-built entry - so the entry
# is shaped the way a real administrator's would be.
#
# TWO LEVELS RATHER THAN ONE, deliberately. A single group would exercise a path of length two,
# which a rule that only ever looked one hop down would still pass. The expected finding names
# Domain Users with the path SecureADLapsReaders -> SecureADLapsMid -> Domain Users.
#
# RUN IT ON THE LAB MACHINE. It writes to the directory and to an OU's security descriptor.
#
# USAGE
#   pwsh -File next/tools/Set-LabLapsDelegation.ps1
#   pwsh -File next/tools/Set-LabLapsDelegation.ps1 -Remove
#
# The removal deletes only objects carrying the prefix below and refuses anything else. It does
# NOT undo the permission it set on the organisational unit - see the note at the end.

[CmdletBinding()]
param(
    [switch] $Remove,

    # The organisational unit whose computers become readable. Its own security descriptor is
    # edited, so it is named in full rather than defaulted to something broad.
    [string] $TargetOu = 'OU=Workstations,OU=BA Lab,DC=ba,DC=ad,DC=lab',

    # Where the groups are created.
    [string] $Path = 'OU=BA Lab,DC=ba,DC=ad,DC=lab'
)

$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module LAPS -ErrorAction Stop

$prefix = 'SecureADLaps'
$readers = "${prefix}Readers"
$middle = "${prefix}Mid"

$domain = (Get-ADDomain).DNSRoot

function Remove-TestGroups {
    Write-Host ''
    Write-Host 'Removing the planted groups'
    Write-Host '---------------------------'

    # Re-checked against the prefix here rather than trusted from the variables above, so an
    # edited variable cannot turn this into a delete of something real.
    foreach ($name in @($readers, $middle)) {
        if (-not $name.StartsWith($prefix, [StringComparison]::Ordinal)) {
            throw "Refusing to delete '$name': it does not carry the '$prefix' prefix."
        }

        $found = Get-ADGroup -Filter "sAMAccountName -eq '$name'" -ErrorAction SilentlyContinue

        if ($null -eq $found) {
            Write-Host ("  {0,-24} already absent" -f $name)
            continue
        }

        Remove-ADGroup -Identity $found.DistinguishedName -Confirm:$false
        Write-Host ("  {0,-24} removed" -f $name)
    }

    Write-Host ''
    Write-Host 'NOTE: the access control entry on the organisational unit is NOT removed.'
    Write-Host 'It names a group that no longer exists, so it becomes an unresolved SID - which is'
    Write-Host 'itself a useful state to capture, and is why this is left rather than guessed at.'
    Write-Host 'Remove it by hand from the OU security tab if the lab should be returned to clean.'
}

if ($Remove) {
    Remove-TestGroups
    return
}

Write-Host ''
Write-Host '================================================================'
Write-Host ' Planting a nested LAPS read delegation'
Write-Host '================================================================'
Write-Host ''
Write-Host ("Domain      : {0}" -f $domain)
Write-Host ("Groups into : {0}" -f $Path)
Write-Host ("Delegating  : {0}" -f $TargetOu)
Write-Host ''

foreach ($name in @($readers, $middle)) {
    if (Get-ADGroup -Filter "sAMAccountName -eq '$name'" -ErrorAction SilentlyContinue) {
        Write-Host ("  {0,-24} already present" -f $name)
        continue
    }

    New-ADGroup -Name $name -SamAccountName $name -GroupScope Global `
        -GroupCategory Security -Path $Path
    Write-Host ("  {0,-24} created" -f $name)
}

# Global into Global within one domain, which Microsoft's scope table allows. Domain Users is the
# broad principal at the bottom, and it is broad by SID rather than by name - which is the whole
# point of BroadPrincipalCatalogue.
Add-ADGroupMember -Identity $readers -Members $middle -ErrorAction SilentlyContinue
Add-ADGroupMember -Identity $middle -Members 'Domain Users' -ErrorAction SilentlyContinue

Write-Host ''
Write-Host ("  nesting: {0} -> {1} -> Domain Users" -f $readers, $middle)

# Microsoft's own cmdlet, not a hand-built entry. It writes an object-specific entry scoped to the
# LAPS password attributes, so a rule reading the object type correctly should report
# ThisAttributeOnly rather than EveryAttribute - which is the second thing this plant checks.
Set-LapsADReadPasswordPermission -Identity $TargetOu -AllowedPrincipals @("$domain\$readers") |
    Out-Null

Write-Host ("  delegated read of the LAPS password attributes to {0}" -f $readers)
Write-Host ''
Write-Host 'What SEC-090 should now report for each computer in that organisational unit:'
Write-Host ''
Write-Host ('  broad principal : Domain Users (S-1-5-21-...-513)')
Write-Host ("  path            : {0} -> {1} -> Domain Users" -f $readers, $middle)
Write-Host ('  reach           : ThisAttributeOnly, because the cmdlet scopes the entry')
Write-Host ('  rights          : Both')
Write-Host ('  inherited from  : the organisational unit, not the computer object')
Write-Host ''
Write-Host 'Capture the forest, then judge it. Re-run with -Remove to delete the two groups.'
