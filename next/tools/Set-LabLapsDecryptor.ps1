<#
.SYNOPSIS
    Plants the three shapes of LAPS decryptor SEC-093 reports, so a lab run measures something.

.DESCRIPTION
    The lab has no positive case for SEC-093 on its own. All three real decryptors in ad.lab expand
    cleanly with no broad principals, measured 2026-09-03, so a run against an untouched lab
    produces zero findings and proves nothing. A green light over an unmeasured rule is the first
    item on this repository's stop-the-work list, which is why this script exists.

    It creates three Group Policy Objects, one for each shape the rule can report:

      SecureADLapsDecryptorNested   decryptor is a wrapper group with Domain Users nested inside
                                    two levels down. The finding should name Domain Users and show
                                    the route. This is the case the rule was written for, because a
                                    wrapper group is Microsoft's own documented answer to LAPS
                                    encrypting against only one principal.

      SecureADLapsDecryptorDirect   decryptor is the Domain Users SID outright. The plainest form:
                                    one step, no nesting.

      SecureADLapsDecryptorUnknown  decryptor is a name nothing resolves. This is NOT the broad
                                    finding - it is the separate one, because Microsoft records
                                    that an invalid principal makes policy processing fail and the
                                    password is not backed up at all.

    THE POLICIES ARE DELIBERATELY NOT LINKED ANYWHERE. SEC-093's subject is the policy and never a
    machine, so the rule reads the policy's own Registry.pol and does not care what the policy is
    linked to. Leaving them unlinked means they apply to no computer in the lab and cannot change
    how any real machine behaves.

    THE DECRYPTOR IS WRITTEN AS A SID, NOT AS A NAME, for the two shapes meant to fire. This
    product resolves principals by identifier - the capture reads objects, not the name-mapping a
    domain controller does - so a value written as DOMAIN\name is reported as unresolvable rather
    than expanded. Writing the name would exercise the wrong branch.

.PARAMETER Path
    Where to create the groups.

.PARAMETER Remove
    Deletes the three policies and the two groups this script created, and nothing else.

.EXAMPLE
    .\Set-LabLapsDecryptor.ps1
    .\Set-LabLapsDecryptor.ps1 -Remove
#>
[CmdletBinding()]
param(
    [string] $Path = 'CN=Users,DC=ad,DC=lab',
    [switch] $Remove
)

$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

$prefix = 'SecureADLapsDecryptor'

$wrapper = "${prefix}Wrap"
$middle = "${prefix}Mid"

$nestedGpo = "${prefix}Nested"
$directGpo = "${prefix}Direct"
$unknownGpo = "${prefix}Unknown"

$lapsKey = 'HKLM\Software\Policies\Microsoft\Windows\LAPS'
$valueName = 'ADPasswordEncryptionPrincipal'

$domain = (Get-ADDomain).DNSRoot
$domainSid = (Get-ADDomain).DomainSID.Value

function Assert-Planted {
    param([string] $Name)

    # Re-checked against the prefix here rather than trusted from the variables above, so an edited
    # variable cannot turn a cleanup into a delete of something real.
    if (-not $Name.StartsWith($prefix, [StringComparison]::Ordinal)) {
        throw "Refusing to touch '$Name': it does not carry the '$prefix' prefix."
    }
}

function Remove-Planted {
    Write-Host ''
    Write-Host 'Removing the planted policies and groups'
    Write-Host '----------------------------------------'

    foreach ($name in @($nestedGpo, $directGpo, $unknownGpo)) {
        Assert-Planted $name

        $found = Get-GPO -Name $name -ErrorAction SilentlyContinue

        if ($null -eq $found) {
            Write-Host ("  {0,-32} already absent" -f $name)
            continue
        }

        Remove-GPO -Name $name -Confirm:$false
        Write-Host ("  {0,-32} removed" -f $name)
    }

    foreach ($name in @($wrapper, $middle)) {
        Assert-Planted $name

        $found = Get-ADGroup -Filter "sAMAccountName -eq '$name'" -ErrorAction SilentlyContinue

        if ($null -eq $found) {
            Write-Host ("  {0,-32} already absent" -f $name)
            continue
        }

        Remove-ADGroup -Identity $found.DistinguishedName -Confirm:$false
        Write-Host ("  {0,-32} removed" -f $name)
    }

    Write-Host ''
    Write-Host 'The lab is back to having no positive case for SEC-093.'
}

if ($Remove) {
    Remove-Planted
    return
}

Write-Host ''
Write-Host '================================================================'
Write-Host ' Planting LAPS decryptors for SEC-093'
Write-Host '================================================================'
Write-Host ''
Write-Host ("Domain      : {0}" -f $domain)
Write-Host ("Groups into : {0}" -f $Path)
Write-Host ''
Write-Host 'The policies are created UNLINKED and apply to no computer.'
Write-Host ''

# --------------------------------------------------------------------------------------------
# The groups
# --------------------------------------------------------------------------------------------

foreach ($name in @($wrapper, $middle)) {
    if (Get-ADGroup -Filter "sAMAccountName -eq '$name'" -ErrorAction SilentlyContinue) {
        Write-Host ("  {0,-32} already present" -f $name)
        continue
    }

    New-ADGroup -Name $name -SamAccountName $name -GroupScope Global `
        -GroupCategory Security -Path $Path
    Write-Host ("  {0,-32} created" -f $name)
}

# Global into Global within one domain, which Microsoft's scope table allows. Domain Users sits at
# the bottom, and it is broad by SID rather than by name - which is the whole point of
# BroadPrincipalCatalogue.
Add-ADGroupMember -Identity $wrapper -Members $middle -ErrorAction SilentlyContinue
Add-ADGroupMember -Identity $middle -Members 'Domain Users' -ErrorAction SilentlyContinue

$wrapperSid = (Get-ADGroup -Identity $wrapper).SID.Value
$domainUsersSid = "$domainSid-513"

Write-Host ''
Write-Host ("  nesting: {0} -> {1} -> Domain Users" -f $wrapper, $middle)
Write-Host ("  wrapper SID     : {0}" -f $wrapperSid)
Write-Host ("  Domain Users SID: {0}" -f $domainUsersSid)

# --------------------------------------------------------------------------------------------
# The policies
# --------------------------------------------------------------------------------------------

function Set-Decryptor {
    param([string] $GpoName, [string] $Value, [string] $Explains)

    if (-not (Get-GPO -Name $GpoName -ErrorAction SilentlyContinue)) {
        New-GPO -Name $GpoName -Comment 'Planted by Set-LabLapsDecryptor.ps1 for SEC-093.' |
            Out-Null
        Write-Host ("  {0,-32} created" -f $GpoName)
    }
    else {
        Write-Host ("  {0,-32} already present" -f $GpoName)
    }

    # HKLM puts this in the machine half of Registry.pol, which is the half the rule reads. LAPS is
    # a machine policy and a decryptor in the user half applies to nothing.
    Set-GPRegistryValue -Name $GpoName -Key $lapsKey -ValueName $valueName `
        -Type String -Value $Value | Out-Null

    Write-Host ("      {0} = {1}" -f $valueName, $Value)
    Write-Host ("      {0}" -f $Explains)
}

Write-Host ''
Write-Host 'Policies'
Write-Host '--------'

Set-Decryptor $nestedGpo $wrapperSid 'should fire, naming Domain Users, showing the route'
Set-Decryptor $directGpo $domainUsersSid 'should fire, one step, no nesting'
Set-Decryptor $unknownGpo "$domain\SecureADLapsDecryptorNoSuchGroup" `
    'should report unresolvable - a DIFFERENT finding, not the broad one'

# --------------------------------------------------------------------------------------------
# What to expect
# --------------------------------------------------------------------------------------------

Write-Host ''
Write-Host 'What SEC-093 should report after a capture and judge:'
Write-Host ''
Write-Host ("  {0}" -f $nestedGpo)
Write-Host ('    broad principal : Domain Users')
Write-Host ("    route           : {0} -> {1} -> Domain Users" -f $wrapper, $middle)
Write-Host ('    nesting depth   : 2')
Write-Host ('    severity        : Critical')
Write-Host ''
Write-Host ("  {0}" -f $directGpo)
Write-Host ('    broad principal : Domain Users')
Write-Host ('    nesting depth   : 0, named by the policy directly')
Write-Host ''
Write-Host ("  {0}" -f $unknownGpo)
Write-Host ('    NOT a broad-principal finding. The detail should say the value could not be')
Write-Host ('    resolved, and that if the name is wrong these machines have no stored password')
Write-Host ('    at all rather than a badly protected one.')
Write-Host ''
Write-Host 'The subject of every one of these is the POLICY, never a computer. A finding naming a'
Write-Host 'machine means the rule has started claiming something the evidence cannot support.'
Write-Host ''
Write-Host 'Capture the forest, then judge it. Re-run with -Remove to delete what this planted.'
