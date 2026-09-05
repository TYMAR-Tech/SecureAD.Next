# Plants the conditions SEC-060 and SEC-032 exist to find, so both run against a real directory.
#
# WHY THIS EXISTS. Both rules returned zero against ad.lab on 2026-09-05. The evidence was queried
# directly and confirmed the forest genuinely holds no such grant - but building-a-rule.md is
# explicit that a reading which has only ever returned zero proves nothing, and F-S45-4 is exactly
# what that warning is about: three rules were green, documented and judging nothing at all. A rule
# that has never been observed firing end to end has not been verified, only unit tested.
#
# WHAT IT MAKES
#
#   For SEC-060, a nested takeover path:
#       SecureADTakeoverOuter -> SecureADTakeoverInner -> Domain Users
#   and grants SecureADTakeoverOuter two rights on a new organisational unit:
#       WriteDacl  on OU=SecureADTakeoverTarget
#       WriteOwner on OU=SecureADTakeoverTarget
#   Two rights rather than one, because the rule reports the STRONGEST and a rule that picked the
#   weaker would still pass a single-right fixture. Expect one finding naming Domain Users at
#   depth two, reporting WriteDacl.
#
#   For SEC-032, a protected object owned by somebody who is not an administrator:
#       SecureADProtObject is added to Backup Operators, which Appendix C lists as protected
#       its owner is set to SecureADPlainOwner, an ordinary user
#   Expect one SEC-032 finding at High, and NO SEC-031 finding for the same object - the two rules
#   cover disjoint sets and that is the property most worth proving against a real directory.
#
# THIS ALSO SETTLES AN OPEN QUESTION, and that is half the reason for the shape above.
# SEC-032 asserts that AdminSDHolder re-stamping does not rescue a protected object from a
# non-administrative owner, because SDProp rewrites the DACL and does not change the owner.
# Microsoft's own pages disagree with themselves: most say SDProp resets "permissions" or "the
# ACL", but the Event 4780 article says it makes the descriptor match the template "on the binary
# level", and a security descriptor includes the owner field. -TestSdProp forces SDProp and
# re-reads the owner, which answers it from the directory rather than from the documentation.
#
# BACKUP OPERATORS IS A REAL PRIVILEGE GRANT while this exists. It is the least powerful of the
# protected groups and it is removed by -Remove. Nothing here touches Domain Admins.
#
# RUN IT ON THE LAB MACHINE. It writes to the directory and to two security descriptors.
#
# USAGE
#   pwsh -File next/tools/Set-LabOwnershipAndTakeover.ps1
#   pwsh -File next/tools/Set-LabOwnershipAndTakeover.ps1 -TestSdProp
#   pwsh -File next/tools/Set-LabOwnershipAndTakeover.ps1 -Remove

[CmdletBinding()]
param(
    [switch] $Remove,

    # Forces SDProp and re-reads the planted owner, to settle whether it survives.
    [switch] $TestSdProp,

    # Where the planted objects are created.
    [string] $Path = 'OU=BA Lab,DC=ba,DC=ad,DC=lab'
)

$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop

$prefix = 'SecureAD'

$outer  = 'SecureADTakeoverOuter'
$inner  = 'SecureADTakeoverInner'
$target = 'SecureADTakeoverTarget'
$member = 'SecureADProtObject'
$owner  = 'SecureADPlainOwner'

$domain = Get-ADDomain
$targetDn = "OU=$target,$Path"

function Assert-Prefixed([string] $name) {
    if (-not $name.StartsWith($prefix, [StringComparison]::Ordinal)) {
        throw "Refusing to touch '$name': it does not carry the '$prefix' prefix."
    }
}

function Remove-Planted {
    Write-Host ''
    Write-Host 'Removing the planted objects'
    Write-Host '----------------------------'

    foreach ($name in @($member, $owner)) {
        Assert-Prefixed $name
        $found = Get-ADUser -Filter "sAMAccountName -eq '$name'" -ErrorAction SilentlyContinue

        if ($null -eq $found) {
            Write-Host ('  {0,-26} already absent' -f $name)
            continue
        }

        # Taken out of the protected group first, so the account is not left protected if the
        # delete fails for any reason.
        if ($name -eq $member) {
            try {
                Remove-ADGroupMember -Identity 'Backup Operators' -Members $found -Confirm:$false
                Write-Host ('  {0,-26} removed from Backup Operators' -f $name)
            }
            catch {
                Write-Host ('  {0,-26} was not in Backup Operators' -f $name)
            }
        }

        Remove-ADUser -Identity $found -Confirm:$false
        Write-Host ('  {0,-26} deleted' -f $name)
    }

    foreach ($name in @($outer, $inner)) {
        Assert-Prefixed $name
        $found = Get-ADGroup -Filter "sAMAccountName -eq '$name'" -ErrorAction SilentlyContinue

        if ($null -eq $found) {
            Write-Host ('  {0,-26} already absent' -f $name)
            continue
        }

        Remove-ADGroup -Identity $found -Confirm:$false
        Write-Host ('  {0,-26} deleted' -f $name)
    }

    Assert-Prefixed $target
    $ou = Get-ADOrganizationalUnit -Filter "name -eq '$target'" -ErrorAction SilentlyContinue

    if ($null -eq $ou) {
        Write-Host ('  {0,-26} already absent' -f $target)
    }
    else {
        Set-ADObject -Identity $ou -ProtectedFromAccidentalDeletion $false
        Remove-ADOrganizationalUnit -Identity $ou -Confirm:$false
        Write-Host ('  {0,-26} deleted' -f $target)
    }

    Write-Host ''
    Write-Host 'Done. The permissions planted on the organisational unit went with it.'
}

function Add-Planted {
    Write-Host ''
    Write-Host 'Planting SEC-060: a nested takeover path'
    Write-Host '---------------------------------------'

    foreach ($name in @($outer, $inner)) {
        if ($null -eq (Get-ADGroup -Filter "sAMAccountName -eq '$name'" -EA SilentlyContinue)) {
            New-ADGroup -Name $name -SamAccountName $name -GroupCategory Security `
                -GroupScope Global -Path $Path
            Write-Host ('  {0,-26} created' -f $name)
        }
        else {
            Write-Host ('  {0,-26} already there' -f $name)
        }
    }

    # Outer contains Inner contains Domain Users. Two levels, so a rule that only looked one hop
    # down would find nothing and the fixture would still look like a positive.
    Add-ADGroupMember -Identity $outer -Members $inner -ErrorAction SilentlyContinue
    Add-ADGroupMember -Identity $inner -Members 'Domain Users' -ErrorAction SilentlyContinue
    Write-Host "  $outer -> $inner -> Domain Users"

    if ($null -eq (Get-ADOrganizationalUnit -Filter "name -eq '$target'" -EA SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $target -Path $Path
        Write-Host ('  {0,-26} created' -f $target)
    }

    $ou = Get-ADOrganizationalUnit -Filter "name -eq '$target'"
    $outerSid = (Get-ADGroup -Identity $outer).SID

    $acl = Get-Acl -Path "AD:$($ou.DistinguishedName)"

    foreach ($right in @('WriteDacl', 'WriteOwner')) {
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $outerSid,
            [System.DirectoryServices.ActiveDirectoryRights]::$right,
            [System.Security.AccessControl.AccessControlType]::Allow,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

        $acl.AddAccessRule($ace)
    }

    Set-Acl -Path "AD:$($ou.DistinguishedName)" -AclObject $acl
    Write-Host "  granted WriteDacl and WriteOwner to $outer on $target"

    Write-Host ''
    Write-Host 'Planting SEC-032: a protected object owned by a non-administrator'
    Write-Host '----------------------------------------------------------------'

    foreach ($name in @($owner, $member)) {
        if ($null -eq (Get-ADUser -Filter "sAMAccountName -eq '$name'" -EA SilentlyContinue)) {
            New-ADUser -Name $name -SamAccountName $name -Path $Path -Enabled $false
            Write-Host ('  {0,-26} created (disabled)' -f $name)
        }
        else {
            Write-Host ('  {0,-26} already there' -f $name)
        }
    }

    # Backup Operators is protected per Appendix C, and is the least powerful group on that list.
    Add-ADGroupMember -Identity 'Backup Operators' -Members $member -ErrorAction SilentlyContinue
    Write-Host "  $member added to Backup Operators, which makes it a protected object"

    Set-PlantedOwner

    Write-Host ''
    Write-Host 'Expected on the next capture and judge:'
    Write-Host "  SEC-060  one High finding on OU=$target naming Domain Users at depth two"
    Write-Host "  SEC-032  one High finding on $member, owned by $owner"
    Write-Host "  SEC-031  NO finding on $member - it is SEC-032's, and the two are disjoint"
}

function Set-PlantedOwner {
    $memberObject = Get-ADUser -Identity $member
    $ownerObject = Get-ADUser -Identity $owner

    $acl = Get-Acl -Path "AD:$($memberObject.DistinguishedName)"
    $acl.SetOwner($ownerObject.SID)
    Set-Acl -Path "AD:$($memberObject.DistinguishedName)" -AclObject $acl

    $now = (Get-Acl -Path "AD:$($memberObject.DistinguishedName)").Owner
    Write-Host "  owner of $member set to $owner (reads back as: $now)"
}

function Test-SdProp {
    $memberObject = Get-ADUser -Identity $member

    Write-Host ''
    Write-Host 'Forcing SDProp to settle whether it resets the owner'
    Write-Host '---------------------------------------------------'

    # THE OWNER IS RE-SET FIRST, AND THE FIRST VERSION OF THIS DID NOT DO THAT. It read the owner,
    # forced SDProp, read it again, and reported "no change" - but SDProp had already run in the
    # interim, so it was comparing an already-reset value with itself and concluding the reset
    # never happens. A check that compares a thing with itself measures nothing, which is the
    # failure this repository puts first.
    Set-PlantedOwner

    $before = (Get-Acl -Path "AD:$($memberObject.DistinguishedName)").Owner
    Write-Host "  owner before: $before"

    $pdc = (Get-ADDomain).PDCEmulator
    $root = [ADSI]"LDAP://$pdc/RootDSE"
    $root.Put('RunProtectAdminGroupsTask', 1)
    $root.SetInfo()

    Write-Host '  SDProp triggered; waiting 45 seconds'
    Start-Sleep -Seconds 45

    $after = (Get-Acl -Path "AD:$($memberObject.DistinguishedName)").Owner
    Write-Host "  owner after:  $after"
    Write-Host ''

    if ($before -eq $after) {
        Write-Host '  ANSWER: SDProp did NOT reset the owner. A protected object does not heal'
        Write-Host '          itself against a non-administrative owner.'
    }
    else {
        Write-Host '  ANSWER: SDProp DID reset the owner, from'
        Write-Host "            $before"
        Write-Host "          to"
        Write-Host "            $after"
        Write-Host '          A SEC-032 finding is therefore self-healing within the hour, and'
        Write-Host '          the rule must say what it actually means rather than treating the'
        Write-Host '          ownership as durable.'
    }
}

if ($Remove) { Remove-Planted; return }
if ($TestSdProp) { Test-SdProp; return }

Add-Planted
