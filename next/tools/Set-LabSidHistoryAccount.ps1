# Plants a real sIDHistory value in the lab forest, by moving an account between domains.
#
# WHAT THIS IS FOR. SEC-027 reports a security principal carrying a privileged identifier in its SID
# history. Proving the rule works needs an object that genuinely carries SID history - not one this
# script wrote the attribute on directly, because that is not something Active Directory permits and
# a lab that faked it would prove nothing about a real forest.
#
# HOW SID HISTORY IS ACTUALLY CREATED, in Microsoft's words. From "Security identifiers":
#
#   "an administrator for the enterprise can move the employee's User object from, for example,
#    Contoso\NoAm to Contoso\Europe. In this case, the User object for the account needs a new SID
#    ... Before the new value is written to the property, the previous value is copied to another
#    property of a User object, SIDHistory."
#
# So moving an account between two domains of one forest is the supported, first-party way to make
# an object that carries SID history, and Move-ADObject is the supported way to do the move.
#
# WHAT THIS CANNOT DO, AND WHY THAT MATTERS. The value this produces is the account's own former
# SID, whose relative identifier is an ordinary one allocated by the RID master. It is NOT one of
# the identifiers SEC-027 treats as privileged, so THE RULE WILL CORRECTLY NOT FIRE ON IT.
#
#   That is not a failure of this script. It is the strongest negative control available: an object
#   that really does carry SID history, in a real directory, that the rule correctly stays silent
#   about. An empty forest cannot distinguish a working rule from a broken one; this can.
#
# Getting a PRIVILEGED identifier into SID history needs DsAddSidHistory, and Microsoft documents
# that "the source and destination domains must not be in the same forest" - so it needs a second
# forest and an external trust, which this lab does not have. See section 12 of
# docs/layers/judgement/rules/SEC-027-privileged-sid-history.md for what is verified without it.
#
# THIS RUNS UNDER WINDOWS POWERSHELL 5.1, the owner's default shell. It needs only the
# ActiveDirectory module and rights to create and move an account in both domains.
#
# USAGE
#   powershell -File next\tools\Set-LabSidHistoryAccount.ps1 `
#       -SourceDomain 'ph.ad.lab' -TargetDomain 'ba.ad.lab'
#
#   powershell -File next\tools\Set-LabSidHistoryAccount.ps1 -SourceDomain '...' -TargetDomain '...' -Remove

[CmdletBinding()]
param(
    # The domain the account is created in, and whose SID ends up in sIDHistory.
    [Parameter(Mandatory = $true)]
    [string] $SourceDomain,

    # The domain the account is moved to, and where it will be found afterwards.
    [Parameter(Mandatory = $true)]
    [string] $TargetDomain,

    [string] $SamAccountName = 'lab.sidhistory',

    # Take the account away again, so the lab can be returned to the state it was in.
    [switch] $Remove
)

$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop

function Get-DomainController([string] $domain) {
    (Get-ADDomainController -DomainName $domain -Discover -Writable -ErrorAction Stop).HostName[0]
}

$sourceDc = Get-DomainController $SourceDomain
$targetDc = Get-DomainController $TargetDomain

Write-Host "Source domain: $SourceDomain (via $sourceDc)"
Write-Host "Target domain: $TargetDomain (via $targetDc)"

if ($Remove) {
    foreach ($pair in @(@($targetDc, $TargetDomain), @($sourceDc, $SourceDomain))) {
        $dc = $pair[0]
        $existing = Get-ADUser -Filter "sAMAccountName -eq '$SamAccountName'" -Server $dc -ErrorAction SilentlyContinue
        if ($existing) {
            Remove-ADUser -Identity $existing.DistinguishedName -Server $dc -Confirm:$false
            Write-Host "Removed $($existing.DistinguishedName) from $($pair[1])."
        }
    }
    return
}

# A move between domains needs the account to exist in the source first. It is created disabled and
# with no rights: this object is here to carry an attribute, and nothing should be able to log on as
# it.
$sourceRoot = (Get-ADDomain -Server $sourceDc).DistinguishedName
$sourceUsers = "CN=Users,$sourceRoot"

$existingSource = Get-ADUser -Filter "sAMAccountName -eq '$SamAccountName'" -Server $sourceDc -ErrorAction SilentlyContinue
$existingTarget = Get-ADUser -Filter "sAMAccountName -eq '$SamAccountName'" -Server $targetDc -ErrorAction SilentlyContinue

if ($existingTarget) {
    Write-Host ""
    Write-Host "The account already exists in the target domain:" -ForegroundColor Yellow
    Get-ADUser -Identity $existingTarget.DistinguishedName -Server $targetDc -Properties sIDHistory, objectSid |
        Select-Object DistinguishedName, objectSid, @{ n = 'sIDHistory'; e = { $_.sIDHistory -join ', ' } } |
        Format-List
    Write-Host "Re-run with -Remove first if you want to plant it again."
    return
}

if (-not $existingSource) {
    New-ADUser `
        -Name $SamAccountName `
        -SamAccountName $SamAccountName `
        -Path $sourceUsers `
        -Server $sourceDc `
        -Enabled $false `
        -Description 'SecureAD lab object. Carries SID history after a cross-domain move. Safe to delete.'

    Write-Host "Created $SamAccountName in $SourceDomain (disabled)."
    $existingSource = Get-ADUser -Filter "sAMAccountName -eq '$SamAccountName'" -Server $sourceDc
}

$sidBefore = (Get-ADUser -Identity $existingSource.DistinguishedName -Server $sourceDc -Properties objectSid).objectSid.Value
Write-Host "SID in the source domain: $sidBefore"

$targetRoot = (Get-ADDomain -Server $targetDc).DistinguishedName
$targetUsers = "CN=Users,$targetRoot"

# THE MOVE IS WHAT CREATES THE SID HISTORY. Nothing writes sIDHistory here; the domain controller
# does it, which is the only way it happens in a real directory.
Move-ADObject `
    -Identity $existingSource.DistinguishedName `
    -TargetPath $targetUsers `
    -TargetServer $targetDc `
    -Server $sourceDc

Write-Host "Moved to $TargetDomain."
Write-Host ""

$moved = Get-ADUser -Filter "sAMAccountName -eq '$SamAccountName'" -Server $targetDc -Properties sIDHistory, objectSid

$moved |
    Select-Object DistinguishedName,
                  @{ n = 'objectSid';  e = { $_.objectSid.Value } },
                  @{ n = 'sIDHistory'; e = { ($_.sIDHistory | ForEach-Object { $_.Value }) -join ', ' } } |
    Format-List

if (-not $moved.sIDHistory -or $moved.sIDHistory.Count -eq 0) {
    Write-Warning "The move completed but the account carries no sIDHistory. Nothing has been planted, so a capture taken now would prove nothing. Do not record a verification from this run."
    exit 1
}

Write-Host "Planted. Capture the forest, then read the sealed evidence back with:" -ForegroundColor Green
Write-Host "  pwsh -File next\tools\list-sid-history.ps1 -BundlePath '<bundle>' -All"
Write-Host ""
Write-Host "SEC-027 should NOT fire on this account: its history value carries an ordinary relative"
Write-Host "identifier, not a privileged one. That silence is the thing being tested."
