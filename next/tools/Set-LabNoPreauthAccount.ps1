<#
.SYNOPSIS
    Plants, shows or removes a lab account that does not require Kerberos pre-authentication, for
    verifying SecureAD's SEC-022 against a real directory.

.DESCRIPTION
    SEC-022 reports any account whose userAccountControl carries ADS_UF_DONT_REQUIRE_PREAUTH
    (0x400000). A domain controller will answer an authentication request for such an account
    WITHOUT the asker proving it knows the password first, and the reply contains material derived
    from that password which can be cracked offline. Microsoft documents the attack as AS-REP
    roasting and the remedy as clearing this setting:

        https://learn.microsoft.com/defender-for-identity/security-assessment-unsecure-account-attributes

    THIS CREATES A GENUINELY WEAK ACCOUNT IN A REAL FOREST. Anybody who can reach a domain
    controller can attack it, with no credentials of their own. Run it against a throwaway lab and
    nothing else, and use -Remove when the verification is finished.

    The account is created disabled unless -Enabled is given. A disabled account is still reported
    by SEC-022 - deliberately, because no Microsoft source says a key distribution centre refuses
    the request for one - so the disabled default is enough to verify the rule fires, without
    leaving a live weak credential in the lab. Use -Enabled only if you want to confirm the
    attack itself works.

.PARAMETER Name
    The account to create. Defaults to lab.nopreauth, matching lab.unconstrained, the account
    planted for the delegation rules.

.PARAMETER Path
    The container to create it in. Defaults to the Users container of the target domain.

.PARAMETER Server
    The domain controller to write to. Defaults to the domain you are logged into, which is the one
    you want when you are running this from a member server or a controller in that domain. Pass it
    only to act on a different domain - for example -Server phdc.ph.ad.lab.

.PARAMETER Enabled
    Leave the account enabled. Off by default - see above.

.PARAMETER Show
    Report every account in the target domain carrying the flag, and change nothing.

.PARAMETER Remove
    Delete the planted account.

.EXAMPLE
    .\Set-LabNoPreauthAccount.ps1 -Show

    Reports what the current domain - ba.ad.lab, when run from a ba machine - already carries.

.EXAMPLE
    .\Set-LabNoPreauthAccount.ps1

    Plants lab.nopreauth in the current domain. No arguments needed when you are already in it.

.EXAMPLE
    .\Set-LabNoPreauthAccount.ps1 -Remove

.EXAMPLE
    .\Set-LabNoPreauthAccount.ps1 -Server phdc.ph.ad.lab

    Acts on a different domain of the same forest.

.NOTES
    Requires the ActiveDirectory module and rights to create and modify a user account.

    RUNS IN EITHER SHELL. Windows PowerShell 5.1 is the default on a domain-joined server, so this
    script avoids anything that needs modern .NET - which is why the password bytes come from
    RandomNumberGenerator.Create().GetBytes rather than the tidier static Fill, absent on .NET
    Framework. Verified against 5.1.26100 on 2026-09-01. next/tools/count-uac-flag.ps1 is the
    opposite: it loads the product's assemblies and needs pwsh.

    Supports -WhatIf, which reports what it would do and writes nothing.

    THE TARGET DOMAIN IS PRINTED BEFORE ANYTHING IS WRITTEN. A lab has several domains that differ
    only by one label, and a script that acted on whichever one the module happened to pick would be
    a way to plant a weak account in the wrong place and not notice.

    After planting, capture the forest again and judge it. SEC-022 should report exactly this
    account. If it reports nothing, run next/tools/count-uac-flag.ps1 against the new bundle first:
    that reads the sealed evidence directly and tells you whether the flag was captured at all,
    which separates a capture problem from a rule problem.
#>

[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Plant')]
param(
    [Parameter(ParameterSetName = 'Plant')]
    [Parameter(ParameterSetName = 'Remove')]
    [string] $Name = 'lab.nopreauth',

    [Parameter(ParameterSetName = 'Plant')]
    [string] $Path,

    [string] $Server,

    [Parameter(ParameterSetName = 'Plant')]
    [switch] $Enabled,

    [Parameter(ParameterSetName = 'Show', Mandatory = $true)]
    [switch] $Show,

    [Parameter(ParameterSetName = 'Remove', Mandatory = $true)]
    [switch] $Remove
)

$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop

# ADS_UF_DONT_REQUIRE_PREAUTH. Published by Microsoft in three places that agree - the
# ADS_USER_FLAG_ENUM enumeration, the User-Account-Control schema page, and the UserAccountControl
# troubleshooting article, which also gives the decimal.
$DontRequirePreauth = 0x400000

$common = @{}
if ($Server) { $common['Server'] = $Server }

# Resolved once, and named out loud. Without -Server the ActiveDirectory module uses the domain this
# machine is joined to, which is what you want when you are already logged into the domain you mean
# to change - but "what you want" and "what the module picked" are different claims, and only one of
# them can be checked. Printing it makes the difference visible before a weak account is created.
$targetDomain = Get-ADDomain @common

Write-Output "Domain:             $($targetDomain.DNSRoot)"
Write-Output "Writing through:    $(if ($Server) { $Server } else { $targetDomain.PDCEmulator })"
Write-Output ''

function Get-FlaggedAccounts {
    # The LDAP bitwise-AND matching rule, 1.2.840.113556.1.4.803. Asking for the flag this way
    # rather than reading every account and filtering here means the controller does the work and
    # the answer cannot drift from what SEC-022 asks of the captured value.
    Get-ADObject -LDAPFilter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=$DontRequirePreauth))" `
        -Properties userAccountControl, sAMAccountName @common |
        Select-Object @{ n = 'DistinguishedName'; e = { $_.DistinguishedName } },
                      @{ n = 'UserAccountControl'; e = { $_.userAccountControl } },
                      @{ n = 'Disabled'; e = { ($_.userAccountControl -band 0x2) -ne 0 } }
}

if ($Show) {
    $found = @(Get-FlaggedAccounts)

    if ($found.Count -eq 0) {
        Write-Output "No account in $($targetDomain.DNSRoot) carries ADS_UF_DONT_REQUIRE_PREAUTH. SEC-022 has nothing to report there, and reporting nothing is the correct answer."
    }
    else {
        Write-Output "$($found.Count) account(s) in $($targetDomain.DNSRoot) carry ADS_UF_DONT_REQUIRE_PREAUTH. SEC-022 should report each of these:"
        $found | Format-Table -AutoSize
    }

    return
}

$existing = Get-ADUser -Filter "sAMAccountName -eq '$Name'" -Properties userAccountControl @common

if ($Remove) {
    if (-not $existing) {
        Write-Output "There is no account named '$Name' to remove."
        return
    }

    if ($PSCmdlet.ShouldProcess($existing.DistinguishedName, 'Delete the planted account')) {
        Remove-ADUser -Identity $existing.DistinguishedName -Confirm:$false @common
        Write-Output "Removed $($existing.DistinguishedName)."
        Write-Output "Capture and judge again: SEC-022 should go back to reporting nothing."
    }

    return
}

if ($existing) {
    Write-Output "'$Name' already exists at $($existing.DistinguishedName). Setting the flag on it rather than creating a second one."
}
else {
    if (-not $Path) {
        $Path = "CN=Users,$($targetDomain.DistinguishedName)"
    }

    # A long random password. The point of this account is the missing pre-authentication, not a
    # guessable password, and a weak one would make the lab prove something other than what is
    # being tested.
    #
    # RandomNumberGenerator.Create().GetBytes is used rather than the tidier static Fill, because
    # Fill does not exist on .NET Framework and this script has to run under Windows PowerShell 5.1
    # - which is the default shell on a domain-joined server and therefore the one it will usually
    # be run in. Create() and GetBytes have existed in both since the beginning.
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $password = ConvertTo-SecureString ([Convert]::ToBase64String($bytes) + '!aA1') -AsPlainText -Force

    if ($PSCmdlet.ShouldProcess("$Name in $Path", 'Create the lab account')) {
        New-ADUser -Name $Name `
            -SamAccountName $Name `
            -DisplayName $Name `
            -Description 'SecureAD lab: plants ADS_UF_DONT_REQUIRE_PREAUTH so SEC-022 has something to find. Safe to delete.' `
            -Path $Path `
            -AccountPassword $password `
            -Enabled:$Enabled.IsPresent `
            @common
    }
}

if ($PSCmdlet.ShouldProcess($Name, 'Set DoesNotRequirePreAuth')) {
    Set-ADAccountControl -Identity $Name -DoesNotRequirePreAuth $true @common
}

# Nothing was written under -WhatIf, so there is nothing to read back. Reading anyway looked for an
# account that was never created and failed with "cannot find an object with identity", which reads
# like a broken script rather than a dry run that worked.
if ($WhatIfPreference) {
    Write-Output ''
    Write-Output 'That was a dry run: nothing was created and nothing was changed.'
    Write-Output 'Run it again without -WhatIf to plant the account.'
    return
}

$after = Get-ADUser -Identity $Name -Properties userAccountControl @common
$isSet = ($after.userAccountControl -band $DontRequirePreauth) -ne 0

Write-Output ''
Write-Output "Account:            $($after.DistinguishedName)"
Write-Output ("userAccountControl: {0} (0x{0:X})" -f $after.userAccountControl)
Write-Output "Flag set:           $isSet"
Write-Output "Enabled:            $(($after.userAccountControl -band 0x2) -eq 0)"

if (-not $isSet) {
    throw "The flag is not set after writing it, so this lab account would not test anything. Investigate before capturing."
}

Write-Output ''
Write-Output "Next: capture the forest again and judge it. SEC-022 should report exactly this account,"
Write-Output "in $($targetDomain.DNSRoot). A finding attributed to any other domain is a defect."
Write-Output 'When finished, run this script with -Remove to delete it.'
