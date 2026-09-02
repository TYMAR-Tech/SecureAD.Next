# Plants the account states SEC-021, SEC-029 and SEC-033 report, so each can be seen firing.
#
# WHAT THIS IS FOR. A rule that has only been seen reporting nothing is a rule nobody has watched
# work. next/tools/count-uac-flag.ps1 proves what the forest holds; this creates something for the
# rules to find, so the other half can be proven too.
#
# WHAT IT CHANGES IN ACTIVE DIRECTORY. Three accounts in one domain, and one group membership:
#
#   lab.reversible   a user with "Store password using reversible encryption" set   -> SEC-029
#   lab.desonly      a user with "Use Kerberos DES encryption types" set            -> SEC-033
#   lab.kerberoast   a user with a service name, added to Domain Admins             -> SEC-021
#
# EVERY ACCOUNT IS CREATED DISABLED and stays that way. The rules report a disabled account - that
# is deliberate and tested - so disabling costs nothing and means nothing can authenticate as an
# object this script made. lab.kerberoast is nonetheless a real member of Domain Admins while it
# exists, which is why it is disabled and why -Remove exists.
#
# NOTHING HERE IS SUBTLE ABOUT WHAT IT DOES. Run -Remove when the verification is finished.
#
# THIS RUNS UNDER WINDOWS POWERSHELL 5.1, the owner's default shell. It needs the ActiveDirectory
# module and rights to create accounts and change group membership in the domain named.
#
# USAGE
#   powershell -File next\tools\Set-LabAccountFlags.ps1 -Domain 'ba.ad.lab'
#   powershell -File next\tools\Set-LabAccountFlags.ps1 -Domain 'ba.ad.lab' -Remove

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Domain,

    [switch] $Remove
)

$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop

$dc = (Get-ADDomainController -DomainName $Domain -Discover -Writable -ErrorAction Stop).HostName[0]
$root = (Get-ADDomain -Server $dc).DistinguishedName
$users = "CN=Users,$root"

Write-Host "Domain: $Domain (via $dc)"

$planted = @('lab.reversible', 'lab.desonly', 'lab.kerberoast')

if ($Remove) {
    foreach ($name in $planted) {
        $existing = Get-ADUser -Filter "sAMAccountName -eq '$name'" -Server $dc -ErrorAction SilentlyContinue
        if ($existing) {
            Remove-ADUser -Identity $existing.DistinguishedName -Server $dc -Confirm:$false
            Write-Host "Removed $($existing.DistinguishedName)"
        }
        else {
            Write-Host "Not present: $name"
        }
    }
    return
}

function New-LabUser([string] $name, [string] $description) {
    $existing = Get-ADUser -Filter "sAMAccountName -eq '$name'" -Server $dc -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "Already present: $name"
        return $existing.DistinguishedName
    }

    New-ADUser `
        -Name $name `
        -SamAccountName $name `
        -Path $users `
        -Server $dc `
        -Enabled $false `
        -Description $description

    Write-Host "Created $name (disabled)"
    return (Get-ADUser -Filter "sAMAccountName -eq '$name'" -Server $dc).DistinguishedName
}

# SEC-029. ENCRYPTED_TEXT_PWD_ALLOWED, 0x80.
$reversible = New-LabUser 'lab.reversible' 'SecureAD lab object for SEC-029. Safe to delete.'
Set-ADAccountControl -Identity $reversible -Server $dc -AllowReversiblePasswordEncryption $true

# SEC-033. USE_DES_KEY_ONLY, 0x200000.
$des = New-LabUser 'lab.desonly' 'SecureAD lab object for SEC-033. Safe to delete.'
Set-ADAccountControl -Identity $des -Server $dc -UseDESKeyOnly $true

# SEC-021. A service name, and membership of a group AdminSDHolder protects. The service name is
# deliberately one no real service would answer for, so nothing can be confused about what it is.
$kerberoast = New-LabUser 'lab.kerberoast' 'SecureAD lab object for SEC-021. Safe to delete.'
Set-ADUser -Identity $kerberoast -Server $dc -ServicePrincipalNames @{ Replace = 'SECUREADLAB/notareal.service' }
Add-ADGroupMember -Identity 'Domain Admins' -Members $kerberoast -Server $dc

Write-Host ""
Write-Host "Planted. Read them back from the directory:" -ForegroundColor Green

Get-ADUser -Filter "sAMAccountName -like 'lab.*'" -Server $dc `
           -Properties userAccountControl, servicePrincipalName, memberOf |
    Select-Object SamAccountName,
                  @{ n = 'uac';    e = { '0x{0:X}' -f $_.userAccountControl } },
                  @{ n = 'spn';    e = { $_.servicePrincipalName -join ',' } },
                  @{ n = 'groups'; e = { ($_.memberOf | ForEach-Object { ($_ -split ',')[0] }) -join ',' } } |
    Format-Table -AutoSize

Write-Host "Now capture and judge, then read the findings back:"
Write-Host "  securead-cli --library <library>"
Write-Host "  pwsh -File next\tools\show-findings.ps1 -BundlePath '<bundle>'"
Write-Host ""
Write-Host "Run this script with -Remove when the verification is finished." -ForegroundColor Yellow
