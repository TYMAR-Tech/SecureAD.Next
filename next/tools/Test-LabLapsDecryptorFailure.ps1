# Settles what an unresolvable LAPS decryptor principal actually does, because two Microsoft pages
# disagree and a rule this product already ships depends on the answer.
#
# THE DISAGREEMENT.
#   laps-management-policy-settings: an invalid principal causes a policy processing failure and
#     THE PASSWORD IS NOT BACKED UP.
#   laps-csp: the device FALLS BACK TO DOMAIN ADMINS.
#
# WHY IT MATTERS. If the first is right, a typo in one Group Policy setting means the machine stores
# no LAPS attributes at all. SEC-091 then sees no timestamp, reports the machine as unmanaged, and
# tells the operator to deploy Windows LAPS to a machine that already has it. That is wrong advice
# in a shipped rule, and the operator would chase the wrong thing.
#
# WHAT THIS SCRIPT DOES AND DOES NOT DO. It records the before state, breaks the setting, compares
# the after state and puts the setting back. It CANNOT do the middle: applying policy and rotating a
# password happen on the managed machine, and must be run there.
#
# USAGE
#   pwsh -File next/tools/Test-LabLapsDecryptorFailure.ps1 -Baseline
#   pwsh -File next/tools/Test-LabLapsDecryptorFailure.ps1 -Break
#       ... then on the managed machine, elevated:
#           gpupdate /force; Invoke-LapsPolicyProcessing; Reset-LapsPassword
#           Get-WinEvent -LogName "Microsoft-Windows-LAPS/Operational" -MaxEvents 30
#   pwsh -File next/tools/Test-LabLapsDecryptorFailure.ps1 -Check
#   pwsh -File next/tools/Test-LabLapsDecryptorFailure.ps1 -Restore
#
# Reset-LapsPassword ROTATES THE LOCAL ADMINISTRATOR PASSWORD on the managed machine. If the backup
# genuinely fails there is a window where the directory holds no copy of it, which is the whole
# point of the test and the reason it belongs on a lab workstation and never on a domain controller.

[CmdletBinding()]
param(
    [switch] $Baseline,
    [switch] $Break,
    [switch] $Check,
    [switch] $Restore,

    [string] $Computer = 'BAWK1',
    [string] $Domain = 'ba.ad.lab',
    [string] $PolicyName = 'Workstation LAPS policy',

    # Recorded so the healthy value is restored from what was measured rather than from memory.
    [string] $StatePath = (Join-Path $env:TEMP 'laps-decryptor-test.json')
)

$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

$key = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
$valueName = 'ADPasswordEncryptionPrincipal'
$brokenValue = "$Domain\NoSuchGroupHere"

function Get-MachineState {
    $c = Get-ADComputer -Identity $Computer -Server $Domain -Properties `
        'msLAPS-PasswordExpirationTime', 'msLAPS-EncryptedPassword', 'msLAPS-Password'

    $raw = $c.'msLAPS-PasswordExpirationTime'

    [pscustomobject]@{
        Name              = $c.Name
        ExpirationRaw     = if ($raw) { [string]$raw } else { $null }
        ExpirationUtc     = if ($raw) { [datetime]::FromFileTimeUtc($raw).ToString('u') } else { $null }
        HasEncrypted      = [bool]$c.'msLAPS-EncryptedPassword'
        HasClearText      = [bool]$c.'msLAPS-Password'
        ReadAtUtc         = (Get-Date).ToUniversalTime().ToString('u')
    }
}

function Get-PolicyPrincipal {
    $v = Get-GPRegistryValue -Name $PolicyName -Domain $Domain -Key $key -ErrorAction SilentlyContinue |
        Where-Object ValueName -eq $valueName
    if ($v) { return [string]$v.Value }
    return $null
}

if ($Baseline) {
    $state = Get-MachineState
    $principal = Get-PolicyPrincipal

    $record = [pscustomobject]@{
        Computer          = $Computer
        Domain            = $Domain
        PolicyName        = $PolicyName
        HealthyPrincipal  = $principal
        Before            = $state
    }

    $record | ConvertTo-Json -Depth 5 | Set-Content -Path $StatePath -Encoding UTF8

    Write-Host ''
    Write-Host 'BASELINE'
    Write-Host '--------'
    Write-Host ("  computer            : {0}" -f $state.Name)
    Write-Host ("  expiration (UTC)    : {0}" -f $state.ExpirationUtc)
    Write-Host ("  encrypted password  : {0}" -f $state.HasEncrypted)
    Write-Host ("  clear-text password : {0}" -f $state.HasClearText)
    Write-Host ("  healthy principal   : {0}" -f $principal)
    Write-Host ''
    Write-Host ("  recorded to {0}" -f $StatePath)
    return
}

if ($Break) {
    if (-not (Test-Path $StatePath)) { throw 'Run with -Baseline first, so the healthy value is recorded.' }

    Set-GPRegistryValue -Name $PolicyName -Domain $Domain -Key $key `
        -ValueName $valueName -Type String -Value $brokenValue | Out-Null

    Write-Host ''
    Write-Host ("Set {0} to '{1}'." -f $valueName, $brokenValue)
    Write-Host ''
    Write-Host ('Now, ON {0}, elevated:' -f $Computer)
    Write-Host '  gpupdate /force'
    Write-Host '  Invoke-LapsPolicyProcessing'
    Write-Host '  Reset-LapsPassword'
    Write-Host '  Get-WinEvent -LogName "Microsoft-Windows-LAPS/Operational" -MaxEvents 30 |'
    Write-Host '    Select-Object TimeCreated,Id,LevelDisplayName,Message | Format-List'
    Write-Host ''
    Write-Host 'Event 10035 = the principal could not be mapped. 10017 = Active Directory was not'
    Write-Host 'updated. 10018 = a password was stored.'
    Write-Host 'Then re-run this script with -Check.'
    return
}

if ($Check) {
    if (-not (Test-Path $StatePath)) { throw 'No baseline recorded.' }

    $record = Get-Content -Path $StatePath -Raw | ConvertFrom-Json
    $after = Get-MachineState

    Write-Host ''
    Write-Host 'BEFORE / AFTER'
    Write-Host '--------------'
    Write-Host ("  expiration  : {0}   ->   {1}" -f $record.Before.ExpirationUtc, $after.ExpirationUtc)
    Write-Host ("  encrypted   : {0}   ->   {1}" -f $record.Before.HasEncrypted, $after.HasEncrypted)
    Write-Host ("  clear text  : {0}   ->   {1}" -f $record.Before.HasClearText, $after.HasClearText)
    Write-Host ("  principal   : {0}" -f (Get-PolicyPrincipal))
    Write-Host ''

    $moved = $record.Before.ExpirationRaw -ne $after.ExpirationRaw

    if ($moved) {
        Write-Host '  RESULT: the expiration MOVED, so a password was stored despite the bad principal.'
        Write-Host '          The laps-csp page is right - the device fell back to Domain Admins.'
        Write-Host '          SEC-091 is NOT affected, and P-121 is settled that way.'
    }
    else {
        Write-Host '  RESULT: the expiration DID NOT MOVE.'
        Write-Host '          Read the event log on the machine before concluding: if it shows 10035'
        Write-Host '          and no 10018, the laps-management-policy-settings page is right and'
        Write-Host '          nothing was backed up.'
        Write-Host '          THAT WOULD MEAN SEC-091 GIVES WRONG ADVICE on such a machine: it sees'
        Write-Host '          no timestamp, calls the machine unmanaged, and says deploy Windows'
        Write-Host '          LAPS to a machine that already has it.'
        Write-Host ''
        Write-Host '          A machine simply switched off looks identical here, so the event log is'
        Write-Host '          what separates the two and this script cannot read it.'
    }

    Write-Host ''
    Write-Host '  Re-run with -Restore to put the policy back.'
    return
}

if ($Restore) {
    if (-not (Test-Path $StatePath)) { throw 'No baseline recorded, so there is nothing to restore to.' }

    $record = Get-Content -Path $StatePath -Raw | ConvertFrom-Json

    if ([string]::IsNullOrWhiteSpace($record.HealthyPrincipal)) {
        throw 'The baseline recorded no principal, so restoring would guess. Set it by hand.'
    }

    Set-GPRegistryValue -Name $PolicyName -Domain $Domain -Key $key `
        -ValueName $valueName -Type String -Value $record.HealthyPrincipal | Out-Null

    Write-Host ''
    Write-Host ("Restored {0} to '{1}'." -f $valueName, $record.HealthyPrincipal)
    Write-Host ''
    Write-Host ('Now, ON {0}, elevated, and confirm the expiration moves forward:' -f $Computer)
    Write-Host '  gpupdate /force; Invoke-LapsPolicyProcessing; Reset-LapsPassword'
    return
}

Write-Host 'Choose one of -Baseline, -Break, -Check or -Restore. See the header for the order.'
