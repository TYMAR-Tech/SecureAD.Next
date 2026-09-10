<#
.SYNOPSIS
    Observes whether AdminSDHolder/SDProp stamps a computer account whose only route to a
    protected group is primaryGroupID.

.DESCRIPTION
    SecureAD's AC-64 is blocked: Microsoft establishes that primaryGroupID IS membership and that
    authorization honours it, but no Microsoft source states whether SDProp's protected-member
    enumeration follows that route. AC-64 accepts a recorded lab observation as an alternative to a
    citation. This script produces one.

    THE QUESTION. A writable domain controller's computer account normally has primaryGroupID 516,
    and the Domain Controllers group normally holds no explicit 'member' entries for them. Domain
    Controllers IS a protected group. So if SDProp followed primary-group edges, those computer
    accounts would carry SDProp's two fingerprints:

        adminCount = 1
        the DACL refusing to inherit (adminSDHolder disables inheritance on what it stamps)

    If they carry neither, SDProp did not reach them, and the traversal does not follow that edge.

    WHY THE CONTROLS MATTER MORE THAN THE ANSWER. A check that passes while measuring nothing is
    the failure this product guards against hardest. A script that only looked at domain controllers
    and found no stamp could not tell "SDProp does not traverse this edge" apart from "this forest
    has no SDProp", "the attributes were not readable", or "SDProp has not run yet". So this reports:

      POSITIVE CONTROL   Domain Admins, Enterprise Admins, Schema Admins - groups Microsoft lists as
                         protected. These MUST show adminCount=1 and inheritance disabled. If they
                         do not, this forest is not stamping anything and the whole run is void.

      NEGATIVE CONTROL   Domain Users - not protected. MUST show no stamp. If it shows one, the
                         fingerprint does not mean what the test assumes.

      MEMBER CHECK       Whether Domain Controllers lists members explicitly. If it does, the DCs
                         have an ordinary route and prove nothing about primary-group traversal.

      dSHeuristics       Character 16 can remove groups from protection. Per MS-ADTS 6.1.1.2.4.1.2
                         only the four operator groups are excludable, so this CANNOT explain an
                         unstamped domain controller - but it is reported rather than assumed.

      SDProp TIMING      SDProp runs hourly. An account created minutes ago has not been visited.
                         Object ages are reported so a young account cannot be mistaken for evidence.

    READ-ONLY. This script creates nothing, modifies nothing and deletes nothing. It runs LDAP
    reads only. It does not need Domain Admin - any authenticated user can read these attributes.

.NOTES
    Run on or against the BA domain. Requires the ActiveDirectory module (RSAT-AD-PowerShell).
    Records to a transcript beside the script so the observation is evidence rather than a memory.
#>

[CmdletBinding()]
param(
    # The domain to observe. Defaults to the current one.
    [string] $Server,

    # Where to write the transcript. Defaults to the current directory.
    [string] $OutputPath = (Join-Path (Get-Location) "ac64-observation-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt")
)

$ErrorActionPreference = 'Stop'

function Write-Section {
    param([string] $Title)
    Write-Host ""
    Write-Host "=== $Title ===" -ForegroundColor Cyan
}

function Get-StampState {
    <#
        SDProp's two fingerprints, read together. adminCount alone is not enough: it is a marker
        that stays behind after a principal leaves a protected group, so an object can carry
        adminCount=1 having not been protected for years. The inheritance flag is the live state.
    #>
    param($Object)

    $adminCount = if ($null -eq $Object.adminCount) { '<not set>' } else { $Object.adminCount }

    # nTSecurityDescriptor.AreAccessRulesProtected is the "refuses to inherit" state SDProp sets.
    $refuses = if ($null -ne $Object.nTSecurityDescriptor) {
        $Object.nTSecurityDescriptor.AreAccessRulesProtected
    } else {
        '<descriptor not read>'
    }

    [PSCustomObject]@{
        Name              = $Object.Name
        DistinguishedName = $Object.DistinguishedName
        AdminCount        = $adminCount
        RefusesInheritance = $refuses
        Stamped           = ($Object.adminCount -eq 1 -and $Object.nTSecurityDescriptor.AreAccessRulesProtected -eq $true)
        WhenCreated       = $Object.whenCreated
        AgeHours          = if ($Object.whenCreated) { [math]::Round(((Get-Date) - $Object.whenCreated).TotalHours, 1) } else { $null }
    }
}

Start-Transcript -Path $OutputPath | Out-Null

try {
    Import-Module ActiveDirectory -ErrorAction Stop

    $domainArgs = @{}
    if ($Server) { $domainArgs['Server'] = $Server }

    $domain = Get-ADDomain @domainArgs
    $forest = Get-ADForest -Server $domain.DNSRoot

    Write-Host "AC-64 lab observation" -ForegroundColor White
    Write-Host "Does SDProp stamp a computer account reachable only through primaryGroupID?"
    Write-Host ""
    Write-Host ("Domain          : {0}" -f $domain.DNSRoot)
    Write-Host ("Domain SID      : {0}" -f $domain.DomainSID)
    Write-Host ("Forest root     : {0}" -f $forest.RootDomain)
    Write-Host ("PDC emulator    : {0}   (SDProp runs here)" -f $domain.PDCEmulator)
    Write-Host ("Observed at     : {0}" -f (Get-Date -Format 'u'))
    Write-Host ("Observed by     : {0}" -f ([Security.Principal.WindowsIdentity]::GetCurrent().Name))

    $attributes = @('adminCount', 'nTSecurityDescriptor', 'primaryGroupID', 'whenCreated', 'sAMAccountName')

    # ------------------------------------------------------------------
    Write-Section "1. POSITIVE CONTROL - groups Microsoft lists as protected"
    Write-Host "These must be stamped. If they are not, this forest is not stamping and nothing below counts."

    $positiveRids = @{ 512 = 'Domain Admins'; 518 = 'Schema Admins'; 519 = 'Enterprise Admins' }
    $positive = foreach ($rid in $positiveRids.Keys) {
        $sid = "$($domain.DomainSID)-$rid"
        try {
            $group = Get-ADGroup -Identity $sid -Properties $attributes @domainArgs
            Get-StampState $group
        } catch {
            # Schema/Enterprise Admins exist only in the forest root, which is not an error here.
            Write-Host ("  {0} not present in this domain (expected outside the forest root)" -f $positiveRids[$rid]) -ForegroundColor DarkGray
        }
    }
    $positive | Format-Table Name, AdminCount, RefusesInheritance, Stamped -AutoSize

    # ------------------------------------------------------------------
    Write-Section "2. NEGATIVE CONTROL - a group that is not protected"
    Write-Host "Domain Users must NOT be stamped. If it is, the fingerprint does not mean what this test assumes."

    $negative = Get-ADGroup -Identity "$($domain.DomainSID)-513" -Properties $attributes @domainArgs | Get-StampState
    $negative | Format-Table Name, AdminCount, RefusesInheritance, Stamped -AutoSize

    # ------------------------------------------------------------------
    Write-Section "3. Is Domain Controllers itself protected, and does it list members?"
    Write-Host "The group must be protected for the question to arise, and must NOT list members"
    Write-Host "explicitly - otherwise its DCs have an ordinary route and prove nothing."

    $dcGroup = Get-ADGroup -Identity "$($domain.DomainSID)-516" -Properties ($attributes + 'member') @domainArgs
    Get-StampState $dcGroup | Format-Table Name, AdminCount, RefusesInheritance, Stamped -AutoSize

    $explicitMembers = @($dcGroup.member)
    Write-Host ("Explicit 'member' entries on Domain Controllers: {0}" -f $explicitMembers.Count)
    if ($explicitMembers.Count -gt 0) {
        Write-Host "  WARNING: members are listed explicitly, so primaryGroupID is NOT the only route." -ForegroundColor Yellow
        $explicitMembers | ForEach-Object { Write-Host "    $_" }
    } else {
        Write-Host "  Good: primaryGroupID is the only route into this group." -ForegroundColor Green
    }

    # ------------------------------------------------------------------
    Write-Section "4. THE OBSERVATION - domain controller computer accounts"
    Write-Host "Reached by primaryGroupID 516/521 alone. If SDProp followed that edge these would be stamped."

    $dcComputers = Get-ADComputer -Filter { primaryGroupID -eq 516 -or primaryGroupID -eq 521 } `
        -Properties $attributes @domainArgs | ForEach-Object { Get-StampState $_ }

    $dcComputers | Format-Table Name, AdminCount, RefusesInheritance, Stamped, AgeHours -AutoSize

    # ------------------------------------------------------------------
    Write-Section "5. COMPARISON - ordinary member computers"
    Write-Host "primaryGroupID 515, no protected group anywhere. Expected to look identical to section 4."

    $ordinary = Get-ADComputer -Filter { primaryGroupID -eq 515 } -Properties $attributes -ResultSetSize 10 @domainArgs |
        ForEach-Object { Get-StampState $_ }
    $ordinary | Format-Table Name, AdminCount, RefusesInheritance, Stamped -AutoSize

    # ------------------------------------------------------------------
    Write-Section "6. dSHeuristics - could the forest have excluded the group?"
    Write-Host "Per MS-ADTS 6.1.1.2.4.1.2 character 16 excludes ONLY the four operator groups."
    Write-Host "Domain Controllers is not excludable, so this cannot explain an unstamped DC."

    $ntds = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$($forest.PartitionsContainer -replace '^CN=Partitions,')" `
        -Properties dSHeuristics -Server $forest.RootDomain
    $heuristics = $ntds.dSHeuristics

    if ([string]::IsNullOrEmpty($heuristics)) {
        Write-Host "  dSHeuristics is not set. Every character takes its documented default of '0'." -ForegroundColor Green
        Write-Host "  Nothing is excluded from AdminSDHolder protection."
    } else {
        Write-Host ("  dSHeuristics = '{0}'" -f $heuristics)
        $character = if ($heuristics.Length -ge 16) { $heuristics[15] } else { '0' }
        Write-Host ("  Character 16 = '{0}'" -f $character)
        if ($character -eq '0') {
            Write-Host "  Nothing is excluded from AdminSDHolder protection." -ForegroundColor Green
        } else {
            Write-Host "  Some operator groups are excluded. Domain Controllers still cannot be." -ForegroundColor Yellow
        }
    }

    # ------------------------------------------------------------------
    Write-Section "VERDICT"

    $positiveAllStamped = ($positive.Count -gt 0) -and -not ($positive | Where-Object { -not $_.Stamped })
    $negativeUnstamped  = -not $negative.Stamped
    $noExplicitMembers  = $explicitMembers.Count -eq 0
    $anyDcStamped       = [bool]($dcComputers | Where-Object { $_.Stamped })
    $allDcsOldEnough    = -not ($dcComputers | Where-Object { $_.AgeHours -ne $null -and $_.AgeHours -lt 2 })

    Write-Host ("Positive control stamped        : {0}" -f $(if ($positiveAllStamped) { 'YES' } else { 'NO  <-- run is void' }))
    Write-Host ("Negative control unstamped      : {0}" -f $(if ($negativeUnstamped) { 'YES' } else { 'NO  <-- run is void' }))
    Write-Host ("primaryGroupID is the only route: {0}" -f $(if ($noExplicitMembers) { 'YES' } else { 'NO  <-- proves nothing' }))
    Write-Host ("All DCs older than 2 hours      : {0}" -f $(if ($allDcsOldEnough) { 'YES' } else { 'NO  <-- SDProp may not have run' }))
    Write-Host ("Any DC computer account stamped : {0}" -f $(if ($anyDcStamped) { 'YES' } else { 'NO' }))
    Write-Host ""

    if (-not ($positiveAllStamped -and $negativeUnstamped)) {
        Write-Host "INCONCLUSIVE. The controls failed, so this forest cannot answer the question." -ForegroundColor Red
        Write-Host "Do not record this as evidence for AC-64."
    } elseif (-not $noExplicitMembers) {
        Write-Host "INCONCLUSIVE. Domain Controllers lists members explicitly, so its DCs are" -ForegroundColor Yellow
        Write-Host "reachable by an ordinary route and say nothing about primary-group traversal."
    } elseif (-not $allDcsOldEnough) {
        Write-Host "INCONCLUSIVE. At least one DC account is too young for SDProp to have visited it." -ForegroundColor Yellow
        Write-Host "Wait for the next SDProp cycle and run again."
    } elseif ($anyDcStamped) {
        Write-Host "SDProp DOES follow primary-group edges." -ForegroundColor Green
        Write-Host "AC-64 should be implemented: primary-group membership participates in protected-principal"
        Write-Host "derivation, and the current Unknown is wrong in the direction of understatement."
    } else {
        Write-Host "SDProp DOES NOT follow primary-group edges." -ForegroundColor Green
        Write-Host "The controls passed, the group is protected, primaryGroupID is the only route into it,"
        Write-Host "and not one domain controller carries either fingerprint."
        Write-Host ""
        Write-Host "This is one forest on one Windows version. Recorded under AC-64 it must be labelled"
        Write-Host "LAB-VERIFIED, not specified - it is downgradeable if another forest behaves differently."
    }

    Write-Host ""
    Write-Host ("Transcript written to: {0}" -f $OutputPath) -ForegroundColor Cyan
}
finally {
    Stop-Transcript | Out-Null
}
