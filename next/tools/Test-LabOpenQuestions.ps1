# Settles the two questions this product currently has open against a real directory.
#
# WHY THIS EXISTS. Both questions are claims about what Active Directory does, and the instructions
# are explicit that such a claim is checked against Active Directory and never against our own code
# or documentation. Both are recorded in docs/PUNCH-LIST.md, P-121 and P-125, and both currently
# rest on inference or on a source with no citation.
#
# RUN IT ON THE LAB MACHINE, NOT THE DEVELOPMENT MACHINE. It writes to the directory.
#
# USAGE
#   pwsh -File next/tools/Test-LabOpenQuestions.ps1                 # run part one, leave objects in place
#   pwsh -File next/tools/Test-LabOpenQuestions.ps1 -Remove         # delete everything it created
#
# EVERYTHING IT CREATES CARRIES ONE PREFIX AND IT WILL NOT DELETE ANYTHING ELSE. The removal path
# matches on that prefix and refuses anything outside it, because a cleanup that takes a wider
# swing than the thing it created is worse than no cleanup at all.

[CmdletBinding()]
param(
    # Removes the objects this script created, and does nothing else.
    [switch] $Remove,

    # Where to put them. Defaults to the Users container of the current domain.
    [string] $Path
)

$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop

$prefix = 'SecureADCycleTest'
$groupA = "$prefix-A"
$groupB = "$prefix-B"
$groupC = "$prefix-C"

# ONE LETTER, BECAUSE A USER'S sAMAccountName IS CAPPED AT 20 CHARACTERS AND A GROUP'S IS NOT.
# "SecureADCycleTest-User" is 22, so the three groups were created and the user was refused with
# "The name provided is not a properly formed account name" - which does not mention length and
# reads like a character-set problem. Seen against ba.ad.lab on 2026-09-03. "SecureADCycleTest-U"
# is 19 and still carries the prefix the removal path checks.
$member = "$prefix-U"

if (-not $Path) {
    $Path = (Get-ADDomain).UsersContainer
}

function Remove-TestObjects {
    Write-Host ''
    Write-Host 'Removing test objects'
    Write-Host '---------------------'

    # Each name is checked against the prefix again here rather than trusted from the variables
    # above, so that an edited variable cannot turn this into a delete of something real.
    foreach ($name in @($member, $groupA, $groupB, $groupC)) {
        if (-not $name.StartsWith($prefix, [StringComparison]::Ordinal)) {
            throw "Refusing to delete '$name': it does not carry the '$prefix' prefix."
        }

        $found = Get-ADObject -Filter "sAMAccountName -eq '$name'" -ErrorAction SilentlyContinue

        if ($null -eq $found) {
            Write-Host ("  {0,-28} already absent" -f $name)
            continue
        }

        Remove-ADObject -Identity $found.DistinguishedName -Confirm:$false
        Write-Host ("  {0,-28} removed" -f $name)
    }
}

if ($Remove) {
    Remove-TestObjects
    return
}

Write-Host ''
Write-Host '========================================================================'
Write-Host ' PART ONE - can group membership form a loop, and what does it cost?'
Write-Host '========================================================================'
Write-Host ''
Write-Host 'What is already settled, and is not being retested here:'
Write-Host '  Microsoft states that group membership MAY HAVE LOOPS, in'
Write-Host '  "Determining a User''s or Group''s Membership in a Group" (Win32 AD).'
Write-Host ''
Write-Host 'What is NOT settled, and is what this measures:'
Write-Host '  1. Whether a DIRECT loop (a group containing itself) is refused, while an'
Write-Host '     INDIRECT loop is permitted. The only source for that distinction is a'
Write-Host '     practitioner article with no citations.'
Write-Host '  2. Whether a member of one group in a cycle receives the SIDs of EVERY group'
Write-Host '     in it. That is the mechanism behind the token-size argument in P-125, and'
Write-Host '     it is currently an inference from two Microsoft pages rather than a'
Write-Host '     measurement.'
Write-Host ''

# Global groups in one domain, because Microsoft's scope table allows a Global group to contain
# another Global group from the same domain - the simplest shape a cycle can take. A cycle cannot
# mix Global and Domain Local, since a Domain Local group cannot be a member of a Global one.
Write-Host 'Creating three Global groups and one user'
Write-Host '-----------------------------------------'

foreach ($name in @($groupA, $groupB, $groupC)) {
    if (Get-ADGroup -Filter "sAMAccountName -eq '$name'" -ErrorAction SilentlyContinue) {
        Write-Host ("  {0,-28} already present" -f $name)
        continue
    }

    New-ADGroup -Name $name -SamAccountName $name -GroupScope Global -GroupCategory Security -Path $Path
    Write-Host ("  {0,-28} created" -f $name)
}

if (-not (Get-ADUser -Filter "sAMAccountName -eq '$member'" -ErrorAction SilentlyContinue)) {
    New-ADUser -Name $member -SamAccountName $member -Path $Path -Enabled $false
    Write-Host ("  {0,-28} created (disabled)" -f $member)
}

Write-Host ''
Write-Host 'Test 1 - a group containing ITSELF'
Write-Host '----------------------------------'
Write-Host 'Expected, if the practitioner article is right: refused, with a message saying a'
Write-Host 'group cannot be made a member of itself.'
Write-Host ''

try {
    Add-ADGroupMember -Identity $groupA -Members $groupA -ErrorAction Stop
    Write-Host '  RESULT: ACCEPTED. The article is wrong - a direct self-loop is permitted.'
    Write-Host '          This is the more interesting outcome and P-125 must be corrected.'
}
catch {
    Write-Host '  RESULT: REFUSED, as predicted.'
    Write-Host ("  Directory said: {0}" -f $_.Exception.Message)
}

Write-Host ''
Write-Host 'Test 2 - an INDIRECT loop, A contains B contains C contains A'
Write-Host '------------------------------------------------------------'
Write-Host 'Expected: permitted. If this is refused, cycles cannot occur in practice, the'
Write-Host 'expander''s remarks are wrong, and the cycle rule in P-125 has no population.'
Write-Host ''

try {
    Add-ADGroupMember -Identity $groupA -Members $groupB -ErrorAction Stop
    Add-ADGroupMember -Identity $groupB -Members $groupC -ErrorAction Stop
    Add-ADGroupMember -Identity $groupC -Members $groupA -ErrorAction Stop

    Write-Host '  RESULT: ACCEPTED. An indirect cycle exists in this directory now.'
}
catch {
    Write-Host '  RESULT: REFUSED at some hop.'
    Write-Host ("  Directory said: {0}" -f $_.Exception.Message)
    Write-Host '  THIS WOULD BE A FINDING: it contradicts the expander''s remarks.'
}

Write-Host ''
Write-Host 'Test 3 - what a member of ONE group in the cycle ends up carrying'
Write-Host '-----------------------------------------------------------------'
Write-Host 'The user is put into C only. If the cycle inflates membership, the directory'
Write-Host 'should report it as a member of A and B as well.'
Write-Host ''

Add-ADGroupMember -Identity $groupC -Members $member -ErrorAction SilentlyContinue

# tokenGroups is what the domain controller itself computes for authorization, which is the number
# that matters - not what a script works out by walking the graph. Asking the controller is the
# whole point: it is the authority on what the token would contain.
#
# IT MUST BE ASKED FOR WITH A BASE-SCOPE SEARCH. tokenGroups is constructed rather than stored, and
# the controller will only compute it for a single named object; -Identity issues a subtree search
# and the directory answers "The requested search operation is only supported for base searches",
# which names the scope but not the attribute and reads like a permissions problem. Seen against
# ba.ad.lab on 2026-09-03.
$memberDn = (Get-ADUser -Identity $member).DistinguishedName

$user = Get-ADUser -SearchBase $memberDn -SearchScope Base -LDAPFilter '(objectClass=*)' `
    -Properties tokenGroups, memberOf
$cycleSids = @()

foreach ($sid in $user.tokenGroups) {
    $resolved = Get-ADGroup -Filter "objectSid -eq '$($sid.Value)'" -ErrorAction SilentlyContinue

    if ($resolved -and $resolved.SamAccountName.StartsWith($prefix, [StringComparison]::Ordinal)) {
        $cycleSids += $resolved.SamAccountName
    }
}

Write-Host ("  Direct membership (memberOf): {0}" -f (($user.memberOf | ForEach-Object {
    ($_ -split ',')[0] -replace '^CN=' }) -join ', '))
Write-Host ("  Groups from the cycle present in tokenGroups: {0}" -f
    $(if ($cycleSids.Count -gt 0) { ($cycleSids | Sort-Object) -join ', ' } else { 'none' }))
Write-Host ''
Write-Host ("  COUNT: {0} of 3 cycle groups reached the token." -f $cycleSids.Count)
Write-Host ''
Write-Host '  How to read this:'
Write-Host '    3 of 3 - a member of any group in a cycle carries every group SID in it.'
Write-Host '             The token-size argument in P-125 is confirmed by measurement and'
Write-Host '             stops being an inference.'
Write-Host '    1 of 3 - the cycle does NOT inflate the token. P-125 must drop that half of'
Write-Host '             its argument and rest on the authorization point alone.'
Write-Host ''
Write-Host 'Re-run with -Remove to delete all four objects.'

Write-Host ''
Write-Host '========================================================================'
Write-Host ' PART TWO - what an invalid LAPS decryptor principal does (P-121 area)'
Write-Host '========================================================================'
Write-Host ''
Write-Host 'NOT SCRIPTED, because it needs a Group Policy change and a managed machine that'
Write-Host 'will process it. Steps below; it is worth doing because it may mean a rule this'
Write-Host 'product ALREADY SHIPS gives a customer advice they cannot follow.'
Write-Host ''
Write-Host 'The disagreement, between two Microsoft pages:'
Write-Host '  laps-management-policy-settings says an invalid principal causes a policy'
Write-Host '    processing failure and THE PASSWORD IS NOT BACKED UP.'
Write-Host '  laps-csp says the device FALLS BACK TO DOMAIN ADMINS.'
Write-Host ''
Write-Host 'Why it matters:'
Write-Host '  If the first is right, a typo in that one setting means the machine stores no'
Write-Host '  LAPS attributes at all. SEC-091 then reports it as unmanaged and advises'
Write-Host '  "deploy Windows LAPS" - on a machine that already has it. That is wrong advice'
Write-Host '  in a shipped rule, and the operator would chase the wrong thing.'
Write-Host ''
Write-Host 'Steps:'
Write-Host '  1. Pick one managed test machine that currently has a working'
Write-Host '     msLAPS-PasswordExpirationTime. Record the value.'
Write-Host '  2. In the LAPS GPO applying to it, set the authorized decryptor'
Write-Host '     (ADPasswordEncryptionPrincipal) to a name that does not resolve, for'
Write-Host '     example CONTOSO\\NoSuchGroupHere. Ensure password encryption is enabled.'
Write-Host '  3. On the machine: gpupdate /force, then Invoke-LapsPolicyProcessing, then'
Write-Host '     Reset-LapsPassword.'
Write-Host '  4. Read the machine LAPS event log: Applications and Services Logs >'
Write-Host '     Microsoft > Windows > LAPS. Look for event 10034, which names an'
Write-Host '     ambiguous or unresolvable encryption principal.'
Write-Host '  5. Read the computer object again. Record which of these happened:'
Write-Host '       (a) the timestamp STOPPED being updated  -> the policy-settings page is'
Write-Host '           right, and SEC-091 gives wrong advice in this case'
Write-Host '       (b) the timestamp kept updating          -> the CSP page is right, the'
Write-Host '           device fell back to Domain Admins, and nothing is wrong'
Write-Host '  6. Put the GPO setting back and confirm rotation resumes.'
Write-Host ''
Write-Host 'Record the outcome in docs/PUNCH-LIST.md against P-121, naming which page was'
Write-Host 'right, since one of Microsoft''s two pages is wrong and the next session will'
Write-Host 'otherwise read the same contradiction and stop at the same place.'
Write-Host ''
