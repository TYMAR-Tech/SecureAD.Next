# Live laboratory measurement, not part of the product's offline analysis.
# Creates a new isolated OU; never reuses objects. Retains objects and disables callers on exit.
# Self-Membership is ADS_RIGHT_DS_SELF (8), not WRITE_PROPERTY (32):
# https://learn.microsoft.com/windows/win32/ad/control-access-rights
# https://learn.microsoft.com/windows/win32/adschema/r-self-membership
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Server,
    [Parameter(Mandatory)] [string] $Domain,
    [Parameter(Mandatory)] [string] $OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module ActiveDirectory
Add-Type -AssemblyName System.DirectoryServices.Protocols
Add-Type -AssemblyName System.DirectoryServices
$domainInfo = Get-ADDomain -Identity $Domain -Server $Server
$controller = Get-ADDomainController -Identity $Server -Server $Server
if ($controller.IsReadOnly -or $controller.Domain -ne $domainInfo.DNSRoot) { throw 'Wrong domain or read-only controller.' }
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path $output) { throw 'Use a new output directory; existing results must not be overwritten.' }
$null = New-Item -ItemType Directory -Path $output
$tag = 'saSM' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$ouName = 'SecureAD-SelfMembership-' + $tag
$ouDn = "OU=$ouName,$($domainInfo.DistinguishedName)"
$marker = "SecureAD isolated Self-Membership lab $tag; retain for inspection"
$memberGuid = [guid]'bf9679c0-0de6-11d0-a285-00aa003049e2'
$objects = [Collections.Generic.List[object]]::new()
$operations = [Collections.Generic.List[object]]::new()
$disabled = [Collections.Generic.List[string]]::new()
$disableErrors = [Collections.Generic.List[string]]::new()
$grants = [Collections.Generic.List[object]]::new()
$report = [ordered]@{
    StartedUtc = [DateTime]::UtcNow.ToString('o'); Server = $Server; Domain = $domainInfo.DNSRoot
    Tag = $tag; OuDn = $ouDn; Marker = $marker; Objects = $objects; Grants = $grants
    Transport = 'LDAP Negotiate, signing and sealing; fresh explicit caller bind per operation'
    Operations = $operations; DisabledUsers = $disabled; DisableErrors = $disableErrors; Complete = $false
}
function Save-Report { $report | ConvertTo-Json -Depth 12 | Set-Content (Join-Path $output 'live-results.json') -Encoding utf8 }
function Remember($item, $role) {
    $objects.Add([pscustomobject]@{ Role = $role; Dn = $item.DistinguishedName; Guid = $item.ObjectGUID.ToString(); Sid = if ($item.PSObject.Properties['SID']) { $item.SID.Value } else { $null } })
    Save-Report
    $item
}
function Connect-Ldap($credential) {
    $connection = [DirectoryServices.Protocols.LdapConnection]::new($Server)
    try {
        $connection.AuthType = [DirectoryServices.Protocols.AuthType]::Negotiate
        $connection.SessionOptions.ProtocolVersion = 3
        $connection.SessionOptions.Signing = $true
        $connection.SessionOptions.Sealing = $true
        $connection.SessionOptions.ReferralChasing = [DirectoryServices.Protocols.ReferralChasingOptions]::None
        $connection.Timeout = [TimeSpan]::FromSeconds(30)
        if ($null -ne $credential) { $connection.Credential = $credential }
        $connection.Bind()
        return $connection
    } catch { $connection.Dispose(); throw }
}
function Change-Member($connection, $target, $member, $operation) {
    if (-not $target.EndsWith(',' + $ouDn, [StringComparison]::OrdinalIgnoreCase) -or
        -not $member.EndsWith(',' + $ouDn, [StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing membership change outside this run OU.' }
    $change = [DirectoryServices.Protocols.DirectoryAttributeModification]::new()
    $change.Name = 'member'
    $change.Operation = [DirectoryServices.Protocols.DirectoryAttributeOperation]::$operation
    $null = $change.Add($member)
    $request = [DirectoryServices.Protocols.ModifyRequest]::new()
    $request.DistinguishedName = $target
    $null = $request.Modifications.Add($change)
    $connection.SendRequest($request)
}
function Members($target) { @((Get-ADGroup -Identity $target -Server $Server -Properties member).member | Sort-Object) }
function Invoke-MembershipProbe($scenario, $caller, $credential, $target, $member, $operation, $shouldSucceed) {
    $before = @(Members $target)
    $present = $before -contains $member
    if (($operation -eq 'Add' -and $present) -or ($operation -eq 'Delete' -and -not $present)) { throw 'Invalid test precondition: membership already in requested state.' }
    # Binding failures are outside the measured modify and cannot count as authorization refusal.
    $connection = Connect-Ldap $credential
    $code = $null
    $diagnostic = $null
    try {
        try { $response = Change-Member $connection $target $member $operation; $code = [int]$response.ResultCode }
        catch {
            $exception = $_.Exception
            while ($exception -and $exception -isnot [DirectoryServices.Protocols.DirectoryOperationException]) { $exception = $exception.InnerException }
            if ($null -eq $exception -or $null -eq $exception.Response) { throw }
            $code = [int]$exception.Response.ResultCode
            $diagnostic = $exception.Response.ErrorMessage
        }
    } finally { $connection.Dispose() }
    $after = @(Members $target)
    $expected = if ($shouldSucceed -and $operation -eq 'Add') { @($before + $member | Sort-Object) }
        elseif ($shouldSucceed) { @($before | Where-Object { $_ -ne $member } | Sort-Object) } else { $before }
    $same = ($expected -join "`n") -ceq ($after -join "`n")
    $passed = $same -and (($shouldSucceed -and $code -eq 0) -or (-not $shouldSucceed -and $code -eq 50))
    $operations.Add([pscustomobject]@{
        Utc = [DateTime]::UtcNow.ToString('o'); Scenario = $scenario; Caller = $caller.DistinguishedName
        CallerSid = $caller.SID.Value; Target = $target; Member = $member; Operation = $operation
        ExpectedSuccess = $shouldSucceed; LdapResultCode = $code; ServerDiagnostic = $diagnostic
        Before = $before; After = $after; Passed = $passed
    })
    Save-Report
    Write-Host "$scenario $operation : LDAP $code; matched expected membership=$same"
    if (-not $passed) { throw "Live result differs from expectation: $scenario $operation (LDAP $code). Results retained; do not count this as a pass." }
}
function Set-IsolatedDacl($group, $trustee) {
    $entry = [DirectoryServices.DirectoryEntry]::new("LDAP://$Server/$($group.DistinguishedName)")
    try {
        $entry.psbase.AuthenticationType = [DirectoryServices.AuthenticationTypes]::Secure -bor [DirectoryServices.AuthenticationTypes]::Signing -bor [DirectoryServices.AuthenticationTypes]::Sealing
        $entry.psbase.Options.SecurityMasks = [DirectoryServices.SecurityMasks]::Dacl
        $acl = $entry.psbase.ObjectSecurity
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))) { $null = $acl.RemoveAccessRuleSpecific($rule) }
        foreach ($sid in @(($domainInfo.DomainSID.Value + '-512'), 'S-1-5-18')) {
            $acl.AddAccessRule([DirectoryServices.ActiveDirectoryAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), [DirectoryServices.ActiveDirectoryRights]::GenericAll, [Security.AccessControl.AccessControlType]::Allow))
        }
        $acl.AddAccessRule([DirectoryServices.ActiveDirectoryAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-11'), [DirectoryServices.ActiveDirectoryRights]::GenericRead, [Security.AccessControl.AccessControlType]::Allow))
        if ($null -ne $trustee) {
            $acl.AddAccessRule([DirectoryServices.ActiveDirectoryAccessRule]::new($trustee.SID, [DirectoryServices.ActiveDirectoryRights]::Self, [Security.AccessControl.AccessControlType]::Allow, $memberGuid))
        }
        $entry.psbase.ObjectSecurity = $acl
        $entry.psbase.CommitChanges()
        $entry.psbase.RefreshCache(@('ntSecurityDescriptor'))
        $actual = $entry.psbase.ObjectSecurity
        $grants.Add([pscustomobject]@{
            Target = $group.DistinguishedName; TrusteeSid = if ($null -ne $trustee) { $trustee.SID.Value } else { $null }
            Sddl = $actual.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
        })
        Save-Report
        if (-not $actual.AreAccessRulesProtected) { throw 'Target DACL was not protected.' }
        if ($null -ne $trustee) {
            $rules = @($actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -eq $trustee.SID.Value })
            if ($rules.Count -ne 1 -or [int]$rules[0].ActiveDirectoryRights -ne 8 -or $rules[0].ObjectType -ne $memberGuid -or $rules[0].IsInherited) { throw 'Target does not have exactly the intended Self-Membership grant.' }
        }
    } finally { $entry.Dispose() }
}

$admin = $null
$credentials = @{}
try {
    $ou = Remember (New-ADOrganizationalUnit -Name $ouName -Path $domainInfo.DistinguishedName -Description $marker -ProtectedFromAccidentalDeletion $true -Server $Server -PassThru) 'OU'
    $users = @{}
    foreach ($role in @('DirectCaller', 'GroupCaller', 'Other')) {
        $suffix = @{ DirectCaller = 'D'; GroupCaller = 'G'; Other = 'O' }[$role]
        $sam = "$tag-$suffix"
        $password = ConvertTo-SecureString ('Aa1!' + [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48))) -AsPlainText -Force
        $user = Remember (New-ADUser -Name $sam -SamAccountName $sam -UserPrincipalName "$sam@$($domainInfo.DNSRoot)" -Path $ouDn -Description $marker -AccountPassword $password -Enabled $false -Server $Server -PassThru) $role
        $users[$role] = $user
        if ($role -ne 'Other') { $credentials[$role] = [Net.NetworkCredential]::new($sam, $password, $domainInfo.NetBIOSName) }
        $password.Dispose()
    }
    $groups = @{}
    foreach ($role in @('DirectTarget', 'GroupTarget', 'GrantHolders', 'NoGrant')) {
        $name = "$tag-$role"
        $groups[$role] = Remember (New-ADGroup -Name $name -SamAccountName $name -GroupScope Global -GroupCategory Security -Path $ouDn -Description $marker -Server $Server -PassThru) $role
    }
    $admin = Connect-Ldap $null
    $null = Change-Member $admin $groups.GrantHolders.DistinguishedName $users.GroupCaller.DistinguishedName 'Add'
    Set-IsolatedDacl $groups.DirectTarget $users.DirectCaller
    Set-IsolatedDacl $groups.GroupTarget $groups.GrantHolders
    Set-IsolatedDacl $groups.NoGrant $null
    foreach ($role in @('DirectCaller', 'GroupCaller')) { Enable-ADAccount -Identity $users[$role].ObjectGUID -Server $Server }
    foreach ($role in @('DirectCaller', 'GroupCaller')) {
        $caller = $users[$role]
        $credential = $credentials[$role]
        $target = $groups.NoGrant.DistinguishedName
        Invoke-MembershipProbe "$role no grant self" $caller $credential $target $caller.DistinguishedName 'Add' $false
        $null = Change-Member $admin $target $caller.DistinguishedName 'Add'
        Invoke-MembershipProbe "$role no grant self" $caller $credential $target $caller.DistinguishedName 'Delete' $false
        $null = Change-Member $admin $target $caller.DistinguishedName 'Delete'
        $target = if ($role -eq 'DirectCaller') { $groups.DirectTarget.DistinguishedName } else { $groups.GroupTarget.DistinguishedName }
        Invoke-MembershipProbe "$role self" $caller $credential $target $caller.DistinguishedName 'Add' $true
        Invoke-MembershipProbe "$role self" $caller $credential $target $caller.DistinguishedName 'Delete' $true
        $other = $users.Other.DistinguishedName
        # Administrator executes identical value changes before the refusal test, proving the value is legal.
        $null = Change-Member $admin $target $other 'Add'
        $null = Change-Member $admin $target $other 'Delete'
        Invoke-MembershipProbe "$role other" $caller $credential $target $other 'Add' $false
        $null = Change-Member $admin $target $other 'Add'
        Invoke-MembershipProbe "$role other" $caller $credential $target $other 'Delete' $false
        $null = Change-Member $admin $target $other 'Delete'
    }
    $report.Complete = $operations.Count -eq 12 -and @($operations | Where-Object { -not $_.Passed }).Count -eq 0
} finally {
    if ($null -ne $admin) { $admin.Dispose() }
    foreach ($item in @($objects | Where-Object Role -in @('DirectCaller', 'GroupCaller', 'Other'))) {
        try { Disable-ADAccount -Identity ([guid]$item.Guid) -Server $Server; $disabled.Add($item.Dn) }
        catch { $disableErrors.Add("$($item.Dn): $($_.Exception.Message)") }
    }
    $credentials.Clear()
    $report['FinishedUtc'] = [DateTime]::UtcNow.ToString('o')
    Save-Report
    Write-Host "Retained OU: $ouDn"
    Write-Host "Results: $output"
    if ($disableErrors.Count -gt 0) { throw 'One or more test users could not be disabled; inspect DisableErrors immediately.' }
}
