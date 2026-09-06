# Removes only the GUID-identified objects recorded by Test-LabSelfMembership.ps1.
# Preview first with -WhatIf. Refuses renamed, moved, replaced, or additional objects.
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param([Parameter(Mandatory)] [string] $ManifestPath)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module ActiveDirectory
$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
if ($manifest.Tag -notmatch '^saSM[0-9a-f]{8}$') { throw 'Not a Self-Membership lab manifest.' }
$domain = Get-ADDomain -Identity $manifest.Domain -Server $manifest.Server
$expectedOu = "OU=SecureAD-SelfMembership-$($manifest.Tag),$($domain.DistinguishedName)"
$expectedMarker = "SecureAD isolated Self-Membership lab $($manifest.Tag); retain for inspection"
if ($manifest.OuDn -ne $expectedOu -or $manifest.Marker -ne $expectedMarker) { throw 'Manifest scope or ownership marker differs.' }
$names = @{ DirectCaller = 'D'; GroupCaller = 'G'; Other = 'O'; DirectTarget = 'DirectTarget'; GroupTarget = 'GroupTarget'; GrantHolders = 'GrantHolders'; NoGrant = 'NoGrant' }
$ids = [Collections.Generic.HashSet[guid]]::new()
$roles = [Collections.Generic.HashSet[string]]::new()
function Assert-RecordedObject($record) {
    $object = Get-ADObject -Identity ([guid]$record.Guid) -Server $manifest.Server -Properties description
    if ($object.DistinguishedName -ne $record.Dn -or $object.Description -ne $expectedMarker) { throw "Object moved, renamed, or ownership marker changed: $($record.Guid)" }
    $object
}
foreach ($record in $manifest.Objects) {
    if (-not $ids.Add([guid]$record.Guid) -or -not $roles.Add($record.Role)) { throw 'Duplicate object or role in manifest.' }
    if ($record.Role -eq 'OU') { $expectedDn = $expectedOu }
    elseif ($names.ContainsKey($record.Role)) { $expectedDn = "CN=$($manifest.Tag)-$($names[$record.Role]),$expectedOu" }
    else { throw 'Unrecognized lab object role.' }
    if ($record.Dn -ne $expectedDn) { throw 'Manifest names an object outside the expected run scope.' }
    $object = Assert-RecordedObject $record
    $expectedClass = if ($record.Role -eq 'OU') { 'organizationalUnit' } elseif ($record.Role -in @('DirectCaller','GroupCaller','Other')) { 'user' } else { 'group' }
    if ($object.ObjectClass -ne $expectedClass) { throw 'Object class differs from the recorded role.' }
}
if (-not $roles.Contains('OU')) { throw 'Manifest does not identify its OU.' }
$actual = @(Get-ADObject -SearchBase $expectedOu -SearchScope Subtree -Filter * -Server $manifest.Server)
if ($actual.Count -ne $ids.Count -or @($actual | Where-Object { -not $ids.Contains($_.ObjectGUID) }).Count -ne 0) { throw 'OU contains unrecorded objects or recorded objects are missing; nothing was removed.' }
Write-Host "Validated $($actual.Count) recorded objects in $expectedOu"
if ($PSCmdlet.ShouldProcess($expectedOu, "Delete exactly $($actual.Count) recorded lab objects, including the OU; retain all evidence files")) {
    foreach ($record in @($manifest.Objects | Where-Object Role -ne 'OU')) {
        $null = Assert-RecordedObject $record
        Remove-ADObject -Identity ([guid]$record.Guid) -Server $manifest.Server -Confirm:$false
    }
    $ou = @($manifest.Objects | Where-Object Role -eq 'OU')[0]
    $null = Assert-RecordedObject $ou
    Set-ADOrganizationalUnit -Identity ([guid]$ou.Guid) -Server $manifest.Server -ProtectedFromAccidentalDeletion $false
    # Never recursive: a new child arriving after validation must make removal fail, not be deleted.
    Remove-ADOrganizationalUnit -Identity ([guid]$ou.Guid) -Server $manifest.Server -Confirm:$false
}
