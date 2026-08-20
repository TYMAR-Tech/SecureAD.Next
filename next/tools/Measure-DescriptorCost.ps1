<#
.SYNOPSIS
	Measures what storing raw nTSecurityDescriptor bytes would actually cost.

.DESCRIPTION
	Reads a naming context over LDAP using the SAME request shape the rebuild's capture uses
	(SecurityMasks.Owner | Group | Dacl, page size 1000, domain-scoped so no referrals are
	chased), and reports:

		- how many objects were read
		- how many carried a readable security descriptor, and how many did not
		- total raw descriptor bytes
		- DISTINCT descriptor byte-sequences, and what the total would be if deduplicated
		- how many access control entries those descriptors parse into

	It writes nothing anywhere. It only reads and counts.

	The dedup number is the one that decides the argument: most objects in a real forest share
	byte-identical inherited descriptors, so storing descriptors in a table keyed by hash may cost
	a small fraction of storing one blob per object.

.PARAMETER Server
	A domain controller to read from. Example: dc01.corp.example.com

.PARAMETER SearchBase
	The naming context to read. Example: DC=corp,DC=example,DC=com
	If omitted, the server's defaultNamingContext is used.

.PARAMETER MaxObjects
	Stop after this many objects. Use it to bound a first run. 0 means no limit.

.PARAMETER Credential
	Optional. If omitted, the current Windows identity is used.

.EXAMPLE
	.\Measure-DescriptorCost.ps1 -Server dc01.corp.example.com -MaxObjects 50000

.NOTES
	Memory: one hash per distinct descriptor is held in memory. That is bounded by the number of
	DISTINCT descriptors, not by object count, so it stays small on a real forest. If you run
	unbounded against millions of objects and it grows, that is itself a finding worth reporting.
#>
[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[string] $Server,

	[string] $SearchBase,

	[int] $MaxObjects = 0,

	[System.Management.Automation.PSCredential] $Credential
)

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.DirectoryServices.Protocols

function New-Connection {
	param([string] $Server, [System.Management.Automation.PSCredential] $Credential)

	$identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Server, 389)

	if ($Credential) {
		$net = New-Object System.Net.NetworkCredential(
			$Credential.UserName, $Credential.GetNetworkCredential().Password)
		$conn = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier, $net)
	}
	else {
		$conn = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
	}

	$conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
	$conn.SessionOptions.Sealing = $true
	$conn.SessionOptions.Signing = $true
	$conn.SessionOptions.ProtocolVersion = 3
	$conn.Timeout = [TimeSpan]::FromMinutes(30)
	return $conn
}

function Get-DefaultNamingContext {
	param([System.DirectoryServices.Protocols.LdapConnection] $Connection)

	$req = New-Object System.DirectoryServices.Protocols.SearchRequest(
		$null, '(objectClass=*)', [System.DirectoryServices.Protocols.SearchScope]::Base,
		@('defaultNamingContext'))
	$res = $Connection.SendRequest($req)
	return $res.Entries[0].Attributes['defaultNamingContext'][0]
}

Write-Host ''
Write-Host 'Connecting to' $Server -ForegroundColor Cyan
$connection = New-Connection -Server $Server -Credential $Credential
$connection.Bind()

if (-not $SearchBase) {
	$SearchBase = Get-DefaultNamingContext -Connection $connection
	Write-Host 'Using defaultNamingContext:' $SearchBase -ForegroundColor Cyan
}

# --- counters -------------------------------------------------------------

$objectsRead          = 0
$withDescriptor       = 0
$withoutDescriptor    = 0
$totalRawBytes        = [long]0
$totalAceCount        = [long]0
$parseFailures        = 0
$minSize              = [int]::MaxValue
$maxSize              = 0

# hash -> byte length of that distinct descriptor
$distinct = New-Object 'System.Collections.Generic.Dictionary[string,int]'

# hash -> how many access control entries that distinct descriptor holds, or -1 if it would not
# parse. Kept so the per-object entry total is counted rather than estimated.
$distinctAces = New-Object 'System.Collections.Generic.Dictionary[string,int]'

# hash -> how many of those entries are EXPLICIT rather than inherited. The predecessor stored
# only explicit ones (DirectAceWriter.cs:158, "skip inherited - they are redundant with ancestor
# explicit ACEs") and the rebuild intends to store both, so the gap between these two numbers is
# the entire cost of that reversal.
$distinctExplicit = New-Object 'System.Collections.Generic.Dictionary[string,int]'
$totalExplicitCount = [long]0
$explicitPerObject = [long]0

# Entries summed across every object, which is what the `ace` table would actually hold.
$acesPerObject = [long]0

# How many descriptors each page saw for the first time. This is what says whether the dedup
# ratio has converged: while a page is still finding new ones at a steady rate, the ratio is
# wherever the counter happened to be when the data ran out, not a property of the forest.
$newPerPage = New-Object 'System.Collections.Generic.List[int]'
$distinctAtPageStart = 0

$sha = [System.Security.Cryptography.SHA256]::Create()

# --- paged search ---------------------------------------------------------

$pageControl = New-Object System.DirectoryServices.Protocols.PageResultRequestControl(1000)
$pageControl.IsCritical = $true

# Match capture: owner, group and DACL. Never the SACL.
$sdFlags = New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl(
	([System.DirectoryServices.Protocols.SecurityMasks]::Owner -bor
	 [System.DirectoryServices.Protocols.SecurityMasks]::Group -bor
	 [System.DirectoryServices.Protocols.SecurityMasks]::Dacl))

# Domain scope: ask the controller not to generate referrals.
$searchOptions = New-Object System.DirectoryServices.Protocols.SearchOptionsControl(
	[System.DirectoryServices.Protocols.SearchOption]::DomainScope)

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$pages = 0
$stop = $false

Write-Host 'Reading. This will take a while on a real forest.' -ForegroundColor Cyan
Write-Host ''

while (-not $stop) {

	# Attributes are added one at a time, deliberately.
	#
	# Passing them as an inline @('a','b') to the SearchRequest constructor does NOT work: the
	# array is marshalled into the params string[] as a SINGLE space-joined name, so the search
	# asks for one attribute called "nTSecurityDescriptor objectClass", which does not exist. The
	# controller then returns every entry carrying nothing, and this script reported zeroes that
	# looked like a fact about the forest. Verified 2026-08-24:
	#   inline @(...)   -> Attributes.Count = 1
	#   [string[]] $var -> Attributes.Count = 2
	# SecureAD.Audit's CaptureSearchRequestFactory already does it this way.
	$request = New-Object System.DirectoryServices.Protocols.SearchRequest
	$request.DistinguishedName = $SearchBase
	$request.Filter = '(objectClass=*)'
	$request.Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
	$null = $request.Attributes.Add('nTSecurityDescriptor')
	$null = $request.Attributes.Add('objectClass')

	# Zero means no client-imposed limit. A size limit and a page size are easy to confuse, and
	# AD answers a size-limited search with sizeLimitExceeded rather than truncating.
	$request.SizeLimit = 0

	$request.Controls.Add($pageControl)     | Out-Null
	$request.Controls.Add($sdFlags)         | Out-Null
	$request.Controls.Add($searchOptions)   | Out-Null

	$response = $connection.SendRequest($request)
	$pages++

	# A search that returned nothing and a forest with nothing in it must not look the same.
	# This script exists to inform a decision, and a report of zeroes that is really "the read
	# failed" is the exact defect the product it serves is built to prevent. So the first page
	# coming back empty stops the run and says what was actually asked.
	if ($pages -eq 1 -and $response.Entries.Count -eq 0) {
		$returned = ($response.Controls | ForEach-Object { $_.GetType().Name }) -join ', '
		throw ("The first page came back with no entries, so there is nothing to measure and " +
			"the zeroes below would be meaningless." + [Environment]::NewLine +
			"  server      : $Server" + [Environment]::NewLine +
			"  search base : $SearchBase" + [Environment]::NewLine +
			"  result code : $($response.ResultCode)" + [Environment]::NewLine +
			"  controls    : $returned" + [Environment]::NewLine +
			"Run Diagnose-DescriptorRead2.ps1 against the same server to see which stage is empty.")
	}

	foreach ($entry in $response.Entries) {

		$objectsRead++

		$attr = $entry.Attributes['nTSecurityDescriptor']
		if ($null -eq $attr -or $attr.Count -eq 0) {
			$withoutDescriptor++
		}
		else {
			# GetValues([byte[]]) is the only reliable way to get the raw octets. The default
			# indexer converts to a string where it can, which would change the byte count and
			# quietly make every number in this report wrong.
			$bytes = [byte[]]($attr.GetValues([byte[]])[0])

			$withDescriptor++
			$len = $bytes.Length
			$totalRawBytes += $len
			if ($len -lt $minSize) { $minSize = $len }
			if ($len -gt $maxSize) { $maxSize = $len }

			$key = [Convert]::ToBase64String($sha.ComputeHash($bytes))
			if (-not $distinct.ContainsKey($key)) {
				$distinct[$key] = $len

				# Only parse each DISTINCT descriptor once - the ACE count is a property of the
				# bytes, so parsing duplicates would just cost time. The count is remembered so
				# the per-object total below is measured rather than extrapolated.
				$aces = 0
				$explicit = 0
				try {
					$sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($bytes, 0)
					if ($null -ne $sd.DiscretionaryAcl) {
						$aces = $sd.DiscretionaryAcl.Count
						foreach ($ace in $sd.DiscretionaryAcl) {
							if (($ace.AceFlags -band [System.Security.AccessControl.AceFlags]::Inherited) -eq 0) {
								$explicit++
							}
						}
					}
					$totalAceCount += $aces
					$totalExplicitCount += $explicit
				}
				catch {
					$parseFailures++
					$aces = -1
					$explicit = -1
				}
				$distinctAces[$key] = $aces
				$distinctExplicit[$key] = $explicit
			}

			# The number that actually decides the comparison. Entries are stored per object in
			# the `ace` table, so what matters is how many rows the whole forest produces - not
			# how many the distinct descriptors do. Extrapolating one from the other through the
			# byte ratio is close but not right, because larger descriptors carry more entries.
			if ($distinctAces[$key] -ge 0) {
				$acesPerObject += $distinctAces[$key]
				$explicitPerObject += $distinctExplicit[$key]
			}
		}

		if ($MaxObjects -gt 0 -and $objectsRead -ge $MaxObjects) { $stop = $true; break }
	}

	$newThisPage = $distinct.Count - $distinctAtPageStart
	$distinctAtPageStart = $distinct.Count
	$newPerPage.Add($newThisPage) | Out-Null

	# Every page, not almost never. The original condition was $objectsRead % 10000 -lt 1000,
	# which is false after page 1 and page 2 and only true at exact multiples of 10,000 - so a
	# broken run and a working one looked identical until the very end.
	Write-Host ("  page {0,5}: {1,10:N0} objects, {2,8:N0} with a descriptor, {3,8:N0} distinct (+{4,-6:N0} new), {5,8:N1} MB raw" -f `
		$pages, $objectsRead, $withDescriptor, $distinct.Count, $newThisPage, ($totalRawBytes / 1MB))

	# The second guard, and the one that would have caught the defect of 2026-08-24. Entries came
	# back in their thousands and not one carried a descriptor, because the request had asked for
	# an attribute name that does not exist. "Nobody in this forest has a security descriptor" is
	# not a possible fact, so it is a broken read and must say so rather than total to zero.
	if ($pages -eq 1 -and $response.Entries.Count -gt 0 -and $withDescriptor -eq 0) {
		$asked = (@($request.Attributes) -join ', ')
		throw ("$($response.Entries.Count) entries came back and not one carried " +
			"nTSecurityDescriptor. Every object in a directory has one, so this is a broken read " +
			"rather than a fact about the forest." + [Environment]::NewLine +
			"  attributes actually requested : $asked" + [Environment]::NewLine +
			"  attribute count               : $($request.Attributes.Count)" + [Environment]::NewLine +
			"If that count is 1 and the name has a space in it, the attribute list was collapsed " +
			"into a single name and this script has regressed.")
	}

	if ($stop) { break }

	$pageResponse = $response.Controls |
		Where-Object { $_ -is [System.DirectoryServices.Protocols.PageResultResponseControl] } |
		Select-Object -First 1

	if ($null -eq $pageResponse -or $pageResponse.Cookie.Length -eq 0) { break }
	$pageControl.Cookie = $pageResponse.Cookie
}

$stopwatch.Stop()

# --- report ---------------------------------------------------------------

$distinctBytes = [long]0
foreach ($v in $distinct.Values) { $distinctBytes += $v }

if ($minSize -eq [int]::MaxValue) { $minSize = 0 }

$meanSize   = if ($withDescriptor -gt 0) { $totalRawBytes / $withDescriptor } else { 0 }
$dedupRatio = if ($distinctBytes -gt 0) { $totalRawBytes / $distinctBytes } else { 0 }

# Rough SQLite cost of one parsed ACE row in the rebuild's shape:
#   ace_id, object_id, ordinal, ace_type, trustee_id, access_mask, two GUID columns,
#   is_inherited, inheritance_flags, propagation_flags, ace_hash
# ASSUMPTION, stated so it can be challenged rather than hidden: ~110 bytes per row
# including index overhead. Change this and re-read the last two lines.
$assumedAceRowBytes = 110
$parsedRowBytes = $totalAceCount * $assumedAceRowBytes

Write-Host ''
Write-Host '================ RESULT ================' -ForegroundColor Green
Write-Host ''
Write-Host ('Server                     : {0}' -f $Server)
Write-Host ('Search base                : {0}' -f $SearchBase)
Write-Host ('Elapsed                    : {0:N1} minutes' -f $stopwatch.Elapsed.TotalMinutes)
Write-Host ('Pages                      : {0:N0}' -f $pages)
Write-Host ''
Write-Host ('Objects read               : {0,14:N0}' -f $objectsRead)
Write-Host ('  with a descriptor        : {0,14:N0}' -f $withDescriptor)
Write-Host ('  without one              : {0,14:N0}   <- could not read, or none present' -f $withoutDescriptor)
Write-Host ('  descriptors that failed  : {0,14:N0}   <- parse failures, on DISTINCT descriptors' -f $parseFailures)
Write-Host ''
Write-Host ('Raw descriptor bytes       : {0,14:N0}   ({1:N1} MB)' -f $totalRawBytes, ($totalRawBytes / 1MB))
Write-Host ('  smallest                 : {0,14:N0} bytes' -f $minSize)
Write-Host ('  largest                  : {0,14:N0} bytes' -f $maxSize)
Write-Host ('  mean                     : {0,14:N0} bytes' -f $meanSize)
Write-Host ''
Write-Host '---- the number that decides it ----' -ForegroundColor Yellow
Write-Host ('Distinct descriptors       : {0,14:N0}' -f $distinct.Count)
Write-Host ('Deduplicated bytes         : {0,14:N0}   ({1:N1} MB)' -f $distinctBytes, ($distinctBytes / 1MB))
Write-Host ('Dedup ratio                : {0,14:N1} : 1' -f $dedupRatio)
Write-Host ''
Write-Host '---- for comparison ----' -ForegroundColor Yellow
Write-Host ('ACEs in distinct descriptors: {0,13:N0}' -f $totalAceCount)
Write-Host ('Parsed rows would cost     : {0,14:N0}   ({1:N1} MB) at an ASSUMED {2} bytes/row' -f `
	$parsedRowBytes, ($parsedRowBytes / 1MB), $assumedAceRowBytes)
Write-Host ''
Write-Host '---- what each storage choice would cost ----' -ForegroundColor Yellow
Write-Host ('Entries across all objects  : {0,13:N0}   (measured, not extrapolated)' -f $acesPerObject)
Write-Host ('Entries in distinct only    : {0,13:N0}' -f $totalAceCount)
Write-Host ''
Write-Host ('  A. parsed entries, per object : {0,12:N0} bytes  ({1:N1} MB) at an ASSUMED {2} bytes/row' -f `
	($acesPerObject * $assumedAceRowBytes), (($acesPerObject * $assumedAceRowBytes) / 1MB), $assumedAceRowBytes)
Write-Host ('  B. raw descriptors, per object: {0,12:N0} bytes  ({1:N1} MB)' -f `
	$totalRawBytes, ($totalRawBytes / 1MB))
Write-Host ('  C. raw descriptors, dedup     : {0,12:N0} bytes  ({1:N1} MB)' -f `
	$distinctBytes, ($distinctBytes / 1MB))
Write-Host ''

if ($acesPerObject -gt 0) {
	$parsedBytes = $acesPerObject * $assumedAceRowBytes
	$overhead = if ($parsedBytes -gt 0) { 100.0 * $distinctBytes / $parsedBytes } else { 0 }
	Write-Host ('Keeping the raw bytes as well as the parsed entries (A + C) costs {0:N1}% more than' -f $overhead)
	Write-Host ('storing the parsed entries alone (A).')
}
Write-Host ''
Write-Host ''
Write-Host '---- explicit vs inherited: what the predecessor skipped ----' -ForegroundColor Yellow
Write-Host ('Entries across all objects  : {0,13:N0}' -f $acesPerObject)
Write-Host ('  of which EXPLICIT         : {0,13:N0}   ({1:N1}%)' -f `
	$explicitPerObject, $(if ($acesPerObject -gt 0) { 100.0 * $explicitPerObject / $acesPerObject } else { 0 }))
Write-Host ('  of which INHERITED        : {0,13:N0}   ({1:N1}%)' -f `
	($acesPerObject - $explicitPerObject), `
	$(if ($acesPerObject -gt 0) { 100.0 * ($acesPerObject - $explicitPerObject) / $acesPerObject } else { 0 }))
Write-Host ''
Write-Host ('  E. explicit only, per object  : {0,12:N0} bytes  ({1:N1} MB)   <- what the old app stored' -f `
	($explicitPerObject * $assumedAceRowBytes), (($explicitPerObject * $assumedAceRowBytes) / 1MB))
Write-Host ('  F. all entries, deduplicated  : {0,12:N0} bytes  ({1:N1} MB)   <- what the rebuild proposes' -f `
	($totalAceCount * $assumedAceRowBytes), (($totalAceCount * $assumedAceRowBytes) / 1MB))
Write-Host ''

Write-Host '---- can this ratio be trusted? ----' -ForegroundColor Yellow

if ($newPerPage.Count -lt 3) {
	Write-Host 'Too few pages to tell. Read more of the forest before using the ratio above.'
}
else {
	$tail = [Math]::Max(1, [int]($newPerPage.Count / 4))
	$lastNew  = ($newPerPage[($newPerPage.Count - $tail)..($newPerPage.Count - 1)] | Measure-Object -Average).Average
	$firstNew = ($newPerPage[0..($tail - 1)] | Measure-Object -Average).Average

	Write-Host ('New descriptors per page, first {0} page(s) : {1,8:N1}' -f $tail, $firstNew)
	Write-Host ('New descriptors per page, last  {0} page(s) : {1,8:N1}' -f $tail, $lastNew)

	if ($firstNew -le 0) {
		Write-Host 'No descriptors were seen at all. The ratio means nothing.' -ForegroundColor Red
	}
	elseif ($lastNew -le ($firstNew * 0.1)) {
		Write-Host 'CONVERGED. New descriptors have nearly stopped appearing, so the ratio is a' -ForegroundColor Green
		Write-Host 'property of this forest and can be designed against.' -ForegroundColor Green
	}
	else {
		Write-Host 'NOT CONVERGED. Pages are still finding new descriptors at close to the opening' -ForegroundColor Red
		Write-Host 'rate, so the ratio above is just where the counter stopped - not a property of the' -ForegroundColor Red
		Write-Host 'forest. Read more, and prefer a whole naming context over a truncated one.' -ForegroundColor Red
	}
}

if ($MaxObjects -gt 0 -and $objectsRead -ge $MaxObjects) {
	Write-Host ''
	Write-Host ('This run stopped at -MaxObjects {0}, which is a BIASED sample: a subtree search' -f $MaxObjects) -ForegroundColor Red
	Write-Host 'returns objects in tree order, so consecutive objects are usually siblings sharing an' -ForegroundColor Red
	Write-Host 'inherited descriptor. Truncating therefore OVERSTATES deduplication. A complete naming' -ForegroundColor Red
	Write-Host 'context is worth more than a larger truncated one.' -ForegroundColor Red
}

Write-Host ''
Write-Host 'Note: a lab forest flatters the dedup ratio badly. Synthetic objects share a handful of' -ForegroundColor DarkGray
Write-Host 'identical inherited descriptors; a production forest that has been delegated for years has' -ForegroundColor DarkGray
Write-Host 'far more distinct ones. Treat a lab figure as proof the script runs, not as a design input.' -ForegroundColor DarkGray
Write-Host ''

$connection.Dispose()
$sha.Dispose()
