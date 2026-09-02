# Reports every security principal in a sealed bundle that carries a value in sIDHistory.
#
# WHAT THIS IS FOR. When a rule reports nothing, there are two explanations that look identical from
# the outside: the forest is clean, or the rule is broken. This answers the first half directly from
# the evidence, without going through any rule at all - so the two can be told apart.
#
# It opens evidence.db READ ONLY and writes nothing. It is a diagnostic, not part of the product.
#
# IT NEEDS ITS OWN CONTROL, and -All is it. A script that reports zero privileged identifiers is
# worthless until it has been seen reporting something. Run it with -All first: that lists every
# account carrying any SID history at all, so a zero from the default run means "none of them were
# privileged" rather than "this script cannot read the table".
#
# USAGE
#   pwsh -File next/tools/list-sid-history.ps1 -BundlePath 'C:\...\ad.lab-20260902-101500'
#   pwsh -File next/tools/list-sid-history.ps1 -BundlePath '...' -All

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $BundlePath,

    # List every value, not only the ones SEC-027 treats as privileged. This is the control.
    [switch] $All,

    [string] $BinPath
)

$ErrorActionPreference = 'Stop'

# THIS ONE NEEDS pwsh, and says so rather than failing obscurely - the same reason
# count-uac-flag.ps1 gives. It loads the product's SQLite assemblies, which are built for modern
# .NET and cannot be loaded by Windows PowerShell 5.1; that attempt fails with a loader error naming
# a file, which reads like a missing build rather than the wrong shell.
if ($PSVersionTable.PSEdition -ne 'Core') {
    throw "This script must be run with pwsh (PowerShell 7), not Windows PowerShell $($PSVersionTable.PSVersion). It loads assemblies built for modern .NET. Re-run as: pwsh -File $PSCommandPath -BundlePath '...'"
}

$required = @(
    'Microsoft.Data.Sqlite.dll',
    'SQLitePCLRaw.core.dll',
    'SQLitePCLRaw.provider.e_sqlite3.dll',
    'SQLitePCLRaw.batteries_v2.dll')

$candidates = @()
if ($BinPath) {
    $given = [System.IO.Path]::GetFullPath($BinPath)
    if (Test-Path $given -PathType Leaf) { $given = Split-Path $given -Parent }
    $candidates += $given
}
$candidates += $PSScriptRoot
$candidates += (Join-Path $PSScriptRoot '..\tests\SecureAD.Next.Tests\bin\Debug\net10.0-windows\win-x64')
$candidates += (Join-Path $PSScriptRoot '..\tests\SecureAD.Next.Tests\bin\Debug\net10.0-windows')

$bin = $null
foreach ($c in $candidates) {
    if (-not (Test-Path $c)) { continue }
    $missing = @($required | Where-Object { -not (Test-Path (Join-Path $c $_)) })
    if ($missing.Count -eq 0) { $bin = $c; break }
}

if (-not $bin) {
    throw "Could not find a folder holding all of: $($required -join ', '). Build the solution, or pass -BinPath."
}

foreach ($dll in $required) { [void] [System.Reflection.Assembly]::LoadFrom((Join-Path $bin $dll)) }
[SQLitePCL.Batteries_V2]::Init()

$evidence = Join-Path $BundlePath 'evidence.db'
if (-not (Test-Path $evidence)) { throw "There is no evidence.db in '$BundlePath'." }

# The identifiers SEC-027 treats as privileged. DELIBERATELY WRITTEN OUT AGAIN RATHER THAN READ FROM
# THE PRODUCT. This script exists to check the rule from outside; sharing the rule's table would make
# it agree with the rule by construction, and it would then confirm a wrong table as readily as a
# right one. If these two lists ever disagree, that is exactly the disagreement worth seeing.
# Sourced from Microsoft's Security identifiers article, same as the product's own catalogue.
$privilegedRids = @{
    500 = 'Administrator'
    502 = 'krbtgt'
    512 = 'Domain Admins'
    516 = 'Domain Controllers'
    518 = 'Schema Admins'
    519 = 'Enterprise Admins'
    520 = 'Group Policy Creator Owners'
    521 = 'Read-only Domain Controllers'
}

$privilegedSids = @{
    'S-1-5-32-544' = 'BUILTIN\Administrators'
    'S-1-5-32-548' = 'BUILTIN\Account Operators'
    'S-1-5-32-549' = 'BUILTIN\Server Operators'
    'S-1-5-32-550' = 'BUILTIN\Print Operators'
    'S-1-5-32-551' = 'BUILTIN\Backup Operators'
    'S-1-5-32-552' = 'BUILTIN\Replicator'
}

# Turns SID bytes into the S-1-5-21-... form. Uses .NET's own SecurityIdentifier so this does not
# reimplement the product's Sid.ToText and then agree with its bugs.
function ConvertTo-SidText([byte[]] $bytes) {
    try { return (New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)).Value }
    catch { return $null }
}

function Get-PrivilegedName([string] $sid) {
    if ($null -eq $sid) { return $null }
    if ($privilegedSids.ContainsKey($sid)) { return $privilegedSids[$sid] }
    if ($sid.StartsWith('S-1-5-32-')) { return $null }

    $rid = 0
    $last = $sid.Substring($sid.LastIndexOf('-') + 1)
    if (-not [int]::TryParse($last, [ref] $rid)) { return $null }
    if ($privilegedRids.ContainsKey($rid)) { return $privilegedRids[$rid] }
    return $null
}

# READ ONLY, and stated in the connection string rather than merely intended. Sealed evidence is the
# one thing in a bundle nothing may write to.
$builder = New-Object Microsoft.Data.Sqlite.SqliteConnectionStringBuilder
$builder.DataSource = $evidence
$builder.Mode = [Microsoft.Data.Sqlite.SqliteOpenMode]::ReadOnly
$builder.Pooling = $false

$connection = New-Object Microsoft.Data.Sqlite.SqliteConnection $builder.ToString()
$connection.Open()

try {
    # sIDHistory is multi-valued, so it is not a column on captured_object - it has its own value
    # table. The name is checked rather than assumed: a guess that is wrong fails with "no such
    # table", which reads like the attribute was never captured.
    $tables = @()
    $probe = $connection.CreateCommand()
    $probe.CommandText = "SELECT name FROM sqlite_master WHERE type = 'table'"
    $r = $probe.ExecuteReader()
    while ($r.Read()) { $tables += $r.GetString(0) }
    $r.Close()

    $table = @($tables | Where-Object { $_ -replace '_', '' -eq 'sidhistoryvalue' })[0]

    if (-not $table) {
        throw "This bundle has no sIDHistory value table, so the attribute was never captured. Tables: $($tables -join ', ')"
    }

    $command = $connection.CreateCommand()
    $command.CommandText = @"
SELECT o.distinguished_name, o.domain_fqdn, v.ordinal, v.value
FROM $table v
JOIN captured_object o ON o.object_id = v.object_id
ORDER BY o.distinguished_name, v.ordinal
"@

    $reader = $command.ExecuteReader()

    $values = 0
    $unreadable = 0
    $objects = @{}
    $rows = @()

    while ($reader.Read()) {
        $values++
        $dn = $reader.GetString(0)
        $domain = $reader.GetString(1)
        $objects[$dn] = $true

        $bytes = $reader.GetValue(3)
        $sid = ConvertTo-SidText $bytes

        if ($null -eq $sid) { $unreadable++; continue }

        $name = Get-PrivilegedName $sid

        if ($All -or $null -ne $name) {
            $rows += [pscustomobject]@{
                DistinguishedName = $dn
                Domain            = $domain
                Sid               = $sid
                Privileged        = if ($name) { $name } else { '' }
            }
        }
    }

    $reader.Close()

    $privileged = @($rows | Where-Object { $_.Privileged -ne '' })

    "Bundle:                          $BundlePath"
    "Table:                           $table"
    "Objects carrying SID history:    $($objects.Count)"
    "SID history values:              $values"
    "Values that would not decode:    $unreadable"
    "Values naming a privileged principal: $($privileged.Count)"
    ""

    if (-not $All -and $privileged.Count -eq 0) {
        "No privileged identifiers found. Re-run with -All before believing that: a script that"
        "reports zero is worthless until it has been seen reporting something."
        ""
    }

    if ($rows.Count -gt 0) { $rows | Format-Table -AutoSize | Out-String | Write-Output }
}
finally {
    $connection.Dispose()
}
