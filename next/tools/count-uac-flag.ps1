# Reports every account in a sealed bundle whose userAccountControl carries a given flag.
#
# WHAT THIS IS FOR. When a rule reports nothing, there are two explanations that look identical from
# the outside: the forest is clean, or the rule is broken. This answers the first half directly from
# the evidence, without going through any rule at all - so the two can be told apart.
#
# It opens evidence.db READ ONLY and writes nothing. It is a diagnostic, not part of the product.
#
# USAGE
#   pwsh -File next/tools/count-uac-flag.ps1 -BundlePath 'C:\...\ad.lab-20260901-164844'
#   pwsh -File next/tools/count-uac-flag.ps1 -BundlePath '...' -Flag 0x80000

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $BundlePath,

    # Defaults to ADS_UF_DONT_REQUIRE_PREAUTH, the flag SEC-022 reports.
    [int] $Flag = 0x400000,

    [string] $BinPath
)

$ErrorActionPreference = 'Stop'

# THIS ONE NEEDS pwsh, and says so rather than failing obscurely. It loads the product's own SQLite
# assemblies, which are built for modern .NET and cannot be loaded by Windows PowerShell 5.1 - that
# attempt fails with a loader error naming a file, which reads like a missing build rather than the
# wrong shell. Set-LabNoPreauthAccount.ps1 runs in either shell; this does not.
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

# READ ONLY, and stated in the connection string rather than merely intended. Sealed evidence is the
# one thing in a bundle nothing may write to, and a diagnostic opened read-write would invalidate the
# seal on any accidental write.
$builder = New-Object Microsoft.Data.Sqlite.SqliteConnectionStringBuilder
$builder.DataSource = $evidence
$builder.Mode = [Microsoft.Data.Sqlite.SqliteOpenMode]::ReadOnly
$builder.Pooling = $false

$connection = New-Object Microsoft.Data.Sqlite.SqliteConnection $builder.ToString()
$connection.Open()

try {
    # The column is found rather than assumed. Single-valued attributes are columns on
    # captured_object whose names are derived from the LDAP display name, and a guess that is wrong
    # fails with "no such column" - which reads like the attribute was never captured.
    $columns = @()
    $probe = $connection.CreateCommand()
    $probe.CommandText = "SELECT name FROM pragma_table_info('captured_object')"
    $r = $probe.ExecuteReader()
    while ($r.Read()) { $columns += $r.GetString(0) }
    $r.Close()

    $column = @($columns | Where-Object { $_ -replace '_', '' -eq 'useraccountcontrol' })[0]

    if (-not $column) {
        throw "captured_object has no userAccountControl column. Columns: $($columns -join ', ')"
    }

    $sql = "SELECT distinguished_name, $column FROM captured_object WHERE $column IS NOT NULL ORDER BY distinguished_name"

    $command = $connection.CreateCommand()
    $command.CommandText = $sql
    $reader = $command.ExecuteReader()

    $total = 0
    $unreadable = 0
    $hits = @()

    while ($reader.Read()) {
        $total++
        $dn = $reader.GetString(0)
        $raw = $reader.GetValue(1).ToString()

        $value = 0
        if (-not [int]::TryParse($raw, [ref] $value)) { $unreadable++; continue }
        if (($value -band $Flag) -ne 0) { $hits += [pscustomobject]@{ DistinguishedName = $dn; UserAccountControl = $value } }
    }

    $reader.Close()

    "Bundle:              $BundlePath"
    "Column:              $column"
    "Flag:                0x{0:X} ({0})" -f $Flag
    "Accounts with userAccountControl: $total"
    "Values not a number:              $unreadable"
    "Accounts carrying the flag:       $($hits.Count)"
    ""

    if ($hits.Count -gt 0) { $hits | Format-Table -AutoSize | Out-String | Write-Output }
}
finally {
    $connection.Dispose()
}
