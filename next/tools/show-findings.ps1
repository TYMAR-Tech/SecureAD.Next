# Prints what a judging concluded, straight from the store, without opening the application.
#
# WHAT THIS IS FOR. A lab check needs to see what each rule made of a real forest - including the
# rules that reported nothing, because a rule that found nothing and a rule that fell over look
# identical from a count of findings. This prints one line per rule that ran, then every finding.
#
# It opens the judgement store READ ONLY and writes nothing. It is a diagnostic, not part of the
# product. The judgement store is disposable and rebuildable; the evidence beside it is never
# touched.
#
# NEEDS pwsh, for the reason count-uac-flag.ps1 gives: it loads the product's own SQLite assemblies,
# which are built for modern .NET and cannot be loaded by Windows PowerShell 5.1.
#
# USAGE
#   pwsh -File next/tools/show-findings.ps1 -BundlePath 'C:\...\ad.lab-20260902-030124'
#   pwsh -File next/tools/show-findings.ps1 -BundlePath '...' -Rule SEC-028

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $BundlePath,

    # Show only one rule's findings. The per-rule summary is always printed in full.
    [string] $Rule,

    [string] $BinPath
)

$ErrorActionPreference = 'Stop'

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
$candidates += (Join-Path $PSScriptRoot '..\src\SecureAD.Cli\bin\Debug\net10.0-windows\win-x64')

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

# There is one judgement store per generation, named for it. Taking the newest matches what the
# product reads back, and naming the file found means an operator can tell which run this was.
$store = Get-ChildItem $BundlePath -Filter 'judgement.*.db' |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1

if (-not $store) { throw "There is no judgement store in '$BundlePath'. Has it been judged?" }

$builder = New-Object Microsoft.Data.Sqlite.SqliteConnectionStringBuilder
$builder.DataSource = $store.FullName
$builder.Mode = [Microsoft.Data.Sqlite.SqliteOpenMode]::ReadOnly
$builder.Pooling = $false

$connection = New-Object Microsoft.Data.Sqlite.SqliteConnection $builder.ToString()
$connection.Open()

function Read-Rows([string] $sql) {
    $command = $connection.CreateCommand()
    $command.CommandText = $sql
    $reader = $command.ExecuteReader()
    $rows = @()
    while ($reader.Read()) {
        $row = [ordered]@{}
        for ($i = 0; $i -lt $reader.FieldCount; $i++) {
            $row[$reader.GetName($i)] = if ($reader.IsDBNull($i)) { $null } else { $reader.GetValue($i) }
        }
        $rows += [pscustomobject]$row
    }
    $reader.Close()
    return $rows
}

try {
    "Bundle:  $BundlePath"
    "Store:   $($store.Name)"
    ""

    # EVERY RULE THAT RAN, INCLUDING THE QUIET ONES. A rule that found nothing and a rule that threw
    # both contribute zero findings; only the outcome tells them apart, which is the whole reason
    # this summary exists rather than a list of findings alone.
    $executions = Read-Rows @"
SELECT e.rule_id, e.outcome, e.objects_judged, e.objects_not_judged, e.error,
       (SELECT COUNT(*) FROM finding f WHERE f.rule_id = e.rule_id) AS findings
FROM rule_execution e
ORDER BY e.rule_id
"@

    "RULES THAT RAN"
    $executions |
        Select-Object @{ n = 'Rule'; e = { $_.rule_id } },
                      @{ n = 'Outcome'; e = { $_.outcome } },
                      @{ n = 'Judged'; e = { $_.objects_judged } },
                      @{ n = 'NotJudged'; e = { $_.objects_not_judged } },
                      @{ n = 'Findings'; e = { $_.findings } } |
        Format-Table -AutoSize | Out-String | Write-Output

    $failed = @($executions | Where-Object { $_.outcome -ne 'Succeeded' })
    if ($failed.Count -gt 0) {
        "RULES THAT DID NOT COMPLETE - their silence says nothing about the forest"
        $failed | ForEach-Object { "  $($_.rule_id): $($_.outcome) $($_.error)" }
        ""
    }

    $unread = Read-Rows "SELECT * FROM rule_execution_missing_input"
    if ($unread.Count -gt 0) {
        "INPUTS A RULE COULD NOT READ"
        $unread | ForEach-Object { "  " + (($_.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join "  ") }
        ""
    }

    $where = if ($Rule) { "WHERE rule_id = '$($Rule.Replace("'", "''"))'" } else { '' }

    $findings = Read-Rows @"
SELECT rule_id, severity, domain_fqdn, object_class, distinguished_name, detail
FROM finding
$where
ORDER BY severity_rank DESC, rule_id, distinguished_name
"@

    "FINDINGS ($($findings.Count))"
    ""

    foreach ($f in $findings) {
        "  [$($f.severity)] $($f.rule_id)  $($f.distinguished_name)"
        "      domain: $($f.domain_fqdn)   class: $($f.object_class)"
        "      $($f.detail)"
        ""
    }
}
finally {
    $connection.Dispose()
}
