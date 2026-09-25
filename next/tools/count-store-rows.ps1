# Counts every non-empty table in an analysis store, so a change has something to be measured
# against. Read-only: the store is opened ReadOnly and nothing is written.
param([Parameter(Mandatory)] [string] $Database)

$sqlite = Get-ChildItem (Join-Path $PSScriptRoot '..\src\SecureAD.Cli\bin\Release') -Recurse `
    -Filter 'Microsoft.Data.Sqlite.dll' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $sqlite) { throw 'Build SecureAD.Cli in Release first.' }

Add-Type -Path $sqlite.FullName
$native = Get-ChildItem (Split-Path $sqlite.FullName) -Recurse -Filter 'SQLitePCLRaw*.dll' -ErrorAction SilentlyContinue
foreach ($n in $native) { try { Add-Type -Path $n.FullName -ErrorAction SilentlyContinue } catch { } }

$builder = New-Object Microsoft.Data.Sqlite.SqliteConnectionStringBuilder
$builder.DataSource = $Database
$builder.Mode = [Microsoft.Data.Sqlite.SqliteOpenMode]::ReadOnly
$builder.Pooling = $false

$connection = New-Object Microsoft.Data.Sqlite.SqliteConnection $builder.ToString()
$connection.Open()

$list = $connection.CreateCommand()
$list.CommandText = "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
$names = @()
$reader = $list.ExecuteReader()
while ($reader.Read()) { $names += $reader.GetString(0) }
$reader.Close()

$rows = foreach ($name in $names) {
    $count = $connection.CreateCommand()
    $count.CommandText = "SELECT COUNT(*) FROM [$name]"
    [pscustomobject]@{ Table = $name; Rows = [int64] $count.ExecuteScalar() }
}

$connection.Close()

"{0:N0} bytes on disk" -f (Get-Item $Database).Length
$rows | Where-Object { $_.Rows -gt 0 } | Sort-Object Rows -Descending |
    Format-Table @{ n = 'Rows'; e = { '{0:N0}' -f $_.Rows }; a = 'right' }, Table -AutoSize
