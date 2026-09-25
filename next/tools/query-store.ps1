# Runs one read-only query against an analysis store and prints the rows. Exists so a measurement
# can be taken without hand-quoting SQL through a shell that mangles it.
param(
    [Parameter(Mandatory)] [string] $Database,
    [Parameter(Mandatory)] [string] $Sql)

$sqlite = Get-ChildItem (Join-Path $PSScriptRoot '..\src\SecureAD.Cli\bin\Release') -Recurse `
    -Filter 'Microsoft.Data.Sqlite.dll' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $sqlite) { throw 'Build SecureAD.Cli in Release first.' }

Add-Type -Path $sqlite.FullName

$builder = New-Object Microsoft.Data.Sqlite.SqliteConnectionStringBuilder
$builder.DataSource = $Database
$builder.Mode = [Microsoft.Data.Sqlite.SqliteOpenMode]::ReadOnly
$builder.Pooling = $false

$connection = New-Object Microsoft.Data.Sqlite.SqliteConnection $builder.ToString()
$connection.Open()

$command = $connection.CreateCommand()
$command.CommandText = $Sql
$reader = $command.ExecuteReader()

$columns = @()
for ($i = 0; $i -lt $reader.FieldCount; $i++) { $columns += $reader.GetName($i) }

$out = while ($reader.Read()) {
    $row = [ordered]@{}
    for ($i = 0; $i -lt $reader.FieldCount; $i++) {
        $row[$columns[$i]] = if ($reader.IsDBNull($i)) { $null } else { $reader.GetValue($i) }
    }
    [pscustomobject] $row
}

$reader.Close()
$connection.Close()
$out | Format-Table -AutoSize
