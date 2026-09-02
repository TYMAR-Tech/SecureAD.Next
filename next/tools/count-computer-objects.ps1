#Requires -Version 7.0
# Counts computer-class objects in a sealed bundle, by domain, so the number a rule reports as
# "objects judged" can be told against the forest's own count.
param([Parameter(Mandatory)][string]$BundlePath)

$dll = Get-ChildItem -Path (Join-Path $PSScriptRoot '..\src\SecureAD.Cli\bin\Release') -Recurse -Filter 'Microsoft.Data.Sqlite.dll' | Select-Object -First 1
Add-Type -Path $dll.FullName

$evidence = Get-ChildItem -Path $BundlePath -Filter 'evidence*.db' | Select-Object -First 1
$connection = [Microsoft.Data.Sqlite.SqliteConnection]::new("Data Source=$($evidence.FullName);Mode=ReadOnly")
$connection.Open()

$command = $connection.CreateCommand()
$command.CommandText = @'
SELECT o.distinguished_name, o.useraccountcontrol, o.primarygroupid, o.operatingsystem
FROM captured_object o
JOIN objectclass_value c ON c.object_id = o.object_id
WHERE c.value = 'computer'
ORDER BY o.distinguished_name
'@

$reader = $command.ExecuteReader()
$rows = while ($reader.Read()) {
    [pscustomobject]@{
        Dn  = $reader.GetString(0)
        Uac = if ($reader.IsDBNull(1)) { $null } else { $reader.GetValue(1) }
        Pgid = if ($reader.IsDBNull(2)) { $null } else { $reader.GetValue(2) }
        Os  = if ($reader.IsDBNull(3)) { '(none)' } else { $reader.GetValue(3) }
    }
}
$connection.Close()

"COMPUTER-CLASS OBJECTS: $($rows.Count)"
$rows | Format-Table -AutoSize | Out-String -Width 200
