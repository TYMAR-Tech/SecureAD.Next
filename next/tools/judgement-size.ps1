# Reports what is actually taking the space in a judgement store, read-only.
# Usage:  pwsh -NoProfile -File judgement-size.ps1 <path-to-judgement.db>
param([Parameter(Mandatory)][string]$Db)

$bin = Join-Path $PSScriptRoot '..\tests\SecureAD.Next.Tests\bin\Release\net10.0-windows\win-x64'
Add-Type -Path (Join-Path $bin 'SQLitePCLRaw.core.dll')
Add-Type -Path (Join-Path $bin 'Microsoft.Data.Sqlite.dll')
[SQLitePCL.Batteries_V2]::Init()

"file: {0}" -f $Db
"size: {0:N2} GB" -f ((Get-Item $Db).Length / 1GB)
""

$c = [Microsoft.Data.Sqlite.SqliteConnection]::new("Data Source=$Db;Mode=ReadOnly;Pooling=False")
$c.Open()

function Scalar($sql) {
    $cmd = $c.CreateCommand(); $cmd.CommandText = $sql
    try { $cmd.ExecuteScalar() } catch { "n/a" } finally { $cmd.Dispose() }
}

"--- row counts"
foreach ($t in @('permission_entry','control_edge','control_ace','control_object','finding',
                 'shared_proof_value','rule_execution','full_control_assessment')) {
    "{0,-28} {1,15:N0}" -f $t, (Scalar "SELECT COUNT(*) FROM $t")
}

""
"--- permission_entry, where the bytes are"
"rows                         {0,15:N0}" -f (Scalar "SELECT COUNT(*) FROM permission_entry")
"distinct targets (DNs)       {0,15:N0}" -f (Scalar "SELECT COUNT(DISTINCT target) FROM permission_entry")
"total bytes of target text   {0,15:N0}" -f (Scalar "SELECT SUM(LENGTH(target)) FROM permission_entry")
"total bytes of sid text      {0,15:N0}" -f (Scalar "SELECT SUM(LENGTH(sid)) FROM permission_entry")
"total bytes of dn text       {0,15:N0}" -f (Scalar "SELECT SUM(COALESCE(LENGTH(dn),0)) FROM permission_entry")
"total bytes of name text     {0,15:N0}" -f (Scalar "SELECT SUM(COALESCE(LENGTH(name),0)) FROM permission_entry")
"total bytes application_data {0,15:N0}" -f (Scalar "SELECT SUM(LENGTH(application_data)) FROM permission_entry")
"total bytes meaning_binding  {0,15:N0}" -f (Scalar "SELECT SUM(LENGTH(meaning_binding)) FROM permission_entry")

""
"--- how repetitive is it"
"distinct (sid,mask,object_type,inherited_object_type,inheritance_flags,propagation_flags,ace_type):"
"  {0,15:N0}" -f (Scalar @"
SELECT COUNT(*) FROM (SELECT DISTINCT sid,mask,object_type,inherited_object_type,
  inheritance_flags,propagation_flags,ace_type FROM permission_entry)
"@)

$c.Close()
