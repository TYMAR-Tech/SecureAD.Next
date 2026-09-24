# Reads a judgement store that is still being written, to answer "how far has it got
# and what is taking the space" WITHOUT disturbing the run.
#
# Safe on a live run: opens read-only, and the writer commits every 500 objects so
# what is there is consistent. It cannot see rows in the uncommitted batch, which is
# at most 500 objects behind - irrelevant at this scale.
#
#   pwsh -NoProfile -File judgement-progress.ps1 <run-directory>
param([Parameter(Mandatory)][string]$RunDirectory)

$partial = Join-Path $RunDirectory 'judgement.db.partial'
$final   = Join-Path $RunDirectory 'judgement.db'
$db = if (Test-Path $partial) { $partial } elseif (Test-Path $final) { $final } else { $null }
if (-not $db) { "No judgement store in $RunDirectory"; exit 1 }

"store:   {0}" -f (Split-Path $db -Leaf)
"size:    {0:N2} GB" -f ((Get-Item $db).Length / 1GB)
"changed: {0}" -f (Get-Item $db).LastWriteTime
""

# Copy first. A live SQLite file plus its -wal must be read together, and copying
# both takes a consistent pair without ever opening the original.
$scratch = Join-Path $env:TEMP ("judge-look-" + [Guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $scratch | Out-Null
try {
    Copy-Item $db (Join-Path $scratch 'look.db')
    foreach ($suffix in '-wal','-shm') {
        if (Test-Path ($db + $suffix)) { Copy-Item ($db + $suffix) (Join-Path $scratch ('look.db' + $suffix)) }
    }

    $bin = Join-Path $PSScriptRoot '..\tests\SecureAD.Next.Tests\bin\Release\net10.0-windows\win-x64'
    Add-Type -Path (Join-Path $bin 'SQLitePCLRaw.core.dll')
    Add-Type -Path (Join-Path $bin 'Microsoft.Data.Sqlite.dll')
    [SQLitePCL.Batteries_V2]::Init()

    $c = [Microsoft.Data.Sqlite.SqliteConnection]::new(
        "Data Source=$(Join-Path $scratch 'look.db');Mode=ReadOnly;Pooling=False")
    $c.Open()

    function Scalar($sql) {
        $cmd = $c.CreateCommand(); $cmd.CommandText = $sql
        try { $v = $cmd.ExecuteScalar(); if ($null -eq $v -or $v -is [DBNull]) { 0 } else { $v } }
        catch { 'n/a' } finally { $cmd.Dispose() }
    }

    "--- how far it has got"
    "objects classified      {0,16:N0}" -f (Scalar "SELECT COUNT(*) FROM permission_classification_object")
    "findings so far         {0,16:N0}" -f (Scalar "SELECT COUNT(*) FROM finding")
    ""
    "--- what is taking the space"
    $entries = Scalar "SELECT COUNT(*) FROM permission_entry"
    "permission_entry rows   {0,16:N0}" -f $entries
    "  distinct targets      {0,16:N0}" -f (Scalar "SELECT COUNT(DISTINCT target) FROM permission_entry")
    "  bytes of target text  {0,16:N0}" -f (Scalar "SELECT SUM(LENGTH(target)) FROM permission_entry")
    "control_edge rows       {0,16:N0}" -f (Scalar "SELECT COUNT(*) FROM control_edge")
    "control_ace rows        {0,16:N0}" -f (Scalar "SELECT COUNT(*) FROM control_ace")
    "shared_proof_value rows {0,16:N0}" -f (Scalar "SELECT COUNT(*) FROM shared_proof_value")
    ""
    "--- repetition (the P-272 question, asked of the judgement store)"
    $distinct = Scalar @"
SELECT COUNT(*) FROM (SELECT DISTINCT sid,mask,object_type,inherited_object_type,
  inheritance_flags,propagation_flags,ace_type FROM permission_entry)
"@
    "distinct entry shapes   {0,16:N0}" -f $distinct
    if ($entries -is [int64] -and $distinct -is [int64] -and $distinct -gt 0) {
        "each stored, on average {0,16:N0} times" -f ($entries / $distinct)
    }

    $c.Close()
}
finally { Remove-Item $scratch -Recurse -Force -ErrorAction SilentlyContinue }
