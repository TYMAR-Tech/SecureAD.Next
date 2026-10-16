using Microsoft.Data.Sqlite;
using SecureAD.Evidence;

namespace SecureAD.Derivation;

/// <summary>Direct saved relationships for selected-principal browsing, not pre-expanded group closures.</summary>
internal static class MembershipBrowseStorage
{
    internal static void Write(SqliteConnection connection, string directory, Guid generation, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var selected = new AnalysisStoreGeneration(AnalysisStoreKind.Derivation, generation);
        var path = BundleLayout.AnalysisSegmentDataPath(directory, selected, StoreSegmentRole.Membership);
        using (File.Open(path, FileMode.CreateNew, FileAccess.Write)) { }
        using var command = connection.CreateCommand();
        command.CommandText = "ATTACH DATABASE $path AS membership";
        command.Parameters.AddWithValue("$path", path);
        command.ExecuteNonQuery();
        command.Parameters.Clear();
        command.CommandText = "PRAGMA membership.journal_mode=WAL; PRAGMA membership.synchronous=NORMAL; PRAGMA membership.cache_size=-2048";
        command.ExecuteNonQuery();
        using var transaction = connection.BeginTransaction();
        command.Transaction = transaction;
        foreach (var table in new[] { "derivation", "derivation_phase", "sid", "sid_identity", "principal",
            "nesting_edge", "nesting_unresolved_link", "membership_input_manifest" })
        {
            token.ThrowIfCancellationRequested();
            command.CommandText = $"CREATE TABLE membership.{table} AS SELECT * FROM main.{table}";
            command.ExecuteNonQuery();
        }
        command.CommandText = """
            CREATE UNIQUE INDEX membership.ix_browse_sid_id ON sid(sid_id);
            CREATE UNIQUE INDEX membership.ix_browse_sid ON sid(sid,scope);
            CREATE UNIQUE INDEX membership.ix_browse_identity ON sid_identity(sid_id);
            CREATE UNIQUE INDEX membership.ix_browse_principal ON principal(sid_id);
            CREATE INDEX membership.ix_nesting_edge_member ON nesting_edge(member_sid_id,group_sid_id);
            CREATE INDEX membership.ix_browse_unresolved ON nesting_unresolved_link(sid_id,direction,distinguished_name);
            """;
        command.ExecuteNonQuery();
        token.ThrowIfCancellationRequested();
        transaction.Commit();
        command.Transaction = null;
        command.CommandText = "PRAGMA membership.wal_checkpoint(TRUNCATE)";
        if ((long)command.ExecuteScalar()! != 0)
            throw new InvalidOperationException("The saved membership browsing product could not be checkpointed.");
    }
}
