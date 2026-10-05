using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SQLitePCL;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

public sealed class ContainingGroupReaderTests
{
    [Fact]
    public void DeepNestingVisitsOnlyContainingGroupsAndRetainsEveryLink()
    {
        using var connection = Graph(depth: 2000, unrelated: 3000);
        var parentReads = 0;
        strdelegate_trace trace = (_, sql) =>
        {
            if (sql.StartsWith("SELECT group_sid_id, 0", StringComparison.Ordinal)) parentReads++;
        };
        raw.sqlite3_trace(connection.Handle!, trace, null!);

        var result = ContainingGroupReader.Read(connection, Description(), 0, CancellationToken.None);

        raw.sqlite3_trace(connection.Handle!, (strdelegate_trace)null!, null!);
        GC.KeepAlive(trace);
        Assert.Equal(2001, result.Nodes.Count);
        Assert.Equal(2000, result.Links.Count);
        Assert.Equal(2001, parentReads);
        Assert.Empty(result.Warnings);
    }

    [Fact]
    public void CancellationStopsADeepWalkInsteadOfReturningAPartialSuccess()
    {
        using var connection = Graph(depth: 40, unrelated: 100);
        using var cancellation = new CancellationTokenSource();
        var reads = 0;
        strdelegate_trace trace = (_, sql) =>
        {
            if (sql.StartsWith("SELECT group_sid_id, 0", StringComparison.Ordinal) && ++reads == 5)
                cancellation.Cancel();
        };
        raw.sqlite3_trace(connection.Handle!, trace, null!);

        Assert.Throws<OperationCanceledException>(() => ContainingGroupReader.Read(connection, Description(), 0, cancellation.Token));

        raw.sqlite3_trace(connection.Handle!, (strdelegate_trace)null!, null!);
        GC.KeepAlive(trace);
        Assert.Equal(5, reads);
    }

    [Fact]
    public void ParentAndPrimaryGroupLookupsUseTheExistingIndexes()
    {
        using var connection = Graph(1, 10);
        using var command = connection.CreateCommand();
        command.CommandText = "EXPLAIN QUERY PLAN " + ContainingGroupReader.ParentSql;
        command.Parameters.AddWithValue("$member", 0);
        using var reader = command.ExecuteReader();
        var plan = new List<string>();
        while (reader.Read()) plan.Add(reader.GetString(3));

        Assert.Contains(plan, line => line.Contains("ix_nesting_edge_member", StringComparison.Ordinal));
        Assert.Contains(plan, line => line.Contains("SEARCH principal", StringComparison.Ordinal));
        Assert.DoesNotContain(plan, line => line.StartsWith("SCAN ", StringComparison.Ordinal));
    }

    [Fact]
    public void PrimaryAndOrdinaryLinksToTheSameGroupRemainDistinctWitnesses()
    {
        using var connection = Graph(1, 0);
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "UPDATE principal SET primary_group_sid_id=1 WHERE sid_id=0";
            command.ExecuteNonQuery();
        }

        var result = ContainingGroupReader.Read(connection, Description(), 0, CancellationToken.None);

        Assert.Equal(2, result.Nodes.Count);
        Assert.Equal(2, result.Links.Count);
        Assert.Contains(result.Links, link => link.IsPrimaryGroup);
        Assert.Contains(result.Links, link => !link.IsPrimaryGroup);
    }

    private static DerivationDescription Description() => new(DerivationSchema.Version, new string('a', 64), Guid.NewGuid(),
        DerivationRunState.Completed, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddMinutes(1));

    private static SqliteConnection Graph(int depth, int unrelated)
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        DerivationSchema.CreateTables(connection);
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO sid VALUES ($id,$sid,'');
            INSERT INTO principal VALUES ($id,$guid,$group,$type,NULL);
            """;
        command.Parameters.Add("$id", SqliteType.Integer);
        command.Parameters.Add("$sid", SqliteType.Text);
        command.Parameters.AddWithValue("$guid", Guid.NewGuid().ToString("D"));
        command.Parameters.Add("$group", SqliteType.Integer);
        command.Parameters.Add("$type", SqliteType.Integer);
        for (var id = 0; id <= depth + unrelated; id++)
        {
            command.Parameters[0].Value = id;
            command.Parameters[1].Value = $"S-1-5-21-1-2-3-{1000 + id}";
            command.Parameters[3].Value = id == 0 ? 0 : 1;
            command.Parameters[4].Value = id == 0 ? DBNull.Value : unchecked((int)0x80000002);
            command.ExecuteNonQuery();
        }
        command.Parameters.Clear();
        command.CommandText = "INSERT INTO nesting_edge VALUES ($parent,$member)";
        command.Parameters.Add("$parent", SqliteType.Integer);
        command.Parameters.Add("$member", SqliteType.Integer);
        for (var id = 1; id <= depth; id++)
        {
            command.Parameters[0].Value = id;
            command.Parameters[1].Value = id - 1;
            command.ExecuteNonQuery();
        }
        command.Parameters.Clear();
        command.CommandText = "INSERT INTO membership_input_manifest VALUES (1,0,1,'synthetic-empty-source')";
        command.ExecuteNonQuery();
        transaction.Commit();
        DerivationSchema.CreateDeferredIndexes(connection);
        return connection;
    }
}
