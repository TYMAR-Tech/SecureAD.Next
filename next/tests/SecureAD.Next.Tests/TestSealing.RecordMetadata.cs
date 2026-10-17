using System.Reflection;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests;

internal static partial class TestSealing
{
    internal static void ReauthenticateRecordMetadata(JudgementWriter writer)
    {
        var field = typeof(JudgementWriter).GetField("_connection", BindingFlags.NonPublic | BindingFlags.Instance);
        var connection = Assert.IsType<SqliteConnection>(field?.GetValue(writer));
        var schema = JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof);
        using var metadata = new RequestedDetailRecordWriter(connection);
        using var transaction = connection.BeginTransaction();
        foreach (var layout in PermissionProofRecordStorage.All)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = $"""
                DELETE FROM temp.{RequestedDetailRecordWriter.Records} WHERE source_schema=$schema AND source_table=$table;
                """;
            command.Parameters.AddWithValue("$schema", schema);
            command.Parameters.AddWithValue("$table", layout.Table);
            command.ExecuteNonQuery();
            command.Parameters.Clear();
            command.CommandText = $"SELECT rowid,* FROM \"{schema}\".\"{layout.Table}\" ORDER BY rowid";
            var rows = new List<(long Id, object?[] Values)>();
            using (var read = command.ExecuteReader())
                while (read.Read())
                    rows.Add((read.GetInt64(0), Enumerable.Range(1, read.FieldCount - 1)
                        .Select(column => read.IsDBNull(column) ? null : read.GetValue(column)).ToArray()));
            foreach (var row in rows)
                metadata.Write(transaction, schema, layout, row.Id, row.Values);
        }
        transaction.Commit();
    }
}
