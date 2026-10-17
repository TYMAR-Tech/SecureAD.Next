using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests;

internal static partial class TestSealing
{
    private static readonly (string Table, string Field, string Column, SavedTextPayloadStorage Store)[] TextPayloads =
    [
        ("permission_classification_descriptor", "descriptor", "descriptor_payload_id", SavedTextPayloadStorage.Classifications),
        ("permission_classification_reading", "payload", "payload_id", SavedTextPayloadStorage.Classifications),
        ("permission_classification_schema", "payload", "payload_id", SavedTextPayloadStorage.Classifications),
        ("shared_proof_value", "payload", "payload_id", SavedTextPayloadStorage.Permissions),
        ("member_attribution_root", "proof", "proof_id", SavedTextPayloadStorage.Permissions),
        ("member_attribution_context", "proof", "proof_id", SavedTextPayloadStorage.Permissions),
    ];

    internal static Dictionary<long, string> ReadSavedTexts(SqliteConnection connection, string table, string field)
    {
        var source = TextPayloads.Single(value => value.Table == table && value.Field == field);
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT rowid,\"{source.Column}\" FROM \"{table}\" ORDER BY rowid";
        var locations = new List<(long Row, long Payload)>();
        using (var read = command.ExecuteReader())
            while (read.Read()) locations.Add((read.GetInt64(0), read.GetInt64(1)));
        return locations.ToDictionary(value => value.Row, value => source.Store.Read(connection, value.Payload));
    }

    internal static bool TryMutateSavedText(SqliteConnection connection, string sql, out int changed)
    {
        changed = 0;
        var match = Regex.Match(sql, @"\A\s*UPDATE\s+(?<table>\w+)\s+SET\s+(?<field>\w+)\s*=",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (!match.Success) return false;
        var sources = TextPayloads.Where(value => value.Table == match.Groups["table"].Value
            && value.Field == match.Groups["field"].Value).ToArray();
        if (sources.Length == 0) return false;
        var source = Assert.Single(sources);
        var originals = ReadSavedTexts(connection, source.Table, source.Field);
        var temporary = "fixture_payload_" + Guid.NewGuid().ToString("N");
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        // Historical controls express the intended JSON mutation, not a legacy production schema.
        command.CommandText = $"CREATE TEMP TABLE \"{temporary}\" AS SELECT rowid AS fixture_rowid,*,NULL AS \"{source.Field}\" FROM \"{source.Table}\"";
        command.ExecuteNonQuery();
        command.CommandText = $"UPDATE temp.\"{temporary}\" SET \"{source.Field}\"=$text WHERE fixture_rowid=$row";
        command.Parameters.Add("$text", SqliteType.Text);
        command.Parameters.Add("$row", SqliteType.Integer);
        foreach (var (row, text) in originals)
        {
            command.Parameters["$text"].Value = text;
            command.Parameters["$row"].Value = row;
            Assert.Equal(1, command.ExecuteNonQuery());
        }
        command.Parameters.Clear();
        var target = match.Groups["table"];
        command.CommandText = sql[..target.Index] + $"temp.\"{temporary}\"" + sql[(target.Index + target.Length)..];
        changed = command.ExecuteNonQuery();
        var altered = new List<(long Row, string Text)>();
        command.CommandText = $"SELECT fixture_rowid,\"{source.Field}\" FROM temp.\"{temporary}\" ORDER BY fixture_rowid";
        using (var read = command.ExecuteReader())
            while (read.Read())
                if (read.GetString(1) != originals[read.GetInt64(0)])
                    altered.Add((read.GetInt64(0), read.GetString(1)));
        using var statements = new PreparedStatements(connection);
        foreach (var (row, text) in altered)
        {
            var payload = source.Store.Write(connection, transaction, statements, text);
            command.CommandText = $"UPDATE \"{source.Table}\" SET \"{source.Column}\"=$payload WHERE rowid=$row";
            command.Parameters.AddWithValue("$payload", payload);
            command.Parameters.AddWithValue("$row", row);
            Assert.Equal(1, command.ExecuteNonQuery());
            command.Parameters.Clear();
        }
        Assert.Equal(changed, altered.Count);
        command.CommandText = $"DROP TABLE temp.\"{temporary}\"";
        command.ExecuteNonQuery();
        transaction.Commit();
        return true;
    }
}
