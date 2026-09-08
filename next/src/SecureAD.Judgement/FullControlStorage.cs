using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal static class FullControlStorage
{
    internal static void CreateTables(SqliteConnection connection) => Execute(connection, null, """
        CREATE TABLE full_control_manifest (target TEXT PRIMARY KEY COLLATE NOCASE REFERENCES control_object(target),
            assessment_count INTEGER NOT NULL CHECK(assessment_count >= 0));
        CREATE TABLE full_control_source (target TEXT PRIMARY KEY COLLATE NOCASE REFERENCES control_object(target),
            ace_count INTEGER NOT NULL, entries TEXT NOT NULL);
        CREATE TABLE full_control_assessment (id INTEGER PRIMARY KEY, target TEXT NOT NULL COLLATE NOCASE REFERENCES full_control_source(target),
            holder_sid TEXT NOT NULL COLLATE NOCASE, holder_scope TEXT NULL COLLATE NOCASE,
            evaluation TEXT NOT NULL, expectedness TEXT NOT NULL, generation TEXT NOT NULL,
            derivation_generation TEXT NULL, support_count INTEGER NOT NULL, proof TEXT NOT NULL);
        CREATE UNIQUE INDEX ux_full_control_identity ON full_control_assessment(target, holder_sid, COALESCE(holder_scope,''));
        CREATE INDEX ix_full_control_holder ON full_control_assessment(holder_sid, holder_scope, id);
        CREATE TABLE full_control_support (assessment_id INTEGER NOT NULL REFERENCES full_control_assessment(id),
            edge_id INTEGER NOT NULL UNIQUE REFERENCES control_edge(id), PRIMARY KEY(assessment_id, edge_id));
        """);

    internal static void Write(SqliteConnection connection, SqliteTransaction transaction, ControlObjectEvaluation result,
        IReadOnlyList<ControlEdge> storedEdges)
    {
        Execute(connection, transaction, "INSERT INTO full_control_manifest VALUES ($target,$count)",
            ("$target", result.Target), ("$count", result.FullControlAssessments.Count));
        if (result.FullControlAssessments.Count == 0) return;
        var entries = result.FullControlAssessments[0].Source.Entries;
        var serializedEntries = JsonSerializer.Serialize(entries);
        Execute(connection, transaction, "INSERT INTO full_control_source VALUES ($target,$count,$entries)",
            ("$target", result.Target), ("$count", entries.Count), ("$entries", serializedEntries));
        foreach (var assessment in result.FullControlAssessments)
        {
            FullControlEvaluator.Validate(assessment, storedEdges);
            if (!FullControlEvaluator.Same(assessment.Source.Target, result.Target)
                || JsonSerializer.Serialize(assessment.Source.Entries) != serializedEntries) throw FullControlEvaluator.InvalidProof();
            var supports = assessment.IsCounted ? storedEdges.Where(edge => FullControlEvaluator.Supports(assessment.Source, edge)).ToArray() : [];
            Execute(connection, transaction, """
                INSERT INTO full_control_assessment(target,holder_sid,holder_scope,evaluation,expectedness,generation,derivation_generation,support_count,proof)
                VALUES ($target,$sid,$scope,$state,$expected,$generation,$derivation,$count,$proof)
                """, ("$target", result.Target), ("$sid", assessment.Source.Holder.Sid), ("$scope", assessment.Source.HolderScope),
                ("$state", assessment.EvaluationState.ToString()), ("$expected", assessment.Expectedness.ToString()),
                ("$generation", assessment.GenerationId.ToString("D")), ("$derivation", assessment.DerivationGenerationId?.ToString("D")),
                ("$count", supports.Length), ("$proof", JsonSerializer.Serialize(assessment with { Id = 0, Source = assessment.Source with { Entries = [] } })));
            using var identity = connection.CreateCommand();
            identity.Transaction = transaction;
            identity.CommandText = "SELECT last_insert_rowid()";
            var id = (long)identity.ExecuteScalar()!;
            foreach (var edge in supports)
                Execute(connection, transaction, "INSERT INTO full_control_support VALUES ($summary,$edge)", ("$summary", id), ("$edge", edge.Id));
        }
    }

    internal static FullControlAssessment Read(SqliteConnection connection, JudgementDescription description, long id)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT a.target,a.holder_sid,a.holder_scope,a.evaluation,a.expectedness,a.generation,a.derivation_generation,a.support_count,a.proof,s.ace_count,s.entries,o.is_complete
            FROM full_control_assessment a JOIN full_control_source s USING(target) JOIN control_object o USING(target) WHERE a.id=$id
            """;
        command.Parameters.AddWithValue("$id", id);
        FullControlAssessment result;
        int supportCount;
        try
        {
            using var read = command.ExecuteReader();
            if (!read.Read()) throw FullControlEvaluator.InvalidProof();
            var value = JsonSerializer.Deserialize<FullControlAssessment>(read.GetString(8));
            var entries = JsonSerializer.Deserialize<PermissionEntry[]>(read.GetString(10));
            if (value?.Source?.Holder is null || entries is null || entries.Length != read.GetInt32(9)
                || value.Id != 0 || value.Source.Entries is null || value.Source.Entries.Count != 0
                || value.Source.Target != read.GetString(0) || value.Source.Holder.Sid != read.GetString(1)
                || value.Source.HolderScope != Text(read, 2) || value.EvaluationState.ToString() != read.GetString(3)
                || value.Expectedness.ToString() != read.GetString(4) || value.GenerationId.ToString("D") != read.GetString(5)
                || value.DerivationGenerationId?.ToString("D") != Text(read, 6)
                || value.GenerationId != description.GenerationId || value.DerivationGenerationId != description.DerivationGenerationId
                || read.GetBoolean(11) && (value.EvaluationState == ControlEvaluationState.Unknown || value.Uncertainty != ControlUncertainty.None))
                throw FullControlEvaluator.InvalidProof();
            result = value with { Id = id, Source = value.Source with { Entries = entries } };
            supportCount = read.GetInt32(7);
        }
        catch (JsonException error) { throw new InvalidOperationException(FullControlEvaluator.InvalidProof().Message, error); }
        var edges = ControlEdgeStorage.ReadHolderEdges(connection, description, result.Source.Target, result.Source.Holder.Sid, result.Source.HolderScope);
        FullControlEvaluator.Validate(result, edges);
        var expected = result.IsCounted ? edges.Where(edge => FullControlEvaluator.Supports(result.Source, edge)).Select(edge => edge.Id).Order().ToArray() : [];
        using var links = connection.CreateCommand();
        links.CommandText = "SELECT edge_id FROM full_control_support WHERE assessment_id=$id ORDER BY edge_id";
        links.Parameters.AddWithValue("$id", id);
        var actual = new List<long>();
        using (var read = links.ExecuteReader()) while (read.Read()) actual.Add(read.GetInt64(0));
        if (actual.Count != supportCount || !actual.SequenceEqual(expected)) throw FullControlEvaluator.InvalidProof();
        return result;
    }

    // Counts must not trust a corrupt summary outside the current page. Stream validation rather than retaining every proof.
    internal static void ValidateSelection(SqliteConnection connection, JudgementDescription description, string predicate,
        string? target, string? holderSid, string? holderScope)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT id FROM full_control_assessment WHERE " + predicate + " ORDER BY id";
        ControlEdgeStorage.BindFilter(command, target, holderSid, holderScope);
        using var read = command.ExecuteReader();
        while (read.Read()) Read(connection, description, read.GetInt64(0));
        using var orphan = connection.CreateCommand();
        orphan.CommandText = """
            SELECT
                (SELECT COUNT(*) FROM full_control_support s
                 LEFT JOIN full_control_assessment a ON a.id=s.assessment_id LEFT JOIN control_edge e ON e.id=s.edge_id
                 WHERE a.id IS NULL OR e.id IS NULL)
                + (SELECT COUNT(*) FROM control_object o LEFT JOIN full_control_manifest m USING(target)
                   WHERE m.target IS NULL OR m.assessment_count <> (SELECT COUNT(*) FROM full_control_assessment a WHERE a.target=o.target))
            """;
        if ((long)orphan.ExecuteScalar()! != 0) throw FullControlEvaluator.InvalidProof();
    }

    internal static IReadOnlyDictionary<long, long> Supports(SqliteConnection connection, IEnumerable<ControlEdge> edges)
    {
        var result = new Dictionary<long, long>();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT assessment_id FROM full_control_support WHERE edge_id=$edge";
        var parameter = command.Parameters.Add("$edge", SqliteType.Integer);
        foreach (var edge in edges)
        {
            parameter.Value = edge.Id;
            if (command.ExecuteScalar() is long id) result.Add(edge.Id, id);
        }
        return result;
    }

    private static string? Text(SqliteDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
    private static void Execute(SqliteConnection connection, SqliteTransaction? transaction, string sql, params (string Name, object? Value)[] parameters)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        command.ExecuteNonQuery();
    }
}
