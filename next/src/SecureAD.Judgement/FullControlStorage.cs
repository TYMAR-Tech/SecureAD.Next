using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal static class FullControlStorage
{
    internal static void CreateTables(SqliteConnection connection) => Execute(connection, null, $"""
        CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.full_control_manifest (target TEXT PRIMARY KEY COLLATE NOCASE REFERENCES control_object(target),
            assessment_count INTEGER NOT NULL CHECK(assessment_count >= 0));
        CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.full_control_source (target TEXT PRIMARY KEY COLLATE NOCASE REFERENCES control_object(target),
            ace_count INTEGER NOT NULL, fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
        CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.full_control_source_entry (target TEXT NOT NULL COLLATE NOCASE REFERENCES full_control_source(target),
            position INTEGER NOT NULL, ordinal INTEGER NOT NULL, entry_id INTEGER NOT NULL REFERENCES permission_entry(id),
            fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32), PRIMARY KEY(target, position));
        CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.full_control_assessment (id INTEGER PRIMARY KEY, target TEXT NOT NULL COLLATE NOCASE REFERENCES full_control_source(target),
            holder_sid TEXT NOT NULL COLLATE NOCASE, holder_scope TEXT NULL COLLATE NOCASE,
            evaluation TEXT NOT NULL, expectedness TEXT NOT NULL, generation TEXT NOT NULL,
            derivation_generation TEXT NULL, support_count INTEGER NOT NULL, proof TEXT NOT NULL,
            route_value_id INTEGER NOT NULL REFERENCES shared_proof_value(id),
            route_fingerprint BLOB NOT NULL CHECK(length(route_fingerprint)=32));
        CREATE UNIQUE INDEX {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.ux_full_control_identity ON full_control_assessment(target, holder_sid, COALESCE(holder_scope,''));
        CREATE INDEX {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.ix_full_control_holder ON full_control_assessment(holder_sid, holder_scope, id);
        CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.full_control_support (assessment_id INTEGER NOT NULL REFERENCES full_control_assessment(id),
            edge_id INTEGER NOT NULL UNIQUE REFERENCES control_edge(id), PRIMARY KEY(assessment_id, edge_id));
        """);

    internal static void Write(SqliteConnection connection, SqliteTransaction transaction, ControlEvidencePreparation prepared,
        IReadOnlyList<ControlEdge> storedEdges, SharedPermissionStorage sharedEntries, bool manifestExists = false)
    {
        var result = prepared.Value;
        // Under Tier-0 gating the stream already recorded a manifest row of zero for this object,
        // because every captured object gets its descriptor record whether or not it is assessed.
        // Inserting a second would collide; the count is corrected here instead.
        if (manifestExists)
            Execute(connection, transaction, "UPDATE full_control_manifest SET assessment_count=$count WHERE target=$target COLLATE NOCASE",
                ("$target", result.Target), ("$count", result.FullControlAssessments.Count));
        else
            Execute(connection, transaction, "INSERT INTO full_control_manifest VALUES ($target,$count)",
                ("$target", result.Target), ("$count", result.FullControlAssessments.Count));
        if (result.FullControlAssessments.Count == 0) return;
        var sourceEntries = prepared.Source ?? throw FullControlEvaluator.InvalidProof();
        var entries = sourceEntries.Entries;
        sharedEntries.InsertRecord(PermissionProofRecordStorage.FullSource, "INSERT INTO full_control_source VALUES (CAST($target AS TEXT),$count,$fingerprint)",
            ("$target", result.Target), ("$count", entries.Length), ("$fingerprint", sourceEntries.Fingerprint));
        for (var position = 0; position < entries.Length; position++)
        {
            var entry = entries[position];
            var reference = sharedEntries.Write(result.Target, result.FullControlAssessments[0].GenerationId, entry);
            sharedEntries.InsertRecord(PermissionProofRecordStorage.FullSourceEntry,
                "INSERT INTO full_control_source_entry VALUES (CAST($target AS TEXT),$position,$ordinal,$entry,$fingerprint)",
                ("$target", result.Target), ("$position", position), ("$ordinal", entry.Ordinal), ("$entry", reference.Id),
                ("$fingerprint", reference.Fingerprint));
        }
        foreach (var item in prepared.Assessments)
        {
            var assessment = item.Value;
            var supports = assessment.IsCounted ? storedEdges.Where(edge => FullControlEvaluator.Supports(assessment.Source, edge)).ToArray() : [];
            var routes = sharedEntries.Proofs.WriteFullControlRoutes(assessment, item.Routes);
            var stored = JsonSerializer.SerializeToNode(assessment with { Id = 0, Source = assessment.Source with { Entries = [] } }, ProofSerialization.Options)!;
            if (stored["Source"] is not JsonObject source || !source.Remove("MembershipRoutes")) throw FullControlEvaluator.InvalidProof();
            var id = sharedEntries.InsertRecord(PermissionProofRecordStorage.FullAssessment, """
                INSERT INTO full_control_assessment(target,holder_sid,holder_scope,evaluation,expectedness,generation,derivation_generation,support_count,proof,route_value_id,route_fingerprint)
                VALUES (CAST($target AS TEXT),CAST($sid AS TEXT),CAST($scope AS TEXT),CAST($state AS TEXT),
                    CAST($expected AS TEXT),CAST($generation AS TEXT),CAST($derivation AS TEXT),$count,
                    CAST($proof AS TEXT),$routes,$routehash)
                """, ("$target", result.Target), ("$sid", assessment.Source.Holder.Sid), ("$scope", assessment.Source.HolderScope),
                ("$state", assessment.EvaluationState.ToString()), ("$expected", assessment.Expectedness.ToString()),
                ("$generation", assessment.GenerationId.ToString("D")), ("$derivation", assessment.DerivationGenerationId?.ToString("D")),
                ("$count", supports.Length), ("$proof", stored.ToJsonString()), ("$routes", routes.Id), ("$routehash", routes.Fingerprint));
            foreach (var edge in supports)
                Execute(connection, transaction, "INSERT INTO full_control_support VALUES ($summary,$edge)", ("$summary", id), ("$edge", edge.Id));
        }
    }

    internal static FullControlAssessment Read(SqliteConnection connection, JudgementDescription description, long id)
    {
        var selected = JudgementStoreLayout.VerifySelected(connection, StoreSegmentRole.PermissionProof, "full_control_assessment", id);
        if (selected is not null)
        {
            var target = selected.CompleteText("target");
            JudgementStoreLayout.VerifySelected(connection, StoreSegmentRole.PermissionProof, "full_control_source", target);
            JudgementStoreLayout.VerifySelected(connection, StoreSegmentRole.PermissionProof, "control_object", target);
            JudgementStoreLayout.VerifySelected(connection, StoreSegmentRole.PermissionProof, "shared_proof_value", selected.Integer("route_value_id"));
            if (JudgementStoreLayout.Requested(connection, StoreSegmentRole.PermissionProof) is { } requested)
                foreach (var link in requested.ReadCompleteScope("full_control_support", id))
                {
                    link.VerifyValues();
                    JudgementStoreLayout.VerifySelected(connection, StoreSegmentRole.PermissionProof, "control_edge", link.Integer("edge_id"));
                }
        }
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT a.target,a.holder_sid,a.holder_scope,a.evaluation,a.expectedness,a.generation,a.derivation_generation,a.support_count,a.proof,s.ace_count,s.fingerprint,o.is_complete,a.route_value_id,a.route_fingerprint
            FROM full_control_assessment a JOIN full_control_source s USING(target) JOIN control_object o USING(target) WHERE a.id=$id
            """;
        command.Parameters.AddWithValue("$id", id);
        FullControlAssessment result;
        int supportCount;
        try
        {
            using var read = command.ExecuteReader();
            if (!read.Read()) throw FullControlEvaluator.InvalidProof();
            var stored = JsonNode.Parse(read.GetString(8));
            if (stored?["Source"] is not JsonObject source || source.ContainsKey("MembershipRoutes")) throw FullControlEvaluator.InvalidProof();
            var value = stored.Deserialize<FullControlAssessment>(ProofSerialization.Options);
            if (value?.Source?.Holder is null) throw FullControlEvaluator.InvalidProof();
            var routes = SharedProofStorage.ReadFullControlRoutes(connection, value, read.GetInt64(12), (byte[])read.GetValue(13));
            value = value with { Source = value.Source with { MembershipRoutes = routes } };
            var entries = ReadEntries(connection, description, read.GetString(0));
            if (value?.Source?.Holder is null || entries.Count != read.GetInt32(9)
                || !SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(entries, ProofSerialization.Options)).AsSpan().SequenceEqual((byte[])read.GetValue(10))
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
        using var links = connection.CreateCommand();
        links.CommandText = "SELECT e.id,e.target,e.holder_sid,e.holder_scope,e.generation,e.derivation_generation FROM full_control_support s "
            + "LEFT JOIN control_edge e ON e.id=s.edge_id WHERE s.assessment_id=$id ORDER BY e.id";
        links.Parameters.AddWithValue("$id", id);
        var found = 0;
        using (var read = links.ExecuteReader())
            while (read.Read())
            {
                if (read.IsDBNull(0) || read.GetString(1) != result.Source.Target || read.GetString(2) != result.Source.Holder.Sid
                    || Text(read, 3) != result.Source.HolderScope || Guid.Parse(read.GetString(4)) != description.GenerationId
                    || Text(read, 5) != description.DerivationGenerationId?.ToString("D")) throw FullControlEvaluator.InvalidProof();
                found++;
            }
        if (found != supportCount || !result.IsCounted && found != 0 || result.PrincipalCatalogueVersion is not (2 or 3))
            throw FullControlEvaluator.InvalidProof();
        return result;
    }

    private static IReadOnlyList<PermissionEntry> ReadEntries(SqliteConnection connection, JudgementDescription description, string target)
    {
        if (JudgementStoreLayout.Requested(connection, StoreSegmentRole.PermissionProof) is { } requested)
            foreach (var occurrence in requested.ReadCompleteScope("full_control_source_entry", target))
            {
                occurrence.VerifyValues();
                JudgementStoreLayout.VerifyPermission(connection, occurrence.Integer("entry_id"));
            }
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT " + SharedPermissionStorage.Projection + ",a.ordinal,a.fingerprint,a.position FROM full_control_source_entry a LEFT JOIN permission_entry p ON p.id=a.entry_id"
            + SharedPermissionStorage.MeaningJoin + "WHERE a.target=$target ORDER BY a.position";
        command.Parameters.AddWithValue("$target", target);
        using var read = command.ExecuteReader();
        var entries = new List<PermissionEntry>();
        while (read.Read())
        {
            if (read.GetInt32(SharedPermissionStorage.ProjectionColumns + 2) != entries.Count) throw FullControlEvaluator.InvalidProof();
            entries.Add(SharedPermissionStorage.Read(connection, read, target, description.GenerationId));
        }
        return entries;
    }

    internal static IReadOnlyDictionary<long, long> Supports(SqliteConnection connection, IEnumerable<ControlEdge> edges)
    {
        var result = new Dictionary<long, long>();
        if (JudgementStoreLayout.Requested(connection, StoreSegmentRole.PermissionProof) is { } requested)
        {
            foreach (var edge in edges)
                if (requested.ReadSingle("detail_control_support", edge.Id) is { } support)
                    result.Add(edge.Id, support.Integer("assessment_id"));
            return result;
        }
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
