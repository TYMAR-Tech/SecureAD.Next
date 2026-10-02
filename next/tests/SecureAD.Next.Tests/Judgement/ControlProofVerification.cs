using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Next.Tests.Judgement;

// Historical resealed-proof tests exercise explicit offline replay, not normal protected browsing.
internal static class ControlProofVerification
{
    internal static Result<ControlEdgePage> ReadResult(string directory, string target, bool expected, long after)
    {
        using var reader = FullControlStorageTests.Open(directory);
        try { return Result<ControlEdgePage>.Success(ReadPage(reader, target, null, null, expected, after)); }
        catch (InvalidOperationException error)
        {
            return Result<ControlEdgePage>.Failure(AuditError.Create(ErrorCategory.Shell, "ControlEdgesUnreadable",
                ErrorSeverity.Failed, "Stored control edges could not be read: " + error.Message, directory));
        }
    }

    internal static ControlEdge ReadEdge(JudgementReader reader, string target, long id)
    {
        ReadPage(reader, target, null, null, true, 0);
        return reader.ReadControlEdge(target, id);
    }

    internal static ControlEdgePage ReadPage(JudgementReader reader, string? target, string? holder,
        string? scope, bool expected, long after)
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = BundleLayout.AnalysisGenerationDataPath(reader.BundleDirectory, AnalysisStoreKind.Judgement, reader.Description.GenerationId),
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        connection.Open();
        using var sources = OpenSources(reader);
        OwnershipAuditValidation.Validate(connection, reader.Description, sources,
            new OwnershipAuditStorage.Snapshot(connection, reader.Description, CancellationToken.None));
        var predicate = target is not null ? "target = $value COLLATE NOCASE"
            : holder is not null ? "holder_sid = $value COLLATE NOCASE AND COALESCE(holder_scope,'') = $scope COLLATE NOCASE" : "1=1";
        ValidateSelection(connection, reader.Description, predicate, target, holder, scope);
        var page = reader.ReadControlEdges(target, holder, scope, expected, after);
        foreach (var edge in page.Edges) ControlEdgeStorage.ReadEdge(connection, reader.Description, edge.Id);
        return page;
    }

    internal static JudgingInputs OpenSources(JudgementReader reader)
    {
        var sources = JudgingInputs.Open(reader.BundleDirectory, CancellationToken.None);
        if (!sources.IsSuccess) throw OwnershipAuditStorage.InvalidProof();
        try
        {
            if (reader.Description.DerivationGenerationId is not null && !sources.Value.OpenDerivation().IsSuccess)
                throw OwnershipAuditStorage.InvalidProof();
            sources.Value.RequireFor(reader.Description);
            return sources.Value;
        }
        catch
        {
            sources.Value.Dispose();
            throw;
        }
    }

    private static void ValidateSelection(SqliteConnection connection, JudgementDescription description, string predicate,
        string? target, string? holderSid, string? holderScope)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT id FROM full_control_assessment WHERE " + predicate + " ORDER BY id";
        ControlEdgeStorage.BindFilter(command, target, holderSid, holderScope);
        using var read = command.ExecuteReader();
        while (read.Read())
        {
            var value = FullControlStorage.Read(connection, description, read.GetInt64(0));
            var edges = ReadHolderEdges(connection, description, value.Source.Target, value.Source.Holder.Sid, value.Source.HolderScope);
            FullControlEvaluator.Validate(value, edges);
            var expected = value.IsCounted ? edges.Where(edge => FullControlEvaluator.Supports(value.Source, edge)).Select(edge => edge.Id).Order().ToArray() : [];
            using var links = connection.CreateCommand();
            links.CommandText = "SELECT edge_id FROM full_control_support WHERE assessment_id=$id ORDER BY edge_id";
            links.Parameters.AddWithValue("$id", value.Id);
            var actual = new List<long>();
            using (var linked = links.ExecuteReader()) while (linked.Read()) actual.Add(linked.GetInt64(0));
            if (!actual.SequenceEqual(expected)) throw FullControlEvaluator.InvalidProof();
        }
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

    private static IReadOnlyList<ControlEdge> ReadHolderEdges(SqliteConnection connection, JudgementDescription description,
        string target, string holder, string? scope)
    {
        using var query = connection.CreateCommand();
        query.CommandText = "SELECT id FROM control_edge WHERE target=$target COLLATE NOCASE AND holder_sid=$holder COLLATE NOCASE AND COALESCE(holder_scope,'')=$scope COLLATE NOCASE ORDER BY id";
        query.Parameters.AddWithValue("$target", target);
        query.Parameters.AddWithValue("$holder", holder);
        query.Parameters.AddWithValue("$scope", scope ?? "");
        var ids = new List<long>();
        using (var read = query.ExecuteReader()) while (read.Read()) ids.Add(read.GetInt64(0));
        return ids.Select(id => ControlEdgeStorage.ReadEdge(connection, description, id)).ToArray();
    }
}
