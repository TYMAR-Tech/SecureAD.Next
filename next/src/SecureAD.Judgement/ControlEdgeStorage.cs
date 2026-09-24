using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Security;
using SecureAD.Storage;

namespace SecureAD.Judgement;

internal static class ControlEdgeStorage
{
    internal const int EngineVersion = 9;

    public static void CreateTables(SqliteConnection connection)
    {
        Execute(connection, null, """
            CREATE TABLE control_product (id INTEGER PRIMARY KEY CHECK(id = 1), engine_version INTEGER NOT NULL,
                capture_complete INTEGER NOT NULL CHECK(capture_complete IN (0,1)), completed INTEGER NOT NULL CHECK(completed IN (0,1)),
                discovery_scoped INTEGER NOT NULL DEFAULT 0 CHECK(discovery_scoped IN (0,1)));
            CREATE TABLE control_object (target TEXT PRIMARY KEY COLLATE NOCASE, principal_sid TEXT NULL, principal_scope TEXT NULL,
                descriptor_outcome TEXT NOT NULL, uncertainty INTEGER NOT NULL, is_complete INTEGER NOT NULL CHECK(is_complete IN (0,1)));
            CREATE TABLE control_edge (id INTEGER PRIMARY KEY, target TEXT NOT NULL REFERENCES control_object(target), target_guid TEXT NULL,
                target_class TEXT NULL, holder_sid TEXT NOT NULL, holder_name TEXT NULL, holder_scope TEXT NULL,
                capability TEXT NOT NULL, edge_class TEXT NOT NULL, evaluation TEXT NOT NULL, uncertainty INTEGER NOT NULL,
                expectedness TEXT NOT NULL, expectedness_reason TEXT NOT NULL, catalogue_version INTEGER NOT NULL,
                generation TEXT NOT NULL, derivation_generation TEXT NULL, counted INTEGER NOT NULL CHECK(counted IN (0,1)),
                ace_count INTEGER NOT NULL, precondition_count INTEGER NOT NULL,
                UNIQUE(target, holder_sid, holder_scope, capability));
            CREATE TABLE control_ace (edge_id INTEGER NOT NULL REFERENCES control_edge(id), ordinal INTEGER NOT NULL,
                entry_id INTEGER NOT NULL REFERENCES permission_entry(id), fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
                PRIMARY KEY(edge_id, ordinal));
            CREATE TABLE control_precondition (edge_id INTEGER NOT NULL REFERENCES control_edge(id), ordinal INTEGER NOT NULL,
                name TEXT NOT NULL, state TEXT NOT NULL, evidence TEXT NOT NULL, PRIMARY KEY(edge_id, ordinal));
            CREATE INDEX ix_control_target ON control_edge(target, id);
            CREATE INDEX ix_control_holder ON control_edge(holder_sid, holder_scope, id);
            CREATE UNIQUE INDEX ux_control_identity ON control_edge(target COLLATE NOCASE, holder_sid COLLATE NOCASE, COALESCE(holder_scope,'') COLLATE NOCASE, capability);
            """);
        SharedPermissionStorage.CreateTables(connection);
        FullControlStorage.CreateTables(connection);
        MemberAttributionStorage.CreateTables(connection);
        OwnershipAuditStorage.CreateTables(connection);
    }

    /// <summary>
    /// Starts the control product. <paramref name="discoveryScoped"/> records whether Tier-0 discovery
    /// decided which objects were assessed, because a reader cannot otherwise tell a scoped count from
    /// a forest-wide one and would present the first as the second.
    /// </summary>
    public static void Start(SqliteConnection connection, bool captureComplete, bool discoveryScoped = false) => Execute(connection, null,
        "INSERT INTO control_product VALUES (1, $version, $complete, 0, $scoped)", ("$version", EngineVersion),
        ("$complete", captureComplete), ("$scoped", discoveryScoped));
    public static void Complete(SqliteConnection connection) => Execute(connection, null, "UPDATE control_product SET completed = 1 WHERE id = 1");

    public static IReadOnlyList<long> SelfMembershipEdgeIds(SqliteConnection connection, string target,
        IEnumerable<string> trusteeSids)
    {
        var wanted = trusteeSids.ToHashSet(StringComparer.OrdinalIgnoreCase);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT id,holder_sid FROM control_edge WHERE target=$target COLLATE NOCASE AND capability='CanAddSelfToGroup' ORDER BY id";
        command.Parameters.AddWithValue("$target", target);
        using var reader = command.ExecuteReader();
        var result = new List<long>();
        while (reader.Read())
            if (wanted.Contains(reader.GetString(1))) result.Add(reader.GetInt64(0));
        return result;
    }

    public static void Write(SqliteConnection connection, SqliteTransaction transaction, PreparedStatements statements, ControlObjectEvaluation result, Tier0Target? ownershipTarget, PermissionWriteSession session)
    {
        var entries = new SharedPermissionStorage(connection, transaction, statements, session);
        Execute(connection, transaction, "INSERT INTO control_object VALUES ($target,$sid,$scope,$outcome,$uncertainty,$complete)",
            ("$target", result.Target), ("$sid", result.PrincipalSid), ("$scope", result.PrincipalScope),
            ("$outcome", result.DescriptorOutcome), ("$uncertainty", (int)result.Uncertainty), ("$complete", result.IsComplete));
        if (ownershipTarget is not null)
        {
            if (ownershipTarget.DistinguishedName != result.Target) throw OwnershipAuditStorage.InvalidProof();
            OwnershipAuditStorage.Observe(connection, transaction, ownershipTarget);
        }
        var storedEdges = WriteEdges(connection, transaction, result.Edges, entries);
        FullControlStorage.Write(connection, transaction, result, storedEdges, entries);
    }

    private static IReadOnlyList<ControlEdge> WriteEdges(SqliteConnection connection, SqliteTransaction transaction,
        IReadOnlyList<ControlEdge> edges, SharedPermissionStorage entries)
    {
        var storedEdges = new List<ControlEdge>();
        foreach (var edge in edges)
        {
            ReplicationControlDeriver.ValidateStored(edge);
            OwnershipControlDeriver.ValidateStored(edge);
            Execute(connection, transaction, """
                INSERT INTO control_edge (target,target_guid,target_class,holder_sid,holder_name,holder_scope,capability,edge_class,
                    evaluation,uncertainty,expectedness,expectedness_reason,catalogue_version,generation,derivation_generation,counted,ace_count,precondition_count)
                VALUES ($target,$guid,$class,$sid,$name,$scope,$capability,$edgeclass,$evaluation,$uncertainty,$expected,$reason,$version,$generation,$derived,$counted,$aces,$conditions)
                """, ("$target", edge.Target), ("$guid", edge.TargetGuid?.ToString("D")), ("$class", edge.TargetClass),
                ("$sid", edge.HolderSid), ("$name", edge.HolderName), ("$scope", edge.HolderScope), ("$capability", edge.Capability.ToString()),
                ("$edgeclass", edge.EdgeClass.ToString()), ("$evaluation", edge.EvaluationState.ToString()), ("$uncertainty", (int)edge.Uncertainty),
                ("$expected", edge.Expectedness.ToString()), ("$reason", edge.ExpectednessReason.ToString()), ("$version", edge.PrincipalCatalogueVersion),
                ("$generation", edge.GenerationId.ToString("D")), ("$derived", edge.DerivationGenerationId?.ToString("D")), ("$counted", edge.IsCounted),
                ("$aces", edge.Evidence.Count), ("$conditions", edge.Preconditions.Count));
            using var identity = connection.CreateCommand();
            identity.Transaction = transaction;
            identity.CommandText = "SELECT last_insert_rowid()";
            var id = (long)identity.ExecuteScalar()!;
            storedEdges.Add(edge with { Id = id });
            foreach (var ace in edge.Evidence)
            {
                var reference = entries.Write(edge.Target, edge.GenerationId, ace);
                Execute(connection, transaction, "INSERT INTO control_ace VALUES ($id,$ordinal,$entry,$fingerprint)",
                    ("$id", id), ("$ordinal", ace.Ordinal), ("$entry", reference.Id), ("$fingerprint", reference.Fingerprint));
            }
            for (var i = 0; i < edge.Preconditions.Count; i++)
            {
                var condition = edge.Preconditions[i];
                Execute(connection, transaction, "INSERT INTO control_precondition VALUES ($id,$ordinal,$name,$state,$evidence)",
                    ("$id", id), ("$ordinal", i), ("$name", condition.Name), ("$state", condition.State.ToString()), ("$evidence", condition.EvidenceSource));
            }
            entries.Proofs.WriteControlRoutes(edge with { Id = id });
        }
        return storedEdges;
    }

    /// <summary>
    /// Adds the detailed products for an admitted target, whose descriptor row already exists.
    /// </summary>
    /// <remarks>
    /// Discovery now runs before assessment, so the stream wrote a descriptor-only row for every
    /// object and this fills in the edges for the few that were admitted. The row's outcome and
    /// uncertainty are rewritten from the real evaluation, because until now they said only that the
    /// descriptor was readable and nothing had assessed it. The ownership target row was already
    /// recorded during the stream and is not written again.
    /// </remarks>
    internal static void Assess(SqliteConnection connection, ControlObjectEvaluation result)
    {
        using var transaction = connection.BeginTransaction();
        using var statements = new PreparedStatements(connection);
        // Its own session, because it is its own transaction: nothing written here may be promoted
        // into a run that is not writing it. Entries the object pass already stored are found through
        // permission_entry.entry_hash, which is why no reading back of this target's rows is needed.
        var entries = new SharedPermissionStorage(connection, transaction, statements, new PermissionWriteSession());
        Execute(connection, transaction, """
            UPDATE control_object SET principal_sid=$sid, principal_scope=$scope, descriptor_outcome=$outcome,
                uncertainty=$uncertainty, is_complete=$complete WHERE target=$target COLLATE NOCASE
            """, ("$target", result.Target), ("$sid", result.PrincipalSid), ("$scope", result.PrincipalScope),
            ("$outcome", result.DescriptorOutcome), ("$uncertainty", (int)result.Uncertainty), ("$complete", result.IsComplete));
        var storedEdges = WriteEdges(connection, transaction, result.Edges, entries);
        FullControlStorage.Write(connection, transaction, result, storedEdges, entries, manifestExists: true);
        transaction.Commit();
    }

    internal static void AppendOwnership(SqliteConnection connection, JudgementDescription description, string target,
        IReadOnlyList<ControlEdge> transitions)
    {
        if (transitions.Any(edge => edge.Target != target || edge.GenerationId != description.GenerationId
            || edge.DerivationGenerationId != description.DerivationGenerationId
            || edge.Capability != ControlCapability.CanBecomeOwnerAndRewriteDacl)) throw OwnershipAuditStorage.InvalidProof();
        using var transaction = connection.BeginTransaction();
        using var statements = new PreparedStatements(connection);
        var entries = new SharedPermissionStorage(connection, transaction, statements, new PermissionWriteSession());
        WriteEdges(connection, transaction, transitions, entries);
        OwnershipAuditStorage.Assessed(connection, transaction, target, transitions.Count);
        transaction.Commit();
    }

    internal static IReadOnlyList<ControlEdge> ReadOwnerCandidates(SqliteConnection connection, JudgementDescription description, string target)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT id FROM control_edge WHERE target=$target COLLATE NOCASE AND capability='CanSetOwner' ORDER BY id";
        command.Parameters.AddWithValue("$target", target);
        var ids = new List<long>();
        using (var read = command.ExecuteReader()) while (read.Read()) ids.Add(read.GetInt64(0));
        return ids.Select(id => ReadEdge(connection, description, id)).ToArray();
    }

    internal static IReadOnlyList<ControlEdge> ReadScopeEdges(SqliteConnection connection, JudgementDescription description)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id,target_guid,target,target_class,holder_sid,holder_name,holder_scope,capability,evaluation,uncertainty,
                expectedness,expectedness_reason,catalogue_version,generation,derivation_generation,counted
            FROM control_edge WHERE capability<>'CanBecomeOwnerAndRewriteDacl' ORDER BY id
            """;
        using var read = command.ExecuteReader();
        var edges = new List<ControlEdge>();
        while (read.Read())
        {
            var generation = Guid.Parse(read.GetString(13));
            var derived = Text(read, 14) is { } value ? Guid.Parse(value) : (Guid?)null;
            if (generation != description.GenerationId || derived != description.DerivationGenerationId) throw OwnershipAuditStorage.InvalidProof();
            edges.Add(new(read.GetInt64(0), Text(read, 1) is { } guid ? Guid.Parse(guid) : null, read.GetString(2), Text(read, 3),
                read.GetString(4), Text(read, 5), Text(read, 6), Enum.Parse<ControlCapability>(read.GetString(7)),
                Enum.Parse<ControlEvaluationState>(read.GetString(8)), (ControlUncertainty)read.GetInt32(9),
                Enum.Parse<ControlExpectedness>(read.GetString(10)), Enum.Parse<ControlExpectednessReason>(read.GetString(11)),
                read.GetInt32(12), generation, derived, read.GetBoolean(15), [], [], SecureAD.Evidence.Findings.MembershipRouteSummary.NotDerived));
        }
        return edges;
    }

    public static ControlEdgePage Read(SqliteConnection connection, JudgementDescription description,
        string? target, string? holderSid, string? holderScope, bool includeExpected, long afterId)
    {
        using var product = connection.CreateCommand();
        product.CommandText = "SELECT capture_complete, completed, discovery_scoped FROM control_product WHERE id=1 AND engine_version=$version";
        product.Parameters.AddWithValue("$version", EngineVersion);
        bool derived, capture, scoped;
        using (var read = product.ExecuteReader())
        {
            derived = read.Read();
            capture = derived && read.GetBoolean(0);
            scoped = derived && read.GetBoolean(2);
            derived = derived && read.GetBoolean(1);
        }
        if (!derived) return new([], 0, 0, 0, 0, false, capture, false, afterId);
        var predicate = target is not null ? "target = $value COLLATE NOCASE"
            : holderSid is not null ? "holder_sid = $value COLLATE NOCASE AND COALESCE(holder_scope,'') = $scope COLLATE NOCASE" : "1=1";
        using var counts = connection.CreateCommand();
        counts.CommandText = $"""
            SELECT expectedness,COUNT(*) FROM (
                SELECT target,holder_sid,holder_scope,expectedness FROM control_edge e
                WHERE counted=1 AND NOT EXISTS (SELECT 1 FROM full_control_support s WHERE s.edge_id=e.id)
                UNION ALL
                SELECT target,holder_sid,holder_scope,expectedness FROM full_control_assessment WHERE evaluation='Established'
            ) WHERE {predicate} GROUP BY expectedness
            """;
        BindFilter(counts, target, holderSid, holderScope);
        long expected = 0, unexpected = 0, unknown = 0;
        using (var read = counts.ExecuteReader())
            while (read.Read())
                switch (Enum.Parse<ControlExpectedness>(read.GetString(0)))
                {
                    case ControlExpectedness.Expected: expected = read.GetInt64(1); break;
                    case ControlExpectedness.Unexpected: unexpected = read.GetInt64(1); break;
                    case ControlExpectedness.Unknown: unknown = read.GetInt64(1); break;
                }
        using var gaps = connection.CreateCommand();
        gaps.CommandText = "SELECT COUNT(*) FROM control_object WHERE is_complete=0" + (target is null ? "" : " AND target=$target COLLATE NOCASE");
        if (target is not null) gaps.Parameters.AddWithValue("$target", target);
        var unanswered = (long)gaps.ExecuteScalar()!;
        if (target is not null)
        {
            using var observed = connection.CreateCommand();
            observed.CommandText = "SELECT COUNT(*) FROM control_object WHERE target=$target COLLATE NOCASE";
            observed.Parameters.AddWithValue("$target", target);
            if ((long)observed.ExecuteScalar()! == 0) return new([], 0, 0, 0, 1, false, capture, false, afterId);
        }
        using var query = connection.CreateCommand();
        query.CommandText = $"""
            SELECT display_id,edge_id,assessment_id FROM (
                SELECT id*2 AS display_id,id AS edge_id,NULL AS assessment_id,target,holder_sid,holder_scope,expectedness FROM control_edge
                UNION ALL
                SELECT id*2-1,NULL,id,target,holder_sid,holder_scope,expectedness FROM full_control_assessment
            ) WHERE {predicate} AND display_id > $after
            """ + (includeExpected ? "" : " AND expectedness <> 'Expected'") + " ORDER BY display_id LIMIT 101";
        BindFilter(query, target, holderSid, holderScope);
        query.Parameters.AddWithValue("$after", afterId);
        var items = new List<(long Display, long? Edge, long? Assessment)>();
        using (var read = query.ExecuteReader())
            while (read.Read()) items.Add((read.GetInt64(0), read.IsDBNull(1) ? null : read.GetInt64(1), read.IsDBNull(2) ? null : read.GetInt64(2)));
        var more = items.Count > 100;
        if (more) items.RemoveAt(100);
        var rows = items.Where(item => item.Edge.HasValue).Select(item => ReadStoredEdge(connection, description, item.Edge!.Value)).ToArray();
        var assessments = items.Where(item => item.Assessment.HasValue).Select(item => FullControlStorage.Read(connection, description, item.Assessment!.Value)).ToArray();
        return new(rows, unexpected, unknown, expected, unanswered, true, capture, more, items.Count == 0 ? afterId : items[^1].Display)
        {
            FullControlAssessments = assessments,
            FullControlSupports = FullControlStorage.Supports(connection, rows),
            IsScopedToDiscovery = scoped,
        };
    }

    internal static ControlEdge ReadExact(SqliteConnection connection, JudgementDescription description, string target, long id)
    {
        using var query = connection.CreateCommand();
        query.CommandText = "SELECT e.id FROM control_edge e JOIN control_product p ON p.id=1 "
            + "WHERE e.id=$id AND e.target=$target COLLATE NOCASE AND p.completed=1 AND p.engine_version=$version";
        query.Parameters.AddWithValue("$id", id);
        query.Parameters.AddWithValue("$target", target);
        query.Parameters.AddWithValue("$version", EngineVersion);
        if (query.ExecuteScalar() is null) throw FullControlEvaluator.InvalidProof();
        return ReadStoredEdge(connection, description, id);
    }

    internal static ControlEdge ReadEdge(SqliteConnection connection, JudgementDescription description, long id)
    {
        var edge = ReadStoredEdge(connection, description, id);
        ReplicationControlDeriver.ValidateStored(edge);
        OwnershipControlDeriver.ValidateStored(edge);
        return edge;
    }

    // Browsing decodes the published answer; production and offline proof verification opt into replay above.
    private static ControlEdge ReadStoredEdge(SqliteConnection connection, JudgementDescription description, long id)
    {
        using var query = connection.CreateCommand();
        query.CommandText = "SELECT control_edge.*, control_object.descriptor_outcome FROM control_edge JOIN control_object USING(target) WHERE id=$id";
        query.Parameters.AddWithValue("$id", id);
        var rows = new List<ControlEdge>();
        var evidenceCounts = new Dictionary<long, (int Aces, int Conditions)>();
        using (var read = query.ExecuteReader())
            while (read.Read())
            {
                var edge = new ControlEdge(read.GetInt64(0), Text(read, 2) is { } guid ? Guid.Parse(guid) : null,
                    read.GetString(1), Text(read, 3), read.GetString(4), Text(read, 5), Text(read, 6),
                    Enum.Parse<ControlCapability>(read.GetString(7)), Enum.Parse<ControlEvaluationState>(read.GetString(9)),
                    (ControlUncertainty)read.GetInt32(10), Enum.Parse<ControlExpectedness>(read.GetString(11)),
                    Enum.Parse<ControlExpectednessReason>(read.GetString(12)), read.GetInt32(13), Guid.Parse(read.GetString(14)),
                    Text(read, 15) is { } derivedId ? Guid.Parse(derivedId) : null, read.GetBoolean(16), [], [],
                    SecureAD.Evidence.Findings.MembershipRouteSummary.NotDerived) { DescriptorOutcome = read.GetString(19) };
                if (edge.GenerationId != description.GenerationId || edge.DerivationGenerationId != description.DerivationGenerationId
                    || read.GetString(8) != edge.EdgeClass.ToString()) throw new InvalidOperationException("Control-edge generation or category mismatch.");
                rows.Add(edge);
                evidenceCounts.Add(edge.Id, (read.GetInt32(17), read.GetInt32(18)));
            }
        for (var i = 0; i < rows.Count; i++)
        {
            var edge = rows[i];
            rows[i] = edge with { Evidence = ReadAces(connection, edge), Preconditions = ReadConditions(connection, edge.Id),
                MembershipRoutes = SharedProofStorage.ReadControlRoutes(connection, edge) };
            if (rows[i].Evidence.Count != evidenceCounts[edge.Id].Aces || rows[i].Preconditions.Count != evidenceCounts[edge.Id].Conditions)
                throw new InvalidOperationException("Control-edge supporting evidence is missing.");
        }
        if (rows.Count != 1) throw FullControlEvaluator.InvalidProof();
        return rows[0];
    }

    private static IReadOnlyList<PermissionEntry> ReadAces(SqliteConnection connection, ControlEdge edge) =>
        ReadExactAces(connection, edge).Select(entry => entry with
        { Trustee = entry.Trustee with { UnresolvedReason = null, Meaning = null } }).ToArray();

    internal static IReadOnlyList<PermissionEntry> ReadExactAces(SqliteConnection connection, ControlEdge edge)
    {
        using var query = connection.CreateCommand();
        query.CommandText = "SELECT " + SharedPermissionStorage.Projection + ",a.ordinal,a.fingerprint FROM control_ace a LEFT JOIN permission_entry p ON p.id=a.entry_id"
            + SharedPermissionStorage.MeaningJoin + "WHERE a.edge_id=$id ORDER BY a.ordinal";
        query.Parameters.AddWithValue("$id", edge.Id);
        using var read = query.ExecuteReader();
        var entries = new List<PermissionEntry>();
        while (read.Read())
        {
            var entry = SharedPermissionStorage.Read(read, edge.Target, edge.GenerationId);
            entries.Add(entry);
        }
        return entries;
    }

    private static IReadOnlyList<ControlPrecondition> ReadConditions(SqliteConnection connection, long id)
    {
        using var query = connection.CreateCommand();
        query.CommandText = "SELECT name,state,evidence FROM control_precondition WHERE edge_id=$id ORDER BY ordinal";
        query.Parameters.AddWithValue("$id", id);
        using var read = query.ExecuteReader();
        var result = new List<ControlPrecondition>();
        while (read.Read()) result.Add(new(read.GetString(0), Enum.Parse<ControlEvaluationState>(read.GetString(1)), read.GetString(2)));
        return result;
    }

    private static string? Text(SqliteDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
    internal static void BindFilter(SqliteCommand command, string? target, string? sid, string? scope)
    {
        if (target is not null || sid is not null) command.Parameters.AddWithValue("$value", target ?? sid!);
        if (target is null && sid is not null) command.Parameters.AddWithValue("$scope", scope ?? "");
    }
    private static void Execute(SqliteConnection connection, SqliteTransaction? transaction, string sql, params (string Name, object? Value)[] values)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var (name, value) in values) command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        command.ExecuteNonQuery();
    }
}
