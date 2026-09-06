using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Kernel.Security;
using SecureAD.Storage;

namespace SecureAD.Judgement;

internal static class ControlEdgeStorage
{
    public static void CreateTables(SqliteConnection connection)
    {
        Execute(connection, null, """
            CREATE TABLE control_product (id INTEGER PRIMARY KEY CHECK(id = 1), engine_version INTEGER NOT NULL,
                capture_complete INTEGER NOT NULL CHECK(capture_complete IN (0,1)), completed INTEGER NOT NULL CHECK(completed IN (0,1)));
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
                ace_type TEXT NOT NULL, sid TEXT NOT NULL, name TEXT NULL, dn TEXT NULL, domain TEXT NULL, role TEXT NULL,
                mask INTEGER NOT NULL, object_type TEXT NULL, inherited_object_type TEXT NULL,
                inherited INTEGER NOT NULL, inheritance_flags INTEGER NOT NULL, propagation_flags INTEGER NOT NULL,
                has_object_type INTEGER NOT NULL, has_inherited_object_type INTEGER NOT NULL, application_data BLOB NOT NULL,
                PRIMARY KEY(edge_id, ordinal));
            CREATE TABLE control_precondition (edge_id INTEGER NOT NULL REFERENCES control_edge(id), ordinal INTEGER NOT NULL,
                name TEXT NOT NULL, state TEXT NOT NULL, evidence TEXT NOT NULL, PRIMARY KEY(edge_id, ordinal));
            CREATE INDEX ix_control_target ON control_edge(target, id);
            CREATE INDEX ix_control_holder ON control_edge(holder_sid, holder_scope, id);
            CREATE UNIQUE INDEX ux_control_identity ON control_edge(target COLLATE NOCASE, holder_sid COLLATE NOCASE, COALESCE(holder_scope,'') COLLATE NOCASE, capability);
            """);
    }

    public static void Start(SqliteConnection connection, bool captureComplete) => Execute(connection, null,
        "INSERT INTO control_product VALUES (1, 1, $complete, 0)", ("$complete", captureComplete));
    public static void Complete(SqliteConnection connection) => Execute(connection, null, "UPDATE control_product SET completed = 1 WHERE id = 1");

    public static void Write(SqliteConnection connection, ControlObjectEvaluation result)
    {
        using var transaction = connection.BeginTransaction();
        Execute(connection, transaction, "INSERT INTO control_object VALUES ($target,$sid,$scope,$outcome,$uncertainty,$complete)",
            ("$target", result.Target), ("$sid", result.PrincipalSid), ("$scope", result.PrincipalScope),
            ("$outcome", result.DescriptorOutcome), ("$uncertainty", (int)result.Uncertainty), ("$complete", result.IsComplete));
        foreach (var edge in result.Edges)
        {
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
            foreach (var ace in edge.Evidence)
                Execute(connection, transaction, """
                    INSERT INTO control_ace VALUES ($id,$ordinal,$type,$sid,$name,$dn,$domain,$role,$mask,$object,$inheritedobject,
                        $inherited,$inheritance,$propagation,$hasobject,$hasinheritedobject,$data)
                    """, ("$id", id), ("$ordinal", ace.Ordinal), ("$type", ace.AceType), ("$sid", ace.Trustee.Sid),
                    ("$name", ace.Trustee.Name), ("$dn", ace.Trustee.DistinguishedName), ("$domain", ace.Trustee.DomainFqdn),
                    ("$role", ace.Trustee.WellKnownRole?.ToString()), ("$mask", ace.AccessMask), ("$object", ace.ObjectTypeGuid),
                    ("$inheritedobject", ace.InheritedObjectTypeGuid), ("$inherited", ace.IsInherited), ("$inheritance", (int)ace.InheritanceFlags),
                    ("$propagation", (int)ace.PropagationFlags), ("$hasobject", ace.HasObjectType), ("$hasinheritedobject", ace.HasInheritedObjectType),
                    ("$data", ace.ApplicationData));
            for (var i = 0; i < edge.Preconditions.Count; i++)
            {
                var condition = edge.Preconditions[i];
                Execute(connection, transaction, "INSERT INTO control_precondition VALUES ($id,$ordinal,$name,$state,$evidence)",
                    ("$id", id), ("$ordinal", i), ("$name", condition.Name), ("$state", condition.State.ToString()), ("$evidence", condition.EvidenceSource));
            }
            MembershipRouteStorage.Write(connection, transaction, "control:" + id, edge.MembershipRoutes);
        }
        transaction.Commit();
    }

    public static ControlEdgePage Read(SqliteConnection connection, JudgementDescription description,
        string? target, string? holderSid, string? holderScope, bool includeExpected, long afterId)
    {
        using var product = connection.CreateCommand();
        product.CommandText = "SELECT capture_complete, completed FROM control_product WHERE id=1 AND engine_version=1";
        bool derived, capture;
        using (var read = product.ExecuteReader())
        {
            derived = read.Read();
            capture = derived && read.GetBoolean(0);
            derived = derived && read.GetBoolean(1);
        }
        if (!derived) return new([], 0, 0, 0, 0, false, capture, false, afterId);
        var predicate = target is not null ? "target = $value COLLATE NOCASE"
            : holderSid is not null ? "holder_sid = $value COLLATE NOCASE AND COALESCE(holder_scope,'') = $scope COLLATE NOCASE" : "1=1";
        using var counts = connection.CreateCommand();
        counts.CommandText = $"SELECT expectedness,COUNT(*) FROM control_edge WHERE counted=1 AND {predicate} GROUP BY expectedness";
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
        query.CommandText = $"SELECT control_edge.*, control_object.descriptor_outcome FROM control_edge JOIN control_object USING(target) WHERE {predicate} AND id > $after"
            + (includeExpected ? "" : " AND expectedness <> 'Expected'") + " ORDER BY id LIMIT 101";
        BindFilter(query, target, holderSid, holderScope);
        query.Parameters.AddWithValue("$after", afterId);
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
        var more = rows.Count > 100;
        if (more) rows.RemoveAt(100);
        for (var i = 0; i < rows.Count; i++)
        {
            var edge = rows[i];
            rows[i] = edge with { Evidence = ReadAces(connection, edge.Id), Preconditions = ReadConditions(connection, edge.Id),
                MembershipRoutes = MembershipRouteStorage.Read(connection, "control:" + edge.Id)["control:" + edge.Id] };
            if (rows[i].Evidence.Count != evidenceCounts[edge.Id].Aces || rows[i].Preconditions.Count != evidenceCounts[edge.Id].Conditions)
                throw new InvalidOperationException("Control-edge supporting evidence is missing.");
        }
        return new(rows, unexpected, unknown, expected, unanswered, true, capture, more, rows.Count == 0 ? afterId : rows[^1].Id);
    }

    private static IReadOnlyList<PermissionEntry> ReadAces(SqliteConnection connection, long id)
    {
        using var query = connection.CreateCommand();
        query.CommandText = "SELECT * FROM control_ace WHERE edge_id=$id ORDER BY ordinal";
        query.Parameters.AddWithValue("$id", id);
        using var read = query.ExecuteReader();
        var entries = new List<PermissionEntry>();
        while (read.Read()) entries.Add(new(read.GetInt32(1), read.GetString(2),
            new(read.GetString(3), Text(read, 4), Text(read, 5), Text(read, 6), null,
                Text(read, 7) is { } role ? Enum.Parse<WellKnownSidRole>(role) : null, null), read.GetInt32(8), Text(read, 9), Text(read, 10),
            read.GetBoolean(11), (byte)read.GetInt32(12), (byte)read.GetInt32(13), read.GetBoolean(14), read.GetBoolean(15), (byte[])read.GetValue(16)));
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
    private static void BindFilter(SqliteCommand command, string? target, string? sid, string? scope)
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
