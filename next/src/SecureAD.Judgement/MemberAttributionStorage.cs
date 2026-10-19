using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal static partial class MemberAttributionStorage
{
    private sealed record Configuration(MemberAttributionBudget Budget, string Forest, IReadOnlyDictionary<string, NamingContextKind> NamingContexts);
    internal const string SourceSql = """
        SELECT e.id*2 AS display_id,e.target,e.holder_sid,COALESCE(e.holder_scope,'') AS holder_scope,
            e.capability,e.expectedness,(e.counted=1 AND NOT EXISTS(SELECT 1 FROM full_control_support s WHERE s.edge_id=e.id)) AS counted,
            e.evaluation AS source_evaluation,EXISTS(SELECT 1 FROM full_control_support s WHERE s.edge_id=e.id) AS included,
            e.generation,e.derivation_generation
        FROM control_edge e
        UNION ALL
        SELECT id*2-1,target,holder_sid,COALESCE(holder_scope,''),'HasFullControl',expectedness,evaluation='Established',evaluation,0,generation,derivation_generation
        FROM full_control_assessment
        """;

    internal static void CreateTables(SqliteConnection connection)
    {
        Execute(connection, $"""
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.Judgement)}.member_attribution_product (id INTEGER PRIMARY KEY CHECK(id=1), configuration TEXT NULL, configuration_hash TEXT NULL,
                root_count INTEGER NOT NULL, permission_count INTEGER NOT NULL);
            INSERT INTO member_attribution_product VALUES (1,NULL,NULL,0,0);
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.member_attribution_root (id INTEGER PRIMARY KEY, holder_sid TEXT NOT NULL COLLATE NOCASE,
                holder_scope TEXT NOT NULL COLLATE NOCASE, proof TEXT NOT NULL, proof_hash TEXT NOT NULL,
                UNIQUE(holder_sid,holder_scope));
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.member_attribution_member (root_id INTEGER NOT NULL REFERENCES member_attribution_root(id),
                identity TEXT NOT NULL COLLATE NOCASE, sid TEXT NULL COLLATE NOCASE, scope TEXT NOT NULL COLLATE NOCASE,
                PRIMARY KEY(root_id,identity));
            CREATE INDEX {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.ix_member_attribution_reverse ON member_attribution_member(sid,scope,root_id);
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.member_attribution_context (root_id INTEGER NOT NULL REFERENCES member_attribution_root(id),
                context TEXT NOT NULL, proof TEXT NOT NULL, proof_hash TEXT NOT NULL, PRIMARY KEY(root_id,context));
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.member_attribution_permission (display_id INTEGER PRIMARY KEY, root_id INTEGER NOT NULL,
                context TEXT NOT NULL, target TEXT NOT NULL COLLATE NOCASE REFERENCES control_object(target),
                FOREIGN KEY(root_id,context) REFERENCES member_attribution_context(root_id,context));
            CREATE INDEX {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.ix_member_attribution_permission_root ON member_attribution_permission(root_id,target,display_id);
            """);
    }

    internal static void Write(SqliteConnection connection, CapturedMembershipInput input, MemberAttributionBudget budget,
        Guid generation, string forest, IReadOnlyDictionary<string, NamingContextKind> namingContexts, CancellationToken cancellationToken)
    {
        var engine = new MemberAttributionDeriver(input, budget, TimeProvider.System, cancellationToken);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT DISTINCT holder_sid,holder_scope FROM (" + SourceSql + ") ORDER BY holder_sid,holder_scope";
        var holders = new List<(string Sid, string Scope)>();
        using (var reader = command.ExecuteReader())
            while (reader.Read()) holders.Add((reader.GetString(0), reader.GetString(1)));
        var rootId = 0;
        var permissions = 0;
        foreach (var holder in holders)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!engine.RequiresAssessment(holder.Sid, holder.Scope)) continue;
            command.Transaction = null;
            command.CommandText = "SELECT display_id,target FROM (" + SourceSql + ") WHERE holder_sid=$sid COLLATE NOCASE AND holder_scope=$scope COLLATE NOCASE ORDER BY display_id";
            command.Parameters.Clear();
            command.Parameters.AddWithValue("$sid", holder.Sid);
            command.Parameters.AddWithValue("$scope", holder.Scope);
            var links = new List<(long Id, string Target)>();
            using (var reader = command.ExecuteReader())
                while (reader.Read()) links.Add((reader.GetInt64(0), reader.GetString(1)));
            var contexts = links.Select(link => MemberAttributionScope.ContextKey(link.Target, forest, namingContexts)).Distinct().ToArray();
            var expansion = engine.Derive(holder.Sid, string.IsNullOrEmpty(holder.Scope) ? null : holder.Scope, generation, contexts.Length, cancellationToken);
            var contextProofs = contexts.ToDictionary(context => context,
                context => JsonSerializer.Serialize(MemberAttributionScope.Assess(expansion, context, forest, engine.WithinTime, cancellationToken), ProofSerialization.Options));
            expansion = engine.Finish(expansion);
            using var transaction = connection.BeginTransaction();
            command.Transaction = transaction;
            var json = JsonSerializer.Serialize(expansion, ProofSerialization.Options);
            Execute(connection, "INSERT INTO member_attribution_root VALUES ($id,$sid,$scope,$proof,$hash)",
                ("$id", ++rootId), ("$sid", holder.Sid), ("$scope", holder.Scope), ("$proof", json), ("$hash", Hash(json)));
            foreach (var member in expansion.Members)
            {
                var sid = member.Source is null ? null : RequesterTrusteeReading.SidOf(member.Source);
                Execute(connection, "INSERT INTO member_attribution_member VALUES ($root,$identity,$sid,$scope)",
                    ("$root", rootId), ("$identity", member.Identity), ("$sid", sid),
                    ("$scope", sid is not null && Sid.IsBuiltinDomain(sid) ? member.Source?.DomainFqdn ?? "" : ""));
            }
            foreach (var (context, proof) in contextProofs)
                Execute(connection, "INSERT INTO member_attribution_context VALUES ($root,$context,$proof,$hash)",
                    ("$root", rootId), ("$context", context), ("$proof", proof), ("$hash", Hash(proof)));
            foreach (var link in links)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var context = MemberAttributionScope.ContextKey(link.Target, forest, namingContexts);
                Execute(connection, "INSERT INTO member_attribution_permission VALUES ($id,$root,$context,$target)",
                    ("$id", link.Id), ("$root", rootId), ("$context", context), ("$target", link.Target));
                permissions++;
            }
            transaction.Commit();
        }
        var configuration = JsonSerializer.Serialize(new Configuration(budget, forest, namingContexts), ProofSerialization.Options);
        Execute(connection, "UPDATE member_attribution_product SET configuration=$configuration,configuration_hash=$hash,root_count=$roots,permission_count=$permissions WHERE id=1",
            ("$configuration", configuration), ("$hash", Hash(configuration)), ("$roots", rootId), ("$permissions", permissions));
    }

    internal static MemberAttributionDetail Read(SqliteConnection connection, JudgementDescription description,
        string sid, string? scope, string target)
    {
        if (!ReadManifest(connection)) return new(false, null, []);
        if (JudgementStoreLayout.Requested(connection, StoreSegmentRole.PermissionProof) is { } requested)
            return ReadRequested(connection, requested, description, sid, scope, target);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT r.id,p.context,p.display_id FROM member_attribution_root r JOIN member_attribution_permission p ON p.root_id=r.id "
            + "WHERE r.holder_sid=$sid COLLATE NOCASE AND r.holder_scope=$scope COLLATE NOCASE AND p.target=$target COLLATE NOCASE LIMIT 1";
        command.Parameters.AddWithValue("$sid", sid);
        command.Parameters.AddWithValue("$scope", scope ?? "");
        command.Parameters.AddWithValue("$target", target);
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return new(true, null, []);
        var id = reader.GetInt32(0);
        var context = reader.GetString(1);
        var permission = reader.GetInt64(2);
        reader.Close();
        ValidateLink(connection, description, permission, sid, scope, target, context);
        var expansion = ReadRoot(connection, description, id);
        var applicability = ReadContext(connection, id, context, expansion);
        return new(true, expansion, applicability);
    }

    internal static MemberPermissionPage ReadReverse(SqliteConnection connection, JudgementDescription description,
        string memberSid, string? memberScope, bool includeExpected, long afterId)
    {
        if (!ReadManifest(connection)) return new(false, false, description.GenerationId, [], false, afterId);
        if (JudgementStoreLayout.Requested(connection, StoreSegmentRole.PermissionProof) is { } requested)
            return ReadRequestedReverse(connection, requested, description, memberSid, memberScope, includeExpected, afterId);
        using var command = connection.CreateCommand();
        // Every incomplete source can hide an unvisited member; absence from its index is not non-membership.
        command.CommandText = "SELECT NOT EXISTS(SELECT 1 FROM member_attribution_root WHERE COALESCE(json_extract(proof,'$.IsComplete'),0)<>1)";
        var complete = (long)command.ExecuteScalar()! == 1;
        command.Parameters.AddWithValue("$sid", memberSid);
        command.Parameters.AddWithValue("$scope", memberScope ?? "");
        command.CommandText = """
            SELECT NOT EXISTS(
                SELECT 1 FROM member_attribution_permission p JOIN member_attribution_member m ON m.root_id=p.root_id
                LEFT JOIN member_attribution_context c ON c.root_id=p.root_id AND c.context=p.context
                WHERE m.sid=$sid COLLATE NOCASE AND m.scope=$scope COLLATE NOCASE AND NOT EXISTS(
                    SELECT 1 FROM json_each(c.proof) value WHERE json_extract(value.value,'$.Member')=m.identity COLLATE NOCASE
                    AND json_extract(value.value,'$.State') IN ('Established','NotEstablished')))
            """;
        complete &= (long)command.ExecuteScalar()! == 1;
        command.CommandText = "SELECT COUNT(DISTINCT p.display_id) FROM member_attribution_permission p "
            + "JOIN member_attribution_member m ON m.root_id=p.root_id JOIN (" + SourceSql + ") s ON s.display_id=p.display_id "
            + "WHERE m.sid=$sid COLLATE NOCASE AND m.scope=$scope COLLATE NOCASE AND s.expectedness='Expected' AND s.counted=1";
        var expected = (long)command.ExecuteScalar()!;
        command.CommandText = "SELECT p.display_id,p.root_id,p.context,p.target,s.holder_sid,s.holder_scope,s.capability,s.expectedness,s.counted,MIN(m.identity),s.source_evaluation,s.included,s.generation,s.derivation_generation "
            + "FROM member_attribution_permission p JOIN member_attribution_member m ON m.root_id=p.root_id "
            + "JOIN (" + SourceSql + ") s ON s.display_id=p.display_id "
            + "WHERE m.sid=$sid COLLATE NOCASE AND m.scope=$scope COLLATE NOCASE AND p.display_id>$after "
            + (includeExpected ? "" : "AND s.expectedness<>'Expected' ") + "GROUP BY p.display_id ORDER BY p.display_id LIMIT 101";
        command.Parameters.AddWithValue("$after", afterId);
        var rows = new List<(long Id, int Root, string Context, string Target, string Sid, string Scope, string Capability, ControlExpectedness Expected, bool Counted, string Member, ControlEvaluationState State, bool Included)>();
        using (var reader = command.ExecuteReader())
            while (reader.Read())
            {
                if (Guid.Parse(reader.GetString(12)) != description.GenerationId
                    || (reader.IsDBNull(13) ? null : reader.GetString(13)) != description.DerivationGenerationId?.ToString("D")) throw Invalid();
                rows.Add((reader.GetInt64(0), reader.GetInt32(1), reader.GetString(2), reader.GetString(3),
                    reader.GetString(4), reader.GetString(5), reader.GetString(6), Enum.Parse<ControlExpectedness>(reader.GetString(7)), reader.GetBoolean(8), reader.GetString(9),
                    Enum.Parse<ControlEvaluationState>(reader.GetString(10)), reader.GetBoolean(11)));
            }
        var more = rows.Count > 100;
        if (more) rows.RemoveAt(100);
        var roots = rows.Select(row => row.Root).Distinct().ToDictionary(id => id, id => ReadRoot(connection, description, id));
        var contextProof = rows.Select(row => (row.Root, row.Context)).Distinct().ToDictionary(key => key,
            key => ReadContext(connection, key.Root, key.Context, roots[key.Root]).ToDictionary(value => value.Member, StringComparer.OrdinalIgnoreCase));
        var result = new List<MemberPermissionReference>();
        foreach (var row in rows)
        {
            var root = roots[row.Root];
            if (!Same(root.HolderSid, row.Sid) || !Same(root.HolderScope ?? "", row.Scope)) throw Invalid();
            ValidateLink(connection, description, row.Id, row.Sid, row.Scope, row.Target, row.Context);
            var member = root.Members.Single(item => Same(item.Identity, row.Member));
            var resource = contextProof[(row.Root, row.Context)][row.Member];
            if (resource.State == MemberAttributionState.Unknown) complete = false;
            result.Add(new(row.Id, row.Sid, row.Scope.Length == 0 ? null : row.Scope, row.Target, row.Capability,
                row.Expected, row.Counted, member.State, resource.State, resource.Reason) { PermissionState = row.State, IncludedInFullControl = row.Included });
        }
        return new(true, complete, description.GenerationId, result, more, rows.Count == 0 ? afterId : rows[^1].Id) { ExpectedCount = expected };
    }

    private static void ValidateLink(SqliteConnection connection, JudgementDescription description, long id,
        string holder, string? scope, string target, string context)
    {
        var configuration = ReadConfiguration(connection);
        if (context != MemberAttributionScope.ContextKey(target, configuration.Forest, configuration.NamingContexts)) throw Invalid();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT target,holder_sid,holder_scope,generation,derivation_generation FROM (" + SourceSql + ") WHERE display_id=$id";
        command.Parameters.AddWithValue("$id", id);
        using var reader = command.ExecuteReader();
        if (!reader.Read() || !Same(reader.GetString(0), target) || !Same(reader.GetString(1), holder)
            || !Same(reader.GetString(2), scope ?? "") || Guid.Parse(reader.GetString(3)) != description.GenerationId
            || (reader.IsDBNull(4) ? null : reader.GetString(4)) != description.DerivationGenerationId?.ToString("D")) throw Invalid();
    }

    private static bool ReadManifest(SqliteConnection connection, SqliteTransaction? transaction = null)
    {
        var requested = JudgementStoreLayout.Requested(connection, StoreSegmentRole.PermissionProof);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = requested is null
            ? "SELECT configuration,root_count,permission_count,(SELECT COUNT(*) FROM member_attribution_root),"
                + "(SELECT COUNT(*) FROM member_attribution_permission) FROM member_attribution_product WHERE id=1"
            : "SELECT configuration,root_count,permission_count,$roots,$permissions FROM member_attribution_product WHERE id=1";
        if (requested is not null)
        {
            command.Parameters.AddWithValue("$roots", requested.ReadRowCount("member_attribution_root"));
            command.Parameters.AddWithValue("$permissions", requested.ReadRowCount("member_attribution_permission"));
        }
        using var reader = command.ExecuteReader();
        if (!reader.Read() || reader.GetInt64(1) != reader.GetInt64(3) || reader.GetInt64(2) != reader.GetInt64(4)) throw Invalid();
        var ran = !reader.IsDBNull(0);
        if (!ran && (reader.GetInt64(1) != 0 || reader.GetInt64(2) != 0)) throw Invalid();
        return ran;
    }

    private static MemberAttribution ReadRoot(SqliteConnection connection, JudgementDescription description, int id,
        SqliteTransaction? transaction = null)
    {
        JudgementStoreLayout.VerifySelected(connection, StoreSegmentRole.PermissionProof, "member_attribution_root", id);
        JudgementStoreLayout.VerifyScope(connection, StoreSegmentRole.PermissionProof, "member_attribution_member", id);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT holder_sid,holder_scope,proof,proof_hash FROM member_attribution_root WHERE id=$id";
        command.Parameters.AddWithValue("$id", id);
        using var reader = command.ExecuteReader();
        if (!reader.Read()) throw Invalid();
        var json = reader.GetString(2);
        if (Hash(json) != reader.GetString(3)) throw Invalid();
        var result = JsonSerializer.Deserialize<MemberAttribution>(json, ProofSerialization.Options) ?? throw Invalid();
        if (result.GenerationId != description.GenerationId || result.DerivationGenerationId != description.DerivationGenerationId
            || !Same(result.HolderSid, reader.GetString(0)) || !Same(result.HolderScope ?? "", reader.GetString(1))
            || result.Budget is null || !Enum.IsDefined(result.Stop)) throw Invalid();
        reader.Close();
        result.Budget.Validate();
        if (result.Budget != ReadConfiguration(connection, transaction).Budget || result.Members is null || result.Links is null || result.Routes is null
            || result.Limitations is null || result.VisitedNodes < 0 || result.TraversedLinks < 0 || result.StoredRecords < 0
            || result.VisitedNodes > result.Budget.MaxNodes || result.TraversedLinks > result.Budget.MaxLinks
            || result.StoredRecords > result.Budget.MaxRecords) throw Invalid();
        var identities = result.Members.Select(member => member.Identity).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (result.Routes.Select(route => route.Id).Where((value, index) => value != index).Any()
            || result.Routes.Any(route => route.LinkIndex < 0 || route.LinkIndex >= result.Links.Count
                || route.ParentRouteId is { } parent && (parent < 0 || parent >= route.Id)
                || !identities.Contains(route.Member))) throw Invalid();
        command.CommandText = "SELECT identity,sid,scope FROM member_attribution_member WHERE root_id=$id";
        var members = result.Members.ToDictionary(member => member.Identity, StringComparer.OrdinalIgnoreCase);
        using var indexReader = command.ExecuteReader();
        var found = 0;
        while (indexReader.Read())
        {
            if (!members.TryGetValue(indexReader.GetString(0), out var member)) throw Invalid();
            var sid = member.Source is null ? null : RequesterTrusteeReading.SidOf(member.Source);
            if (!Same(sid, indexReader.IsDBNull(1) ? null : indexReader.GetString(1))
                || !Same(indexReader.GetString(2), sid is not null && Sid.IsBuiltinDomain(sid) ? member.Source?.DomainFqdn ?? "" : "")) throw Invalid();
            found++;
        }
        if (found != result.Members.Count) throw Invalid();
        return result;
    }

    private static IReadOnlyList<MemberResourceApplicability> ReadContext(SqliteConnection connection, int id, string context,
        MemberAttribution expansion, SqliteTransaction? transaction = null)
    {
        if (JudgementStoreLayout.Requested(connection, StoreSegmentRole.PermissionProof) is { } requested)
        {
            var selected = requested.ReadCompleteScope("member_attribution_context", id)
                .SingleOrDefault(row => row.CompleteText("context") == context) ?? throw Invalid();
            selected.VerifyValues();
        }
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT proof,proof_hash FROM member_attribution_context WHERE root_id=$id AND context=$context";
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$context", context);
        using var reader = command.ExecuteReader();
        if (!reader.Read()) throw Invalid();
        var json = reader.GetString(0);
        if (Hash(json) != reader.GetString(1)) throw Invalid();
        var result = JsonSerializer.Deserialize<MemberResourceApplicability[]>(json, ProofSerialization.Options) ?? throw Invalid();
        var identities = expansion.Members.Select(member => member.Identity).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (result.Length != expansion.Members.Count || result.Select(item => item.Member).Distinct(StringComparer.OrdinalIgnoreCase).Count() != result.Length
            || result.Any(item => !Enum.IsDefined(item.State) || !identities.Contains(item.Member))) throw Invalid();
        return result;
    }

    private static Configuration ReadConfiguration(SqliteConnection connection, SqliteTransaction? transaction = null)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT configuration,configuration_hash FROM member_attribution_product WHERE id=1";
        using var reader = command.ExecuteReader();
        if (!reader.Read() || reader.IsDBNull(0) || reader.IsDBNull(1)) throw Invalid();
        var json = reader.GetString(0);
        if (Hash(json) != reader.GetString(1)) throw Invalid();
        var value = JsonSerializer.Deserialize<Configuration>(json, ProofSerialization.Options) ?? throw Invalid();
        if (value.Budget is null || string.IsNullOrWhiteSpace(value.Forest) || value.NamingContexts is null) throw Invalid();
        value.Budget.Validate();
        return value with { NamingContexts = new Dictionary<string, NamingContextKind>(value.NamingContexts, StringComparer.OrdinalIgnoreCase) };
    }

    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    private static InvalidOperationException Invalid() => new(MemberAttributionMessages.Get("InvalidEvidence"));
    private static void Execute(SqliteConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var parameter in parameters) command.Parameters.AddWithValue(parameter.Name, parameter.Value ?? DBNull.Value);
        command.ExecuteNonQuery();
    }
}
