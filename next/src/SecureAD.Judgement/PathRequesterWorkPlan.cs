using SecureAD.Evidence;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;

namespace SecureAD.Judgement;

internal sealed class PathRequesterWorkPlan(SqliteConnection connection, SqliteTransaction transaction,
    JudgementDescription description, JudgingInputs sources, CancellationToken token) : IDisposable
{
    internal const int PageSize = 64;
    private const int Version = 1;

    internal sealed record Question(long Id, PathRequesterFamily Family, string RequesterDn, string TargetDn,
        string? GroupDn, OwnAccountMembershipPermissionKind? PermissionKind)
    {
        internal string Key => PathRequesterSelector.Key(Family, RequesterDn, TargetDn, GroupDn, PermissionKind);
    }

    internal sealed record Membership(SavedOwnAccountMembershipProof Proof,
        PathSharedProofStorage.PreparedOwnAccount Reference, string CanonicalFingerprint);

    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PathProof)}.path_requester_work (
                id INTEGER PRIMARY KEY CHECK(id>0),
                calculation INTEGER NOT NULL DEFAULT 1 CHECK(calculation=1),
                family TEXT NOT NULL CHECK(family IN ('RequesterDacl','OwnAccountMembership','MembershipDacl')),
                requester TEXT NOT NULL, target TEXT NOT NULL, group_dn TEXT NULL, permission_kind TEXT NULL,
                question_key TEXT NOT NULL UNIQUE, fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
            CREATE INDEX {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PathProof)}.ix_path_requester_work_target ON path_requester_work(target,family,id);
            CREATE INDEX {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PathProof)}.ix_path_requester_work_membership ON path_requester_work(group_dn,requester,permission_kind);
            """;
        command.ExecuteNonQuery();
    }

    internal PathCalculationStorage.RecordSet Write(IReadOnlyList<RequesterDaclRequest> direct,
        IReadOnlyList<OwnAccountMembershipRequest> own, IReadOnlyList<MembershipDaclRequest> combined)
    {
        return Write(Questions());
        IEnumerable<Question> Questions()
        {
            var count = 0;
            foreach (var request in direct.OrderBy(RequesterDaclProofs.Key, StringComparer.Ordinal))
                yield return new(++count, PathRequesterFamily.RequesterDacl, request.RequesterDn, request.TargetDn, null, null);
            foreach (var request in own.OrderBy(OwnAccountMembershipProofs.Key, StringComparer.Ordinal))
                yield return new(++count, PathRequesterFamily.OwnAccountMembership, request.RequesterDn, request.TargetDn, null, request.PermissionKind);
            foreach (var request in combined.OrderBy(MembershipDaclProofs.Key, StringComparer.Ordinal))
                yield return new(++count, PathRequesterFamily.MembershipDacl, request.RequesterDn, request.TargetDn, request.GroupDn, request.PermissionKind);
        }
    }

    internal PathCalculationStorage.RecordSet Write(IEnumerable<Question> questions)
    {
        sources.RequireFor(description);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO path_requester_work(id,family,requester,target,group_dn,permission_kind,question_key,fingerprint)
            VALUES ($id,$family,$requester,$target,$group,$kind,$key,$hash)
            """;
        foreach (var name in new[] { "$id", "$family", "$requester", "$target", "$group", "$kind", "$key", "$hash" })
            command.Parameters.AddWithValue(name, DBNull.Value);
        var count = 0;
        foreach (var question in questions)
        {
            if (question.Id != ++count) throw Tier0PathStorage.InvalidProof();
            Save(question);
        }
        using var temporary = connection.CreateCommand();
        temporary.Transaction = transaction;
        temporary.CommandText = """
            CREATE TEMP TABLE path_membership_prerequisite (
                requester TEXT NOT NULL, target TEXT NOT NULL, kind TEXT NOT NULL,
                proof INTEGER NOT NULL, fingerprint TEXT NOT NULL, source_fingerprint TEXT NOT NULL,
                canonical_fingerprint TEXT NOT NULL, binding TEXT NOT NULL,
                PRIMARY KEY(requester,target,kind));
            """;
        temporary.ExecuteNonQuery();
        return new(count, Tier0PathCalculation.Fingerprint(References(connection, description, token)));

        void Save(Question question)
        {
            token.ThrowIfCancellationRequested();
            Validate(question);
            command.Parameters["$id"].Value = question.Id;
            command.Parameters["$family"].Value = question.Family.ToString();
            command.Parameters["$requester"].Value = question.RequesterDn;
            command.Parameters["$target"].Value = question.TargetDn;
            command.Parameters["$group"].Value = (object?)question.GroupDn ?? DBNull.Value;
            command.Parameters["$kind"].Value = (object?)question.PermissionKind?.ToString() ?? DBNull.Value;
            command.Parameters["$key"].Value = question.Key;
            command.Parameters["$hash"].Value = Convert.FromHexString(Fingerprint(description, question));
            if (command.ExecuteNonQuery() != 1) throw Tier0PathStorage.InvalidProof();
        }
    }

    internal IEnumerable<string> MembershipGroups() => Names("""
        SELECT DISTINCT CASE family WHEN 'OwnAccountMembership' THEN target ELSE group_dn END AS resource
        FROM path_requester_work WHERE family IN ('OwnAccountMembership','MembershipDacl') ORDER BY resource
        """);

    internal IEnumerable<string> DaclTargets() => Names("""
        SELECT DISTINCT target FROM path_requester_work WHERE family IN ('RequesterDacl','MembershipDacl') ORDER BY target
        """);

    private IEnumerable<string> Names(string sql)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        using var read = command.ExecuteReader();
        while (read.Read())
        {
            token.ThrowIfCancellationRequested();
            yield return read.GetString(0);
        }
    }

    internal IReadOnlyList<OwnAccountMembershipRequest> MembershipRequests(string group)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT DISTINCT requester,permission_kind FROM path_requester_work
            WHERE (family='OwnAccountMembership' AND target=$group) OR (family='MembershipDacl' AND group_dn=$group)
            """;
        command.Parameters.AddWithValue("$group", group);
        using var read = command.ExecuteReader();
        var requests = new List<OwnAccountMembershipRequest>();
        while (read.Read())
        {
            token.ThrowIfCancellationRequested();
            requests.Add(new(read.GetString(0), group) { PermissionKind = ReadKind(read.GetString(1)) });
        }
        return requests.OrderBy(OwnAccountMembershipProofs.Key, StringComparer.Ordinal).ToArray();
    }

    internal Question? OwnQuestion(OwnAccountMembershipRequest request)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = Columns + " WHERE family='OwnAccountMembership' AND requester=$requester AND target=$target AND permission_kind=$kind";
        command.Parameters.AddWithValue("$requester", request.RequesterDn);
        command.Parameters.AddWithValue("$target", request.TargetDn);
        command.Parameters.AddWithValue("$kind", request.PermissionKind.ToString());
        using var read = command.ExecuteReader();
        if (!read.Read()) return null;
        var result = ReadQuestion(read, description);
        if (read.Read()) throw Tier0PathStorage.InvalidProof();
        return result;
    }

    internal IEnumerable<Question> DaclQuestions(string target)
    {
        sources.RequireFor(description);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = Columns + " WHERE target=$target AND family IN ('RequesterDacl','MembershipDacl') ORDER BY id";
        command.Parameters.AddWithValue("$target", target);
        using var read = command.ExecuteReader();
        while (read.Read())
        {
            token.ThrowIfCancellationRequested();
            yield return ReadQuestion(read, description);
        }
    }

    internal void SaveMembership(SavedOwnAccountMembershipProof proof, PathSharedProofStorage.PreparedOwnAccount reference)
    {
        sources.RequireProtectedBinding(description);
        if (!ReferenceEquals(proof.Assessment, reference.Assessment) || proof.Steps.Count != 0)
            throw Tier0PathStorage.InvalidProof();
        var request = proof.Assessment.Request;
        var canonical = Tier0PathCalculation.Fingerprint(proof.Assessment);
        var binding = MembershipBinding(request, reference.Id, reference.Fingerprint, proof.SourceFingerprint, canonical);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO temp.path_membership_prerequisite VALUES ($requester,$target,$kind,$proof,$hash,$source,$canonical,$binding)";
        command.Parameters.AddWithValue("$requester", request.RequesterDn);
        command.Parameters.AddWithValue("$target", request.TargetDn);
        command.Parameters.AddWithValue("$kind", request.PermissionKind.ToString());
        command.Parameters.AddWithValue("$proof", reference.Id);
        command.Parameters.AddWithValue("$hash", reference.Fingerprint);
        command.Parameters.AddWithValue("$source", proof.SourceFingerprint);
        command.Parameters.AddWithValue("$canonical", canonical);
        command.Parameters.AddWithValue("$binding", binding);
        if (command.ExecuteNonQuery() != 1) throw Tier0PathStorage.InvalidProof();
    }

    internal Membership ReadMembership(OwnAccountMembershipRequest request, PathSharedProofStorage shared)
    {
        sources.RequireProtectedBinding(description);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT proof,fingerprint,source_fingerprint,canonical_fingerprint,binding
            FROM temp.path_membership_prerequisite WHERE requester=$requester AND target=$target AND kind=$kind
            """;
        command.Parameters.AddWithValue("$requester", request.RequesterDn);
        command.Parameters.AddWithValue("$target", request.TargetDn);
        command.Parameters.AddWithValue("$kind", request.PermissionKind.ToString());
        using var read = command.ExecuteReader();
        if (!read.Read()) throw Tier0PathStorage.InvalidProof();
        var id = read.GetInt64(0);
        var fingerprint = read.GetString(1);
        var source = read.GetString(2);
        var canonical = read.GetString(3);
        if (fingerprint.Length != 64 || source.Length != 64 || canonical.Length != 64
            || MembershipBinding(request, id, fingerprint, source, canonical) != read.GetString(4))
            throw Tier0PathStorage.InvalidProof();
        var value = shared.ReadOwnAccount(id, fingerprint, out var reference);
        if (value.Request != request || value.GenerationId != description.GenerationId
            || value.DerivationGenerationId != description.DerivationGenerationId || value.EvidenceSeal != description.EvidenceSeal)
            throw Tier0PathStorage.InvalidProof();
        return new(new(value, source, []), reference, canonical);
    }

    private string MembershipBinding(OwnAccountMembershipRequest request, long id, string fingerprint, string source, string canonical) =>
        Tier0PathCalculation.Fingerprint(new { description.GenerationId, Request = request, Id = id, Fingerprint = fingerprint,
            Source = source, Canonical = canonical });

    internal static void RequireQuestion(SqliteConnection connection, JudgementDescription description, long id,
        PathRequesterRiskAssessment value)
    {
        JudgementStoreLayout.VerifySelected(connection, StoreSegmentRole.PathProof, "path_requester_work", id);
        using var command = connection.CreateCommand();
        command.CommandText = Columns + " WHERE id=$id";
        command.Parameters.AddWithValue("$id", id);
        using var read = command.ExecuteReader();
        if (!read.Read()) throw Tier0PathStorage.InvalidProof();
        RequireQuestion(read, description, offset: 0, value);
        if (read.Read()) throw Tier0PathStorage.InvalidProof();
    }

    internal static void RequireQuestion(SqliteDataReader read, JudgementDescription description, int offset,
        PathRequesterRiskAssessment value)
    {
        var question = ReadQuestion(read, description, offset);
        if (question.Family != value.Family || question.RequesterDn != value.RequesterDn || question.TargetDn != value.TargetDn
            || question.GroupDn != value.GroupDn || question.PermissionKind != value.PermissionKind)
            throw Tier0PathStorage.InvalidProof();
    }

    internal static void RequirePublishable(SqliteConnection connection, JudgementDescription description,
        PathCalculationStorage.RecordSet expected, CancellationToken token)
    {
        var count = 0;
        var fingerprint = Tier0PathCalculation.Fingerprint(Counted());
        if (count != expected.Count || fingerprint != expected.Fingerprint) throw Tier0PathStorage.InvalidProof();
        IEnumerable<PathProofStorage.Reference> Counted()
        {
            foreach (var reference in References(connection, description, token))
            {
                if (reference.Id != ++count) throw Tier0PathStorage.InvalidProof();
                yield return reference;
            }
        }
    }

    internal static void RequireSelectionMatchesWork(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT
                (SELECT COUNT(*) FROM path_requester_work w LEFT JOIN path_calculation_record c
                    ON c.kind='Candidates' AND c.question_key=w.question_key
                    WHERE c.question_key IS NULL),
                (SELECT COUNT(*) FROM path_calculation_record c LEFT JOIN path_requester_work w
                    ON w.question_key=c.question_key WHERE c.kind='Candidates' AND w.id IS NULL)
            """;
        using var read = command.ExecuteReader();
        if (!read.Read() || read.GetInt64(0) != 0 || read.GetInt64(1) != 0) throw Tier0PathStorage.InvalidProof();
    }

    private static IEnumerable<PathProofStorage.Reference> References(SqliteConnection connection,
        JudgementDescription description, CancellationToken token)
    {
        using var command = connection.CreateCommand();
        command.CommandText = Columns + " ORDER BY id";
        using var read = command.ExecuteReader();
        while (read.Read())
        {
            token.ThrowIfCancellationRequested();
            var question = ReadQuestion(read, description);
            yield return new(question.Id, (byte[])read.GetValue(7));
        }
    }

    private const string Columns = "SELECT id,family,requester,target,group_dn,permission_kind,question_key,fingerprint FROM path_requester_work";

    private static Question ReadQuestion(SqliteDataReader read, JudgementDescription description, int offset = 0)
    {
        if (read.IsDBNull(offset) || !Enum.TryParse<PathRequesterFamily>(read.GetString(offset + 1), out var family)
            || !Enum.IsDefined(family) || family.ToString() != read.GetString(offset + 1)) throw Tier0PathStorage.InvalidProof();
        var value = new Question(read.GetInt64(offset), family, read.GetString(offset + 2), read.GetString(offset + 3),
            read.IsDBNull(offset + 4) ? null : read.GetString(offset + 4),
            read.IsDBNull(offset + 5) ? null : ReadKind(read.GetString(offset + 5)));
        Validate(value);
        if (value.Key != read.GetString(offset + 6)
            || Fingerprint(description, value) != Convert.ToHexString((byte[])read.GetValue(offset + 7)))
            throw Tier0PathStorage.InvalidProof();
        return value;
    }

    private static OwnAccountMembershipPermissionKind ReadKind(string text) =>
        Enum.TryParse<OwnAccountMembershipPermissionKind>(text, out var value) && Enum.IsDefined(value) && value.ToString() == text
            ? value : throw Tier0PathStorage.InvalidProof();

    private static string Fingerprint(JudgementDescription description, Question value) =>
        Tier0PathCalculation.Fingerprint(new { Version, description.GenerationId, Question = value });

    internal static void Validate(Question value)
    {
        if (value.Id <= 0 || !Enum.IsDefined(value.Family) || string.IsNullOrWhiteSpace(value.RequesterDn)
            || string.IsNullOrWhiteSpace(value.TargetDn)
            || value.Family == PathRequesterFamily.RequesterDacl && (value.GroupDn is not null || value.PermissionKind is not null)
            || value.Family != PathRequesterFamily.RequesterDacl && (value.PermissionKind is not { } kind || !Enum.IsDefined(kind))
            || value.Family == PathRequesterFamily.OwnAccountMembership && value.GroupDn is not null
            || value.Family == PathRequesterFamily.MembershipDacl && string.IsNullOrWhiteSpace(value.GroupDn))
            throw Tier0PathStorage.InvalidProof();
    }

    public void Dispose()
    {
        using var command = connection.CreateCommand();
        command.CommandText = "DROP TABLE IF EXISTS temp.path_membership_prerequisite";
        command.ExecuteNonQuery();
    }
}
