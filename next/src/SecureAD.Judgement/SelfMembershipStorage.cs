using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal static class SelfMembershipStorage
{
    private const int EvaluatorVersion = 1;

    public static void CreateTables(SqliteConnection connection) => Execute(connection, null, """
        CREATE TABLE self_membership_product (id INTEGER PRIMARY KEY CHECK(id=1), evaluator_version INTEGER NOT NULL,
            completed INTEGER NOT NULL CHECK(completed IN (0,1)));
        CREATE TABLE self_membership_discovery (id INTEGER PRIMARY KEY CHECK(id=1), coverage_json TEXT NOT NULL);
        CREATE TABLE self_membership_assessment (id INTEGER PRIMARY KEY, requester_dn TEXT NOT NULL, target_dn TEXT NOT NULL,
            operation TEXT NOT NULL, member_dn TEXT NULL, generation TEXT NOT NULL, derivation_generation TEXT NULL,
            evidence_seal TEXT NOT NULL, requester_guid TEXT NULL, requester_sid TEXT NULL, target_guid TEXT NULL,
            target_sid TEXT NULL, member_guid TEXT NULL, member_sid TEXT NULL, authorization TEXT NOT NULL,
            own_account TEXT NOT NULL, readiness TEXT NOT NULL, descriptor_outcome TEXT NOT NULL,
            requester_captured_utc TEXT NULL, user_account_control INTEGER NULL, member_present INTEGER NULL,
            issues_json TEXT NOT NULL, evidence_json TEXT NOT NULL, holder_edges_json TEXT NOT NULL);
        CREATE UNIQUE INDEX ux_self_membership_identity ON self_membership_assessment(
            requester_dn COLLATE NOCASE,target_dn COLLATE NOCASE,operation,COALESCE(member_dn,'') COLLATE NOCASE);
        CREATE INDEX ix_self_membership_target ON self_membership_assessment(target_dn,id);
        CREATE INDEX ix_self_membership_requester ON self_membership_assessment(requester_dn,id);
        """);

    public static void Start(SqliteConnection connection) => Execute(connection, null,
        "INSERT INTO self_membership_product VALUES (1,$version,0)", ("$version", EvaluatorVersion));

    public static void Write(SqliteConnection connection, SqliteTransaction? transaction, SelfMembershipAssessment value) => Execute(connection, transaction, """
        INSERT INTO self_membership_assessment (requester_dn,target_dn,operation,member_dn,generation,derivation_generation,
            evidence_seal,requester_guid,requester_sid,target_guid,target_sid,member_guid,member_sid,authorization,own_account,
            readiness,descriptor_outcome,requester_captured_utc,user_account_control,member_present,issues_json,evidence_json,holder_edges_json)
        VALUES ($requester,$target,$operation,$member,$generation,$derivation,$seal,$requesterguid,$requestersid,$targetguid,
            $targetsid,$memberguid,$membersid,$authorization,$own,$readiness,$descriptor,$captured,$uac,$present,$issues,$evidence,$edges)
        """, ("$requester", value.Request.RequesterDn), ("$target", value.Request.TargetDn),
        ("$operation", value.Request.Operation.ToString()), ("$member", value.Request.MemberDn),
        ("$generation", value.GenerationId.ToString("D")), ("$derivation", value.DerivationGenerationId?.ToString("D")),
        ("$seal", value.EvidenceSeal), ("$requesterguid", value.RequesterGuid?.ToString("D")), ("$requestersid", value.RequesterSid),
        ("$targetguid", value.TargetGuid?.ToString("D")), ("$targetsid", value.TargetSid),
        ("$memberguid", value.MemberGuid?.ToString("D")), ("$membersid", value.MemberSid),
        ("$authorization", value.Authorization.ToString()), ("$own", value.OwnAccount.ToString()),
        ("$readiness", value.Readiness.ToString()), ("$descriptor", value.DescriptorOutcome),
        ("$captured", value.RequesterCapturedUtc?.ToString("O")), ("$uac", value.UserAccountControl),
        ("$present", value.MemberPresent is null ? null : value.MemberPresent.Value ? 1 : 0),
        ("$issues", JsonSerializer.Serialize(value.Issues, ProofSerialization.Options)),
        ("$evidence", JsonSerializer.Serialize(value.Evidence, ProofSerialization.Options)),
        ("$edges", JsonSerializer.Serialize(value.HolderEdgeIds, ProofSerialization.Options)));

    public static void Complete(SqliteConnection connection, SqliteTransaction? transaction, SelfMembershipDiscoveryCoverage coverage)
    {
        SelfMembershipCoverageStorage.Validate(coverage);
        Execute(connection, transaction, "INSERT INTO self_membership_discovery VALUES (1,$coverage)",
            ("$coverage", JsonSerializer.Serialize(coverage, ProofSerialization.Options)));
        Execute(connection, transaction, "UPDATE self_membership_product SET completed=1 WHERE id=1");
    }

    public static SelfMembershipAssessmentSet Read(SqliteConnection connection, JudgementDescription description,
        string? target, string? requester)
    {
        var summary = SelfMembershipCoverageStorage.Read(connection, description);
        if (summary is null) return new([], false, null);
        using var command = connection.CreateCommand();
        var predicates = new List<string>();
        if (target is not null) { predicates.Add("target_dn=$target COLLATE NOCASE"); command.Parameters.AddWithValue("$target", target); }
        if (requester is not null) { predicates.Add("requester_dn=$requester COLLATE NOCASE"); command.Parameters.AddWithValue("$requester", requester); }
        command.CommandText = "SELECT * FROM self_membership_assessment" + (predicates.Count == 0 ? "" : " WHERE " + string.Join(" AND ", predicates))
            + " ORDER BY requester_dn COLLATE NOCASE,target_dn COLLATE NOCASE,operation,COALESCE(member_dn,'') COLLATE NOCASE";
        using var reader = command.ExecuteReader();
        var results = new List<SelfMembershipAssessment>();
        while (reader.Read())
        {
            Field(reader, 0, () => Positive(Integer(reader, 0)));
            var generation = Field(reader, 5, () => Guid.Parse(RequiredText(reader, 5)));
            var seal = Field(reader, 7, () => RequiredText(reader, 7));
            Field(reader, 5, () => Require(generation == description.GenerationId, "Judgement generation mismatch."));
            Field(reader, 7, () => Require(Same(seal, description.EvidenceSeal), "Evidence seal mismatch."));
            var derivation = GuidText(reader, 6);
            Field(reader, 6, () => Require(derivation == description.DerivationGenerationId, "Derivation generation mismatch."));
            var assessment = new SelfMembershipAssessment(new(
                Field(reader, 1, () => RequiredText(reader, 1)), Field(reader, 2, () => RequiredText(reader, 2)),
                EnumText<SelfMembershipOperation>(reader, 3), Text(reader, 4)), generation, derivation, seal,
                GuidText(reader, 8), Text(reader, 9), GuidText(reader, 10), Text(reader, 11), GuidText(reader, 12), Text(reader, 13),
                EnumText<ControlEvaluationState>(reader, 14), EnumText<ControlEvaluationState>(reader, 15),
                EnumText<ControlEvaluationState>(reader, 16), Field(reader, 17, () => RequiredText(reader, 17)),
                Field<DateTimeOffset?>(reader, 18, () => reader.IsDBNull(18) ? null
                    : DateTimeOffset.ParseExact(RequiredText(reader, 18), "O", CultureInfo.InvariantCulture, DateTimeStyles.None)),
                Field<long?>(reader, 19, () => reader.IsDBNull(19) ? null : Integer(reader, 19)),
                Field<bool?>(reader, 20, () => reader.IsDBNull(20) ? null : Integer(reader, 20) switch
                {
                    0 => false, 1 => true, _ => throw new InvalidDataException("Expected 0, 1 or null."),
                }),
                JsonArray<SelfMembershipIssue>(reader, 21, values =>
                {
                    foreach (var value in values) Defined(value);
                }),
                JsonArray<SelfMembershipAceEvidence>(reader, 22, ValidateEvidence),
                JsonArray<long>(reader, 23, values =>
                {
                    var ids = new HashSet<long>();
                    foreach (var value in values)
                        Require(ids.Add(Positive(value)), "Duplicate holder-edge ID.");
                }));
            Field(reader, 23, () => ValidateReferences(connection, assessment));
            results.Add(assessment);
        }
        return new(results, true, description.GenerationId) { Summary = summary };
    }

    private static void ValidateEvidence(SelfMembershipAceEvidence[] values)
    {
        var ordinals = new HashSet<int>();
        for (var index = 0; index < values.Length; index++)
        {
            var value = values[index];
            Require(value is not null && value.Entry is not null && value.Trustee is not null,
                $"Evidence [{index}] requires Entry and Trustee.");
            var entry = value!.Entry;
            Require(entry.Trustee is not null && entry.ApplicationData is not null,
                $"Evidence [{index}].Entry requires Trustee and ApplicationData.");
            Require(entry.Ordinal >= 0 && ordinals.Add(entry.Ordinal), $"Evidence [{index}].Entry.Ordinal is negative or duplicated.");
            NonBlank(entry.AceType);
            NonBlank(entry.Trustee!.Sid);
            NonBlank(value.Trustee.TrusteeSid);
            Require(Same(entry.Trustee.Sid, value.Trustee.TrusteeSid), $"Evidence [{index}] trustee SIDs disagree.");
            Defined(value.Scope);
            Defined(value.Trustee.State);
            Defined(value.Trustee.Reason);
            if (entry.Trustee.UnresolvedReason is { } reason) Defined(reason);
            if (entry.Trustee.WellKnownRole is { } role) Defined(role);
        }
    }

    private static bool ValidateReferences(SqliteConnection connection, SelfMembershipAssessment assessment)
    {
        if (assessment.HolderEdgeIds.Count == 0) return true;
        using var product = connection.CreateCommand();
        product.CommandText = "SELECT engine_version,completed FROM control_product WHERE id=1";
        using (var status = product.ExecuteReader())
            Require(status.Read() && status.GetValue(0) is long version && version == ControlEdgeStorage.EngineVersion
                && status.GetValue(1) is long completed && completed == 1,
                "Referenced control product is missing, incomplete or uses another engine version.");

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT target,target_guid,holder_sid,holder_scope,capability,generation,derivation_generation,counted
            FROM control_edge WHERE id=$id
            """;
        var id = command.Parameters.Add("$id", SqliteType.Integer);
        foreach (var edgeId in assessment.HolderEdgeIds)
        {
            id.Value = edgeId;
            using var edge = command.ExecuteReader();
            try
            {
                Require(edge.Read(), "Edge does not exist.");
                Require(Same(RequiredText(edge, 0), assessment.Request.TargetDn), "Edge target mismatch.");
                var targetGuid = edge.IsDBNull(1) ? (Guid?)null : Guid.Parse(RequiredText(edge, 1));
                Require(assessment.TargetGuid is null || targetGuid == assessment.TargetGuid, "Edge target_guid mismatch.");
                Require(RequiredText(edge, 4) == nameof(ControlCapability.CanAddSelfToGroup), "Edge capability mismatch.");
                Require(Guid.Parse(RequiredText(edge, 5)) == assessment.GenerationId, "Edge generation mismatch.");
                var derivation = edge.IsDBNull(6) ? (Guid?)null : Guid.Parse(RequiredText(edge, 6));
                Require(derivation == assessment.DerivationGenerationId, "Edge derivation_generation mismatch.");
                Require(Integer(edge, 7) == 1, "Edge is not counted.");
                var sid = RequiredText(edge, 2);
                var scope = edge.IsDBNull(3) ? null : RequiredText(edge, 3);
                Require(assessment.Evidence.Any(value =>
                {
                    if (value.Trustee.State == RequesterTrusteeState.DoesNotMatch) return false;
                    var resolvedSid = value.Entry.Trustee.Sid == "S-1-5-10" ? assessment.TargetSid : value.Entry.Trustee.Sid;
                    var resourceScope = resolvedSid is not null && Sid.IsBuiltinDomain(resolvedSid)
                        ? DnHelper.DnToFqdn(assessment.Request.TargetDn) : null;
                    return Same(sid, resolvedSid) && Same(scope, resourceScope)
                        && (!Sid.IsBuiltinDomain(sid) || !string.IsNullOrWhiteSpace(resourceScope));
                }), "Edge holder SID/scope has no applicable requester evidence route.");
            }
            catch (Exception error) when (IsMalformed(error))
            {
                throw new InvalidDataException($"Holder edge {edgeId}: {error.Message}", error);
            }
        }
        return true;
    }

    private static T[] JsonArray<T>(SqliteDataReader reader, int ordinal, Action<T[]> validate) => Field(reader, ordinal, () =>
    {
        var values = JsonSerializer.Deserialize<T[]>(RequiredText(reader, ordinal), ProofSerialization.Options)
            ?? throw new InvalidDataException("Expected an array, not JSON null.");
        validate(values);
        return values;
    });

    private static T EnumText<T>(SqliteDataReader reader, int ordinal) where T : struct, Enum =>
        Field(reader, ordinal, () => Defined(Enum.Parse<T>(RequiredText(reader, ordinal))));
    private static T Defined<T>(T value) where T : struct, Enum => Enum.IsDefined(value)
        ? value : throw new InvalidDataException($"Undefined {typeof(T).Name} value.");
    private static Guid? GuidText(SqliteDataReader reader, int ordinal) => Field<Guid?>(reader, ordinal,
        () => reader.IsDBNull(ordinal) ? null : Guid.Parse(RequiredText(reader, ordinal)));
    private static string? Text(SqliteDataReader reader, int ordinal) => Field(reader, ordinal,
        () => reader.IsDBNull(ordinal) ? null : RequiredText(reader, ordinal));
    private static string RequiredText(SqliteDataReader reader, int ordinal) =>
        NonBlank(reader.GetValue(ordinal) as string);
    private static string NonBlank(string? value) => !string.IsNullOrWhiteSpace(value)
        ? value : throw new InvalidDataException("Expected nonblank text.");
    private static long Integer(SqliteDataReader reader, int ordinal) => reader.GetValue(ordinal) is long value
        ? value : throw new InvalidDataException("Expected an integer.");
    private static long Positive(long value) => value > 0 ? value : throw new InvalidDataException("Expected a positive ID.");
    private static bool Require(bool condition, string message) => condition ? true : throw new InvalidDataException(message);
    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    private static bool IsMalformed(Exception error) => error is InvalidDataException or JsonException
        or FormatException or ArgumentException or OverflowException or InvalidCastException;
    private static T Field<T>(SqliteDataReader reader, int ordinal, Func<T> read)
    {
        try { return read(); }
        catch (Exception error) when (IsMalformed(error))
        {
            throw new InvalidDataException($"Self-Membership assessment {reader.GetValue(0)}, field {reader.GetName(ordinal)}: {error.Message}", error);
        }
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
