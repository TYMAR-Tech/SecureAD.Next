using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

internal static class OwnershipAuditStorage
{
    internal sealed record Header(int Version, Guid Generation, string EvidenceSeal, Guid? DerivationGeneration,
        DateTimeOffset EvaluationAsOf, string OwnerRightsContextHash, Tier0InputBinding? Input, Tier0Coverage Coverage,
        int SelectorVersion, int EvaluatorVersion, int TargetCount, int SeedCount, int RelationCount);
    internal sealed record TargetRow(Tier0Target Identity, OwnershipScopeState Selection,
        OwnershipAssessmentExecution Execution, int Candidates, int Transitions);
    internal sealed record SeedRow(string Target, MembershipRouteSummary Routes, ImmutableArray<byte> Fingerprint,
        Tier0Classification Classification);
    internal sealed record RelationRow(long? EdgeId, string Controller, string Affected,
        string? WitnessTarget, int? WitnessOrdinal, string? WitnessTrustee, bool WitnessIsOwner,
        ControlCapability? WitnessCapability)
    {
        public RequesterMembershipEvidence? GroupMembership { get; init; }
    }

    internal sealed class Snapshot
    {
        private readonly SqliteConnection _connection;
        private readonly JudgementDescription _description;
        private readonly (long Changes, long Version) _revision;

        internal Snapshot(SqliteConnection connection, JudgementDescription description, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _connection = connection;
            _description = description;
            _revision = Revision(connection);
            Header = ReadHeader(connection, requireComplete: true);
            Targets = Header is null ? [] : OwnershipAuditStorage.Targets(connection, cancellationToken).ToImmutableArray();
            ByTarget = Targets.ToImmutableDictionary(row => row.Identity.DistinguishedName, StringComparer.OrdinalIgnoreCase);
            Seeds = Header is null ? [] : OwnershipAuditStorage.Seeds(connection, cancellationToken)
                .Select(seed => seed with { Routes = JudgingInputs.FreezeRoutes(seed.Routes) }).ToImmutableArray();
            Relations = Header is null ? [] : OwnershipAuditStorage.Relations(connection, cancellationToken).ToImmutableArray();
            RequireFor(connection, description);
        }

        internal Header? Header { get; }
        internal ImmutableArray<TargetRow> Targets { get; }
        internal ImmutableDictionary<string, TargetRow> ByTarget { get; }
        internal ImmutableArray<SeedRow> Seeds { get; }
        internal ImmutableArray<RelationRow> Relations { get; }

        internal void RequireFor(SqliteConnection connection, JudgementDescription description)
        {
            if (!ReferenceEquals(connection, _connection) || description != _description
                || Header is { } header && (header.Generation != description.GenerationId
                    || header.EvidenceSeal != description.EvidenceSeal
                    || header.DerivationGeneration != description.DerivationGenerationId
                    || header.EvaluationAsOf != description.EvaluationAsOf)
                || Revision(connection) != _revision) throw InvalidProof();
        }

        private static (long Changes, long Version) Revision(SqliteConnection connection)
        {
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT total_changes()";
            var changes = (long)command.ExecuteScalar()!;
            command.CommandText = "PRAGMA data_version";
            return (changes, (long)command.ExecuteScalar()!);
        }
    }

    internal static void CreateTables(SqliteConnection connection) => Execute(connection, null, """
        CREATE TABLE ownership_audit (id INTEGER PRIMARY KEY CHECK(id=1), header TEXT NOT NULL,
            fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32), completed INTEGER NOT NULL CHECK(completed IN (0,1)));
        CREATE TABLE ownership_target (target TEXT PRIMARY KEY COLLATE NOCASE REFERENCES control_object(target),
            identity_json TEXT NOT NULL, fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32), selection TEXT NOT NULL,
            execution TEXT NOT NULL, candidate_count INTEGER NOT NULL CHECK(candidate_count>=0),
            transition_count INTEGER NOT NULL CHECK(transition_count>=0));
        CREATE TABLE ownership_seed (target TEXT PRIMARY KEY COLLATE NOCASE REFERENCES ownership_target(target),
            routes TEXT NOT NULL, classification_fingerprint BLOB NOT NULL CHECK(length(classification_fingerprint)=32),
            classification TEXT NOT NULL);

        -- A DISCOVERED ROUTE HAS NO CONTROL EDGE TO POINT AT, WHICH IS THE WHOLE POINT OF SCHEMA 28.
        -- Discovery now runs before detailed assessment, so at the moment a route is recorded the
        -- edge it would once have referenced has not been derived and may never be. The witness
        -- columns name the captured fact instead - the object, the entry's position in its stored
        -- DACL and the trustee - which capture already holds. edge_id survives for routes that did
        -- come from a stored edge; exactly one of the two sources is present, and a row carrying
        -- neither would be a route with no provenance at all.
        CREATE TABLE ownership_relation (id INTEGER PRIMARY KEY, edge_id INTEGER NULL REFERENCES control_edge(id),
            controller_target TEXT NOT NULL COLLATE NOCASE REFERENCES ownership_target(target),
            affected_target TEXT NOT NULL COLLATE NOCASE REFERENCES ownership_target(target),
            witness_target TEXT NULL COLLATE NOCASE, witness_ordinal INTEGER NULL CHECK(witness_ordinal IS NULL OR witness_ordinal>=0),
            witness_trustee TEXT NULL, witness_is_owner INTEGER NOT NULL CHECK(witness_is_owner IN (0,1)),
            witness_capability TEXT NULL, witness_membership TEXT NULL,
            CHECK((edge_id IS NULL) <> (witness_target IS NULL)),
            CHECK(witness_target IS NULL OR (witness_trustee IS NOT NULL AND witness_capability IS NOT NULL)),
            CHECK(witness_membership IS NULL OR (edge_id IS NULL AND witness_is_owner=0)),
            CHECK(witness_is_owner = 0 OR witness_ordinal IS NULL));
        CREATE UNIQUE INDEX ux_ownership_relation_edge ON ownership_relation(edge_id) WHERE edge_id IS NOT NULL;
        CREATE UNIQUE INDEX ux_ownership_relation_witness ON ownership_relation(
            controller_target, affected_target, witness_target, COALESCE(witness_ordinal,-1), witness_trustee)
            WHERE witness_target IS NOT NULL;
        """);

    internal static Tier0Coverage UnavailableCoverage => new(false, false, true,
        Tier0Limitations.InputIncomplete | Tier0Limitations.MembershipIncomplete | Tier0Limitations.AssetQualificationUnsupported
        | Tier0Limitations.ControlQualificationUnsupported | Tier0Limitations.DependencyQualificationUnsupported);

    internal static void Start(SqliteConnection connection, Guid generation, string evidenceSeal, Guid? derivationGeneration,
        DateTimeOffset evaluationAsOf, string ownerRightsContextHash)
    {
        var header = new Header(1, generation, evidenceSeal, derivationGeneration, evaluationAsOf, ownerRightsContextHash,
            null, UnavailableCoverage, OwnershipScopeSelector.Version, 1, 0, 0, 0);
        var json = JsonSerializer.Serialize(header, ProofSerialization.Options);
        Execute(connection, null, "INSERT INTO ownership_audit VALUES (1,$header,$hash,0)", ("$header", json), ("$hash", Hash(json)));
    }

    internal static void Observe(SqliteConnection connection, SqliteTransaction transaction, Tier0Target target)
    {
        var json = JsonSerializer.Serialize(target, ProofSerialization.Options);
        Execute(connection, transaction, "INSERT INTO ownership_target VALUES ($target,$identity,$hash,'Undetermined','NotAssessed',0,0)",
            ("$target", target.DistinguishedName), ("$identity", json), ("$hash", Hash(json)));
    }

    internal static IReadOnlyList<TargetRow> Targets(SqliteConnection connection, CancellationToken cancellationToken = default)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT target,identity_json,fingerprint,selection,execution,candidate_count,transition_count FROM ownership_target ORDER BY target";
        using var read = command.ExecuteReader();
        var rows = new List<TargetRow>();
        while (read.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            var json = read.GetString(1);
            if (!Hash(json).AsSpan().SequenceEqual((byte[])read.GetValue(2))) throw InvalidProof();
            var identity = JsonSerializer.Deserialize<Tier0Target>(json, ProofSerialization.Options) ?? throw InvalidProof();
            if (identity.DistinguishedName != read.GetString(0)) throw InvalidProof();
            var selection = Enum.Parse<OwnershipScopeState>(read.GetString(3));
            var execution = Enum.Parse<OwnershipAssessmentExecution>(read.GetString(4));
            if (!Enum.IsDefined(selection) || !Enum.IsDefined(execution)) throw InvalidProof();
            rows.Add(new(identity, selection, execution, read.GetInt32(5), read.GetInt32(6)));
        }
        return rows;
    }

    internal static void Plan(SqliteConnection connection, OwnershipScopeSelection? selection,
        Func<Tier0Target, MembershipRouteSummary?> routes, CancellationToken cancellationToken)
    {
        var header = ReadHeader(connection, requireComplete: false) ?? throw InvalidProof();
        var targets = Targets(connection);
        if (selection is not null && (selection.WasCancelled || selection.JudgementGenerationId != header.Generation
            || selection.Input.EvidenceSeal != header.EvidenceSeal || selection.Input.DerivationGenerationId != header.DerivationGeneration))
            throw InvalidProof();
        var seeds = 0;
        var links = 0;
        using var transaction = connection.BeginTransaction();
        foreach (var target in targets)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var decision = selection is not null && target.Identity.IsValid ? selection.For(target.Identity) : null;
            Execute(connection, transaction, """
                UPDATE ownership_target SET selection=$selection,
                    candidate_count=(SELECT COUNT(*) FROM control_edge WHERE target=$target COLLATE NOCASE AND capability='CanSetOwner')
                WHERE target=$target COLLATE NOCASE
                """, ("$target", target.Identity.DistinguishedName), ("$selection", (decision?.State ?? OwnershipScopeState.Undetermined).ToString()));
            if (decision?.State != OwnershipScopeState.Included) continue;
            if (decision.Classification?.State == Tier0State.Established)
            {
                var summary = routes(target.Identity) ?? MembershipRouteSummary.NotDerived;
                var classification = JsonSerializer.Serialize(decision.Classification, ProofSerialization.Options);
                Execute(connection, transaction, "INSERT INTO ownership_seed VALUES ($target,$routes,$hash,$classification)",
                    ("$target", target.Identity.DistinguishedName), ("$routes", JsonSerializer.Serialize(summary, ProofSerialization.Options)),
                    ("$hash", Hash(classification)), ("$classification", classification));
                seeds++;
            }
            foreach (var relation in decision.Reasons)
            {
                // A route must carry exactly one provenance: a stored edge, or the captured fact
                // discovery found it by. Neither would be a claim with nothing behind it.
                if (relation.ControlEdgeId is { } edge)
                {
                    if (relation.JudgementGenerationId != header.Generation) throw InvalidProof();
                    Execute(connection, transaction, """
                        INSERT INTO ownership_relation (edge_id,controller_target,affected_target,witness_is_owner)
                        VALUES ($edge,$controller,$affected,0)
                        """, ("$edge", edge), ("$controller", relation.Controller.DistinguishedName),
                        ("$affected", relation.Affected.DistinguishedName));
                }
                else if (relation.Witness is { } witness)
                {
                    if (!witness.IsValid || witness.TargetDn != relation.Affected.DistinguishedName
                        || relation.Capability is not { } capability) throw InvalidProof();
                    Execute(connection, transaction, """
                        INSERT INTO ownership_relation (edge_id,controller_target,affected_target,
                            witness_target,witness_ordinal,witness_trustee,witness_is_owner,witness_capability,witness_membership)
                        VALUES (NULL,$controller,$affected,$witness,$ordinal,$trustee,$owner,$capability,$membership)
                        """, ("$controller", relation.Controller.DistinguishedName),
                        ("$affected", relation.Affected.DistinguishedName), ("$witness", witness.TargetDn),
                        ("$ordinal", witness.PermissionOrdinal), ("$trustee", witness.TrusteeSid),
                        ("$owner", witness.IsOwner), ("$capability", capability.ToString()),
                        ("$membership", witness.GroupMembership is { } membership ? JsonSerializer.Serialize(membership, ProofSerialization.Options) : null));
                }
                else throw InvalidProof();
                links++;
            }
        }
        header = header with { Input = selection?.Input, Coverage = selection?.Coverage ?? UnavailableCoverage,
            TargetCount = targets.Count, SeedCount = seeds, RelationCount = links };
        WriteHeader(connection, transaction, header);
        transaction.Commit();
    }

    /// <summary>
    /// Recounts owner candidates once the admitted products exist.
    /// </summary>
    /// <remarks>
    /// <see cref="Plan"/> counts <c>CanSetOwner</c> edges while recording the scope, which under
    /// discovery-first ordering happens before those edges are derived. Left alone the stored count
    /// would be zero for every admitted target and the assessment's own consistency check would
    /// refuse the result.
    /// </remarks>
    internal static void RecountCandidates(SqliteConnection connection, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Execute(connection, null, """
            UPDATE ownership_target SET candidate_count=
                (SELECT COUNT(*) FROM control_edge WHERE target=ownership_target.target COLLATE NOCASE AND capability='CanSetOwner')
            """);
    }

    internal static void Assessed(SqliteConnection connection, SqliteTransaction transaction, string target, int transitionCount)
    {
        using var check = connection.CreateCommand();
        check.Transaction = transaction;
        check.CommandText = "SELECT candidate_count,is_complete FROM ownership_target JOIN control_object USING(target) WHERE target=$target COLLATE NOCASE AND selection='Included' AND execution='NotAssessed'";
        check.Parameters.AddWithValue("$target", target);
        bool complete;
        using (var read = check.ExecuteReader())
        {
            if (!read.Read() || read.GetInt64(0) != transitionCount) throw InvalidProof();
            complete = read.GetBoolean(1);
        }
        Execute(connection, transaction, "UPDATE ownership_target SET transition_count=$count,execution=$state WHERE target=$target COLLATE NOCASE",
            ("$target", target), ("$count", transitionCount), ("$state", transitionCount == 0 && complete
                ? nameof(OwnershipAssessmentExecution.Completed) : nameof(OwnershipAssessmentExecution.CompletedWithLimitations)));
    }

    internal static void Complete(SqliteConnection connection, JudgementDescription description)
    {
        ValidateCounts(connection, description, requireComplete: false);
        Execute(connection, null, "UPDATE ownership_audit SET completed=1 WHERE id=1");
    }

    internal static Header? ReadHeader(SqliteConnection connection, bool requireComplete)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT header,fingerprint,completed FROM ownership_audit WHERE id=1";
        using var read = command.ExecuteReader();
        if (!read.Read()) return null;
        var json = read.GetString(0);
        if (!Hash(json).AsSpan().SequenceEqual((byte[])read.GetValue(1)) || requireComplete && !read.GetBoolean(2)) throw InvalidProof();
        var header = JsonSerializer.Deserialize<Header>(json, ProofSerialization.Options) ?? throw InvalidProof();
        if (header.Version != 1 || header.SelectorVersion != OwnershipScopeSelector.Version || header.EvaluatorVersion != 1
            || header.TargetCount < 0 || header.SeedCount < 0 || header.RelationCount < 0 || header.Coverage is null
            || header.Input is not null && (!header.Input.IsSupported || header.Input.EvidenceSeal != header.EvidenceSeal
                || header.Input.DerivationGenerationId != header.DerivationGeneration)) throw InvalidProof();
        return header;
    }

    internal static Header? ValidateCounts(SqliteConnection connection, JudgementDescription description, bool requireComplete = true)
    {
        var header = ReadHeader(connection, requireComplete);
        if (header is null) return null;
        if (header.Generation != description.GenerationId || header.EvidenceSeal != description.EvidenceSeal
            || header.DerivationGeneration != description.DerivationGenerationId || header.EvaluationAsOf != description.EvaluationAsOf)
            throw InvalidProof();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT (SELECT COUNT(*) FROM ownership_target),(SELECT COUNT(*) FROM control_object),
                (SELECT COUNT(*) FROM ownership_seed),(SELECT COUNT(*) FROM ownership_relation),
                (SELECT COUNT(*) FROM ownership_target t WHERE
                    candidate_count<>(SELECT COUNT(*) FROM control_edge e WHERE e.target=t.target COLLATE NOCASE AND capability='CanSetOwner')
                    OR transition_count<>(SELECT COUNT(*) FROM control_edge e WHERE e.target=t.target COLLATE NOCASE AND capability='CanBecomeOwnerAndRewriteDacl')
                    OR (selection='Included' AND (candidate_count<>transition_count OR execution NOT IN ('Completed','CompletedWithLimitations')))
                    OR (selection<>'Included' AND (transition_count<>0 OR execution<>'NotAssessed')))
            """;
        using var read = command.ExecuteReader();
        if (!read.Read() || read.GetInt64(0) != header.TargetCount || read.GetInt64(1) != header.TargetCount
            || read.GetInt64(2) != header.SeedCount || read.GetInt64(3) != header.RelationCount || read.GetInt64(4) != 0) throw InvalidProof();
        return header;
    }

    internal static OwnershipAuditCoverage? ReadCoverage(SqliteConnection connection, JudgementDescription description, string? target)
    {
        var header = ReadHeader(connection, requireComplete: true);
        if (header is null) return null;
        if (header.Generation != description.GenerationId || header.EvidenceSeal != description.EvidenceSeal
            || header.DerivationGeneration != description.DerivationGenerationId || header.EvaluationAsOf != description.EvaluationAsOf)
            throw InvalidProof();
        // The holder view asks about no target, so neither number was ever produced. It used to
        // report two zeros, which a reader cannot tell from a target assessed and found clean.
        if (target is null) return new(header.Generation, null, header.Input is not null, null, null, header.Coverage,
            OwnershipAuditCount.Unmeasured(OwnershipCountLimit.NoTargetRequested),
            OwnershipAuditCount.Unmeasured(OwnershipCountLimit.NoTargetRequested));
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT target,selection,execution,candidate_count,transition_count FROM ownership_target WHERE target=$target COLLATE NOCASE";
        command.Parameters.AddWithValue("$target", target);
        using var read = command.ExecuteReader();
        // No stored row means this target was never counted, which is not the same as counting none.
        var absent = header.Input is null ? OwnershipCountLimit.OwnershipInputsUnavailable : OwnershipCountLimit.TargetNotStored;
        if (!read.Read()) return new(header.Generation, target, header.Input is not null, OwnershipScopeState.Undetermined,
            OwnershipAssessmentExecution.NotAssessed, header.Coverage with { InputsComplete = false,
                Limitations = header.Coverage.Limitations | Tier0Limitations.InputIncomplete },
            OwnershipAuditCount.Unmeasured(absent), OwnershipAuditCount.Unmeasured(absent));
        var selection = Enum.Parse<OwnershipScopeState>(read.GetString(1));
        var execution = Enum.Parse<OwnershipAssessmentExecution>(read.GetString(2));
        if (!Enum.IsDefined(selection) || !Enum.IsDefined(execution) || header.Input is null && selection != OwnershipScopeState.Undetermined
            || selection == OwnershipScopeState.OutsideComputedScope && !header.Coverage.IsComplete) throw InvalidProof();
        // The candidate count is a count of stored holder edges and is real whenever the row exists.
        // The assessed count is not: ValidateCounts forces it to zero for every target the run did
        // not assess, so reporting that zero as a measurement would say "nothing can take this
        // object" about an object nobody examined.
        var assessed = execution is OwnershipAssessmentExecution.Completed or OwnershipAssessmentExecution.CompletedWithLimitations
            ? OwnershipAuditCount.Of(read.GetInt32(4))
            : OwnershipAuditCount.Unmeasured(OwnershipCountLimit.TargetNotAssessed);
        return new(header.Generation, read.GetString(0), header.Input is not null, selection, execution,
            header.Coverage, OwnershipAuditCount.Of(read.GetInt32(3)), assessed);
    }

    internal static IReadOnlyList<SeedRow> Seeds(SqliteConnection connection, CancellationToken cancellationToken = default)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT target,routes,classification_fingerprint,classification FROM ownership_seed ORDER BY target";
        using var read = command.ExecuteReader();
        var seeds = new List<SeedRow>();
        while (read.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            var json = read.GetString(3);
            var fingerprint = (byte[])read.GetValue(2);
            if (!Hash(json).AsSpan().SequenceEqual(fingerprint)) throw InvalidProof();
            var classification = JsonSerializer.Deserialize<Tier0Classification>(json, ProofSerialization.Options) ?? throw InvalidProof();
            if (classification.Target is null || classification.Target.DistinguishedName != read.GetString(0)
                || classification.Input is null || !classification.Input.IsSupported || classification.Coverage is null
                || classification.Supports.IsDefaultOrEmpty || classification.Supports.Any(support => support is null
                    || !Enum.IsDefined(support.Basis) || support.Root is null || support.Evidence.IsDefault)) throw InvalidProof();
            seeds.Add(new(read.GetString(0),
                JsonSerializer.Deserialize<MembershipRouteSummary>(read.GetString(1), ProofSerialization.Options) ?? throw InvalidProof(),
                fingerprint.ToImmutableArray(), classification));
        }
        return seeds;
    }

    internal static IReadOnlyList<RelationRow> Relations(SqliteConnection connection, CancellationToken cancellationToken = default)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT edge_id,controller_target,affected_target,witness_target,witness_ordinal,witness_trustee,
                witness_is_owner,witness_capability,witness_membership
            FROM ownership_relation ORDER BY id
            """;
        using var read = command.ExecuteReader();
        var rows = new List<RelationRow>();
        while (read.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            rows.Add(new(read.IsDBNull(0) ? null : read.GetInt64(0), read.GetString(1), read.GetString(2),
                read.IsDBNull(3) ? null : read.GetString(3), read.IsDBNull(4) ? null : read.GetInt32(4),
                read.IsDBNull(5) ? null : read.GetString(5), read.GetBoolean(6),
                read.IsDBNull(7) ? null : Enum.TryParse<ControlCapability>(read.GetString(7), out var capability)
                    && Enum.IsDefined(capability) ? capability : throw InvalidProof())
                { GroupMembership = read.IsDBNull(8) ? null : JsonSerializer.Deserialize<RequesterMembershipEvidence>(read.GetString(8), ProofSerialization.Options) ?? throw InvalidProof() });
        }
        return rows;
    }

    internal static byte[] Hash(string value) => SHA256.HashData(Encoding.UTF8.GetBytes(value));
    internal static InvalidOperationException InvalidProof() => new(OwnershipAuditCoverage.Text("InvalidProof"));

    private static void WriteHeader(SqliteConnection connection, SqliteTransaction transaction, Header header)
    {
        var json = JsonSerializer.Serialize(header, ProofSerialization.Options);
        Execute(connection, transaction, "UPDATE ownership_audit SET header=$header,fingerprint=$hash WHERE id=1 AND completed=0",
            ("$header", json), ("$hash", Hash(json)));
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
