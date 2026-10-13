using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal static class ReplicationPermissionFindingStorage
{
    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE finding_replication_permission (
                finding_id INTEGER PRIMARY KEY REFERENCES finding(finding_id),
                edge_id INTEGER NOT NULL UNIQUE REFERENCES control_edge(id),
                generation TEXT NOT NULL, proof TEXT NOT NULL,
                fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
                source_hash BLOB NOT NULL CHECK(length(source_hash)=32));
            """;
        command.ExecuteNonQuery();
    }

    internal static void Write(SqliteConnection connection, SqliteTransaction transaction, long findingId,
        Guid generation, ReplicationPermissionEvidence evidence)
    {
        Validate(evidence);
        if (evidence.GenerationId != generation) throw Invalid();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT id FROM control_edge WHERE target=$target COLLATE BINARY AND holder_sid=$holder COLLATE BINARY
                AND COALESCE(holder_scope,'')=$scope COLLATE BINARY AND capability='CanReplicateSecretDomainData'
                AND generation=$generation
            """;
        command.Parameters.AddWithValue("$target", evidence.NamingContextRoot);
        command.Parameters.AddWithValue("$holder", evidence.HolderSid);
        command.Parameters.AddWithValue("$scope", evidence.HolderScope ?? "");
        command.Parameters.AddWithValue("$generation", generation.ToString("D"));
        var ids = new List<long>();
        using (var reader = command.ExecuteReader()) while (reader.Read()) ids.Add(reader.GetInt64(0));
        if (ids.Count != 1) throw Invalid();
        var description = Description(evidence);
        var edge = Source(connection, description, evidence.NamingContextRoot, ids[0]);
        RequireSource(evidence, edge);
        ReplicationControlDeriver.ValidateStored(edge);
        if (!SharedPermissionStorage.DescriptorFingerprint(generation, evidence.Entries).AsSpan()
            .SequenceEqual(SharedPermissionStorage.DescriptorFingerprint(generation, edge.Evidence))) throw Invalid();

        // The finding references the existing proof; a separate source digest cannot be rewritten by rehashing its body.
        var source = SourceHash(edge, evidence);
        var json = JsonSerializer.Serialize(evidence with { Entries = [] }, ProofSerialization.Options);
        command.CommandText = "INSERT INTO finding_replication_permission VALUES($id,$edge,$generation,$proof,$hash,$source)";
        command.Parameters.Clear();
        command.Parameters.AddWithValue("$id", findingId);
        command.Parameters.AddWithValue("$edge", ids[0]);
        command.Parameters.AddWithValue("$generation", generation.ToString("D"));
        command.Parameters.AddWithValue("$proof", json);
        command.Parameters.AddWithValue("$hash", Fingerprint(generation.ToString("D"), ids[0], json, source));
        command.Parameters.AddWithValue("$source", source);
        if (command.ExecuteNonQuery() != 1) throw Invalid();
    }

    internal static ReplicationPermissionEvidence Read(SqliteConnection connection, long edgeId, string json,
        byte[] fingerprint, byte[] sourceHash, string generation, JudgementDescription description, string? derivationSeal,
        string rule, Guid rootGuid, string dn, string domain, string objectClass, string key, string subjectKind, Severity severity)
    {
        if (generation != description.GenerationId.ToString("D")
            || !Fingerprint(generation, edgeId, json, sourceHash).AsSpan().SequenceEqual(fingerprint)) throw Invalid();
        var metadata = JsonSerializer.Deserialize<ReplicationPermissionEvidence>(json, ProofSerialization.Options) ?? throw Invalid();
        if (metadata.Entries is not { Count: 0 } || metadata.GenerationId != description.GenerationId
            || metadata.EvidenceSeal != description.EvidenceSeal || metadata.DerivationGenerationId != description.DerivationGenerationId
            || metadata.DerivationSeal != derivationSeal) throw Invalid();
        var edge = Source(connection, description, dn, edgeId);
        var evidence = metadata with { Entries = edge.Evidence };
        Validate(evidence);
        if (!SourceHash(edge, evidence).AsSpan().SequenceEqual(sourceHash)) throw Invalid();
        RequireSource(evidence, edge);
        if (rule != "SEC-002" || evidence.RootGuid != rootGuid || evidence.NamingContextRoot != dn || evidence.DomainFqdn != domain
            || evidence.RootClass != objectClass || key != UnexpectedDomainSecretReplication.Key(evidence.HolderSid, evidence.HolderScope)
            || subjectKind != nameof(FindingSubjectKind.DirectoryObject) || severity != Severity.Critical) throw Invalid();
        return evidence;
    }

    internal static void RequirePublishable(SqliteConnection connection, string? derivationSeal, CancellationToken token)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT f.finding_id FROM finding f LEFT JOIN finding_replication_permission p ON p.finding_id=f.finding_id
            WHERE f.rule_id='SEC-002' AND p.finding_id IS NULL
            UNION ALL
            SELECT p.finding_id FROM finding_replication_permission p LEFT JOIN finding f ON f.finding_id=p.finding_id
            WHERE f.finding_id IS NULL OR f.rule_id<>'SEC-002' LIMIT 1
            """;
        if (command.ExecuteScalar() is not null) throw Invalid();
        command.CommandText = """
            SELECT p.edge_id,p.proof,p.fingerprint,p.source_hash,p.generation,f.rule_id,f.object_guid,f.distinguished_name,
                f.domain_fqdn,f.object_class,f.subject_key,f.subject_kind,f.severity,
                j.judgement_generation_id,j.evidence_seal,j.derivation_generation_id
            FROM finding_replication_permission p JOIN finding f ON f.finding_id=p.finding_id CROSS JOIN judgement j
            """;
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            token.ThrowIfCancellationRequested();
            var description = new JudgementDescription(reader.GetString(14), Guid.Parse(reader.GetString(13)),
                reader.IsDBNull(15) ? null : Guid.Parse(reader.GetString(15)), JudgementRunState.Running, default, default, default);
            var proof = Read(connection, reader.GetInt64(0), reader.GetString(1), (byte[])reader.GetValue(2),
                (byte[])reader.GetValue(3), reader.GetString(4), description, derivationSeal, reader.GetString(5),
                Guid.Parse(reader.GetString(6)), reader.GetString(7), reader.GetString(8), reader.GetString(9),
                reader.GetString(10), reader.GetString(11), Enum.Parse<Severity>(reader.GetString(12)));
            ReplicationControlDeriver.ValidateStored(Source(connection, description, proof.NamingContextRoot, reader.GetInt64(0)));
        }
    }

    internal static void Validate(ReplicationPermissionEvidence evidence)
    {
        var binding = new Tier0InputBinding(evidence.EvidenceSeal, evidence.DerivationGenerationId, evidence.DerivationSeal,
            evidence.PrincipalCatalogueVersion, evidence.TierPolicyVersion, evidence.TierContractVersion, null, null);
        if (!binding.IsSupported || evidence.GenerationId == Guid.Empty || evidence.ControlEngineVersion != ControlEdgeStorage.EngineVersion
            || evidence.RootGuid == Guid.Empty || string.IsNullOrWhiteSpace(evidence.NamingContextRoot) || string.IsNullOrWhiteSpace(evidence.DomainFqdn)
            || !string.Equals(DnHelper.DnToFqdn(evidence.NamingContextRoot), evidence.DomainFqdn, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(evidence.RootClass, "domainDNS", StringComparison.OrdinalIgnoreCase)
            || evidence.Tier0Basis != nameof(Tier0Basis.PartitionRoot) || Sid.ToBytes(evidence.HolderSid) is null
            || (Sid.IsBuiltinDomain(evidence.HolderSid) ? evidence.HolderScope != evidence.DomainFqdn : evidence.HolderScope is not null)
            || evidence.Entries is null || evidence.Checks is null || evidence.Limitations is null
            || evidence.Limitations.Any(string.IsNullOrWhiteSpace) || evidence.Limitations.Distinct(StringComparer.Ordinal).Count() != evidence.Limitations.Count
            || !evidence.Limitations.SequenceEqual(evidence.Limitations.Order(StringComparer.Ordinal))
            || evidence.Entries.Any(entry => entry is null || entry.Trustee is null || entry.ApplicationData is null || entry.Ordinal < 0)
            || evidence.Entries.Select(entry => entry.Ordinal).Distinct().Count() != evidence.Entries.Count
            || !evidence.Entries.Select(entry => entry.Ordinal).SequenceEqual(evidence.Entries.Select(entry => entry.Ordinal).Order())
            || evidence.Checks.Any(check => check is null || string.IsNullOrWhiteSpace(check.EvidenceSource)
                || !Enum.TryParse<ControlEvaluationState>(check.State, out var state) || !Enum.IsDefined(state))
            || !Enum.TryParse<ControlExpectednessReason>(evidence.ExpectednessReason, out var expected)
            || expected is not (ControlExpectednessReason.UnexpectedBroadPrincipal or ControlExpectednessReason.UnexpectedNotControlPlane
                or ControlExpectednessReason.UnexpectedOutsideAuthorityScope)
            || expected == ControlExpectednessReason.UnexpectedBroadPrincipal && !BroadPrincipalCatalogue.IsBroad(evidence.HolderSid))
            throw Invalid();
    }

    private static void RequireSource(ReplicationPermissionEvidence proof, ControlEdge edge)
    {
        if (edge.Capability != ControlCapability.CanReplicateSecretDomainData || !edge.IsComplete || !edge.IsCounted
            || edge.Expectedness != ControlExpectedness.Unexpected || edge.ExpectednessReason.ToString() != proof.ExpectednessReason
            || edge.GenerationId != proof.GenerationId || edge.DerivationGenerationId != proof.DerivationGenerationId
            || edge.PrincipalCatalogueVersion != proof.PrincipalCatalogueVersion || edge.TargetGuid != proof.RootGuid
            || edge.Target != proof.NamingContextRoot || edge.TargetClass != proof.RootClass || edge.HolderSid != proof.HolderSid
            || edge.HolderScope != proof.HolderScope || edge.HolderName != proof.HolderName || edge.DescriptorOutcome != proof.DescriptorOutcome
            || edge.ReplicationNamingContextKind != nameof(NamingContextKind.Domain)
            || !proof.Checks.SequenceEqual(edge.Preconditions.Select(check => new ReplicationPermissionCheck(check.Name, check.State.ToString(), check.EvidenceSource)))
            || edge.Preconditions.Count(check => check.Name == "NamingContextRoot" && check.State == ControlEvaluationState.Established
                && check.EvidenceSource == edge.Target) != 1
            || edge.Preconditions.Count(check => check.Name == "NamingContextKind" && check.State == ControlEvaluationState.Established) != 1
            || edge.Preconditions.Count(check => check.Name == ReplicationControlDeriver.Changes && check.State == ControlEvaluationState.Established) != 1
            || edge.Preconditions.Count(check => check.Name == ReplicationControlDeriver.All && check.State == ControlEvaluationState.Established) != 1)
            throw Invalid();
    }

    private static ControlEdge Source(SqliteConnection connection, JudgementDescription description, string root, long id)
    {
        var edge = ControlEdgeStorage.ReadExact(connection, description, root, id);
        return edge with { Evidence = ControlEdgeStorage.ReadExactAces(connection, edge) };
    }

    internal static byte[] SourceHash(ControlEdge edge, ReplicationPermissionEvidence evidence) => OwnershipAuditStorage.Hash(JsonSerializer.Serialize(new
    {
        edge.Id, edge.TargetGuid, edge.Target, edge.TargetClass, edge.HolderSid, edge.HolderScope, edge.HolderName,
        edge.Capability, edge.EvaluationState, edge.Uncertainty, edge.Expectedness, edge.ExpectednessReason,
        edge.PrincipalCatalogueVersion, edge.GenerationId, edge.DerivationGenerationId, edge.IsCounted,
        edge.DescriptorOutcome, edge.Preconditions, edge.MembershipRoutes,
        Entries = Convert.ToHexString(SharedPermissionStorage.DescriptorFingerprint(edge.GenerationId, edge.Evidence)),
        Context = evidence with { Entries = [] },
    }, ProofSerialization.Options));

    internal static byte[] Fingerprint(string generation, long edge, string json, byte[] source) =>
        OwnershipAuditStorage.Hash(generation + "\0" + edge + "\0" + json + "\0" + Convert.ToHexString(source));
    private static JudgementDescription Description(ReplicationPermissionEvidence evidence) => new(evidence.EvidenceSeal,
        evidence.GenerationId, evidence.DerivationGenerationId, JudgementRunState.Running, default, default, default);
    private static InvalidDataException Invalid() => new("The saved replication finding or its original domain-root permission proof is invalid.");
}
