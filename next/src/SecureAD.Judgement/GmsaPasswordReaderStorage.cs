using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal static class GmsaPasswordReaderStorage
{
    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.finding_gmsa_reader (
                finding_id INTEGER PRIMARY KEY, generation TEXT NOT NULL,
                proof TEXT NOT NULL, fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
                context TEXT NOT NULL);
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.finding_gmsa_reader_holder (
                finding_id INTEGER NOT NULL REFERENCES finding_gmsa_reader(finding_id),
                ordinal INTEGER NOT NULL, sid TEXT NOT NULL, scope TEXT NULL, name TEXT NULL,
                direct INTEGER NOT NULL CHECK(direct IN (0,1)), grant_count INTEGER NOT NULL CHECK(grant_count>=0),
                inherited INTEGER NOT NULL CHECK(inherited IN (0,1)), null_dacl INTEGER NOT NULL CHECK(null_dacl IN (0,1)),
                membership_complete INTEGER NOT NULL CHECK(membership_complete IN (0,1)),
                PRIMARY KEY(finding_id,ordinal));
            """;
        command.ExecuteNonQuery();
    }

    internal static void Write(SqliteConnection connection, SqliteTransaction transaction, long findingId,
        Guid generation, string evidenceSeal, Guid? derivationGeneration, string? derivationSeal,
        Finding finding, GmsaPasswordReaderEvidence evidence)
    {
        Validate(evidence);
        ValidateBinding(evidence, generation, evidenceSeal, derivationGeneration, derivationSeal);
        if (generation != evidence.GenerationId || finding.RuleId != "SEC-102" || finding.RuleVersion != 1
            || finding.Severity != Severity.High || finding.ObjectGuid != evidence.Source.ObjectGuid
            || finding.DistinguishedName != evidence.Source.DistinguishedName || finding.DomainFqdn != evidence.Source.DomainFqdn
            || finding.ObjectClass != "msDS-GroupManagedServiceAccount"
            || finding.Subject != new FindingSubject(FindingSubjectKind.Account, BroadPrincipalCanTakeOverObject.SubjectKeyFor(evidence.BroadSid)))
            throw Invalid();
        var context = Context(new(generation, findingId), evidence);
        var json = JsonSerializer.Serialize(evidence, ProofSerialization.Options);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO finding_gmsa_reader VALUES($id,$generation,$proof,$hash,$context)";
        command.Parameters.AddWithValue("$id", findingId);
        command.Parameters.AddWithValue("$generation", generation.ToString("D"));
        command.Parameters.AddWithValue("$proof", json);
        command.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(generation.ToString("D") + "\0" + json));
        command.Parameters.AddWithValue("$context", JsonSerializer.Serialize(context, ProofSerialization.Options));
        if (command.ExecuteNonQuery() != 1) throw Invalid();
        for (var ordinal = 0; ordinal < evidence.Grants.Count; ordinal++)
        {
            var grant = evidence.Grants[ordinal];
            var granting = grant.GrantOrdinals.ToHashSet();
            command.CommandText = "INSERT INTO finding_gmsa_reader_holder VALUES($id,$ordinal,$sid,$scope,$name,$direct,$grants,$inherited,$null,$complete)";
            command.Parameters.Clear();
            command.Parameters.AddWithValue("$id", findingId);
            command.Parameters.AddWithValue("$ordinal", ordinal);
            command.Parameters.AddWithValue("$sid", grant.HolderSid);
            command.Parameters.AddWithValue("$scope", (object?)grant.HolderScope ?? DBNull.Value);
            command.Parameters.AddWithValue("$name", (object?)grant.HolderName ?? DBNull.Value);
            command.Parameters.AddWithValue("$direct", grant.IsDirect ? 1 : 0);
            command.Parameters.AddWithValue("$grants", grant.GrantOrdinals.Count);
            command.Parameters.AddWithValue("$inherited", evidence.Source.Entries.Any(entry => granting.Contains(entry.Ordinal) && entry.IsInherited) ? 1 : 0);
            command.Parameters.AddWithValue("$null", grant.HasNullDacl ? 1 : 0);
            command.Parameters.AddWithValue("$complete", grant.MembershipIsComplete ? 1 : 0);
            if (command.ExecuteNonQuery() != 1) throw Invalid();
        }
    }

    internal static GmsaPasswordReaderEvidence Read(string json, byte[] fingerprint, string generation,
        JudgementDescription description, string? derivationSeal, Guid objectGuid, string dn, string domain,
        string objectClass, string key, string kind, Severity severity) =>
        ReadCore(json, fingerprint, generation, description.GenerationId, description.EvidenceSeal,
            description.DerivationGenerationId, derivationSeal, objectGuid, dn, domain, objectClass, key, kind, severity);

    private static GmsaPasswordReaderEvidence ReadCore(string json, byte[] fingerprint, string generation,
        Guid expectedGeneration, string evidenceSeal, Guid? derivationGeneration, string? derivationSeal,
        Guid objectGuid, string dn, string domain, string objectClass, string key, string kind, Severity severity)
    {
        if (generation != expectedGeneration.ToString("D")
            || !OwnershipAuditStorage.Hash(generation + "\0" + json).AsSpan().SequenceEqual(fingerprint)) throw Invalid();
        var evidence = JsonSerializer.Deserialize<GmsaPasswordReaderEvidence>(json, ProofSerialization.Options) ?? throw Invalid();
        Validate(evidence);
        ValidateBinding(evidence, expectedGeneration, evidenceSeal, derivationGeneration, derivationSeal);
        if (evidence.Source.ObjectGuid != objectGuid || evidence.Source.DistinguishedName != dn || evidence.Source.DomainFqdn != domain
            || objectClass != "msDS-GroupManagedServiceAccount" || kind != nameof(FindingSubjectKind.Account)
            || key != BroadPrincipalCanTakeOverObject.SubjectKeyFor(evidence.BroadSid) || severity != Severity.High) throw Invalid();
        return evidence;
    }

    internal static void Validate(GmsaPasswordReaderEvidence evidence)
    {
        if (evidence.GenerationId == Guid.Empty || evidence.DerivationGenerationId == Guid.Empty
            || !Seal(evidence.EvidenceSeal) || !Seal(evidence.DerivationSeal)
            || evidence.PrincipalCatalogueVersion != PrincipalClassificationRegistry.Version
            || evidence.EngineVersion != GmsaPasswordReaders.EngineVersion || evidence.Source is not { } source
            || source.ObjectGuid == Guid.Empty || string.IsNullOrWhiteSpace(source.DistinguishedName)
            || string.IsNullOrWhiteSpace(source.DomainFqdn) || source.Entries is null || source.Descriptor is not { Length: > 0 }
            || !source.IsComplete || source.AccountSid is not null && Sid.ToBytes(source.AccountSid) is null
            || !BroadPrincipalCatalogue.IsBroad(evidence.BroadSid) || evidence.BroadName != BroadPrincipalCatalogue.NameOf(evidence.BroadSid)
            || evidence.Grants is not { Count: > 0 } || evidence.Limitations is null
            || evidence.Limitations.Any(string.IsNullOrWhiteSpace)
            || evidence.Limitations.Distinct(StringComparer.Ordinal).Count() != evidence.Limitations.Count
            || evidence.Grants.Select(grant => (grant.HolderSid, grant.HolderScope)).Distinct().Count() != evidence.Grants.Count)
            throw Invalid();
        var parsed = SecurityDescriptorParser.Parse(source.Descriptor);
        if (parsed.Errors.Count != 0 || parsed.DaclState != source.DaclState || parsed.DaclCompleteness != source.DaclCompleteness
            || parsed.DaclWasCanonical != source.DaclWasCanonical || parsed.DaclAces.Count != source.Entries.Count
            || !JsonSerializer.Serialize(parsed.DaclAces, ProofSerialization.Options)
                .Equals(JsonSerializer.Serialize(source.Entries, ProofSerialization.Options), StringComparison.Ordinal)) throw Invalid();
        var entries = source.Entries.ToDictionary(entry => entry.Ordinal);
        foreach (var grant in evidence.Grants)
        {
            if (Sid.ToBytes(grant.HolderSid) is null
                || (Sid.IsBuiltinDomain(grant.HolderSid) ? grant.HolderScope != source.DomainFqdn : grant.HolderScope is not null)
                || grant.MembershipPath is not { Count: > 0 } || grant.MembershipPath.Any(step => Sid.ToBytes(step.Sid) is null)
                || grant.MembershipPath[0].Sid != grant.HolderSid || grant.MembershipPath[^1].Sid != evidence.BroadSid
                || grant.GrantOrdinals is null || grant.BlockingOrdinals is null
                || grant.GrantOrdinals.Distinct().Count() != grant.GrantOrdinals.Count
                || grant.BlockingOrdinals.Any(ordinal => !entries.ContainsKey(ordinal))
                || grant.HasNullDacl != (source.DaclState == DaclState.Null)
                || !grant.MembershipIsComplete && evidence.Limitations.Count == 0) throw Invalid();
            if (grant.HasNullDacl)
            {
                if (evidence.BroadSid != "S-1-1-0" || grant.HolderSid != "S-1-1-0" || !grant.IsDirect
                    || grant.GrantOrdinals.Count != 0 || source.Entries.Count != 0) throw Invalid();
                continue;
            }
            if (grant.GrantOrdinals.Count == 0) throw Invalid();
            var answer = GmsaPasswordReaders.ReplayPermission(source, grant.HolderSid, evidence.BroadSid);
            if (!answer.IsComplete || answer.State != ControlEvaluationState.Established
                || !answer.GrantOrdinals.SequenceEqual(grant.GrantOrdinals)
                || !answer.BlockingOrdinals.SequenceEqual(grant.BlockingOrdinals)) throw Invalid();
            foreach (var ordinal in grant.GrantOrdinals)
            {
                if (!entries.TryGetValue(ordinal, out var entry) || (entry.AccessMask & GmsaPasswordReaders.ReadProperty) == 0
                    || entry.AceType is not (AceType.AccessAllowed or AceType.AccessAllowedObject)
                    || (entry.PropagationFlags & 0x08) != 0 || entry.HasObjectType
                    || !string.Equals(entry.TrusteeSid == "S-1-5-10" ? source.AccountSid : entry.TrusteeSid,
                        grant.HolderSid, StringComparison.OrdinalIgnoreCase)) throw Invalid();
            }
        }
    }

    internal static GmsaPasswordReaderContext Context(FindingReference reference, GmsaPasswordReaderEvidence evidence) =>
        new(reference, evidence.Source.ObjectGuid, evidence.Source.DistinguishedName, evidence.Source.DomainFqdn,
            evidence.Source.AccountName, evidence.Source.AccountIsDisabled, evidence.BroadSid, evidence.BroadName,
            evidence.IsComplete, evidence.Grants.Count, evidence.Source.Entries.Count,
            evidence.Source.DaclState == DaclState.Null, evidence.Limitations);

    internal static void RequirePublishable(SqliteConnection connection, Guid generation, string evidenceSeal,
        Guid? derivationGeneration, string? derivationSeal, CancellationToken token)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT EXISTS(SELECT 1 FROM finding f WHERE f.rule_id='SEC-102'
                AND NOT EXISTS(SELECT 1 FROM finding_gmsa_reader g WHERE g.finding_id=f.finding_id))
                OR EXISTS(SELECT 1 FROM finding_gmsa_reader g LEFT JOIN finding f ON f.finding_id=g.finding_id
                    WHERE f.finding_id IS NULL OR f.rule_id!='SEC-102')
                OR EXISTS(SELECT 1 FROM finding_gmsa_reader g
                    WHERE json_extract(g.context,'$.HolderCount') IS NULL
                        OR (SELECT COUNT(*) FROM finding_gmsa_reader_holder h WHERE h.finding_id=g.finding_id)
                            != json_extract(g.context,'$.HolderCount')
                        OR (SELECT MIN(ordinal) FROM finding_gmsa_reader_holder h WHERE h.finding_id=g.finding_id)!=0
                        OR (SELECT MAX(ordinal) FROM finding_gmsa_reader_holder h WHERE h.finding_id=g.finding_id)
                            !=json_extract(g.context,'$.HolderCount')-1)
            """;
        if ((long)command.ExecuteScalar()! != 0) throw Invalid();
        command.CommandText = """
            SELECT g.finding_id,g.proof,g.fingerprint,g.generation,g.context,f.object_guid,f.distinguished_name,
                   f.domain_fqdn,f.object_class,f.subject_key,f.subject_kind,f.severity,r.rule_version
            FROM finding_gmsa_reader g JOIN finding f ON f.finding_id=g.finding_id
                JOIN rule_execution r ON r.rule_id=f.rule_id WHERE f.rule_id='SEC-102'
            """;
        using var row = command.ExecuteReader();
        while (row.Read())
        {
            token.ThrowIfCancellationRequested();
            if (row.GetInt32(12) != 1) throw Invalid();
            var proof = ReadCore(row.GetString(1), (byte[])row.GetValue(2), row.GetString(3), generation, evidenceSeal,
                derivationGeneration, derivationSeal, Guid.Parse(row.GetString(5)), row.GetString(6), row.GetString(7),
                row.GetString(8), row.GetString(9), row.GetString(10), Enum.Parse<Severity>(row.GetString(11)));
            var expected = JsonSerializer.Serialize(Context(new(generation, row.GetInt64(0)), proof), ProofSerialization.Options);
            if (row.GetString(4) != expected) throw Invalid();
        }
    }

    private static void ValidateBinding(GmsaPasswordReaderEvidence evidence, Guid generation, string seal,
        Guid? derivationGeneration, string? derivationSeal)
    {
        if (evidence.GenerationId != generation || evidence.EvidenceSeal != seal
            || evidence.DerivationGenerationId != derivationGeneration || evidence.DerivationSeal != derivationSeal) throw Invalid();
    }

    private static bool Seal(string value) => value is { Length: 64 } && value.All(Uri.IsHexDigit);
    internal static InvalidDataException Invalid() => new(SavedGmsaPasswordReaders.InvalidDetails);
}
