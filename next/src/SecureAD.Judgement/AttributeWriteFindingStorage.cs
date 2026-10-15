using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal static class AttributeWriteFindingStorage
{
    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.finding_attribute_write (
                finding_id INTEGER PRIMARY KEY,
                generation TEXT NOT NULL, proof TEXT NOT NULL,
                fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.finding_attribute_write_entry (
                finding_id INTEGER NOT NULL REFERENCES finding_attribute_write(finding_id),
                ordinal INTEGER NOT NULL, entry_id INTEGER NOT NULL REFERENCES permission_entry(id),
                fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
                PRIMARY KEY(finding_id,ordinal));
            """;
        command.ExecuteNonQuery();
    }

    internal static void Write(SqliteConnection connection, SqliteTransaction transaction, long findingId,
        Guid generation, AttributeWritePermissionEvidence evidence, SharedPermissionStorage shared)
    {
        Validate(evidence);
        if (evidence.GenerationId != generation) throw Invalid();
        var references = evidence.Entries.Select(entry =>
        {
            var reference = shared.Write(evidence.Target.DistinguishedName, generation, entry);
            return new Reference(entry.Ordinal, reference.Id, reference.Fingerprint);
        }).ToArray();
        // Original entries use the existing per-run shared store; the finding keeps exact source occurrences.
        var json = JsonSerializer.Serialize(evidence with { Entries = [] }, ProofSerialization.Options);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO finding_attribute_write VALUES($id,$generation,$proof,$hash)";
        command.Parameters.AddWithValue("$id", findingId);
        command.Parameters.AddWithValue("$generation", generation.ToString("D"));
        command.Parameters.AddWithValue("$proof", json);
        command.Parameters.AddWithValue("$hash", Fingerprint(generation.ToString("D"), json, references));
        if (command.ExecuteNonQuery() != 1) throw Invalid();
        foreach (var reference in references)
        {
            command.CommandText = "INSERT INTO finding_attribute_write_entry VALUES($id,$ordinal,$entry,$fingerprint)";
            command.Parameters.Clear();
            command.Parameters.AddWithValue("$id", findingId);
            command.Parameters.AddWithValue("$ordinal", reference.Ordinal);
            command.Parameters.AddWithValue("$entry", reference.Id);
            command.Parameters.AddWithValue("$fingerprint", reference.Fingerprint);
            if (command.ExecuteNonQuery() != 1) throw Invalid();
        }
    }

    internal static AttributeWritePermissionEvidence Read(SqliteConnection connection, long findingId, string json,
        byte[] fingerprint, string generation, JudgementDescription description, string? derivationSeal,
        string rule, Guid targetGuid, string dn, string domain, string objectClass, string key, string subjectKind, Severity severity)
        => ReadCore(connection, findingId, json, fingerprint, generation, description.GenerationId, description.EvidenceSeal,
            description.DerivationGenerationId, derivationSeal, rule, targetGuid, dn, domain, objectClass, key, subjectKind, severity);

    private static AttributeWritePermissionEvidence ReadCore(SqliteConnection connection, long findingId, string json,
        byte[] fingerprint, string generation, Guid expectedGeneration, string evidenceSeal, Guid? derivationGeneration, string? derivationSeal,
        string rule, Guid targetGuid, string dn, string domain, string objectClass, string key, string subjectKind, Severity severity)
    {
        if (generation != expectedGeneration.ToString("D")) throw Invalid();
        var metadata = JsonSerializer.Deserialize<AttributeWritePermissionEvidence>(json, ProofSerialization.Options) ?? throw Invalid();
        if (metadata.Entries is not { Count: 0 } || metadata.GenerationId != expectedGeneration
            || metadata.EvidenceSeal != evidenceSeal || metadata.DerivationGenerationId != derivationGeneration
            || metadata.DerivationSeal != derivationSeal) throw Invalid();
        var references = ReadReferences(connection, findingId);
        if (!Fingerprint(generation, json, references).AsSpan().SequenceEqual(fingerprint)) throw Invalid();
        var evidence = metadata with { Entries = references.Select(reference =>
            ReadEntry(connection, dn, expectedGeneration, reference)).ToArray() };
        Validate(evidence);
        if (AttributeWriteRules.RuleFor(evidence.PermissionKind) != rule || evidence.Target.ObjectGuid != targetGuid
            || evidence.Target.DistinguishedName != dn || evidence.Target.DomainFqdn != domain
            || evidence.Target.Values.Where(value => value.Attribute == "objectClass").OrderBy(value => value.Ordinal).Last().Value != objectClass
            || key != AttributeWriteRules.Key(evidence.HolderSid, evidence.HolderScope)
            || subjectKind != nameof(FindingSubjectKind.Account) || severity != Severity.High) throw Invalid();
        return evidence;
    }

    internal static void Validate(AttributeWritePermissionEvidence evidence)
    {
        if (evidence.GenerationId == Guid.Empty || evidence.DerivationGenerationId == Guid.Empty
            || !Seal(evidence.EvidenceSeal) || !Seal(evidence.DerivationSeal)
            || evidence.PrincipalCatalogueVersion != PrincipalClassificationRegistry.Version || evidence.ControlEngineVersion != ControlEdgeStorage.EngineVersion
            || evidence.Target is null || evidence.Domains is not { Count: > 0 } || evidence.AccountControl is null
            || evidence.Entries is null || evidence.Scopes is null || evidence.Limitations is null || evidence.SchemaEntries is null || evidence.PropertySetMembers is null
            || evidence.Target.ObjectClass is not ("user" or "computer" or "inetOrgPerson") || evidence.Target.DomainFqdn is null
            || evidence.Target.ObjectGuid == Guid.Empty || evidence.HolderSid is null || Sid.ToBytes(evidence.HolderSid) is null
            || (Sid.IsBuiltinDomain(evidence.HolderSid) ? evidence.HolderScope != evidence.Target.DomainFqdn : evidence.HolderScope is not null)
            || !Enum.TryParse<ControlExpectednessReason>(evidence.ExpectednessReason, out var expected)
            || expected is not (ControlExpectednessReason.UnexpectedBroadPrincipal or ControlExpectednessReason.UnexpectedNotControlPlane
                or ControlExpectednessReason.UnexpectedOutsideAuthorityScope)
            || expected == ControlExpectednessReason.UnexpectedBroadPrincipal && !BroadPrincipalCatalogue.IsBroad(evidence.HolderSid)
            || evidence.Limitations.Any(string.IsNullOrWhiteSpace) || evidence.Limitations.Distinct(StringComparer.Ordinal).Count() != evidence.Limitations.Count
            || evidence.Entries.Count != evidence.Scopes.Count) throw Invalid();
        GroupMembershipFindingStorage.ValidateIdentity(evidence.Target);
        var domains = GroupMembershipFindingStorage.ValidateDomains(evidence.Domains);
        if (!domains.TryGetValue(evidence.Target.DomainFqdn, out var domain)
            || evidence.Target.NamingContext != domain.NamingContext || !Same(Sid.IssuingDomain(evidence.Target.Sid), domain.Sid)) throw Invalid();
        var operation = AttributeWriteRules.Operation(AttributeWriteRules.RuleFor(evidence.PermissionKind));
        if (evidence.Attribute is not { Kind: SchemaGuidKind.Attribute, Source: SchemaGuidSource.Captured }
            || !Same(evidence.Attribute.LdapName, operation.Attribute) || !Same(evidence.Attribute.Guid, operation.Guid)
            || evidence.SchemaEntries.Count(entry => entry == evidence.Attribute) != 1
            || evidence.SchemaEntries.Any(entry => entry is null || !Enum.IsDefined(entry.Kind) || !Enum.IsDefined(entry.Source))
            || evidence.SchemaEntries.Select(entry => entry.LdapName).Distinct(StringComparer.OrdinalIgnoreCase).Count() != evidence.SchemaEntries.Count)
            throw Invalid();
        var catalogue = new SchemaGuidCatalog(evidence.SchemaEntries, evidence.PropertySetMembers);
        if (evidence.Entries.Any(entry => entry is null || entry.Trustee is null || entry.Ordinal < 0
                || entry.AceType is not ("AccessAllowed" or "AccessAllowedObject" or "AccessDenied" or "AccessDeniedObject")
                || (entry.AccessMask & 0x20) == 0 || EntryReachReader.FromPropagationFlags(entry.PropagationFlags) != EntryReach.ThisObject)
            || evidence.Entries.Select(entry => entry.Ordinal).Distinct().Count() != evidence.Entries.Count
            || !evidence.Entries.Select(entry => entry.Ordinal).SequenceEqual(evidence.Entries.Select(entry => entry.Ordinal).Order()))
            throw Invalid();
        var targetClass = evidence.Target.Values.Where(value => value.Attribute == "objectClass").OrderBy(value => value.Ordinal).Last().Value;
        for (var i = 0; i < evidence.Entries.Count; i++)
        {
            var entry = evidence.Entries[i];
            var scope = evidence.Scopes[i];
            var actual = ControlEdgeDeriver.OperationScope(entry, 0x20, operation.Attribute, targetClass, catalogue);
            if (scope is null || scope.Ordinal != entry.Ordinal || scope.State != nameof(ControlEvaluationState.Established)
                || actual.State != ControlEvaluationState.Established || actual.Source != scope.Basis) throw Invalid();
        }
        if (evidence.DescriptorOutcome == nameof(EffectiveAccessOutcome.GrantsEveryoneEverything))
        {
            if (evidence.Entries.Count != 0 || evidence.HolderSid != "S-1-1-0") throw Invalid();
        }
        else
        {
            if (evidence.DescriptorOutcome != nameof(EffectiveAccessOutcome.Computed) || evidence.Entries.Count == 0) throw Invalid();
            var entries = evidence.Entries.Select(entry => entry with
            {
                HasObjectType = false, ObjectTypeGuid = null,
                Trustee = entry.Trustee.Sid == PermissionTrustee.PrincipalSelfSid
                    ? entry.Trustee with { Sid = evidence.Target.Sid, WellKnownRole = null } : entry.Trustee,
            }).ToArray();
            var permissions = new ObjectPermissions(evidence.Target.DistinguishedName, DescriptorAvailability.Read, null, null,
                DaclState.Present, DaclCompleteness.Complete, true, false, entries, []);
            var access = EffectiveAccessCalculator.Over(permissions, objectTypeGuid: null);
            if ((access.Holders.FirstOrDefault(holder => Same(holder.Trustee.Sid, evidence.HolderSid))?.Mask & 0x20) != 0x20) throw Invalid();
            if (entries.Any(entry => entry.AceType.Contains("Denied", StringComparison.Ordinal) && !Same(entry.Trustee.Sid, evidence.HolderSid)))
                throw Invalid();
        }
        if (ServiceAccountReading.ReadControl(evidence.AccountControl) is null && !evidence.Limitations.Contains("AccountStateUnreadable")) throw Invalid();
    }

    internal static void RequirePublishable(SqliteConnection connection, string? derivationSeal, CancellationToken token)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT f.finding_id FROM finding f LEFT JOIN finding_attribute_write w ON w.finding_id=f.finding_id
            WHERE f.rule_id IN ('SEC-014','SEC-024','SEC-025') AND w.finding_id IS NULL
            UNION ALL
            SELECT w.finding_id FROM finding_attribute_write w LEFT JOIN finding f ON f.finding_id=w.finding_id
            WHERE f.finding_id IS NULL OR f.rule_id NOT IN ('SEC-014','SEC-024','SEC-025') LIMIT 1
            """;
        if (command.ExecuteScalar() is not null) throw Invalid();
        command.CommandText = """
            SELECT w.finding_id,w.proof,w.fingerprint,w.generation,f.rule_id,f.object_guid,f.distinguished_name,f.domain_fqdn,
                f.object_class,f.subject_key,f.subject_kind,f.severity,j.judgement_generation_id,j.evidence_seal,j.derivation_generation_id
            FROM finding_attribute_write w JOIN finding f ON f.finding_id=w.finding_id CROSS JOIN judgement j
            """;
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            token.ThrowIfCancellationRequested();
            ReadCore(connection, reader.GetInt64(0), reader.GetString(1), (byte[])reader.GetValue(2), reader.GetString(3),
                Guid.Parse(reader.GetString(12)), reader.GetString(13), reader.IsDBNull(14) ? null : Guid.Parse(reader.GetString(14)), derivationSeal,
                reader.GetString(4), Guid.Parse(reader.GetString(5)), reader.GetString(6), reader.GetString(7), reader.GetString(8),
                reader.GetString(9), reader.GetString(10), Enum.Parse<Severity>(reader.GetString(11)));
        }
    }

    internal sealed record Reference(int Ordinal, long Id, byte[] Fingerprint);
    private static PermissionEntry ReadEntry(SqliteConnection connection, string target, Guid generation, Reference reference)
    {
        try { return SharedPermissionStorage.ReadReference(connection, target, generation, reference.Id, reference.Ordinal, reference.Fingerprint); }
        catch (InvalidOperationException error)
        {
            throw new InvalidDataException("The saved attribute-write finding has an invalid source permission reference.", error);
        }
    }

    private static Reference[] ReadReferences(SqliteConnection connection, long findingId)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT ordinal,entry_id,fingerprint FROM finding_attribute_write_entry WHERE finding_id=$id ORDER BY ordinal";
        command.Parameters.AddWithValue("$id", findingId);
        using var reader = command.ExecuteReader();
        var result = new List<Reference>();
        while (reader.Read()) result.Add(new(reader.GetInt32(0), reader.GetInt64(1), (byte[])reader.GetValue(2)));
        return result.ToArray();
    }
    internal static byte[] Fingerprint(string generation, string json, IReadOnlyList<Reference> references) =>
        OwnershipAuditStorage.Hash(generation + "\0" + json + "\0" + string.Join("\n", references.Select(reference =>
            reference.Ordinal + ":" + reference.Id + ":" + Convert.ToHexString(reference.Fingerprint))));
    private static bool Seal(string value) => value is { Length: 64 } && value.All(Uri.IsHexDigit);
    private static bool Same(string? first, string? second) => string.Equals(first, second, StringComparison.OrdinalIgnoreCase);
    private static InvalidDataException Invalid() => new("The saved attribute-write finding or its source permission proof is invalid.");
}
