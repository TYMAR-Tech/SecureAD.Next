using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal static class GpoDirectoryPermissionStorage
{
    internal sealed record Reference(int Ordinal, long Id, byte[] Fingerprint, bool Selected);

    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.finding_gpo_directory (
                finding_id INTEGER PRIMARY KEY, generation TEXT NOT NULL, proof TEXT NOT NULL,
                fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32), context TEXT NOT NULL);
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.finding_gpo_directory_entry (
                finding_id INTEGER NOT NULL REFERENCES finding_gpo_directory(finding_id),
                ordinal INTEGER NOT NULL, entry_id INTEGER NOT NULL REFERENCES permission_entry(id),
                fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
                selected INTEGER NOT NULL CHECK(selected IN (0,1)), display TEXT NOT NULL,
                PRIMARY KEY(finding_id,ordinal));
            """;
        command.ExecuteNonQuery();
    }

    internal static void Write(SqliteConnection connection, SqliteTransaction transaction, long findingId, Guid generation,
        string evidenceSeal, Guid? derivationGeneration, string? derivationSeal, Finding finding,
        GpoDirectoryPermissionEvidence evidence, SharedPermissionStorage shared)
    {
        Validate(evidence);
        RequireBinding(evidence, generation, evidenceSeal, derivationGeneration, derivationSeal);
        RequireFinding(evidence, finding.RuleId, finding.ObjectGuid, finding.DistinguishedName, finding.DomainFqdn,
            finding.ObjectClass, finding.Subject.Key, finding.Subject.Kind.ToString(), finding.Severity);
        var selected = evidence.Rights.SelectMany(right => right.GrantOrdinals.Concat(right.BlockingOrdinals)).ToHashSet();
        var references = evidence.Permissions.Entries.Select(entry =>
        {
            var saved = shared.Write(evidence.Target.DistinguishedName, generation, entry);
            return new Reference(entry.Ordinal, saved.Id, saved.Fingerprint, selected.Contains(entry.Ordinal));
        }).ToArray();
        var json = JsonSerializer.Serialize(evidence with { Permissions = evidence.Permissions with { Entries = [] } }, ProofSerialization.Options);
        var context = Context(new(generation, findingId), evidence, references.Count(reference => reference.Selected));
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO finding_gpo_directory VALUES($id,$generation,$proof,$hash,$context)";
        command.Parameters.AddWithValue("$id", findingId);
        command.Parameters.AddWithValue("$generation", generation.ToString("D"));
        command.Parameters.AddWithValue("$proof", json);
        command.Parameters.AddWithValue("$hash", Fingerprint(generation.ToString("D"), json, references));
        command.Parameters.AddWithValue("$context", JsonSerializer.Serialize(context, ProofSerialization.Options));
        if (command.ExecuteNonQuery() != 1) throw GpoDirectoryPermissionRules.Invalid();
        foreach (var (entry, reference) in evidence.Permissions.Entries.Zip(references))
        {
            command.CommandText = "INSERT INTO finding_gpo_directory_entry VALUES($id,$ordinal,$entry,$fingerprint,$selected,$display)";
            command.Parameters.Clear();
            command.Parameters.AddWithValue("$id", findingId);
            command.Parameters.AddWithValue("$ordinal", reference.Ordinal);
            command.Parameters.AddWithValue("$entry", reference.Id);
            command.Parameters.AddWithValue("$fingerprint", reference.Fingerprint);
            command.Parameters.AddWithValue("$selected", reference.Selected ? 1 : 0);
            command.Parameters.AddWithValue("$display", JsonSerializer.Serialize(Display(entry, evidence), ProofSerialization.Options));
            if (command.ExecuteNonQuery() != 1) throw GpoDirectoryPermissionRules.Invalid();
        }
    }

    internal static GpoDirectoryPermissionEvidence Read(SqliteConnection connection, long findingId, string json,
        byte[] fingerprint, string generation, JudgementDescription description, string? derivationSeal,
        string rule, Guid guid, string dn, string domain, string objectClass, string key, string kind, Severity severity) =>
        ReadCore(connection, findingId, json, fingerprint, generation, description.GenerationId, description.EvidenceSeal,
            description.DerivationGenerationId, derivationSeal, rule, guid, dn, domain, objectClass, key, kind, severity);

    private static GpoDirectoryPermissionEvidence ReadCore(SqliteConnection connection, long findingId, string json,
        byte[] fingerprint, string generation, Guid expectedGeneration, string evidenceSeal, Guid? derivationGeneration,
        string? derivationSeal, string rule, Guid guid, string dn, string domain, string objectClass, string key, string kind, Severity severity)
    {
        if (generation != expectedGeneration.ToString("D")) throw GpoDirectoryPermissionRules.Invalid();
        var metadata = JsonSerializer.Deserialize<GpoDirectoryPermissionEvidence>(json, ProofSerialization.Options) ?? throw GpoDirectoryPermissionRules.Invalid();
        RequireBinding(metadata, expectedGeneration, evidenceSeal, derivationGeneration, derivationSeal);
        if (metadata.Permissions?.Entries is not { Count: 0 }) throw GpoDirectoryPermissionRules.Invalid();
        var references = References(connection, findingId);
        if (!Fingerprint(generation, json, references).AsSpan().SequenceEqual(fingerprint)) throw GpoDirectoryPermissionRules.Invalid();
        var entries = references.Select(reference => SharedPermissionStorage.ReadReference(connection, dn, expectedGeneration,
            reference.Id, reference.Ordinal, reference.Fingerprint)).ToArray();
        var evidence = metadata with { Permissions = metadata.Permissions with { Entries = entries } };
        Validate(evidence);
        RequireFinding(evidence, rule, guid, dn, domain, objectClass, key, kind, severity);
        var selected = evidence.Rights.SelectMany(right => right.GrantOrdinals.Concat(right.BlockingOrdinals)).ToHashSet();
        if (references.Any(reference => reference.Selected != selected.Contains(reference.Ordinal))) throw GpoDirectoryPermissionRules.Invalid();
        return evidence;
    }

    internal static void Validate(GpoDirectoryPermissionEvidence evidence)
    {
        if (evidence.GenerationId == Guid.Empty || evidence.DerivationGenerationId == Guid.Empty
            || !Seal(evidence.EvidenceSeal) || !Seal(evidence.DerivationSeal)
            || evidence.PrincipalCatalogueVersion != PrincipalClassificationRegistry.Version
            || evidence.EngineVersion != GpoDirectoryPermissionRules.EngineVersion
            || !SavedGpoDirectoryPermission.SupportsRule(evidence.RuleId) || evidence.Target is not { IsValid: true }
            || evidence.ObjectClasses is not { Count: > 0 } || evidence.ObjectClasses[^1] != evidence.Target.ObjectClass
            || evidence.Holder is null || Sid.ToBytes(evidence.Holder.Sid) is null
            || (Sid.IsBuiltinDomain(evidence.Holder.Sid) ? evidence.HolderScope != evidence.Target.DomainFqdn : evidence.HolderScope is not null)
            || evidence.Permissions is null || evidence.Permissions.DistinguishedName != evidence.Target.DistinguishedName
            || evidence.Permissions.Entries is null || evidence.SchemaEntries is null || evidence.PropertySets is null
            || evidence.DomainSids is null || evidence.MembershipRoutes is null || evidence.Rights is null || evidence.Limitations is null
            || evidence.Limitations.Any(string.IsNullOrWhiteSpace)) throw GpoDirectoryPermissionRules.Invalid();
        if (evidence.RuleId == "SEC-080" ? evidence.Target.ObjectClass != "groupPolicyContainer"
            : evidence.Target.ObjectClass is not ("domain" or "domainDNS" or "organizationalUnit" or "site")
                || evidence.Target.ObjectClass is "domain" or "domainDNS" && !evidence.NamingContextRoot)
            throw GpoDirectoryPermissionRules.Invalid();
        if (!evidence.Rights.Select(right => right.Operation).SequenceEqual(GpoDirectoryPermissionRules.For(evidence.RuleId).Select(value => value.Operation))
            || !evidence.Rights.Any(right => right.State == GpoDirectoryPermissionState.Established)
            || evidence.Permissions.Entries.Select(entry => entry.Ordinal).Distinct().Count() != evidence.Permissions.Entries.Count
            || !evidence.Permissions.Entries.Select(entry => entry.Ordinal).SequenceEqual(evidence.Permissions.Entries.Select(entry => entry.Ordinal).Order()))
            throw GpoDirectoryPermissionRules.Invalid();
        var catalogue = SchemaGuidCatalog.CapturedOver(evidence.SchemaEntries, SchemaGuidCatalog.Embedded, evidence.PropertySets);
        var target = Subject(evidence);
        string? DomainSid(string domain) => evidence.DomainSids.GetValueOrDefault(domain);
        var resource = !Sid.IsBuiltinDomain(evidence.Holder.Sid) || ControlEdgeDeriver.IsDomainTarget(target, evidence.ForestFqdn)
            && !string.IsNullOrWhiteSpace(DomainSid(evidence.Target.DomainFqdn));
        var source = new FullControlSource(evidence.Target.DistinguishedName, evidence.Target.ObjectGuid, null,
            evidence.Target.DomainFqdn, evidence.ObjectClasses, evidence.Holder, evidence.HolderScope, resource,
            evidence.NamingContextRoot, evidence.Permissions.Availability, evidence.Permissions.DaclState,
            evidence.Permissions.DaclCompleteness, evidence.Permissions.DaclWasCanonical, evidence.Permissions.Entries);
        var rights = GpoDirectoryPermissionRules.For(evidence.RuleId).Select(operation => GpoDirectoryPermissionRules.Evaluate(source, operation, catalogue)).ToArray();
        if (JsonSerializer.Serialize(rights, ProofSerialization.Options) != JsonSerializer.Serialize(evidence.Rights, ProofSerialization.Options))
            throw GpoDirectoryPermissionRules.Invalid();
        var expected = ControlEdgeDeriver.Expected(evidence.Holder, target, evidence.ForestFqdn, evidence.MembershipRoutes,
            evidence.Permissions.DaclCompleteness == DaclCompleteness.Complete,
            rights.Any(right => right.State == GpoDirectoryPermissionState.Established) && evidence.Permissions.DaclState != DaclState.Null, DomainSid);
        if (expected.State != ControlExpectedness.Unexpected || evidence.ExpectednessReason != expected.Reason.ToString())
            throw GpoDirectoryPermissionRules.Invalid();
    }

    internal static GpoDirectoryPermissionContext Context(FindingReference reference, GpoDirectoryPermissionEvidence evidence, int count) =>
        new(reference, evidence.RuleId, evidence.Target, evidence.Holder.Sid, evidence.HolderScope, evidence.Holder.Name,
            evidence.ExpectednessReason, evidence.IsComplete, evidence.Permissions.DaclState == DaclState.Null, count,
            evidence.Rights.Select(right => new SavedGpoDirectoryOperation(right.Operation, right.State)).ToArray(), evidence.Limitations);

    private static SavedGpoDirectoryEntry Display(PermissionEntry entry, GpoDirectoryPermissionEvidence evidence)
    {
        var operations = evidence.Rights.Where(right => right.GrantOrdinals.Contains(entry.Ordinal) || right.BlockingOrdinals.Contains(entry.Ordinal)).ToArray();
        var definition = entry.ObjectTypeGuid is { } guid ? evidence.SchemaEntries.FirstOrDefault(value =>
            string.Equals(value.Guid, guid, StringComparison.OrdinalIgnoreCase) && value.Kind is SchemaGuidKind.Attribute or SchemaGuidKind.PropertySet or SchemaGuidKind.ObjectClass) : null;
        var scope = !entry.HasObjectType ? (entry.AccessMask & 0x20) != 0 ? "All properties" : "Standard directory-object permission"
            : definition is null ? "Object-specific scope (captured meaning unavailable)"
            : definition.Kind switch { SchemaGuidKind.Attribute => "Property: " + definition.LdapName,
                SchemaGuidKind.PropertySet => "Property set: " + definition.LdapName, _ => "Object class: " + definition.LdapName };
        return new(entry.Ordinal, FullControlEvaluator.IsDeny(entry), entry.IsInherited, scope,
            string.Join("; ", operations.Select(right => GpoDirectoryPermissionRules.Operation(right.Operation).Label)),
            operations.All(right => right.Scopes.FirstOrDefault(value => value.Ordinal == entry.Ordinal)?.State != GpoDirectoryPermissionState.Unresolved));
    }

    private static ObjectAttributes Subject(GpoDirectoryPermissionEvidence evidence) =>
        new(evidence.Target.DistinguishedName, evidence.Target.ObjectGuid, evidence.Target.CapturedUtc, EvidenceCompleteness.Complete,
            [new("objectClass", AttributeCardinality.MultiValued,
                evidence.ObjectClasses.Select((value, ordinal) => new AttributeValue(ordinal, value, null)).ToArray())], evidence.Target.DomainFqdn);

    private static Reference[] References(SqliteConnection connection, long findingId)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT ordinal,entry_id,fingerprint,selected FROM finding_gpo_directory_entry WHERE finding_id=$id ORDER BY ordinal";
        command.Parameters.AddWithValue("$id", findingId);
        using var row = command.ExecuteReader();
        var references = new List<Reference>();
        while (row.Read()) references.Add(new(row.GetInt32(0), row.GetInt64(1), (byte[])row.GetValue(2),
            row.GetInt64(3) switch { 0 => false, 1 => true, _ => throw GpoDirectoryPermissionRules.Invalid() }));
        return references.ToArray();
    }
    private static byte[] Fingerprint(string generation, string json, IReadOnlyList<Reference> references) =>
        OwnershipAuditStorage.Hash(generation + "\0" + json + "\0" + string.Join("\n", references.Select(reference =>
            reference.Ordinal + ":" + reference.Id + ":" + reference.Selected + ":" + Convert.ToHexString(reference.Fingerprint))));
    private static bool Seal(string value) => value is { Length: 64 } && value.All(Uri.IsHexDigit);
    private static void RequireBinding(GpoDirectoryPermissionEvidence evidence, Guid generation, string seal, Guid? derived, string? derivedSeal)
    {
        if (evidence.GenerationId != generation || evidence.EvidenceSeal != seal || evidence.DerivationGenerationId != derived
            || evidence.DerivationSeal != derivedSeal) throw GpoDirectoryPermissionRules.Invalid();
    }
    private static void RequireFinding(GpoDirectoryPermissionEvidence evidence, string rule, Guid guid, string dn, string domain,
        string objectClass, string key, string kind, Severity severity)
    {
        if (evidence.RuleId != rule || evidence.Target.ObjectGuid != guid || evidence.Target.DistinguishedName != dn
            || evidence.Target.DomainFqdn != domain || evidence.Target.ObjectClass != objectClass
            || key != GpoDirectoryPermissionRules.Key(evidence.Holder.Sid, evidence.HolderScope)
            || kind != nameof(FindingSubjectKind.Account) || severity != Severity.High) throw GpoDirectoryPermissionRules.Invalid();
    }

    internal static void RequirePublishable(SqliteConnection connection, Guid generation, string seal,
        Guid? derivation, string? derivedSeal, CancellationToken token)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT f.finding_id FROM finding f LEFT JOIN finding_gpo_directory g ON g.finding_id=f.finding_id
            WHERE f.rule_id IN ('SEC-080','SEC-081') AND g.finding_id IS NULL
            UNION ALL SELECT g.finding_id FROM finding_gpo_directory g LEFT JOIN finding f ON f.finding_id=g.finding_id
            WHERE f.finding_id IS NULL OR f.rule_id NOT IN ('SEC-080','SEC-081') LIMIT 1
            """;
        if (command.ExecuteScalar() is not null) throw GpoDirectoryPermissionRules.Invalid();
        command.CommandText = """
            SELECT g.finding_id,g.proof,g.fingerprint,g.generation,g.context,f.rule_id,f.object_guid,f.distinguished_name,
                f.domain_fqdn,f.object_class,f.subject_key,f.subject_kind,f.severity,r.rule_version
            FROM finding_gpo_directory g JOIN finding f ON f.finding_id=g.finding_id JOIN rule_execution r ON r.rule_id=f.rule_id
            """;
        using var row = command.ExecuteReader();
        while (row.Read())
        {
            token.ThrowIfCancellationRequested();
            if (row.GetInt32(13) != 1) throw GpoDirectoryPermissionRules.Invalid();
            var evidence = ReadCore(connection, row.GetInt64(0), row.GetString(1), (byte[])row.GetValue(2), row.GetString(3),
                generation, seal, derivation, derivedSeal, row.GetString(5), Guid.Parse(row.GetString(6)), row.GetString(7),
                row.GetString(8), row.GetString(9), row.GetString(10), row.GetString(11), Enum.Parse<Severity>(row.GetString(12)));
            var selected = References(connection, row.GetInt64(0)).Count(reference => reference.Selected);
            if (row.GetString(4) != JsonSerializer.Serialize(Context(new(generation, row.GetInt64(0)), evidence, selected), ProofSerialization.Options))
                throw GpoDirectoryPermissionRules.Invalid();
            using var displays = connection.CreateCommand();
            displays.CommandText = "SELECT ordinal,display FROM finding_gpo_directory_entry WHERE finding_id=$id ORDER BY ordinal";
            displays.Parameters.AddWithValue("$id", row.GetInt64(0));
            using var display = displays.ExecuteReader();
            var originals = evidence.Permissions.Entries.ToDictionary(entry => entry.Ordinal);
            while (display.Read())
            {
                if (!originals.TryGetValue(display.GetInt32(0), out var entry)
                    || display.GetString(1) != JsonSerializer.Serialize(Display(entry, evidence), ProofSerialization.Options))
                    throw GpoDirectoryPermissionRules.Invalid();
            }
        }
    }
}
