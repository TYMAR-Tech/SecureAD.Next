using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal static class DelegationConfigurationFindingStorage
{
    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE finding_delegation_configuration (
                finding_id INTEGER PRIMARY KEY REFERENCES finding(finding_id), generation TEXT NOT NULL,
                proof TEXT NOT NULL, fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
                account_source_hash BLOB NOT NULL CHECK(length(account_source_hash)=32),
                resource_source_hash BLOB NOT NULL CHECK(length(resource_source_hash)=32));
            """;
        command.ExecuteNonQuery();
    }

    internal static void Write(SqliteConnection connection, SqliteTransaction transaction, long id, Guid generation,
        DelegationConfigurationEvidence evidence)
    {
        Validate(evidence);
        if (evidence.Scope.GenerationId != generation) throw Invalid();
        var json = JsonSerializer.Serialize(evidence, ProofSerialization.Options);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO finding_delegation_configuration VALUES($id,$generation,$proof,$hash,$account,$resource)";
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$generation", generation.ToString("D"));
        command.Parameters.AddWithValue("$proof", json);
        command.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(generation.ToString("D") + "\0" + json));
        command.Parameters.AddWithValue("$account", SourceHash(evidence, evidence.Account));
        command.Parameters.AddWithValue("$resource", SourceHash(evidence, evidence.Resource));
        if (command.ExecuteNonQuery() != 1) throw Invalid();
    }

    internal static DelegationConfigurationEvidence Read(SqliteConnection connection, string json, byte[] hash,
        byte[] accountSourceHash, byte[] resourceSourceHash, string generation,
        JudgementDescription description, string? derivationSeal, string rule, Guid guid, string dn, string domain,
        string objectClass, string subjectKey, string subjectKind, Severity severity)
    {
        var evidence = Decode(json, hash, accountSourceHash, resourceSourceHash, generation, description, derivationSeal,
            rule, guid, dn, domain, objectClass, subjectKey, subjectKind, severity);
        DelegationScopeReader.Validate(connection, description, evidence.Scope, CancellationToken.None);
        return evidence;
    }

    private static DelegationConfigurationEvidence Decode(string json, byte[] hash, byte[] accountSourceHash, byte[] resourceSourceHash,
        string generation, JudgementDescription description,
        string? derivationSeal, string rule, Guid guid, string dn, string domain, string objectClass, string key, string kind, Severity severity)
    {
        if (generation != description.GenerationId.ToString("D")
            || !OwnershipAuditStorage.Hash(generation + "\0" + json).AsSpan().SequenceEqual(hash)) throw Invalid();
        var evidence = JsonSerializer.Deserialize<DelegationConfigurationEvidence>(json, ProofSerialization.Options) ?? throw Invalid();
        Validate(evidence);
        if (!SourceHash(evidence, evidence.Account).AsSpan().SequenceEqual(accountSourceHash)
            || !SourceHash(evidence, evidence.Resource).AsSpan().SequenceEqual(resourceSourceHash)) throw Invalid();
        var account = evidence.Account;
        var constrained = evidence.ConfigurationKind == DelegationConfigurationKind.Constrained;
        if (evidence.EvidenceSeal != description.EvidenceSeal || evidence.DerivationGenerationId != description.DerivationGenerationId
            || evidence.DerivationSeal != derivationSeal || evidence.Scope.GenerationId != description.GenerationId
            || rule != (constrained ? "SEC-012" : "SEC-013") || account.ObjectGuid != guid
            || account.DistinguishedName != dn || account.DomainFqdn != domain || account.ObjectClass != objectClass
            || key != (constrained ? DelegationConfigurationRules.Key(guid, evidence.Resource.ObjectGuid) : guid.ToString("D"))
            || kind != nameof(FindingSubjectKind.Account) || severity != Severity.High) throw Invalid();
        return evidence;
    }

    internal static void Validate(DelegationConfigurationEvidence evidence)
    {
        if (!Enum.IsDefined(evidence.ConfigurationKind) || !Seal(evidence.EvidenceSeal) || !Seal(evidence.DerivationSeal)
            || evidence.DerivationGenerationId == Guid.Empty || evidence.PolicyVersion != DelegationConfigurationRules.PolicyVersion
            || evidence.DescriptorParserVersion != SecurityDescriptorParser.Version || evidence.Account is null || evidence.Resource is null
            || evidence.Scope is null || evidence.Scope.GenerationId == Guid.Empty || !Seal(evidence.Scope.Fingerprint)
            || evidence.Scope.ResourceGuid != evidence.Resource.ObjectGuid || evidence.Scope.TargetDn != evidence.Resource.DistinguishedName
            || evidence.Services is null || evidence.Grants is null
            || evidence.Limitations is null || evidence.Limitations.Any(string.IsNullOrWhiteSpace)
            || evidence.Limitations.Distinct(StringComparer.Ordinal).Count() != evidence.Limitations.Count
            || !evidence.InputsComplete && !evidence.Limitations.Contains("CaptureIncomplete")) throw Invalid();
        ValidateAccount(evidence.Account);
        ValidateAccount(evidence.Resource);
        if (evidence.Scope.ClassificationBases is null || evidence.Scope.AnchorDns is not { Count: > 0 }
            || evidence.Scope.RelationIds is null || evidence.Scope.RelationIds.Any(value => value <= 0)
            || evidence.Scope.RelationIds.Distinct().Count() != evidence.Scope.RelationIds.Count || evidence.Scope.Limitations is null)
            throw Invalid();
        if (evidence.ConfigurationKind == DelegationConfigurationKind.Constrained)
        {
            if (evidence.Services.Count == 0 || evidence.Grants.Count != 0) throw Invalid();
            var configured = DelegationConfigurationAssessment.Find(evidence.Account, DelegationConfigurationRules.ConstrainedAttribute)?.Values ?? [];
            var registered = DelegationConfigurationAssessment.Find(evidence.Resource, "servicePrincipalName")?.Values ?? [];
            foreach (var service in evidence.Services)
                if (service is null || service.ConfigurationOrdinal < 0 || service.RegistrationOrdinal < 0
                    || !DuplicateServicePrincipalNames.Supports(service.ConfiguredService)
                    || !service.ConfiguredService.Equals(service.RegisteredService, StringComparison.OrdinalIgnoreCase)
                    || !configured.Any(value => value.Ordinal == service.ConfigurationOrdinal && value.Bytes is null && value.Text == service.ConfiguredService)
                    || !registered.Any(value => value.Ordinal == service.RegistrationOrdinal && value.Bytes is null && value.Text == service.RegisteredService))
                    throw Invalid();
            if (evidence.Services.Distinct().Count() != evidence.Services.Count) throw Invalid();
        }
        else
        {
            if (evidence.Account.ObjectGuid != evidence.Resource.ObjectGuid || evidence.Account.DistinguishedName != evidence.Resource.DistinguishedName
                || JsonSerializer.Serialize(evidence.Account, ProofSerialization.Options) != JsonSerializer.Serialize(evidence.Resource, ProofSerialization.Options)
                || evidence.Services.Count != 0 || evidence.Grants.Count == 0) throw Invalid();
            var values = DelegationConfigurationAssessment.Find(evidence.Resource, DelegationConfigurationRules.ResourceAttribute)?.Values;
            if (values is not { Count: 1 } || values[0] is not { Ordinal: 0, Text: null, Bytes: { } bytes }) throw Invalid();
            var parsed = ResourceDelegationGrantReader.Read(bytes);
            if (JsonSerializer.Serialize(parsed.Grants, ProofSerialization.Options) != JsonSerializer.Serialize(evidence.Grants, ProofSerialization.Options)
                || parsed.Limits.Any(value => !evidence.Limitations.Contains(value))) throw Invalid();
        }
    }

    private static void ValidateAccount(DelegationConfigurationAccount account)
    {
        if (account.ObjectGuid == Guid.Empty || string.IsNullOrWhiteSpace(account.DistinguishedName)
            || string.IsNullOrWhiteSpace(account.DomainFqdn) || string.IsNullOrWhiteSpace(account.ObjectClass)
            || !Enum.IsDefined(account.Completeness) || account.Attributes is null
            || account.Attributes.Any(attribute => attribute is null || attribute.Values is null
                || !DelegationConfigurationRules.IdentityAttributes.Contains(attribute.LdapDisplayName, StringComparer.OrdinalIgnoreCase))
            || account.Attributes.Select(attribute => attribute.LdapDisplayName).Distinct(StringComparer.OrdinalIgnoreCase).Count() != account.Attributes.Count)
            throw Invalid();
        var subject = new ObjectAttributes(account.DistinguishedName, account.ObjectGuid, account.CapturedUtc,
            account.Completeness, account.Attributes, account.DomainFqdn);
        if (!AttributeWriteRules.IsAccount(subject) || subject.Find("objectClass")?.Values.LastOrDefault()?.Text != account.ObjectClass
            || subject.Find("isDeleted")?.Values.Any(value => !string.Equals(value.Text, "FALSE", StringComparison.OrdinalIgnoreCase)) == true)
            throw Invalid();
    }

    internal static void RequirePublishable(SqliteConnection connection, JudgementDescription? description,
        string? derivationSeal, CancellationToken token)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT f.finding_id FROM finding f LEFT JOIN finding_delegation_configuration d ON d.finding_id=f.finding_id
            WHERE f.rule_id IN ('SEC-012','SEC-013') AND d.finding_id IS NULL
            UNION ALL SELECT d.finding_id FROM finding_delegation_configuration d LEFT JOIN finding f ON f.finding_id=d.finding_id
            WHERE f.finding_id IS NULL OR f.rule_id NOT IN ('SEC-012','SEC-013') LIMIT 1
            """;
        if (command.ExecuteScalar() is not null) throw Invalid();
        command.CommandText = """
            SELECT d.proof,d.fingerprint,d.generation,f.rule_id,f.object_guid,f.distinguished_name,f.domain_fqdn,
                   f.object_class,f.subject_key,f.subject_kind,f.severity,d.account_source_hash,d.resource_source_hash
            FROM finding_delegation_configuration d JOIN finding f ON f.finding_id=d.finding_id
            """;
        using var row = command.ExecuteReader();
        while (row.Read())
        {
            token.ThrowIfCancellationRequested();
            if (description is null) throw Invalid();
            if (!Enum.TryParse<Severity>(row.GetString(10), out var severity)) throw Invalid();
            var evidence = Decode(row.GetString(0), (byte[])row.GetValue(1), (byte[])row.GetValue(11), (byte[])row.GetValue(12),
                row.GetString(2), description, derivationSeal,
                row.GetString(3), Guid.Parse(row.GetString(4)), row.GetString(5), row.GetString(6), row.GetString(7),
                row.GetString(8), row.GetString(9), severity);
            DelegationScopeReader.Validate(connection, description, evidence.Scope, token);
        }
    }

    private static byte[] SourceHash(DelegationConfigurationEvidence evidence, DelegationConfigurationAccount source) =>
        OwnershipAuditStorage.Hash(evidence.Scope.GenerationId.ToString("D") + "\0" + evidence.EvidenceSeal + "\0"
            + evidence.DerivationGenerationId.ToString("D") + "\0" + evidence.DerivationSeal + "\0"
            + JsonSerializer.Serialize(source, ProofSerialization.Options));

    private static bool Seal(string value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigit);
    private static InvalidDataException Invalid() => new("The saved delegation configuration does not match its original values, resource scope, rule or generation.");
}
