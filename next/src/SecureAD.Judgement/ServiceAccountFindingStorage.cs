using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal static class ServiceAccountFindingStorage
{
    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.finding_service_account (
                finding_id INTEGER PRIMARY KEY,
                generation TEXT NOT NULL, proof TEXT NOT NULL,
                fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
            """;
        command.ExecuteNonQuery();
    }

    internal static void Write(SqliteConnection connection, SqliteTransaction transaction, long findingId,
        Guid generation, ServiceAccountFindingEvidence evidence)
    {
        Validate(evidence);
        var json = JsonSerializer.Serialize(evidence, ProofSerialization.Options);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO finding_service_account VALUES($id,$generation,$proof,$hash)";
        command.Parameters.AddWithValue("$id", findingId);
        command.Parameters.AddWithValue("$generation", generation.ToString("D"));
        command.Parameters.AddWithValue("$proof", json);
        command.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(generation.ToString("D") + "\0" + json));
        if (command.ExecuteNonQuery() != 1) throw Invalid();
    }

    internal static ServiceAccountFindingEvidence Read(string json, byte[] fingerprint, string generation,
        JudgementDescription description, string? derivationSeal, string rule, Guid accountGuid, string dn, string domain,
        string objectClass, string subjectKey, string subjectKind, Severity severity) =>
        Decode(json, fingerprint, generation, description.GenerationId, description.EvidenceSeal, description.DerivationGenerationId, derivationSeal,
            rule, accountGuid, dn, domain, objectClass, subjectKey, subjectKind, severity);

    private static ServiceAccountFindingEvidence Decode(string json, byte[] fingerprint, string generation,
        Guid expectedGeneration, string evidenceSeal, Guid? derivationGeneration, string? derivationSeal, string rule, Guid accountGuid,
        string dn, string domain, string objectClass, string subjectKey, string subjectKind, Severity severity)
    {
        if (generation != expectedGeneration.ToString("D")
            || !OwnershipAuditStorage.Hash(generation + "\0" + json).AsSpan().SequenceEqual(fingerprint)) throw Invalid();
        var evidence = JsonSerializer.Deserialize<ServiceAccountFindingEvidence>(json, ProofSerialization.Options) ?? throw Invalid();
        Validate(evidence);
        var account = evidence.Account;
        if (account.ObjectGuid != accountGuid || account.DistinguishedName != dn || account.DomainFqdn != domain
            || ServiceAccountReading.ObjectClass(account) != objectClass || subjectKind != nameof(FindingSubjectKind.Account)) throw Invalid();
        if (rule == "SEC-100")
        {
            if (evidence.AdministrativeMembership is not { } membership || membership.EvidenceSeal != evidenceSeal
                || membership.DerivationGenerationId != derivationGeneration || membership.DerivationSeal != derivationSeal || severity != Severity.High
                || subjectKey != ServiceAccountWithAdministrativeMembership.Key(accountGuid, membership.TargetGuid)) throw Invalid();
        }
        else if (rule != "SEC-101" || evidence.AdministrativeMembership is not null || severity != Severity.Medium
            || subjectKey != accountGuid.ToString("D")) throw Invalid();
        return evidence;
    }

    internal static void Validate(ServiceAccountFindingEvidence evidence)
    {
        var account = evidence.Account;
        if (account is null || account.ObjectGuid == Guid.Empty || string.IsNullOrWhiteSpace(account.DistinguishedName)
            || string.IsNullOrWhiteSpace(account.DomainFqdn) || !Enum.IsDefined(account.Kind) || !Enum.IsDefined(account.Completeness)
            || account.ObjectClasses is null || account.ServicePrincipalNames is null || account.AccountControl is null
            || account.ObjectClasses.Concat(account.ServicePrincipalNames).Concat(account.AccountControl).Any(value => value is null)
            || account.MissingAttributes is null || account.MissingAttributes.Any(string.IsNullOrWhiteSpace)
            || account.MissingAttributes.Distinct(StringComparer.OrdinalIgnoreCase).Count() != account.MissingAttributes.Count)
            throw Invalid();
        var attributes = new[] { Attribute("objectClass", account.ObjectClasses), Attribute("servicePrincipalName", account.ServicePrincipalNames),
            Attribute("userAccountControl", account.AccountControl) };
        var subject = new ObjectAttributes(account.DistinguishedName, account.ObjectGuid, account.CapturedUtc, account.Completeness, attributes, account.DomainFqdn);
        var read = ServiceAccountReading.Read(subject, includeManaged: true);
        if (read.Account is null || read.Account.Kind != account.Kind || read.Account.UserAccountControl != account.UserAccountControl
            || !read.Missing.Order(StringComparer.Ordinal).SequenceEqual(account.MissingAttributes.Order(StringComparer.Ordinal))) throw Invalid();
        if (evidence.AdministrativeMembership is not { } membership)
        {
            if (account.Kind != ServiceAccountKind.SpnBearingUser || account.UserAccountControl is not { } control
                || (control & ServiceAccountWithNonExpiringPassword.DontExpirePassword) == 0) throw Invalid();
            return;
        }
        ValidateMembership(account, membership);
    }

    private static ObjectAttribute Attribute(string name, IReadOnlyList<AttributeValue> values) =>
        new(name, name is "objectClass" or "servicePrincipalName" ? AttributeCardinality.MultiValued : AttributeCardinality.SingleValued, values);

    private static void ValidateMembership(ServiceAccountAssociation account, ServiceAdministrativeMembership membership)
    {
        var knownReasons = Enum.GetValues<MembershipRouteIncompleteReason>().Aggregate(MembershipRouteIncompleteReason.None, (a, b) => a | b);
        if (!Seal(membership.EvidenceSeal) || !Seal(membership.DerivationSeal) || membership.DerivationGenerationId == Guid.Empty
            || membership.PrincipalCatalogueVersion != PrincipalClassificationRegistry.Version
            || membership.PolicyVersion != ServiceAccountWithAdministrativeMembership.PolicyVersion
            || membership.AccountGuid != account.ObjectGuid || membership.TargetGuid == Guid.Empty || membership.TargetGuid == membership.AccountGuid
            || membership.Principals is not { Count: > 1 } || membership.Domains is not { Count: > 0 } || membership.Links is not { Count: > 0 }
            || membership.Limitations is null || (membership.RouteIncompleteReasons & ~knownReasons) != 0
            || membership.RouteIncompleteReasons.HasFlag(MembershipRouteIncompleteReason.ForestMaskUnreadable)
            || membership.Limitations.Any(limit => limit is null || string.IsNullOrWhiteSpace(limit.DistinguishedName) || !Enum.IsDefined(limit.Reason))
            || membership.Limitations.Distinct().Count() != membership.Limitations.Count
            || !membership.InputsComplete && !membership.Limitations.Any(limit => limit.Reason == AdministrativeMembershipReason.CaptureIncomplete))
            throw Invalid();
        var all = membership.Principals.Concat(membership.Domains).ToArray();
        if (all.Any(identity => identity is null || identity.ObjectGuid == Guid.Empty)
            || all.Select(identity => identity.ObjectGuid).Distinct().Count() != all.Length
            || all.Select(identity => identity.DistinguishedName).Distinct(StringComparer.OrdinalIgnoreCase).Count() != all.Length) throw Invalid();
        var domains = GroupMembershipFindingStorage.ValidateDomains(membership.Domains);
        var principals = membership.Principals.ToDictionary(identity => identity.ObjectGuid);
        if (membership.Principals.Where(identity => identity.ObjectClass != "foreignSecurityPrincipal")
            .GroupBy(identity => (identity.Sid.ToUpperInvariant(), identity.SidScope?.ToUpperInvariant()))
            .Any(group => group.Count() != 1)) throw Invalid();
        if (!principals.TryGetValue(account.ObjectGuid, out var source) || !principals.TryGetValue(membership.TargetGuid, out var target)) throw Invalid();
        foreach (var identity in membership.Principals)
        {
            GroupMembershipFindingStorage.ValidateIdentity(identity, includeMembershipValues: true);
            if (identity.ObjectClass is not ("group" or "user" or "computer" or "foreignSecurityPrincipal")
                || identity.DomainFqdn is null || !domains.TryGetValue(identity.DomainFqdn, out var domain)
                || !Same(identity.NamingContext, domain.NamingContext)
                || identity.ObjectClass != "foreignSecurityPrincipal" && !Sid.IsBuiltinDomain(identity.Sid) && !Same(Sid.IssuingDomain(identity.Sid), domain.Sid))
                throw Invalid();
            if (identity.ObjectClass == "group")
            {
                if (identity.GroupType is not { } type || (type & 0x80000000L) == 0 || (type & 0x0f) is not (2 or 4 or 5 or 8)
                    || ((type & 0x0f) == 5) != Sid.IsBuiltinDomain(identity.Sid)) throw Invalid();
            }
            else if (identity.GroupType is not null || identity.ObjectClass != "foreignSecurityPrincipal" && identity.ObjectGuid != account.ObjectGuid) throw Invalid();
        }
        if (source.DistinguishedName != account.DistinguishedName || source.DomainFqdn != account.DomainFqdn
            || source.CapturedUtc != account.CapturedUtc || source.Completeness != account.Completeness
            || source.ObjectClass is not ("user" or "computer")
            || !source.Values.Where(value => value.Attribute == "objectClass").OrderBy(value => value.Ordinal).Select(value => (value.Ordinal, value.Value))
                .SequenceEqual(account.ObjectClasses.OrderBy(value => value.Ordinal).Select(value => (value.Ordinal, value.Text!)))
            || !CapturedGroupMembershipIndex.TargetScopeMatches(target, PrincipalClassificationRegistry.For(target.Sid), membership.ForestRootNamingContext))
            throw Invalid();
        var keys = new HashSet<(Guid Group, Guid Member, Guid Reference)>();
        var references = new HashSet<Guid>();
        foreach (var link in membership.Links)
        {
            if (link is null || !principals.TryGetValue(link.GroupGuid, out var group) || !principals.TryGetValue(link.MemberGuid, out var member)
                || !principals.TryGetValue(link.MemberReferenceGuid, out var reference) || group.ObjectClass != "group"
                || member.ObjectClass is not ("group" or "user" or "computer") || !Same(member.Sid, reference.Sid)
                || !keys.Add((link.GroupGuid, link.MemberGuid, link.MemberReferenceGuid)) || link.Witnesses is not { Count: > 0 }
                || link.Witnesses.Distinct().Count() != link.Witnesses.Count
                || link.MemberGuid != link.MemberReferenceGuid && (reference.ObjectClass != "foreignSecurityPrincipal"
                    || !Same(reference.DomainFqdn, group.DomainFqdn) || Sid.IsBuiltinDomain(member.Sid) && !Same(reference.DomainFqdn, member.DomainFqdn))
                || !RequesterTrusteeReading.SupportsSecurityNesting(group.GroupType!.Value, member.GroupType,
                    Same(group.DomainFqdn, member.DomainFqdn), Sid.IsBuiltinDomain(group.Sid))
                || (group.GroupType.Value & 0x0f) is 4 or 5 && !Same(group.DomainFqdn, target.DomainFqdn)) throw Invalid();
            foreach (var witness in link.Witnesses)
            {
                if (witness is null || witness.Ordinal < 0 || (witness.Attribute switch
                {
                    "member" => witness.SourceObjectGuid != group.ObjectGuid || !Same(witness.Value, reference.DistinguishedName),
                    "memberOf" => witness.SourceObjectGuid != reference.ObjectGuid || !Same(witness.Value, group.DistinguishedName),
                    "primaryGroupID" => !PrimaryWitness(witness, member, group, reference),
                    _ => true,
                })) throw Invalid();
            }
            references.Add(reference.ObjectGuid);
        }
        var fromAccount = GroupMembershipFindingStorage.Reach([account.ObjectGuid], membership.Links, reverse: true);
        var fromTarget = GroupMembershipFindingStorage.Reach([target.ObjectGuid], membership.Links, reverse: false);
        if (!fromAccount.Contains(target.ObjectGuid) || membership.Links.Any(link => !fromAccount.Contains(link.MemberGuid) || !fromTarget.Contains(link.GroupGuid))
            || membership.Principals.Any(identity => !fromAccount.Contains(identity.ObjectGuid) && !references.Contains(identity.ObjectGuid))
            || all.Any(identity => identity.Completeness != EvidenceCompleteness.Complete && !membership.Limitations.Any(limit =>
                Same(limit.DistinguishedName, identity.DistinguishedName) && limit.Reason == AdministrativeMembershipReason.SourceIncomplete))) throw Invalid();
    }

    private static bool PrimaryWitness(AdministrativeMembershipWitness witness, AdministrativeMembershipIdentity member,
        AdministrativeMembershipIdentity group, AdministrativeMembershipIdentity reference) =>
        witness.SourceObjectGuid == member.ObjectGuid && member.ObjectGuid == reference.ObjectGuid && member.ObjectClass is "user" or "computer"
        && witness.Ordinal == 0 && uint.TryParse(witness.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var rid)
        && Same(member.DomainFqdn, group.DomainFqdn) && Same(group.Sid, Sid.IssuingDomain(member.Sid) + "-" + rid.ToString(CultureInfo.InvariantCulture))
        && member.Values.Any(value => value.Attribute == "primaryGroupID" && value.Ordinal == witness.Ordinal && value.Value == witness.Value);

    internal static void RequirePublishable(SqliteConnection connection, string? derivationSeal, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT f.finding_id FROM finding f LEFT JOIN finding_service_account s ON s.finding_id=f.finding_id
            WHERE f.rule_id IN ('SEC-100','SEC-101') AND s.finding_id IS NULL
            UNION ALL
            SELECT s.finding_id FROM finding_service_account s LEFT JOIN finding f ON f.finding_id=s.finding_id
            WHERE f.finding_id IS NULL OR f.rule_id NOT IN ('SEC-100','SEC-101') LIMIT 1
            """;
        if (command.ExecuteScalar() is not null) throw Invalid();
        command.CommandText = """
            SELECT s.proof,s.fingerprint,s.generation,j.judgement_generation_id,j.evidence_seal,j.derivation_generation_id,
                   f.rule_id,f.object_guid,f.distinguished_name,f.domain_fqdn,f.object_class,f.subject_key,f.subject_kind,f.severity
            FROM finding_service_account s JOIN finding f ON f.finding_id=s.finding_id CROSS JOIN judgement j
            """;
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            token.ThrowIfCancellationRequested();
            Decode(reader.GetString(0), (byte[])reader.GetValue(1), reader.GetString(2), Guid.Parse(reader.GetString(3)), reader.GetString(4),
                reader.IsDBNull(5) ? null : Guid.Parse(reader.GetString(5)), derivationSeal, reader.GetString(6), Guid.Parse(reader.GetString(7)),
                reader.GetString(8), reader.GetString(9), reader.GetString(10), reader.GetString(11), reader.GetString(12),
                Enum.Parse<Severity>(reader.GetString(13)));
        }
    }

    private static bool Seal(string value) => value is { Length: 64 } && value.All(Uri.IsHexDigit);
    private static bool Same(string? first, string? second) => string.Equals(first, second, StringComparison.OrdinalIgnoreCase);
    private static InvalidDataException Invalid() => new("The saved service-account finding or its captured membership evidence is invalid.");
}
