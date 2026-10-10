using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal static class AdministrativeMembershipStorage
{
    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE finding_broad_administrative_membership (
                finding_id INTEGER PRIMARY KEY REFERENCES finding(finding_id),
                generation TEXT NOT NULL, proof TEXT NOT NULL,
                fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
            """;
        command.ExecuteNonQuery();
    }

    internal static void Write(SqliteConnection connection, SqliteTransaction transaction, long findingId,
        Guid generation, BroadAdministrativeMembershipEvidence evidence)
    {
        Validate(evidence);
        var json = JsonSerializer.Serialize(evidence, ProofSerialization.Options);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO finding_broad_administrative_membership VALUES($id,$generation,$proof,$hash)";
        command.Parameters.AddWithValue("$id", findingId);
        command.Parameters.AddWithValue("$generation", generation.ToString("D"));
        command.Parameters.AddWithValue("$proof", json);
        command.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(generation.ToString("D") + "\0" + json));
        if (command.ExecuteNonQuery() != 1) throw Invalid();
    }

    internal static BroadAdministrativeMembershipEvidence Read(string json, byte[] fingerprint, string generation,
        JudgementDescription description, Guid targetGuid, string dn, string domain, string subjectKey, string subjectKind, Severity severity) =>
        Decode(json, fingerprint, generation, description.GenerationId, description.EvidenceSeal, description.DerivationGenerationId,
            targetGuid, dn, domain, subjectKey, subjectKind, severity);

    private static BroadAdministrativeMembershipEvidence Decode(string json, byte[] fingerprint, string generation,
        Guid expectedGeneration, string evidenceSeal, Guid? derivationGeneration, Guid targetGuid,
        string dn, string domain, string subjectKey, string subjectKind, Severity severity)
    {
        if (generation != expectedGeneration.ToString("D")
            || !OwnershipAuditStorage.Hash(generation + "\0" + json).AsSpan().SequenceEqual(fingerprint)) throw Invalid();
        var evidence = JsonSerializer.Deserialize<BroadAdministrativeMembershipEvidence>(json, ProofSerialization.Options) ?? throw Invalid();
        Validate(evidence);
        var target = evidence.Principals.Single(identity => identity.ObjectGuid == evidence.TargetGuid);
        if (evidence.EvidenceSeal != evidenceSeal || evidence.DerivationGenerationId != derivationGeneration
            || target.ObjectGuid != targetGuid || target.DistinguishedName != dn || target.DomainFqdn != domain
            || subjectKey != targetGuid.ToString("D") || subjectKind != nameof(FindingSubjectKind.DirectoryObject)
            || severity != Severity.High) throw Invalid();
        return evidence;
    }

    internal static void Validate(BroadAdministrativeMembershipEvidence evidence)
    {
        if (!Seal(evidence.EvidenceSeal) || !Seal(evidence.DerivationSeal) || evidence.DerivationGenerationId == Guid.Empty
            || evidence.PrincipalCatalogueVersion != PrincipalClassificationRegistry.Version
            || evidence.PolicyVersion != BroadAdministrativeGroupMembership.PolicyVersion || evidence.TargetGuid == Guid.Empty
            || evidence.Principals is not { Count: > 0 } || evidence.Domains is not { Count: > 0 }
            || evidence.BroadSources is not { Count: > 0 } || evidence.Links is not { Count: > 0 } || evidence.Limitations is null
            || evidence.Limitations.Any(limit => limit is null || string.IsNullOrWhiteSpace(limit.DistinguishedName) || !Enum.IsDefined(limit.Reason))
            || evidence.Limitations.Distinct().Count() != evidence.Limitations.Count
            || !evidence.InputsComplete && !evidence.Limitations.Any(limit => limit.Reason == AdministrativeMembershipReason.CaptureIncomplete))
            throw Invalid();
        var all = evidence.Principals.Concat(evidence.Domains).ToArray();
        if (all.Any(identity => identity is null || identity.ObjectGuid == Guid.Empty)
            || all.Select(identity => identity.ObjectGuid).Distinct().Count() != all.Length
            || all.Select(identity => identity.DistinguishedName).Distinct(StringComparer.OrdinalIgnoreCase).Count() != all.Length)
            throw Invalid();
        var domains = new Dictionary<string, AdministrativeMembershipIdentity>(StringComparer.OrdinalIgnoreCase);
        foreach (var domain in evidence.Domains)
        {
            ValidateIdentity(domain);
            if (domain.ObjectClass != "domainDNS" || domain.DomainFqdn is null || domain.GroupType is not null || domain.SidScope is not null
                || domain.NamingContext != domain.DistinguishedName || !Same(DnHelper.DnToFqdn(domain.NamingContext), domain.DomainFqdn)
                || PrincipalClassificationRegistry.DomainRid(domain.Sid + "-0") != 0
                || !domains.TryAdd(domain.DomainFqdn, domain)) throw Invalid();
        }
        if (domains.Values.Select(domain => domain.Sid).Distinct(StringComparer.OrdinalIgnoreCase).Count() != domains.Count) throw Invalid();
        var principals = evidence.Principals.ToDictionary(identity => identity.ObjectGuid);
        if (!principals.TryGetValue(evidence.TargetGuid, out var target)) throw Invalid();
        foreach (var identity in evidence.Principals)
        {
            ValidateIdentity(identity);
            if (identity.ObjectClass is not ("group" or "foreignSecurityPrincipal")) throw Invalid();
            // The capture's partition-associated DNS label is not an issuer for a special SID.
            var configurationIdentity = identity.ObjectClass == "foreignSecurityPrincipal" && AdministrativeMembershipIndex.Special(identity.Sid)
                && Same(identity.NamingContext, evidence.ConfigurationNamingContext)
                && (identity.DomainFqdn is null || Same(identity.DomainFqdn, DnHelper.DnToFqdn(identity.NamingContext)));
            if (!configurationIdentity && (identity.DomainFqdn is null || !domains.TryGetValue(identity.DomainFqdn, out var domain)
                || !Same(identity.NamingContext, domain.NamingContext)
                || identity.ObjectClass != "foreignSecurityPrincipal" && !Sid.IsBuiltinDomain(identity.Sid)
                    && !Same(Sid.IssuingDomain(identity.Sid), domain.Sid))) throw Invalid();
            if (identity.ObjectClass == "group")
            {
                if (identity.GroupType is not { } type || (type & 0x80000000L) == 0 || (type & 0x0f) is not (2 or 4 or 5 or 8)
                    || ((type & 0x0f) == 5) != Sid.IsBuiltinDomain(identity.Sid)) throw Invalid();
            }
            else if (identity.GroupType is not null) throw Invalid();
        }
        if (evidence.Principals.Where(identity => identity.ObjectClass == "group")
            .GroupBy(identity => (identity.Sid.ToUpperInvariant(), identity.SidScope?.ToUpperInvariant()))
            .Any(group => group.Count() != 1)) throw Invalid();
        var definition = PrincipalClassificationRegistry.For(target.Sid);
        var targetScope = target.GroupType.GetValueOrDefault() & 0x0f;
        if (!AdministrativeMembershipIndex.IsTarget(definition) || target.ObjectClass != "group" || target.DomainFqdn is null
            || (definition.Tier0Scope switch
            {
                Tier0IdentityScope.Domain => targetScope != 2,
                Tier0IdentityScope.BuiltinDomain => targetScope != 5,
                Tier0IdentityScope.ForestRoot => targetScope is not (2 or 8) || !Same(target.NamingContext, evidence.ForestRootNamingContext),
                _ => true,
            })) throw Invalid();
        var sourceKeys = new HashSet<(string Sid, string Scope)>();
        var broadIds = new HashSet<Guid>();
        foreach (var source in evidence.BroadSources)
        {
            if (source is null || !BroadPrincipalCatalogue.IsBroad(source.Sid) || source.Name != BroadPrincipalCatalogue.NameOf(source.Sid)
                || source.IdentityGuids is not { Count: > 0 }
                || !sourceKeys.Add((source.Sid.ToUpperInvariant(), source.SidScope?.ToUpperInvariant() ?? ""))) throw Invalid();
            foreach (var id in source.IdentityGuids)
            {
                if (!broadIds.Add(id) || !principals.TryGetValue(id, out var identity)
                    || !Same(identity.Sid, source.Sid) || !Same(identity.SidScope, source.SidScope)
                    || identity.ObjectClass == "foreignSecurityPrincipal" && !AdministrativeMembershipIndex.Special(identity.Sid)) throw Invalid();
            }
        }
        var linkKeys = new HashSet<(Guid Group, Guid Member, Guid Reference)>();
        var references = new HashSet<Guid>();
        foreach (var link in evidence.Links)
        {
            if (link is null || !principals.TryGetValue(link.GroupGuid, out var group)
                || !principals.TryGetValue(link.MemberGuid, out var member) || !principals.TryGetValue(link.MemberReferenceGuid, out var reference)
                || group.ObjectClass != "group" || !Same(member.Sid, reference.Sid)
                || !linkKeys.Add((link.GroupGuid, link.MemberGuid, link.MemberReferenceGuid))
                || link.Witnesses is not { Count: > 0 } || link.Witnesses.Distinct().Count() != link.Witnesses.Count
                || link.MemberGuid != link.MemberReferenceGuid && (reference.ObjectClass != "foreignSecurityPrincipal"
                    || member.ObjectClass != "group" || !Same(reference.DomainFqdn, group.DomainFqdn)
                    || Sid.IsBuiltinDomain(member.Sid) && !Same(reference.DomainFqdn, member.DomainFqdn))) throw Invalid();
            var supports = AdministrativeMembershipIndex.Special(member.Sid)
                ? (group.GroupType!.Value & 0x0f) is 4 or 5
                : RequesterTrusteeReading.SupportsSecurityNesting(group.GroupType!.Value, member.GroupType,
                    Same(group.DomainFqdn, member.DomainFqdn), Sid.IsBuiltinDomain(group.Sid));
            if (!supports || member.GroupType is { } memberType && (memberType & 0x0f) is 4 or 5
                && !Same(member.DomainFqdn, target.DomainFqdn)) throw Invalid();
            foreach (var witness in link.Witnesses)
            {
                if (witness is null || witness.Ordinal < 0 || (witness.Attribute switch
                {
                    "member" => witness.SourceObjectGuid != group.ObjectGuid || !Same(witness.Value, reference.DistinguishedName),
                    "memberOf" => witness.SourceObjectGuid != reference.ObjectGuid || !Same(witness.Value, group.DistinguishedName),
                    _ => true,
                })) throw Invalid();
            }
            references.Add(link.MemberReferenceGuid);
        }
        var fromTarget = Reach([evidence.TargetGuid], evidence.Links, false);
        var toBroad = Reach(broadIds, evidence.Links, true);
        if (!broadIds.IsSubsetOf(fromTarget) || evidence.Links.Any(link => !fromTarget.Contains(link.GroupGuid) || !toBroad.Contains(link.MemberGuid))
            || evidence.Principals.Any(identity => !fromTarget.Contains(identity.ObjectGuid) && !references.Contains(identity.ObjectGuid))
            || !evidence.Links.Where(link => BroadPrincipalCatalogue.IsBroad(principals[link.MemberGuid].Sid))
                .Select(link => link.MemberGuid).ToHashSet().SetEquals(broadIds)) throw Invalid();
        if (all.Any(identity => identity.Completeness != EvidenceCompleteness.Complete
            && !evidence.Limitations.Any(limit => Same(limit.DistinguishedName, identity.DistinguishedName)
                && limit.Reason == AdministrativeMembershipReason.SourceIncomplete))) throw Invalid();
    }

    private static void ValidateIdentity(AdministrativeMembershipIdentity identity)
    {
        if (string.IsNullOrWhiteSpace(identity.DistinguishedName) || string.IsNullOrWhiteSpace(identity.NamingContext)
            || string.IsNullOrWhiteSpace(identity.Sid) || !Within(identity.DistinguishedName, identity.NamingContext)
            || Sid.ToBytes(identity.Sid) is not { } bytes
            || identity.Values is not { Count: > 0 } || !Enum.IsDefined(identity.Completeness)
            || identity.Values.Any(value => value is null || value.Ordinal < 0
                || value.Attribute is not ("objectSid" or "objectClass" or "groupType" or "isDeleted"))
            || (Sid.IsBuiltinDomain(identity.Sid) ? identity.DomainFqdn is null || !Same(identity.SidScope, identity.DomainFqdn) : identity.SidScope is not null))
            throw Invalid();
        var sids = identity.Values.Where(value => value.Attribute == "objectSid").ToArray();
        var classes = identity.Values.Where(value => value.Attribute == "objectClass").ToArray();
        var types = identity.Values.Where(value => value.Attribute == "groupType").ToArray();
        if (sids.Length != 1 || sids[0].Ordinal != 0
            || !Same(sids[0].Value, identity.Sid) && !Same(sids[0].Value, Convert.ToHexString(bytes))
            || classes.Length == 0 || !classes.OrderBy(value => value.Ordinal).Select(value => value.Ordinal).SequenceEqual(Enumerable.Range(0, classes.Length))
            || !classes.Any(value => Same(value.Value, identity.ObjectClass))
            || identity.Values.Any(value => value.Attribute == "isDeleted" && !Same(value.Value, "FALSE"))
            || identity.GroupType is { } type && (types.Length != 1 || types[0].Ordinal != 0
                || !long.TryParse(types[0].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
                || parsed != type || type is < int.MinValue or > uint.MaxValue)) throw Invalid();
    }

    private static HashSet<Guid> Reach(IEnumerable<Guid> starts, IReadOnlyList<AdministrativeMembershipLink> links, bool reverse)
    {
        var adjacent = links.GroupBy(link => reverse ? link.MemberGuid : link.GroupGuid)
            .ToDictionary(group => group.Key, group => group.Select(link => reverse ? link.GroupGuid : link.MemberGuid).ToArray());
        var seen = starts.ToHashSet();
        var queue = new Queue<Guid>(seen);
        while (queue.TryDequeue(out var current))
            foreach (var next in adjacent.GetValueOrDefault(current) ?? [])
                if (seen.Add(next)) queue.Enqueue(next);
        return seen;
    }

    internal static void RequirePublishable(SqliteConnection connection, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT f.finding_id FROM finding f LEFT JOIN finding_broad_administrative_membership b ON b.finding_id=f.finding_id
            WHERE f.rule_id='SEC-062' AND b.finding_id IS NULL
            UNION ALL
            SELECT b.finding_id FROM finding_broad_administrative_membership b LEFT JOIN finding f ON f.finding_id=b.finding_id
            WHERE f.finding_id IS NULL OR f.rule_id<>'SEC-062'
            LIMIT 1
            """;
        if (command.ExecuteScalar() is not null) throw Invalid();
        command.CommandText = """
            SELECT b.proof,b.fingerprint,b.generation,j.judgement_generation_id,j.evidence_seal,j.derivation_generation_id,
                   f.object_guid,f.distinguished_name,f.domain_fqdn,f.subject_key,f.subject_kind,f.severity
            FROM finding_broad_administrative_membership b JOIN finding f ON f.finding_id=b.finding_id CROSS JOIN judgement j
            """;
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            token.ThrowIfCancellationRequested();
            if (reader.IsDBNull(5) || reader.GetString(11) != nameof(Severity.High)) throw Invalid();
            Decode(reader.GetString(0), (byte[])reader.GetValue(1), reader.GetString(2), Guid.Parse(reader.GetString(3)),
                reader.GetString(4), Guid.Parse(reader.GetString(5)), Guid.Parse(reader.GetString(6)), reader.GetString(7),
                reader.GetString(8), reader.GetString(9), reader.GetString(10), Severity.High);
        }
    }

    private static bool Seal(string value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigit);
    private static bool Same(string? first, string? second) => string.Equals(first, second, StringComparison.OrdinalIgnoreCase);
    private static bool Within(string dn, string context)
    {
        for (string? current = dn; current is not null; current = DnHelper.GetParentDn(current))
            if (Same(current, context)) return true;
        return false;
    }
    private static InvalidDataException Invalid() => new("The saved broad administrative-membership finding does not match its scoped membership evidence or generation.");
}
