using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal static class GroupMembershipReviewFindingStorage
{
    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE finding_membership_review (
                finding_id INTEGER PRIMARY KEY REFERENCES finding(finding_id),
                generation TEXT NOT NULL, proof TEXT NOT NULL,
                fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
            """;
        command.ExecuteNonQuery();
    }

    internal static void Write(SqliteConnection connection, SqliteTransaction transaction, long findingId,
        Guid generation, GroupMembershipReviewEvidence evidence)
    {
        Validate(evidence, requireTotal: false);
        var json = JsonSerializer.Serialize(evidence, ProofSerialization.Options);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO finding_membership_review VALUES($id,$generation,$proof,$hash)";
        command.Parameters.AddWithValue("$id", findingId);
        command.Parameters.AddWithValue("$generation", generation.ToString("D"));
        command.Parameters.AddWithValue("$proof", json);
        command.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(generation.ToString("D") + "\0" + json));
        if (command.ExecuteNonQuery() != 1) throw Invalid();
    }

    internal static GroupMembershipReviewEvidence Read(SqliteConnection connection, string json, byte[] fingerprint, string generation,
        JudgementDescription description, string? derivationSeal, string rule, Guid guid, string dn, string domain,
        string objectClass, string subjectKey, string subjectKind, Severity severity)
    {
        var evidence = Decode(json, fingerprint, generation, description.GenerationId, description.EvidenceSeal,
            description.DerivationGenerationId, derivationSeal, rule, guid, dn, domain, objectClass, subjectKey, subjectKind, severity);
        ValidateSavedTotal(connection, evidence, description.GenerationId);
        return evidence;
    }

    private static GroupMembershipReviewEvidence Decode(string json, byte[] fingerprint, string generation,
        Guid expectedGeneration, string evidenceSeal, Guid? derivationGeneration, string? derivationSeal,
        string rule, Guid guid, string dn, string domain, string objectClass, string subjectKey, string subjectKind, Severity severity)
    {
        if (generation != expectedGeneration.ToString("D")
            || !OwnershipAuditStorage.Hash(generation + "\0" + json).AsSpan().SequenceEqual(fingerprint)) throw Invalid();
        var evidence = JsonSerializer.Deserialize<GroupMembershipReviewEvidence>(json, ProofSerialization.Options) ?? throw Invalid();
        Validate(evidence, requireTotal: true);
        var subjectGuid = evidence.NestedGroupGuid ?? evidence.TargetGuid;
        var subject = evidence.Principals.Single(identity => identity.ObjectGuid == subjectGuid);
        var expectedRule = evidence.ReviewKind == GroupMembershipReviewKind.PrivilegedGroupSize ? "SEC-050" : "SEC-051";
        var expectedKey = evidence.NestedGroupGuid is not null
            ? GroupNestedInDomainAdmins.Key(subjectGuid, evidence.TargetGuid) : subjectGuid.ToString("D");
        if (rule != expectedRule || evidence.EvidenceSeal != evidenceSeal || evidence.DerivationGenerationId != derivationGeneration
            || evidence.DerivationSeal != derivationSeal || subjectGuid != guid || subject.DistinguishedName != dn || subject.DomainFqdn != domain
            || objectClass != "group" || subjectKey != expectedKey || subjectKind != nameof(FindingSubjectKind.DirectoryObject)
            || severity != Severity.Low) throw Invalid();
        return evidence;
    }

    internal static void Validate(GroupMembershipReviewEvidence evidence, bool requireTotal)
    {
        if (!Enum.IsDefined(evidence.ReviewKind) || !Seal(evidence.EvidenceSeal) || !Seal(evidence.DerivationSeal)
            || evidence.DerivationGenerationId == Guid.Empty || evidence.PrincipalCatalogueVersion != PrincipalClassificationRegistry.Version
            || evidence.PolicyVersion != GroupMembershipReviewRules.PolicyVersion || evidence.TargetGuid == Guid.Empty
            || evidence.Principals is not { Count: > 0 } || evidence.Domains is not { Count: > 0 }
            || evidence.MemberValues is not { Count: > 0 } || evidence.Links is null || evidence.Limitations is null
            || evidence.Limitations.Any(limit => limit is null || string.IsNullOrWhiteSpace(limit.DistinguishedName) || !Enum.IsDefined(limit.Reason))
            || evidence.Limitations.Distinct().Count() != evidence.Limitations.Count
            || !evidence.InputsComplete && !evidence.Limitations.Any(limit => limit.Reason == AdministrativeMembershipReason.CaptureIncomplete)
            || evidence.MemberValues.Any(value => value is null || value.Ordinal < 0 || value.Text is not null && value.Bytes is not null)
            || evidence.MemberValues.Select(value => value.Ordinal).Distinct().Count() != evidence.MemberValues.Count) throw Invalid();
        var all = evidence.Principals.Concat(evidence.Domains).ToArray();
        if (all.Any(identity => identity is null || identity.ObjectGuid == Guid.Empty)
            || all.Select(identity => identity.ObjectGuid).Distinct().Count() != all.Length
            || all.Select(identity => identity.DistinguishedName).Distinct(StringComparer.OrdinalIgnoreCase).Count() != all.Length) throw Invalid();
        var domains = GroupMembershipFindingStorage.ValidateDomains(evidence.Domains);
        var principals = evidence.Principals.ToDictionary(identity => identity.ObjectGuid);
        if (!principals.TryGetValue(evidence.TargetGuid, out var target)) throw Invalid();
        foreach (var identity in evidence.Principals)
            GroupMembershipFindingStorage.ValidateScopedIdentity(identity, domains, evidence.ConfigurationNamingContext,
                securityGroup: identity.ObjectGuid == evidence.TargetGuid);
        if (all.Any(identity => identity.Completeness != EvidenceCompleteness.Complete
            && !evidence.Limitations.Any(limit => Same(limit.DistinguishedName, identity.DistinguishedName)
                && limit.Reason == AdministrativeMembershipReason.SourceIncomplete))) throw Invalid();
        var definition = PrincipalClassificationRegistry.For(target.Sid);
        if (!CapturedGroupMembershipIndex.TargetScopeMatches(target, definition, evidence.ForestRootNamingContext)) throw Invalid();
        if (evidence.ReviewKind == GroupMembershipReviewKind.PrivilegedGroupSize)
        {
            if (evidence.NestedGroupGuid is not null || evidence.Links.Count != 0 || evidence.Principals.Count != 1
                || evidence.ReviewThreshold != LargePrivilegedGroupReview.ThresholdFor(definition)
                || evidence.DirectMembers != GroupInventoryStorage.DirectCount(evidence.MemberValues)
                || evidence.DirectMembers <= evidence.ReviewThreshold || requireTotal && evidence.KnownTotal is null) throw Invalid();
            var ordered = evidence.MemberValues.Select(value => value.Ordinal).Order().SequenceEqual(Enumerable.Range(0, evidence.MemberValues.Count));
            if ((!ordered || evidence.MemberValues.Any(value => value.Bytes is not null || string.IsNullOrWhiteSpace(value.Text)))
                && !evidence.Limitations.Any(limit => Same(limit.DistinguishedName, target.DistinguishedName)
                    && limit.Reason == AdministrativeMembershipReason.MembershipValuesMalformed)) throw Invalid();
            if (evidence.KnownTotal is { } total) ValidateTotal(total);
            return;
        }
        if (!CapturedGroupMembershipIndex.IsDomainAdmins(definition) || evidence.NestedGroupGuid is not { } nested
            || !principals.TryGetValue(nested, out var member) || member.ObjectClass != "group" || evidence.Links.Count == 0
            || evidence.DirectMembers is not null || evidence.ReviewThreshold is not null || evidence.KnownTotal is not null) throw Invalid();
        var references = new HashSet<Guid> { target.ObjectGuid, member.ObjectGuid };
        var witnessed = new HashSet<(int Ordinal, string Value)>();
        var keys = new HashSet<Guid>();
        foreach (var link in evidence.Links)
        {
            if (link is null || link.GroupGuid != target.ObjectGuid || link.MemberGuid != member.ObjectGuid
                || !principals.TryGetValue(link.MemberReferenceGuid, out var reference)
                || !keys.Add(link.MemberReferenceGuid) || !Same(reference.Sid, member.Sid)
                || link.MemberReferenceGuid != member.ObjectGuid && (reference.ObjectClass != "foreignSecurityPrincipal"
                    || !Same(reference.DomainFqdn, target.DomainFqdn)
                    || Sid.IsBuiltinDomain(member.Sid) && !Same(reference.DomainFqdn, member.DomainFqdn))
                || link.Witnesses is not { Count: > 0 } || link.Witnesses.Distinct().Count() != link.Witnesses.Count) throw Invalid();
            references.Add(reference.ObjectGuid);
            foreach (var witness in link.Witnesses)
            {
                if (witness is null || witness.SourceObjectGuid != target.ObjectGuid || witness.Attribute != "member"
                    || witness.Ordinal < 0 || !Same(witness.Value, reference.DistinguishedName)
                    || !evidence.MemberValues.Any(value => value.Ordinal == witness.Ordinal && value.Bytes is null && value.Text == witness.Value)
                    || !witnessed.Add((witness.Ordinal, witness.Value))) throw Invalid();
            }
        }
        if (!references.SetEquals(principals.Keys) || witnessed.Count != evidence.MemberValues.Count) throw Invalid();
    }

    internal static void AttachKnownTotals(SqliteConnection connection, Guid generation, CancellationToken token)
    {
        var updates = new List<(long Id, GroupMembershipReviewEvidence Evidence)>();
        using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT r.finding_id,r.proof,r.fingerprint,r.generation,g.object_guid,g.direct_members,
                       g.known_total,g.unresolved_members,g.unreadable_members,g.membership_limitations,p.generation,p.completed
                FROM finding_membership_review r JOIN finding f ON f.finding_id=r.finding_id
                LEFT JOIN group_inventory g ON g.distinguished_name=f.distinguished_name
                CROSS JOIN group_inventory_product p WHERE f.rule_id='SEC-050'
                """;
            using var row = command.ExecuteReader();
            while (row.Read())
            {
                token.ThrowIfCancellationRequested();
                var json = row.GetString(1);
                if (row.GetString(3) != generation.ToString("D") || row.IsDBNull(4) || row.IsDBNull(6) || row.IsDBNull(7)
                    || row.IsDBNull(8) || row.IsDBNull(9) || row.GetString(10) != generation.ToString("D") || !row.GetBoolean(11)
                    || !OwnershipAuditStorage.Hash(row.GetString(3) + "\0" + json).AsSpan().SequenceEqual((byte[])row.GetValue(2))) throw Invalid();
                var evidence = JsonSerializer.Deserialize<GroupMembershipReviewEvidence>(json, ProofSerialization.Options) ?? throw Invalid();
                Validate(evidence, requireTotal: false);
                if (evidence.ReviewKind != GroupMembershipReviewKind.PrivilegedGroupSize || row.GetString(4) != evidence.TargetGuid.ToString("D")
                    || row.GetInt32(5) != evidence.DirectMembers) throw Invalid();
                var flags = (GroupMembershipLimitations)row.GetInt32(9);
                if ((flags & ~Enum.GetValues<GroupMembershipLimitations>().Aggregate(GroupMembershipLimitations.None,
                    (all, value) => all | value)) != 0) throw Invalid();
                var total = new MembershipReviewKnownTotal(row.GetInt32(6), row.GetInt32(7), row.GetInt32(8),
                    Enum.GetValues<GroupMembershipLimitations>().Where(value => value != GroupMembershipLimitations.None && flags.HasFlag(value))
                        .Select(value => value.ToString()).ToArray());
                ValidateTotal(total);
                updates.Add((row.GetInt64(0), evidence with { KnownTotal = total }));
            }
        }
        if (updates.Count == 0) return;
        using var transaction = connection.BeginTransaction();
        foreach (var (id, evidence) in updates)
        {
            token.ThrowIfCancellationRequested();
            var json = JsonSerializer.Serialize(evidence, ProofSerialization.Options);
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "UPDATE finding_membership_review SET proof=$proof,fingerprint=$hash WHERE finding_id=$id AND generation=$generation";
            command.Parameters.AddWithValue("$proof", json);
            command.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(generation.ToString("D") + "\0" + json));
            command.Parameters.AddWithValue("$id", id);
            command.Parameters.AddWithValue("$generation", generation.ToString("D"));
            if (command.ExecuteNonQuery() != 1) throw Invalid();
            command.Parameters.Clear();
            command.CommandText = "UPDATE finding SET detail=$detail WHERE finding_id=$id AND rule_id='SEC-050'";
            command.Parameters.AddWithValue("$detail", GroupMembershipReviewRules.Detail(evidence));
            command.Parameters.AddWithValue("$id", id);
            if (command.ExecuteNonQuery() != 1) throw Invalid();
        }
        transaction.Commit();
    }

    internal static void RequirePublishable(SqliteConnection connection, string? derivationSeal, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT f.finding_id FROM finding f LEFT JOIN finding_membership_review r ON r.finding_id=f.finding_id
            WHERE f.rule_id IN ('SEC-050','SEC-051') AND r.finding_id IS NULL
            UNION ALL
            SELECT r.finding_id FROM finding_membership_review r LEFT JOIN finding f ON f.finding_id=r.finding_id
            WHERE f.finding_id IS NULL OR f.rule_id NOT IN ('SEC-050','SEC-051') LIMIT 1
            """;
        if (command.ExecuteScalar() is not null) throw Invalid();
        command.CommandText = """
            SELECT r.proof,r.fingerprint,r.generation,j.judgement_generation_id,j.evidence_seal,j.derivation_generation_id,
                   f.rule_id,f.object_guid,f.distinguished_name,f.domain_fqdn,f.object_class,f.subject_key,f.subject_kind,f.severity
            FROM finding_membership_review r JOIN finding f ON f.finding_id=r.finding_id CROSS JOIN judgement j
            """;
        using var row = command.ExecuteReader();
        while (row.Read())
        {
            token.ThrowIfCancellationRequested();
            if (row.IsDBNull(5) || !Enum.TryParse<Severity>(row.GetString(13), out var severity)) throw Invalid();
            var generation = Guid.Parse(row.GetString(3));
            var evidence = Decode(row.GetString(0), (byte[])row.GetValue(1), row.GetString(2), generation, row.GetString(4),
                Guid.Parse(row.GetString(5)), derivationSeal, row.GetString(6), Guid.Parse(row.GetString(7)), row.GetString(8),
                row.GetString(9), row.GetString(10), row.GetString(11), row.GetString(12), severity);
            ValidateSavedTotal(connection, evidence, generation);
        }
    }

    private static void ValidateSavedTotal(SqliteConnection connection, GroupMembershipReviewEvidence evidence, Guid generation)
    {
        if (evidence.ReviewKind != GroupMembershipReviewKind.PrivilegedGroupSize) return;
        var target = evidence.Principals.Single(identity => identity.ObjectGuid == evidence.TargetGuid);
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT g.object_guid,g.direct_members,g.known_total,g.unresolved_members,g.unreadable_members,g.membership_limitations
            FROM group_inventory g CROSS JOIN group_inventory_product p
            WHERE g.distinguished_name=$dn AND p.id=1 AND p.generation=$generation AND p.completed=1
            """;
        command.Parameters.AddWithValue("$dn", target.DistinguishedName);
        command.Parameters.AddWithValue("$generation", generation.ToString("D"));
        using var row = command.ExecuteReader();
        var total = evidence.KnownTotal;
        if (total is null || !row.Read() || row.IsDBNull(0) || row.IsDBNull(2) || row.IsDBNull(3) || row.IsDBNull(4) || row.IsDBNull(5)
            || row.GetString(0) != evidence.TargetGuid.ToString("D") || row.GetInt32(1) != evidence.DirectMembers
            || row.GetInt32(2) != total.KnownMembers || row.GetInt32(3) != total.UnresolvedReferences
            || row.GetInt32(4) != total.UnreadableReferences) throw Invalid();
        var flags = total.Limitations.Aggregate(GroupMembershipLimitations.None,
            (all, value) => all | Enum.Parse<GroupMembershipLimitations>(value));
        if (row.GetInt32(5) != (int)flags || row.Read()) throw Invalid();
    }

    private static void ValidateTotal(MembershipReviewKnownTotal total)
    {
        var allowed = Enum.GetValues<GroupMembershipLimitations>().Where(value => value != GroupMembershipLimitations.None)
            .Select(value => value.ToString()).ToHashSet(StringComparer.Ordinal);
        if (total.KnownMembers < 0 || total.UnresolvedReferences < 0 || total.UnreadableReferences < 0
            || total.Limitations is null || total.Limitations.Distinct(StringComparer.Ordinal).Count() != total.Limitations.Count
            || total.Limitations.Any(value => !allowed.Contains(value))
            || total.UnresolvedReferences > 0 != total.Limitations.Contains(nameof(GroupMembershipLimitations.UnresolvedReferences))
            || total.UnreadableReferences > 0 != total.Limitations.Contains(nameof(GroupMembershipLimitations.UnreadableReferences))) throw Invalid();
    }

    private static bool Seal(string value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigit);
    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    private static InvalidDataException Invalid() => new("The saved membership review does not match its source list, scoped identities, policy or generation.");
}
