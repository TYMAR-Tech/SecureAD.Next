using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal sealed partial class CapturedGroupMembershipIndex
{
    internal sealed record ReviewAssessment(IReadOnlyList<GroupMembershipReviewEvidence> Evidence,
        IReadOnlyList<string> Missing, IReadOnlyList<UnresolvedInput> Unresolved);

    internal ReviewAssessment Review(ObjectAttributes subject, GroupMembershipReviewKind kind)
    {
        _token.ThrowIfCancellationRequested();
        if (!Enum.IsDefined(kind)) throw new ArgumentOutOfRangeException(nameof(kind));
        var limits = (kind == GroupMembershipReviewKind.PrivilegedGroupSize
            ? _inventoryLimitations : _domainAdminInventoryLimitations).ToHashSet();
        var domains = new Dictionary<string, AdministrativeMembershipIdentity>(StringComparer.OrdinalIgnoreCase);
        if (!_input.IsComplete) limits.Add(new(subject.DistinguishedName, AdministrativeMembershipReason.CaptureIncomplete));
        var source = _input.FindUnique(subject.DistinguishedName, _token);
        if (source is null || source.ObjectGuid != subject.ObjectGuid || source.CapturedUtc != subject.CapturedUtc
            || source.Completeness != subject.Completeness || !Same(source.DomainFqdn, subject.DomainFqdn)
            || new[] { "objectClass", "objectSid", "groupType", "isDeleted" }.Any(name =>
                !Values(source, name).Select(ValueKey).SequenceEqual(Values(subject, name).Select(ValueKey))))
        {
            limits.Add(new(subject.DistinguishedName, AdministrativeMembershipReason.IdentityUnverified));
            return Result([], []);
        }
        var sid = ReadSid(source);
        if (sid is null) return Result([], ["objectSid"]);
        var definition = PrincipalClassificationRegistry.For(sid);
        if (!IsTarget(definition) || kind == GroupMembershipReviewKind.GroupNestedInDomainAdmins && !IsDomainAdmins(definition))
            return Result([], []);
        var context = NamingContext(source);
        if (definition.Tier0Scope == Tier0IdentityScope.ForestRoot && _binding.ForestRootNamingContext is { } root
            && context is not null && !Same(context, root)) return Result([], []);
        if (!Values(source, "member").Select(ValueKey).SequenceEqual(Values(subject, "member").Select(ValueKey)))
        {
            limits.Add(new(subject.DistinguishedName, AdministrativeMembershipReason.IdentityUnverified));
            return Result([], []);
        }
        var target = QualifiedIdentity(source, domains, limits);
        if (target is null) return Result([], []);
        if (!TargetScopeMatches(target, definition, _binding.ForestRootNamingContext))
        {
            limits.Add(new(source.DistinguishedName, target.GroupType is null
                ? AdministrativeMembershipReason.GroupTypeUnavailable : AdministrativeMembershipReason.GroupScopeUnsupported));
            return Result([], []);
        }
        var values = source.Find("member")?.Values;
        if (values is not { Count: > 0 })
        {
            limits.Add(new(source.DistinguishedName, AdministrativeMembershipReason.MembershipValuesUnavailable));
            return Result([], ["member"]);
        }
        if (!OrderedValues(values) || values.Any(value => !MembershipValue(value)))
            limits.Add(new(source.DistinguishedName, AdministrativeMembershipReason.MembershipValuesMalformed));
        if (values.Any(value => value.Ordinal < 0 || value.Text is not null && value.Bytes is not null))
            return Result([], ["member"]);
        if (kind == GroupMembershipReviewKind.PrivilegedGroupSize)
        {
            var count = GroupInventoryStorage.DirectCount(values);
            var threshold = LargePrivilegedGroupReview.ThresholdFor(definition);
            return Result(count > threshold
                ? [Proof([target], values.ToArray(), [], null, count, threshold)] : [], []);
        }
        var nested = new Dictionary<Guid, DirectGroupReview>();
        foreach (var value in values)
        {
            _token.ThrowIfCancellationRequested();
            if (!MembershipValue(value)) continue;
            var referenceSource = _input.FindUnique(value.Text!, _token);
            if (referenceSource is null)
            {
                limits.Add(new(source.DistinguishedName, AdministrativeMembershipReason.MemberUncaptured));
                continue;
            }
            var memberSource = referenceSource;
            if (RequesterTrusteeReading.HasClass(referenceSource, "foreignSecurityPrincipal"))
            {
                var referenceSid = ReadSid(referenceSource);
                if (referenceSid is null)
                {
                    limits.Add(new(referenceSource.DistinguishedName, AdministrativeMembershipReason.IdentityUnverified));
                    continue;
                }
                if (Special(referenceSid)) continue;
                var key = Key(referenceSid, referenceSource.DomainFqdn);
                if (!_groups.TryGetValue(key, out var matches) || matches.Count != 1)
                {
                    if (_identities.GetValueOrDefault(key) is { Count: 1, KnownAccount: true }) continue;
                    limits.Add(new(referenceSource.DistinguishedName, _historicalIdentities.Contains(key)
                        ? AdministrativeMembershipReason.HistoricalIdentityUnsupported : AdministrativeMembershipReason.ForeignPrincipalUnresolved));
                    continue;
                }
                memberSource = matches[0];
                if (!Same(referenceSource.DomainFqdn, target.DomainFqdn))
                {
                    limits.Add(new(referenceSource.DistinguishedName, AdministrativeMembershipReason.GroupScopeUnsupported));
                    continue;
                }
            }
            if (!RequesterTrusteeReading.HasClass(memberSource, "group"))
            {
                if (memberSource.Find("objectClass")?.HasValue != true)
                    limits.Add(new(memberSource.DistinguishedName, AdministrativeMembershipReason.IdentityUnverified));
                continue;
            }
            var member = QualifiedIdentity(memberSource, domains, limits);
            var reference = QualifiedIdentity(referenceSource, domains, limits);
            if (member is null || reference is null) continue;
            if (member.GroupType is null)
                limits.Add(new(member.DistinguishedName, AdministrativeMembershipReason.GroupTypeUnavailable));
            if (!nested.TryGetValue(member.ObjectGuid, out var review))
                nested.Add(member.ObjectGuid, review = new(member));
            review.Principals.TryAdd(reference.ObjectGuid, reference);
            if (!review.Witnesses.TryGetValue(reference.ObjectGuid, out var witnesses))
                review.Witnesses.Add(reference.ObjectGuid, witnesses = []);
            witnesses.Add(new(target.ObjectGuid, "member", value.Ordinal, value.Text!));
            review.Values.Add(value);
        }
        return Result(nested.OrderBy(pair => pair.Key).Select(pair =>
        {
            var review = pair.Value;
            var principals = review.Principals.Values.Append(target).DistinctBy(identity => identity.ObjectGuid)
                .OrderBy(identity => identity.ObjectGuid).ToArray();
            var links = review.Witnesses.OrderBy(value => value.Key).Select(value =>
                new AdministrativeMembershipLink(target.ObjectGuid, review.Member.ObjectGuid, value.Key,
                    value.Value.Distinct().OrderBy(witness => witness.Ordinal).ToArray())).ToArray();
            return Proof(principals, review.Values.OrderBy(value => value.Ordinal).ToArray(), links, review.Member.ObjectGuid, null, null);
        }).ToArray(), []);

        GroupMembershipReviewEvidence Proof(IReadOnlyList<AdministrativeMembershipIdentity> principals, IReadOnlyList<AttributeValue> members,
            IReadOnlyList<AdministrativeMembershipLink> links, Guid? child, int? direct, int? threshold)
        {
            var domainNames = principals.Where(identity => identity.DomainFqdn is not null).Select(identity => identity.DomainFqdn!)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            return new(_binding.EvidenceSeal, _binding.DerivationGenerationId, _binding.DerivationSeal,
                PrincipalClassificationRegistry.Version, GroupMembershipReviewRules.PolicyVersion, _binding.ForestRootNamingContext,
                _binding.ConfigurationNamingContext, kind, target.ObjectGuid, child, principals,
                domains.Values.Where(domain => domainNames.Contains(domain.DomainFqdn!))
                    .OrderBy(domain => domain.DistinguishedName, StringComparer.OrdinalIgnoreCase).ToArray(),
                members, links, direct, threshold, null, _input.IsComplete, limits.OrderBy(limit => limit.Reason)
                    .ThenBy(limit => limit.DistinguishedName, StringComparer.OrdinalIgnoreCase).ToArray());
        }
        ReviewAssessment Result(IReadOnlyList<GroupMembershipReviewEvidence> evidence, IReadOnlyList<string> missing) =>
            new(evidence, missing, limits.Select(limit => new UnresolvedInput(DerivedFactKind.AdministrativeMembership, Reason(limit.Reason)))
                .Distinct().OrderBy(value => value.Reason).ToArray());
    }

    internal static bool IsDomainAdmins(PrincipalClassification definition) =>
        IsTarget(definition) && definition.Tier0Scope == Tier0IdentityScope.Domain;

    private static IReadOnlyList<AttributeValue> Values(ObjectAttributes source, string attribute) => source.Find(attribute)?.Values ?? [];
    private static (int Ordinal, string? Text, string? Bytes) ValueKey(AttributeValue value) =>
        (value.Ordinal, value.Text, value.Bytes is null ? null : Convert.ToHexString(value.Bytes));

    private sealed class DirectGroupReview(AdministrativeMembershipIdentity member)
    {
        internal AdministrativeMembershipIdentity Member { get; } = member;
        internal Dictionary<Guid, AdministrativeMembershipIdentity> Principals { get; } = new() { [member.ObjectGuid] = member };
        internal Dictionary<Guid, List<AdministrativeMembershipWitness>> Witnesses { get; } = [];
        internal List<AttributeValue> Values { get; } = [];
    }
}
