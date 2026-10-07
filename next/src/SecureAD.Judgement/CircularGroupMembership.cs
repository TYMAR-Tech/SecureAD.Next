using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>SEC-052 reports recorded circular membership, not effective permission or a Tier 0 route.</summary>
public sealed class CircularGroupMembership : IObjectRule
{
    internal const string Explanation = "These groups form a circular membership relationship. Review the recorded links and the membership "
        + "or permissions that depend on them; this finding does not establish a route to Tier 0.";
    internal const string Guidance = "Remove unintended nesting links after reviewing their impact. A set containing "
        + "overlapping loops may require more than one link to be removed.";

    public RuleDefinition Definition { get; } = new("SEC-052", "Circular group membership", Severity.Medium, 1,
        ["group"], ["objectClass", "objectSid"], [nameof(DerivedFactKind.NestingCycles)]);

    public RuleVerdict Judge(ObjectAttributes subject) =>
        throw new InvalidOperationException("SEC-052 requires its declared saved cycle product.");

    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(context);
        if (!RequesterTrusteeReading.HasClass(subject, "group")) return RuleVerdict.Judged([]);
        if (context.NestingCycles is not { } cycles)
            return RuleVerdict.CouldNotResolve([new(DerivedFactKind.NestingCycles, UnresolvedReason.NotDerived)]);
        if (subject.ObjectGuid is null || RequesterTrusteeReading.SidOf(subject) is null)
            return RuleVerdict.CouldNotResolve([new(DerivedFactKind.NestingCycles, UnresolvedReason.IdentityUnreadable)]);
        var findings = new List<Finding>();
        if (cycles.Findings.TryGetValue(subject.ObjectGuid.Value, out var evidence))
        {
            var anchor = evidence.Groups[0];
            if (anchor.DistinguishedName != subject.DistinguishedName || anchor.DomainFqdn != subject.DomainFqdn)
                throw new InvalidDataException("The saved cycle anchor does not match its captured group.");
            var names = evidence.Groups.ToDictionary(group => group.ObjectGuid, group => group.DistinguishedName);
            var detail = Explanation + "\n\nGroups:\n" + string.Join("\n", evidence.Groups.Select(group => group.DistinguishedName))
                + "\n\nRecorded membership links:\n" + string.Join("\n", evidence.Links.Select(link =>
                    names[link.GroupGuid] + " contains " + names[link.MemberGuid]));
            findings.Add(new("SEC-052", 1, Severity.Medium,
                new(FindingSubjectKind.DirectoryObject, evidence.ComponentKey), anchor.ObjectGuid, subject.DistinguishedName,
                subject.DomainFqdn!, "group", detail, subject.Completeness, evidence)
                { PrincipalName = anchor.DistinguishedName });
        }
        return new(findings, [], cycles.IsComplete ? [] : [new(DerivedFactKind.NestingCycles, UnresolvedReason.MembershipIncomplete)]);
    }
}

internal sealed record CircularMembershipIndex(bool IsComplete, IReadOnlyDictionary<Guid, CircularMembershipEvidence> Findings)
{
    internal static CircularMembershipIndex Create(StoredDerivation facts, CapturedMembershipInput input,
        IReadOnlyDictionary<int, (string Sid, string Scope)> identities, string evidenceSeal, CancellationToken cancellationToken)
    {
        if (input.DerivationGenerationId != facts.Description.GenerationId
            || facts.Description.EvidenceSeal != evidenceSeal) throw new InvalidDataException("Cycle input generation mismatch.");
        var product = facts.NestingCycles;
        if (product.Availability is not (NestingCycleAvailability.Available or NestingCycleAvailability.Partial) || product.Cycles is null)
            throw new InvalidDataException("The declared cycle product is unavailable.");
        var complete = product.IsComplete && facts.Completeness.IsComplete && input.IsComplete;
        var groups = new Dictionary<(string Sid, string Scope), List<ObjectAttributes>>();
        foreach (var source in input.Objects)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!RequesterTrusteeReading.HasClass(source, "group")) continue;
            if (source.Completeness != EvidenceCompleteness.Complete) complete = false;
            if (RequesterTrusteeReading.SidOf(source) is not { } sid) { complete = false; continue; }
            var key = (sid.ToUpperInvariant(), Sid.IsBuiltinDomain(sid) ? source.DomainFqdn?.ToUpperInvariant() ?? "" : "");
            if (!groups.TryGetValue(key, out var matches)) groups[key] = matches = [];
            matches.Add(source);
        }
        var findings = new Dictionary<Guid, CircularMembershipEvidence>();
        var claimed = new HashSet<Guid>();
        foreach (var component in product.Cycles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var sources = new List<ObjectAttributes>();
            foreach (var id in component)
            {
                if (!identities.TryGetValue(id, out var identity)
                    || !groups.TryGetValue((identity.Sid.ToUpperInvariant(), identity.Scope.ToUpperInvariant()), out var matches)
                    || matches.Count != 1 || matches[0].ObjectGuid is null || string.IsNullOrWhiteSpace(matches[0].DomainFqdn))
                    break;
                sources.Add(matches[0]);
            }
            if (sources.Count != component.Count || sources.Count == 0) { complete = false; continue; }
            var members = sources.Select(source => new CircularMembershipGroup(source.ObjectGuid!.Value,
                source.DistinguishedName, source.DomainFqdn!, RequesterTrusteeReading.SidOf(source)!,
                Sid.IsBuiltinDomain(RequesterTrusteeReading.SidOf(source)!) ? source.DomainFqdn : null))
                .OrderBy(group => group.ObjectGuid.ToString("D"), StringComparer.Ordinal).ToArray();
            if (members.Select(group => group.ObjectGuid).Distinct().Count() != members.Length
                || members.Any(group => claimed.Contains(group.ObjectGuid)))
                throw new InvalidDataException("Saved cycle sets overlap or contain ambiguous group identities.");
            var byDn = members.ToDictionary(group => group.DistinguishedName, StringComparer.OrdinalIgnoreCase);
            var links = new Dictionary<(Guid Group, Guid Member), List<CircularMembershipWitness>>();
            foreach (var source in sources)
                foreach (var attribute in new[] { "member", "memberOf" })
                    foreach (var value in source.Find(attribute)?.Values ?? [])
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        if (value.Text is null || !byDn.TryGetValue(value.Text, out var other)) continue;
                        var key = attribute == "member" ? (source.ObjectGuid!.Value, other.ObjectGuid)
                            : (other.ObjectGuid, source.ObjectGuid!.Value);
                        if (!links.TryGetValue(key, out var witnesses)) links[key] = witnesses = [];
                        witnesses.Add(new(source.ObjectGuid.Value, attribute, value.Ordinal, value.Text));
                    }
            var savedLinks = links.OrderBy(pair => pair.Key.Group).ThenBy(pair => pair.Key.Member)
                .Select(pair => new CircularMembershipLink(pair.Key.Group, pair.Key.Member,
                    pair.Value.OrderBy(value => value.SourceObjectGuid).ThenBy(value => value.Attribute, StringComparer.Ordinal)
                        .ThenBy(value => value.Ordinal).ToArray())).ToArray();
            if (!Connected(members, savedLinks, cancellationToken)) { complete = false; continue; }
            foreach (var group in members) claimed.Add(group.ObjectGuid);
            var keyValue = Key(members);
            findings.Add(members[0].ObjectGuid, new(evidenceSeal, facts.Description.GenerationId, keyValue, members, savedLinks, false));
        }
        return new(complete, findings.ToDictionary(pair => pair.Key, pair => pair.Value with { InventoryComplete = complete }));
    }

    internal static string Key(IReadOnlyList<CircularMembershipGroup> groups) =>
        "cycle:" + Tier0PathCalculation.Fingerprint(groups.Select(group => group.ObjectGuid.ToString("D")).Order(StringComparer.Ordinal));

    internal static bool Connected(IReadOnlyList<CircularMembershipGroup> groups, IReadOnlyList<CircularMembershipLink> links,
        CancellationToken cancellationToken)
    {
        if (groups.Count == 0 || links.Count == 0) return false;
        var ids = groups.Select(group => group.ObjectGuid).ToHashSet();
        if (links.Any(link => !ids.Contains(link.GroupGuid) || !ids.Contains(link.MemberGuid))) return false;
        foreach (var reverse in new[] { false, true })
        {
            var adjacent = links.GroupBy(link => reverse ? link.MemberGuid : link.GroupGuid)
                .ToDictionary(group => group.Key, group => group.Select(link => reverse ? link.GroupGuid : link.MemberGuid).ToArray());
            var seen = new HashSet<Guid> { groups[0].ObjectGuid };
            var pending = new Stack<Guid>();
            pending.Push(groups[0].ObjectGuid);
            while (pending.TryPop(out var current))
            {
                cancellationToken.ThrowIfCancellationRequested();
                foreach (var next in adjacent.GetValueOrDefault(current) ?? [])
                    if (seen.Add(next)) pending.Push(next);
            }
            if (seen.Count != groups.Count) return false;
        }
        return true;
    }
}
