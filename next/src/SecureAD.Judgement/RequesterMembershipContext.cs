using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Naming;

namespace SecureAD.Judgement;

/// <summary>One qualified, original member value, not a flattened authorization identity.</summary>
public sealed record RequesterMembershipLink(Tier0Target Member, Tier0Target Group, long GroupType,
    DateTimeOffset CapturedUtc, Tier0Evidence Witness, string SourceFingerprint);

/// <summary>A captured-only membership answer, including unavailable work and unsupported links.</summary>
public sealed record RequesterMembershipEvidence(PrincipalExpansionOutcome Verdict, string SourceFingerprint,
    IReadOnlyList<RequesterMembershipLink> Links, IReadOnlyList<PathRequesterSelectionReason> Limitations);

internal sealed class RequesterMembershipContext
{
    private readonly DerivationReader _derivation;
    private readonly Tier0InputBinding _binding;
    private readonly Func<string, ObjectAttributes?> _read;
    private readonly IReadOnlyDictionary<string, Tier0Target> _identities;
    private readonly IReadOnlyDictionary<string, NamingContextKind> _contexts;
    private readonly CancellationToken _cancellationToken;
    private readonly Dictionary<(string Sid, string Scope), List<Tier0Target>> _bySid = [];
    private readonly Dictionary<string, ObjectAttributes?> _attributes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _fingerprints = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Dictionary<string, AttributeValue>> _memberValues = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<(string Member, string Group), RequesterMembershipLink> _links = [];
    private readonly Dictionary<string, Expansion> _expansions = new(StringComparer.OrdinalIgnoreCase);

    private sealed record Expansion(PrincipalExpansion Members, string Fingerprint,
        IReadOnlyList<(PathRequesterSelectionReason Reason, string Dn)> Limitations)
    {
        internal Dictionary<string, ExpandedPrincipal> BySid { get; } = (Members.Members ?? [])
            .ToDictionary(member => member.Sid, StringComparer.OrdinalIgnoreCase);
        internal Dictionary<string, RequesterMembershipEvidence> Routes { get; } = new(StringComparer.OrdinalIgnoreCase);
        internal IReadOnlyList<(string GroupDn, RequesterMembershipEvidence Evidence)>? Groups { get; set; }
    }

    internal RequesterMembershipContext(DerivationReader derivation, Tier0InputBinding binding,
        Func<string, ObjectAttributes?> read, IReadOnlyDictionary<string, Tier0Target> identities,
        IReadOnlyDictionary<string, NamingContextKind> contexts, CancellationToken cancellationToken)
    {
        if (derivation.Description.GenerationId != binding.DerivationGenerationId
            || derivation.Description.EvidenceSeal != binding.EvidenceSeal) throw Tier0PathStorage.InvalidProof();
        (_derivation, _binding, _read, _identities, _contexts, _cancellationToken) =
            (derivation, binding, read, identities, contexts, cancellationToken);
        foreach (var identity in identities.Values)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (identity.Sid is not { } sid) continue;
            var key = Key(sid, identity.SidScope);
            if (!_bySid.TryGetValue(key, out var values)) _bySid[key] = values = [];
            values.Add(identity);
        }
    }

    internal static RequesterMembershipContext? Create(JudgingInputs sources,
        IReadOnlyDictionary<string, Tier0Target> identities, PathInputs inputs, CancellationToken cancellationToken)
    {
        if (inputs.Availability != PathInputAvailability.Recorded) return null;
        var binding = inputs.Input ?? throw Tier0PathStorage.InvalidProof();
        return sources.RequesterMemberships(binding, identities, cancellationToken);
    }

    internal void RequireBinding(Tier0InputBinding binding)
    {
        if (_binding != binding) throw Tier0PathStorage.InvalidProof();
    }

    internal bool Qualified(ObjectAttributes? source, Tier0Target? identity) =>
        source is not null && identity is { ObjectGuid: not null, IsValid: true }
        && Tier0Target.From(source, identity.NamingContext) == identity
        && !RequesterTrusteeReading.HasClass(source, "foreignSecurityPrincipal")
        && !Same(source.Find("isDeleted")?.OnlyValue?.Text, "TRUE")
        && (identity.Sid is null || Resolve(identity.Sid, identity.SidScope) == identity);

    internal IEnumerable<(string RequesterDn, RequesterMembershipEvidence Evidence)> Requesters(string holderDn)
    {
        var expansion = ExpansionFor(holderDn);
        foreach (var member in expansion.Members.Members ?? [])
        {
            _cancellationToken.ThrowIfCancellationRequested();
            if (member.PathFromRoot.Count < 3 || Resolve(member.Sid, member.Scope) is not { } identity
                || !User(Attributes(identity.DistinguishedName))) continue;
            yield return (identity.DistinguishedName, Read(identity.DistinguishedName, holderDn));
        }
    }

    internal IReadOnlyList<(PathRequesterSelectionReason Reason, string Dn)> Limitations(string holderDn) =>
        ExpansionFor(holderDn).Limitations;

    internal IReadOnlyList<(string GroupDn, RequesterMembershipEvidence Evidence)> Groups(string holderDn)
    {
        if (!Global(Attributes(holderDn))) return [];
        var expansion = ExpansionFor(holderDn);
        if (expansion.Groups is { } existing) return existing;
        var result = new List<(string, RequesterMembershipEvidence)>();
        foreach (var member in expansion.Members.Members ?? [])
        {
            _cancellationToken.ThrowIfCancellationRequested();
            if (Resolve(member.Sid, member.Scope) is not { } identity || !Global(Attributes(identity.DistinguishedName))) continue;
            result.Add((identity.DistinguishedName, Read(identity.DistinguishedName, holderDn)));
        }
        return expansion.Groups = result;
    }

    internal RequesterMembershipEvidence Read(string requesterDn, string holderDn)
    {
        var expansion = ExpansionFor(holderDn);
        if (expansion.Routes.TryGetValue(requesterDn, out var existing)) return existing;
        var links = new List<RequesterMembershipLink>();
        if (_identities.TryGetValue(requesterDn, out var requester) && requester.Sid is { } sid
            && expansion.BySid.TryGetValue(sid, out var member))
        {
            for (var index = member.PathFromRoot.Count - 1; index > 0; index--)
            {
                _cancellationToken.ThrowIfCancellationRequested();
                var from = Resolve(member.PathFromRoot[index], null) ?? throw Tier0PathStorage.InvalidProof();
                var group = Resolve(member.PathFromRoot[index - 1], null) ?? throw Tier0PathStorage.InvalidProof();
                links.Add(Link(from, group));
            }
        }
        var result = new RequesterMembershipEvidence(expansion.Members.Outcome, expansion.Fingerprint, links,
            expansion.Limitations.Select(value => value.Reason).Distinct().Order().ToArray());
        expansion.Routes.Add(requesterDn, result);
        return result;
    }

    private Expansion ExpansionFor(string holderDn)
    {
        _cancellationToken.ThrowIfCancellationRequested();
        if (_expansions.TryGetValue(holderDn, out var existing)) return existing;
        var holder = _identities.GetValueOrDefault(holderDn) ?? throw Tier0PathStorage.InvalidProof();
        var limits = new HashSet<(PathRequesterSelectionReason Reason, string Dn)>();
        var sources = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { holderDn };
        var members = _derivation.MembersOf(holder.Sid ?? throw Tier0PathStorage.InvalidProof(),
            holder.SidScope ?? "", Qualify, _cancellationToken);
        if (members.Outcome == PrincipalExpansionOutcome.NoNestingDerived)
            limits.Add((PathRequesterSelectionReason.InputsUnavailable, holderDn));
        else if (members.Outcome is PrincipalExpansionOutcome.PrincipalNotFound or PrincipalExpansionOutcome.PrincipalDoesNotExist
            or PrincipalExpansionOutcome.ExpandedWithUnidentifiedMember)
            limits.Add((PathRequesterSelectionReason.IdentityUnresolved, holderDn));
        var fingerprint = Tier0PathCalculation.Fingerprint(new
        {
            Input = _binding, Holder = holder, members.Outcome,
            Sources = sources.Order(StringComparer.OrdinalIgnoreCase).Select(dn => new PathRequesterSelectionSource(dn, Fingerprint(dn))).ToArray(),
        });
        var result = new Expansion(members, fingerprint, limits.OrderBy(value => value.Reason)
            .ThenBy(value => value.Dn, StringComparer.OrdinalIgnoreCase).ToArray());
        _expansions.Add(holderDn, result);
        return result;

        bool Qualify((string Sid, string Scope) parent, (string Sid, string Scope) child)
        {
            _cancellationToken.ThrowIfCancellationRequested();
            var group = Resolve(parent.Sid, parent.Scope);
            var member = Resolve(child.Sid, child.Scope);
            if (group is null || member is null)
            {
                limits.Add((PathRequesterSelectionReason.IdentityUnresolved, group?.DistinguishedName ?? holderDn));
                return false;
            }
            sources.Add(group.DistinguishedName);
            sources.Add(member.DistinguishedName);
            var groupSource = Attributes(group.DistinguishedName);
            var memberSource = Attributes(member.DistinguishedName);
            if (!Qualified(groupSource, group) || !Qualified(memberSource, member))
                return Limit(PathRequesterSelectionReason.IdentityUnresolved, member.DistinguishedName);
            if (!Domain(group) || !Domain(member) || !Same(group.NamingContext, holder.NamingContext)
                || !Same(member.NamingContext, holder.NamingContext) || !Same(group.DomainFqdn, holder.DomainFqdn)
                || !Same(member.DomainFqdn, holder.DomainFqdn))
                return Limit(PathRequesterSelectionReason.ResourceContextUnsupported, member.DistinguishedName);
            var memberIsGroup = RequesterTrusteeReading.HasClass(memberSource, "group");
            if (!Global(groupSource) || memberIsGroup && !Global(memberSource))
                return Limit(PathRequesterSelectionReason.GlobalGroupRequired, member.DistinguishedName);
            if (!memberIsGroup && !User(memberSource))
                return Limit(PathRequesterSelectionReason.RequesterKindUnsupported, member.DistinguishedName);
            if (groupSource!.Find("sIDHistory")?.HasValue == true
                || memberIsGroup && memberSource!.Find("sIDHistory")?.HasValue == true)
                return Limit(PathRequesterSelectionReason.PermissionUnsupported, group.DistinguishedName);
            if (MemberValue(group.DistinguishedName, member.DistinguishedName) is null)
                return Limit(PathRequesterSelectionReason.MembershipVisibilityUnknown, member.DistinguishedName);
            return true;
        }

        bool Limit(PathRequesterSelectionReason reason, string dn)
        {
            limits.Add((reason, dn));
            return false;
        }
    }

    private RequesterMembershipLink Link(Tier0Target from, Tier0Target group)
    {
        var key = (from.DistinguishedName.ToUpperInvariant(), group.DistinguishedName.ToUpperInvariant());
        if (_links.TryGetValue(key, out var existing)) return existing;
        var source = Attributes(group.DistinguishedName) ?? throw Tier0PathStorage.InvalidProof();
        var witness = MemberValue(group.DistinguishedName, from.DistinguishedName) ?? throw Tier0PathStorage.InvalidProof();
        var link = new RequesterMembershipLink(from, group, RequesterTrusteeReading.Number(source, "groupType")!.Value,
            source.CapturedUtc, new(group, "member", witness.Ordinal, witness.Stored),
            Tier0PathCalculation.Fingerprint(new { Member = Fingerprint(from.DistinguishedName), Group = Fingerprint(group.DistinguishedName) }));
        _links.Add(key, link);
        return link;
    }

    internal static void RequireGroupSources(RequesterMembershipEvidence evidence, Tier0Target origin, Tier0Target resource,
        string trusteeSid, Func<string, ObjectAttributes?> attributes, CancellationToken cancellationToken)
    {
        if (evidence.Links is not { Count: > 0 } || evidence.SourceFingerprint is not { Length: 64 }
            || !Enum.IsDefined(evidence.Verdict) || evidence.Limitations is null) throw Tier0PathStorage.InvalidProof();
        var current = origin;
        var seen = new HashSet<Tier0Target> { origin };
        foreach (var link in evidence.Links)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (link is null || link.Member != current || link.Group is null || link.Witness is null
                || !seen.Add(link.Group)) throw Tier0PathStorage.InvalidProof();
            var member = attributes(link.Member.DistinguishedName);
            var group = attributes(link.Group.DistinguishedName);
            if (member is null || group is null || !Global(member) || !Global(group)
                || member.Find("sIDHistory")?.HasValue == true || group.Find("sIDHistory")?.HasValue == true
                || Tier0Target.From(member, resource.NamingContext) != link.Member
                || Tier0Target.From(group, resource.NamingContext) != link.Group
                || !Same(link.Member.DomainFqdn, resource.DomainFqdn) || !Same(link.Group.DomainFqdn, resource.DomainFqdn)
                || link.GroupType != RequesterTrusteeReading.Number(group, "groupType") || link.CapturedUtc != group.CapturedUtc
                || link.Witness.Object != link.Group || link.Witness.Attribute != "member"
                || !Same(link.Witness.Value, link.Member.DistinguishedName)
                || group.Find("member")?.Values.Any(value => value.Ordinal == link.Witness.Ordinal && value.Stored == link.Witness.Value) != true
                || link.SourceFingerprint != Tier0PathCalculation.Fingerprint(new
                {
                    Member = Tier0PathCalculation.Fingerprint(member), Group = Tier0PathCalculation.Fingerprint(group),
                })) throw Tier0PathStorage.InvalidProof();
            current = link.Group;
        }
        if (!Same(current.Sid, trusteeSid)) throw Tier0PathStorage.InvalidProof();
    }

    private AttributeValue? MemberValue(string group, string member)
    {
        if (!_memberValues.TryGetValue(group, out var values))
        {
            values = new(StringComparer.OrdinalIgnoreCase);
            foreach (var value in Attributes(group)?.Find("member")?.Values ?? [])
            {
                _cancellationToken.ThrowIfCancellationRequested();
                if (!string.IsNullOrWhiteSpace(value.Text)) values.TryAdd(value.Text, value);
            }
            _memberValues.Add(group, values);
        }
        return values.GetValueOrDefault(member);
    }

    private Tier0Target? Resolve(string sid, string? scope) =>
        _bySid.TryGetValue(Key(sid, scope), out var values) && values.Count == 1 ? values[0] : null;
    private ObjectAttributes? Attributes(string dn)
    {
        if (!_attributes.TryGetValue(dn, out var value)) _attributes[dn] = value = _read(dn);
        return value;
    }
    private string Fingerprint(string dn)
    {
        if (!_fingerprints.TryGetValue(dn, out var value))
            _fingerprints[dn] = value = Tier0PathCalculation.Fingerprint(Attributes(dn));
        return value;
    }
    private bool Domain(Tier0Target identity) => _contexts.TryGetValue(identity.NamingContext, out var kind)
        && kind == NamingContextKind.Domain && !string.IsNullOrWhiteSpace(identity.DomainFqdn)
        && Same(DnHelper.DnToFqdn(identity.NamingContext), identity.DomainFqdn);
    private static bool Global(ObjectAttributes? source) => RequesterTrusteeReading.HasClass(source, "group")
        && RequesterTrusteeReading.Number(source, "groupType") is { } type && (type & 0x8000000fL) == 0x80000002L;
    private static bool User(ObjectAttributes? source) => RequesterTrusteeReading.HasClass(source, "user")
        && !RequesterTrusteeReading.HasClass(source, "computer");
    private static (string, string) Key(string sid, string? scope) => (sid.ToUpperInvariant(), (scope ?? "").ToUpperInvariant());
    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}
