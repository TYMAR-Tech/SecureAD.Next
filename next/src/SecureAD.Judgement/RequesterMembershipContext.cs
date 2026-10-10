using System.Collections.Immutable;
using System.Diagnostics.Metrics;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>One qualified, original member value, not a flattened authorization identity.</summary>
public sealed record RequesterMembershipLink(Tier0Target Member, Tier0Target Group, long GroupType,
    DateTimeOffset CapturedUtc, Tier0Evidence Witness, string SourceFingerprint);

/// <summary>A captured-only membership answer, including unavailable work and unsupported links.</summary>
public sealed record RequesterMembershipEvidence(PrincipalExpansionOutcome Verdict, string SourceFingerprint,
    IReadOnlyList<RequesterMembershipLink> Links, IReadOnlyList<PathRequesterSelectionReason> Limitations);

/// <summary>The captured resource domain and forest declaration, not a complete authentication token.</summary>
public sealed record RequesterResourceContext(Tier0Target ResourceDomain, IReadOnlyList<string> ReadDomains, string ScopeFingerprint)
{
    public bool IsComplete => ResourceDomain is { IsValid: true, ObjectGuid: not null, Sid: not null, DomainFqdn: not null }
        && ResourceDomain.DistinguishedName == ResourceDomain.NamingContext && ScopeFingerprint is { Length: 64 }
        && ReadDomains.Contains(ResourceDomain.DomainFqdn, StringComparer.OrdinalIgnoreCase);
}

internal sealed class RequesterMembershipContext : IDisposable
{
    internal const string MeterName = "SecureAD.Judgement.MembershipPreparation";
    private static readonly Meter Meter = new(MeterName);
    private static readonly Counter<long> AttributePreparations = Meter.CreateCounter<long>("membership.attribute_preparations");
    private static readonly Counter<long> SourceFingerprints = Meter.CreateCounter<long>("membership.source_fingerprints");
    private readonly DerivationReader _derivation;
    private readonly Tier0InputBinding _binding;
    private Func<string, ObjectAttributes?>? _read;
    private readonly Dictionary<string, Tier0Target> _identities = new(StringComparer.OrdinalIgnoreCase);
    private readonly IReadOnlyDictionary<string, NamingContextKind> _contexts;
    private readonly CancellationToken _cancellationToken;
    private readonly Dictionary<(string Sid, string Scope), List<Tier0Target>> _bySid = [];
    private readonly Dictionary<string, ObjectAttributes?> _attributes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _fingerprints = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Dictionary<string, AttributeValue>> _memberValues = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<(string Member, string Group), RequesterMembershipLink> _links = [];
    private readonly Dictionary<string, Expansion> _expansions = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string>? _readDomains;
    private string? _scopeFingerprint;
    private readonly Dictionary<string, Tier0Target?> _domainRoots = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, RequesterResourceContext> _resources = new(StringComparer.OrdinalIgnoreCase);
    private bool _disposed;

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
        (_derivation, _binding, _read, _contexts, _cancellationToken) =
            (derivation, binding, read, contexts, cancellationToken);
        foreach (var pair in identities)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var identity = pair.Value;
            _identities.Add(pair.Key, identity);
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
        RequireUsable();
        if (_binding != binding) throw Tier0PathStorage.InvalidProof();
    }

    internal bool HasForestScope
    {
        get { RequireUsable(); return _readDomains is not null; }
    }

    internal void BindForestScope(RunScope scope)
    {
        RequireUsable();
        var fingerprint = Tier0PathCalculation.Fingerprint(scope);
        if (_scopeFingerprint is not null && _scopeFingerprint != fingerprint) throw Tier0PathStorage.InvalidProof();
        _scopeFingerprint = fingerprint;
        _readDomains ??= scope.Domains.Where(domain => domain.Outcome == DomainReadOutcome.Read)
            .Select(domain => domain.DomainFqdn).ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    internal bool InResourceForest(Tier0Target subject, Tier0Target resource) => KnownDomain(subject) is not null && KnownDomain(resource) is not null;

    internal RequesterResourceContext? Resource(Tier0Target target)
    {
        if (KnownDomain(target) is not { } domain) return null;
        if (!_resources.TryGetValue(domain.NamingContext, out var value))
            _resources[domain.NamingContext] = value = new(domain,
                _readDomains!.Order(StringComparer.OrdinalIgnoreCase).ToImmutableArray(), _scopeFingerprint!);
        return value;
    }

    internal ObjectAttributes? Holder(PermissionTrustee trustee, Tier0Target resource)
    {
        RequireUsable();
        return trustee.Sid == "S-1-5-10" ? Attributes(resource.DistinguishedName)
            : Sid.IsBuiltinDomain(trustee.Sid) ? Resolve(trustee.Sid, resource.DomainFqdn) is { } local ? Attributes(local.DistinguishedName) : null
            : trustee.DistinguishedName is { } dn ? Attributes(dn) : null;
    }

    internal RequesterTrusteeEvidence Trustee(ObjectAttributes user, ObjectAttributes resource, PermissionTrustee trustee,
        ObjectAttributes? holder, string forest)
    {
        RequireUsable();
        return RequesterTrusteeReading.ReadSameForest(user, resource, trustee, holder, forest,
            _readDomains ?? throw Tier0PathStorage.InvalidProof());
    }

    private Tier0Target? KnownDomain(Tier0Target identity)
    {
        RequireUsable();
        if (_readDomains is null || identity.DomainFqdn is null || !_readDomains.Contains(identity.DomainFqdn) || !Domain(identity))
            return null;
        if (!_domainRoots.TryGetValue(identity.NamingContext, out var root))
        {
            root = _identities.GetValueOrDefault(identity.NamingContext);
            var source = Attributes(identity.NamingContext);
            if (root is null || !Qualified(source, root) || root.Sid is null
                || !RequesterTrusteeReading.HasClass(source, "domainDNS")) root = null;
            _domainRoots.Add(identity.NamingContext, root);
        }
        if (root is null || !Same(root.DomainFqdn, identity.DomainFqdn)) return null;
        return identity.Sid is null || Same(identity.Sid, root.Sid)
            || Sid.IsBuiltinDomain(identity.Sid) && Same(identity.SidScope, identity.DomainFqdn)
            || Same(Sid.IssuingDomain(identity.Sid), root.Sid) ? root : null;
    }

    internal bool Qualified(ObjectAttributes? source, Tier0Target? identity)
    {
        RequireUsable();
        return source is not null && identity is { ObjectGuid: not null, IsValid: true }
            && Tier0Target.From(source, identity.NamingContext) == identity
            && !RequesterTrusteeReading.HasClass(source, "foreignSecurityPrincipal")
            && !Same(source.Find("isDeleted")?.OnlyValue?.Text, "TRUE")
            && (identity.Sid is null || Resolve(identity.Sid, identity.SidScope) == identity);
    }

    internal IEnumerable<(string RequesterDn, RequesterMembershipEvidence Evidence)> Requesters(string holderDn)
    {
        var expansion = ExpansionFor(holderDn);
        foreach (var member in expansion.Members.Members ?? [])
        {
            RequireUsable();
            if (member.PathFromRoot.Count < 3 || Resolve(member.Sid, member.Scope) is not { } identity
                || !User(Attributes(identity.DistinguishedName))) continue;
            yield return (identity.DistinguishedName, Read(identity.DistinguishedName, holderDn));
        }
    }

    internal IEnumerable<(string RequesterDn, RequesterMembershipEvidence Evidence)> CapturedRequesters(string holderDn)
    {
        var expansion = ExpansionFor(holderDn, true);
        foreach (var member in expansion.Members.Members ?? [])
        {
            RequireUsable();
            if (Resolve(member.Sid, member.Scope) is not { } identity || !User(Attributes(identity.DistinguishedName))) continue;
            yield return (identity.DistinguishedName, Read(identity.DistinguishedName, holderDn, true));
        }
    }

    internal IReadOnlyList<(PathRequesterSelectionReason Reason, string Dn)> CapturedLimitations(string holderDn) =>
        ExpansionFor(holderDn, true).Limitations;

    internal IReadOnlyList<(PathRequesterSelectionReason Reason, string Dn)> Limitations(string holderDn) =>
        ExpansionFor(holderDn).Limitations;

    internal IReadOnlyList<(string GroupDn, RequesterMembershipEvidence Evidence)> Groups(string holderDn, Tier0Target resource)
    {
        RequireUsable();
        if (!_identities.TryGetValue(holderDn, out var holder) || !InResourceForest(holder, resource)) return [];
        var expansion = ExpansionFor(holderDn, true);
        if (expansion.Groups is null)
        {
            var result = new List<(string, RequesterMembershipEvidence)>();
            foreach (var member in expansion.Members.Members ?? [])
            {
                RequireUsable();
                if (Resolve(member.Sid, member.Scope) is not { } identity || !Global(Attributes(identity.DistinguishedName))) continue;
                result.Add((identity.DistinguishedName, Read(identity.DistinguishedName, holderDn, true)));
            }
            expansion.Groups = result;
        }
        return expansion.Groups.Where(route => AppliesToResource(route.Evidence, resource)).ToArray();
    }

    internal bool AppliesToResource(RequesterMembershipEvidence evidence, Tier0Target resource)
    {
        RequireUsable();
        return evidence.Links.Count != 0 && evidence.Links.All(link =>
            InResourceForest(link.Member, resource) && InResourceForest(link.Group, resource)
            && ((link.GroupType & 0x0f) is not (4 or 5) || Same(link.Group.DomainFqdn, resource.DomainFqdn)));
    }

    internal RequesterMembershipEvidence Read(string requesterDn, string holderDn) => Read(requesterDn, holderDn, false);

    internal RequesterMembershipEvidence Read(string requesterDn, string holderDn, bool sameForest)
    {
        var expansion = ExpansionFor(holderDn, sameForest);
        if (expansion.Routes.TryGetValue(requesterDn, out var existing)) return existing;
        var links = new List<RequesterMembershipLink>();
        if (_identities.TryGetValue(requesterDn, out var requester) && requester.Sid is { } sid
            && expansion.BySid.TryGetValue(sid, out var member))
        {
            for (var index = member.PathFromRoot.Count - 1; index > 0; index--)
            {
                RequireUsable();
                var domain = _identities[holderDn].DomainFqdn;
                var fromSid = member.PathFromRoot[index];
                var groupSid = member.PathFromRoot[index - 1];
                var from = Resolve(fromSid, Sid.IsBuiltinDomain(fromSid) ? domain : null) ?? throw Tier0PathStorage.InvalidProof();
                var group = Resolve(groupSid, Sid.IsBuiltinDomain(groupSid) ? domain : null) ?? throw Tier0PathStorage.InvalidProof();
                links.Add(Link(from, group));
            }
        }
        var result = new RequesterMembershipEvidence(expansion.Members.Outcome, expansion.Fingerprint, links.ToImmutableArray(),
            expansion.Limitations.Select(value => value.Reason).Distinct().Order().ToImmutableArray());
        expansion.Routes.Add(requesterDn, result);
        return result;
    }

    private Expansion ExpansionFor(string holderDn) => ExpansionFor(holderDn, false);

    private Expansion ExpansionFor(string holderDn, bool sameForest)
    {
        RequireUsable();
        var key = (sameForest ? "forest\0" : "global\0") + holderDn;
        if (_expansions.TryGetValue(key, out var existing)) return existing;
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
            SameForest = sameForest, ForestScope = sameForest ? _scopeFingerprint : null,
            Sources = sources.Order(StringComparer.OrdinalIgnoreCase).Select(dn => new PathRequesterSelectionSource(dn, Fingerprint(dn))).ToArray(),
        });
        var result = new Expansion(members, fingerprint, limits.OrderBy(value => value.Reason)
            .ThenBy(value => value.Dn, StringComparer.OrdinalIgnoreCase).ToArray());
        _expansions.Add(key, result);
        return result;

        bool Qualify((string Sid, string Scope) parent, (string Sid, string Scope) child)
        {
            RequireUsable();
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
            if (sameForest ? KnownDomain(group) is null || KnownDomain(member) is null
                : !Domain(group) || !Domain(member) || !Same(group.NamingContext, holder.NamingContext)
                || !Same(member.NamingContext, holder.NamingContext) || !Same(group.DomainFqdn, holder.DomainFqdn)
                || !Same(member.DomainFqdn, holder.DomainFqdn))
                return Limit(PathRequesterSelectionReason.ResourceContextUnsupported, member.DistinguishedName);
            var memberIsGroup = RequesterTrusteeReading.HasClass(memberSource, "group");
            if (sameForest ? !RequesterTrusteeReading.SupportsSecurityNesting(groupSource!, memberSource!)
                : !Global(groupSource) || memberIsGroup && !Global(memberSource))
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

    internal void RequireGroupSources(RequesterMembershipEvidence evidence, Tier0Target origin, Tier0Target resource,
        string trusteeSid, CancellationToken cancellationToken)
    {
        RequireUsable();
        cancellationToken.ThrowIfCancellationRequested();
        if (evidence.Links is not { Count: > 0 } || evidence.SourceFingerprint is not { Length: 64 }
            || !Enum.IsDefined(evidence.Verdict) || evidence.Limitations is null) throw Tier0PathStorage.InvalidProof();
        if (!Global(Attributes(origin.DistinguishedName))
            || !AppliesToResource(evidence, resource)) throw Tier0PathStorage.InvalidProof();
        var current = origin;
        var seen = new HashSet<Tier0Target> { origin };
        foreach (var link in evidence.Links)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (link is null || link.Member != current || link.Group is null || link.Witness is null
                || !seen.Add(link.Group)) throw Tier0PathStorage.InvalidProof();
            var member = Attributes(link.Member.DistinguishedName);
            var group = Attributes(link.Group.DistinguishedName);
            if (member is null || group is null
                || !Qualified(member, link.Member) || !Qualified(group, link.Group)
                || !RequesterTrusteeReading.SupportsSecurityNesting(group, member)
                || member.Find("sIDHistory")?.HasValue == true || group.Find("sIDHistory")?.HasValue == true
                || Tier0Target.From(member, link.Member.NamingContext) != link.Member
                || Tier0Target.From(group, link.Group.NamingContext) != link.Group
                || link.GroupType != RequesterTrusteeReading.Number(group, "groupType") || link.CapturedUtc != group.CapturedUtc
                || link.Witness.Object != link.Group || link.Witness.Attribute != "member"
                || !Same(link.Witness.Value, link.Member.DistinguishedName)
                || group.Find("member")?.Values.Any(value => value.Ordinal == link.Witness.Ordinal && value.Stored == link.Witness.Value) != true
                || link.SourceFingerprint != Tier0PathCalculation.Fingerprint(new
                {
                    Member = Fingerprint(link.Member.DistinguishedName), Group = Fingerprint(link.Group.DistinguishedName),
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
                RequireUsable();
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
        RequireUsable();
        if (!_attributes.TryGetValue(dn, out var value))
        {
            _attributes[dn] = value = (_read ?? throw Tier0PathStorage.InvalidProof())(dn)?.Snapshot();
            AttributePreparations.Add(1, new KeyValuePair<string, object?>("derivation", _binding.DerivationGenerationId.ToString("D")));
        }
        return value;
    }
    private string Fingerprint(string dn)
    {
        RequireUsable();
        if (!_fingerprints.TryGetValue(dn, out var value))
        {
            _fingerprints[dn] = value = Tier0PathCalculation.Fingerprint(Attributes(dn));
            SourceFingerprints.Add(1, new KeyValuePair<string, object?>("derivation", _binding.DerivationGenerationId.ToString("D")));
        }
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

    private void RequireUsable()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _cancellationToken.ThrowIfCancellationRequested();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _read = null;
        _identities.Clear();
        _bySid.Clear();
        _attributes.Clear();
        _fingerprints.Clear();
        _memberValues.Clear();
        _links.Clear();
        _expansions.Clear();
        _domainRoots.Clear();
        _resources.Clear();
        _readDomains = null;
        _scopeFingerprint = null;
    }
}
