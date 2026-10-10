using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>SEC-062 reports source-qualified broad membership, not logon, takeover or a computed Tier 0 path.</summary>
public sealed class BroadAdministrativeGroupMembership : IObjectRule
{
    internal const int PolicyVersion = 1;
    internal const string MembershipSummary = "Broad membership reaches this administrative group through the recorded security-group relationships.";
    internal const string ScopeNote = "This finding does not prove a successful logon or account takeover.";
    internal const string Explanation = MembershipSummary + " " + ScopeNote;
    internal const string Guidance = "Review and remove unintended broad membership paths, replace them with role-specific security groups, "
        + "and check the other recorded routes before concluding the exposure is removed.";

    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new("SEC-062", "Broad membership of administrative directory groups", Severity.High, 1,
        ["group"], ["objectClass", "objectSid", "groupType", "member", "memberOf"], [nameof(DerivedFactKind.AdministrativeMembership)]);

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) =>
        throw new InvalidOperationException("SEC-062 requires its declared saved membership inputs.");

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(context);
        if (!RequesterTrusteeReading.HasClass(subject, "group")) return RuleVerdict.Judged([]);
        if (context.AdministrativeMembership is not { } index)
            return RuleVerdict.CouldNotResolve([new(DerivedFactKind.AdministrativeMembership, UnresolvedReason.NotDerived)]);
        if (AdministrativeMembershipIndex.ReadSid(subject) is null) return RuleVerdict.CouldNotJudge(["objectSid"]);
        var assessment = index.For(subject);
        var findings = new List<Finding>();
        if (assessment.Evidence is { } evidence)
        {
            var target = evidence.Principals.Single(identity => identity.ObjectGuid == evidence.TargetGuid);
            var names = evidence.Principals.ToDictionary(identity => identity.ObjectGuid, identity => identity.DistinguishedName);
            var detail = Explanation + "\n\nBroad identities:\n" + string.Join("\n", evidence.BroadSources.Select(source =>
                source.Name + " (" + source.Sid + (source.SidScope is null ? "" : "; " + source.SidScope) + ")"))
                + "\n\nRecorded membership links:\n" + string.Join("\n", evidence.Links.Select(link =>
                    names[link.GroupGuid] + " contains " + names[link.MemberGuid]
                    + (link.MemberReferenceGuid == link.MemberGuid ? "" : " (recorded through " + names[link.MemberReferenceGuid] + ")")));
            if (!evidence.IsComplete)
                detail += "\n\nAdditional membership could not be fully assessed:\n" + string.Join("\n",
                    evidence.Limitations.Select(limit => AdministrativeMembershipIndex.Describe(limit.Reason) + ": " + limit.DistinguishedName));
            findings.Add(new("SEC-062", 1, Severity.High, new(FindingSubjectKind.DirectoryObject, target.ObjectGuid.ToString("D")),
                target.ObjectGuid, target.DistinguishedName, target.DomainFqdn!, "group", detail, subject.Completeness, evidence)
                { PrincipalName = subject.Find("sAMAccountName")?.OnlyValue?.Text ?? subject.DistinguishedName });
        }
        return new(findings, assessment.Missing, assessment.Unresolved);
    }
}

internal sealed class AdministrativeMembershipIndex
{
    private readonly CapturedMembershipInput _input;
    private readonly Tier0InputBinding _binding;
    private readonly IReadOnlyDictionary<string, NamingContextKind> _contexts;
    private readonly CancellationToken _token;
    private readonly Dictionary<Guid, int> _guids = [];
    private readonly Dictionary<(string Sid, string Scope), int> _identities = [];
    private readonly Dictionary<(string Sid, string Scope), List<ObjectAttributes>> _groups = [];
    private readonly Dictionary<string, ObjectAttributes?> _domains = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<(ObjectAttributes Source, AttributeValue Value)>> _backlinks = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Assessment> _assessments = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<AdministrativeMembershipLimitation> _inventoryLimitations = [];

    private AdministrativeMembershipIndex(CapturedMembershipInput input, Tier0InputBinding binding,
        IReadOnlyDictionary<string, NamingContextKind> contexts, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!binding.IsSupported || input.DerivationGenerationId != binding.DerivationGenerationId)
            throw new InvalidDataException("Administrative membership inputs do not match their sealed derivation.");
        _input = input;
        _binding = binding;
        _contexts = contexts;
        _token = token;
        foreach (var source in input.Objects)
        {
            token.ThrowIfCancellationRequested();
            if (source.ObjectGuid is { } guid) _guids[guid] = _guids.GetValueOrDefault(guid) + 1;
            var sid = ReadSid(source);
            if (sid is not null && !RequesterTrusteeReading.HasClass(source, "foreignSecurityPrincipal"))
            {
                var identityKey = Key(sid, source.DomainFqdn);
                _identities[identityKey] = _identities.GetValueOrDefault(identityKey) + 1;
            }
            if (RequesterTrusteeReading.HasClass(source, "group") && sid is not null)
            {
                var key = Key(sid, source.DomainFqdn);
                if (!_groups.TryGetValue(key, out var matches)) _groups[key] = matches = [];
                matches.Add(source);
            }
            // Ordinary narrow accounts are leaves. Keep group, stub and unidentified backlinks,
            // without building another forest-wide account expansion.
            if (sid is not null && !BroadPrincipalCatalogue.IsBroad(sid)
                && !RequesterTrusteeReading.HasClass(source, "group")
                && (RequesterTrusteeReading.HasClass(source, "user") || RequesterTrusteeReading.HasClass(source, "computer")))
                continue;
            foreach (var value in source.Find("memberOf")?.Values ?? [])
            {
                token.ThrowIfCancellationRequested();
                if (value.Text is not { } dn || string.IsNullOrWhiteSpace(dn)) continue;
                if (!_backlinks.TryGetValue(dn, out var links)) _backlinks[dn] = links = [];
                links.Add((source, value));
            }
        }
        var roots = contexts.Where(pair => pair.Value == NamingContextKind.Domain)
            .Select(pair => input.FindUnique(pair.Key, token)).ToArray();
        foreach (var pair in contexts.Where(pair => pair.Value == NamingContextKind.Domain))
        {
            var root = input.FindUnique(pair.Key, token);
            var domain = DnHelper.DnToFqdn(pair.Key);
            var sid = root is null ? null : ReadSid(root);
            if (domain is null) continue;
            var verified = root is not null && Same(root.DomainFqdn, domain) && Unique(root)
                && RequesterTrusteeReading.HasClass(root, "domainDNS") && sid is not null
                && PrincipalClassificationRegistry.DomainRid(sid + "-0") == 0
                && root.Find("isDeleted")?.Values.Any(value => !Same(value.Text, "FALSE")) != true
                && OrderedValues(root.Find("objectClass")?.Values ?? [])
                && roots.Count(value => value is not null && Same(ReadSid(value), sid)) == 1;
            _domains[domain] = verified ? root : null;
        }
        foreach (var pair in contexts.Where(pair => pair.Value == NamingContextKind.Domain))
        {
            token.ThrowIfCancellationRequested();
            var domain = DnHelper.DnToFqdn(pair.Key);
            var root = domain is null ? null : _domains.GetValueOrDefault(domain);
            if (root is null)
            {
                _inventoryLimitations.Add(new(pair.Key, AdministrativeMembershipReason.IdentityUnverified));
                continue;
            }
            var expected = WellKnownSidCatalog.AllSids.Select(value => PrincipalClassificationRegistry.For(value.Sid))
                .Where(value => IsTarget(value) && value.Tier0Scope == Tier0IdentityScope.BuiltinDomain)
                .Concat(WellKnownSidCatalog.AllRelativeIdentifiers.Select(value =>
                    PrincipalClassificationRegistry.For(ReadSid(root) + "-" + value.Rid))
                    .Where(value => IsTarget(value) && (value.Tier0Scope == Tier0IdentityScope.Domain
                        || value.Tier0Scope == Tier0IdentityScope.ForestRoot && Same(pair.Key, binding.ForestRootNamingContext))));
            foreach (var target in expected)
                if (_groups.GetValueOrDefault(Key(target.Sid, domain)) is not { Count: 1 } matches
                    || !Unique(matches[0]) || !Same(matches[0].DomainFqdn, domain) || !Same(NamingContext(matches[0]), pair.Key))
                {
                    _inventoryLimitations.Add(new(pair.Key, AdministrativeMembershipReason.IdentityUnverified));
                    break;
                }
        }
    }

    internal static AdministrativeMembershipIndex Create(CapturedMembershipInput input, Tier0InputBinding binding,
        IReadOnlyDictionary<string, NamingContextKind> contexts, CancellationToken token) => new(input, binding, contexts, token);

    internal sealed record Assessment(BroadAdministrativeMembershipEvidence? Evidence, IReadOnlyList<string> Missing,
        IReadOnlyList<UnresolvedInput> Unresolved);

    internal Assessment For(ObjectAttributes subject)
    {
        _token.ThrowIfCancellationRequested();
        var source = _input.FindUnique(subject.DistinguishedName, _token);
        if (source is null || source.ObjectGuid != subject.ObjectGuid || !Same(source.DomainFqdn, subject.DomainFqdn)
            || source.CapturedUtc != subject.CapturedUtc || !Same(ReadSid(source), ReadSid(subject))
            || GroupType(source) != GroupType(subject))
            return new(null, [], [new(DerivedFactKind.AdministrativeMembership, UnresolvedReason.IdentityUnreadable)]);
        if (_assessments.TryGetValue(source.DistinguishedName, out var existing)) return WithInventory(existing);
        var sid = ReadSid(source);
        if (sid is null) return new(null, ["objectSid"], []);
        var definition = PrincipalClassificationRegistry.For(sid);
        if (!IsTarget(definition)) return WithInventory(new(null, [], []));
        var context = NamingContext(source);
        if (definition.Tier0Scope == Tier0IdentityScope.ForestRoot && _binding.ForestRootNamingContext is { } root
            && context is not null && !Same(context, root)) return WithInventory(new(null, [], []));
        var result = Assess(source, definition);
        _assessments.Add(source.DistinguishedName, result);
        return WithInventory(result);
    }

    private Assessment WithInventory(Assessment assessment) => assessment with
    {
        Unresolved = assessment.Unresolved
            .Concat(_inventoryLimitations.Count == 0 ? [] : new[] { new UnresolvedInput(DerivedFactKind.AdministrativeMembership, UnresolvedReason.IdentityUnreadable) })
            .Concat(_input.IsComplete ? [] : new[] { new UnresolvedInput(DerivedFactKind.AdministrativeMembership, UnresolvedReason.MembershipIncomplete) })
            .Distinct().OrderBy(value => value.Reason).ToArray(),
    };

    internal static bool IsTarget(PrincipalClassification value) => value.Tier0ObjectClass == "group"
        && value.ControlPlaneScope is PrincipalAuthorityScope.Domain or PrincipalAuthorityScope.Forest or PrincipalAuthorityScope.Schema;

    private Assessment Assess(ObjectAttributes targetSource, PrincipalClassification definition)
    {
        var limits = _inventoryLimitations.ToHashSet();
        var principals = new Dictionary<Guid, AdministrativeMembershipIdentity>();
        var domains = new Dictionary<string, AdministrativeMembershipIdentity>(StringComparer.OrdinalIgnoreCase);
        var links = new Dictionary<(Guid Group, Guid Member, Guid Reference), List<AdministrativeMembershipWitness>>();
        var broad = new Dictionary<(string Sid, string Scope), HashSet<Guid>>();
        if (!_input.IsComplete) Limit(targetSource, AdministrativeMembershipReason.CaptureIncomplete);
        var target = Identity(targetSource);
        if (target is null) return Result(null);
        if (definition.Tier0Scope == Tier0IdentityScope.ForestRoot
            && (_binding.ForestRootNamingContext is null || !Same(target.NamingContext, _binding.ForestRootNamingContext)))
        {
            Limit(targetSource, AdministrativeMembershipReason.IdentityUnverified);
            return Result(null);
        }
        var targetScope = target.GroupType.GetValueOrDefault() & 0x0f;
        var expectedScope = definition.Tier0Scope switch
        {
            Tier0IdentityScope.BuiltinDomain => targetScope == 5,
            Tier0IdentityScope.Domain => targetScope == 2,
            Tier0IdentityScope.ForestRoot => targetScope is 2 or 8,
            _ => false,
        };
        if (target.GroupType is null || !expectedScope || (target.GroupType.Value & 0x80000000L) == 0)
        {
            Limit(targetSource, target.GroupType is null ? AdministrativeMembershipReason.GroupTypeUnavailable
                : AdministrativeMembershipReason.GroupScopeUnsupported);
            return Result(null);
        }
        principals.Add(target.ObjectGuid, target);
        var queue = new Queue<ObjectAttributes>();
        var seen = new HashSet<Guid> { target.ObjectGuid };
        queue.Enqueue(targetSource);
        while (queue.TryDequeue(out var groupSource))
        {
            _token.ThrowIfCancellationRequested();
            var group = principals[groupSource.ObjectGuid!.Value];
            var memberValues = groupSource.Find("member")?.Values;
            if (memberValues is not { Count: > 0 }) Limit(groupSource, AdministrativeMembershipReason.MembershipValuesUnavailable);
            else if (!OrderedValues(memberValues)) Limit(groupSource, AdministrativeMembershipReason.MembershipValuesMalformed);
            foreach (var value in memberValues ?? [])
            {
                _token.ThrowIfCancellationRequested();
                if (value.Text is not { } dn || string.IsNullOrWhiteSpace(dn) || value.Bytes is not null || value.Ordinal < 0)
                {
                    Limit(groupSource, AdministrativeMembershipReason.MembershipValuesMalformed);
                    continue;
                }
                var member = _input.FindUnique(dn, _token);
                if (member is null) { Limit(groupSource, AdministrativeMembershipReason.MemberUncaptured); continue; }
                Visit(groupSource, group, member, new(group.ObjectGuid, "member", value.Ordinal, value.Text));
            }
            foreach (var (member, value) in _backlinks.GetValueOrDefault(group.DistinguishedName) ?? [])
            {
                _token.ThrowIfCancellationRequested();
                if (!OrderedValues(member.Find("memberOf")!.Values))
                    Limit(member, AdministrativeMembershipReason.MembershipValuesMalformed);
                if (member.ObjectGuid is null || value.Ordinal < 0 || value.Bytes is not null)
                {
                    Limit(member, AdministrativeMembershipReason.MembershipValuesMalformed);
                    continue;
                }
                Visit(groupSource, group, member, new(member.ObjectGuid.Value, "memberOf", value.Ordinal, value.Text!));
            }
        }
        if (broad.Count == 0) return Result(null);

        // Keep all supported alternatives as links, not every possible ordered path through them.
        // Reverse reachability removes narrow/dead branches without enumerating cycles or routes.
        var incoming = links.Keys.GroupBy(key => key.Member).ToDictionary(group => group.Key, group => group.ToArray());
        var retained = broad.Values.SelectMany(ids => ids).ToHashSet();
        var reverse = new Queue<Guid>(retained.Order());
        while (reverse.TryDequeue(out var member))
        {
            _token.ThrowIfCancellationRequested();
            foreach (var link in incoming.GetValueOrDefault(member) ?? [])
                if (retained.Add(link.Group)) reverse.Enqueue(link.Group);
        }
        var savedLinks = links.Where(pair => retained.Contains(pair.Key.Group) && retained.Contains(pair.Key.Member))
            .OrderBy(pair => pair.Key.Group).ThenBy(pair => pair.Key.Member).ThenBy(pair => pair.Key.Reference)
            .Select(pair => new AdministrativeMembershipLink(pair.Key.Group, pair.Key.Member, pair.Key.Reference,
                pair.Value.Distinct().OrderBy(value => value.SourceObjectGuid).ThenBy(value => value.Attribute, StringComparer.Ordinal)
                    .ThenBy(value => value.Ordinal).ToArray())).ToArray();
        foreach (var link in savedLinks) retained.Add(link.MemberReferenceGuid);
        var savedPrincipals = principals.Values.Where(identity => retained.Contains(identity.ObjectGuid)).OrderBy(identity => identity.ObjectGuid).ToArray();
        var usedDomains = savedPrincipals.Where(identity => identity.DomainFqdn is not null).Select(identity => identity.DomainFqdn!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var evidence = new BroadAdministrativeMembershipEvidence(_binding.EvidenceSeal, _binding.DerivationGenerationId, _binding.DerivationSeal,
            PrincipalClassificationRegistry.Version, BroadAdministrativeGroupMembership.PolicyVersion, _binding.ForestRootNamingContext,
            _binding.ConfigurationNamingContext, target.ObjectGuid, savedPrincipals,
            domains.Values.Where(domain => usedDomains.Contains(domain.DomainFqdn!)).OrderBy(domain => domain.DistinguishedName, StringComparer.OrdinalIgnoreCase).ToArray(),
            broad.OrderBy(pair => pair.Key.Sid, StringComparer.Ordinal).ThenBy(pair => pair.Key.Scope, StringComparer.Ordinal)
                .Select(pair => new AdministrativeBroadSource(pair.Key.Sid, pair.Key.Scope.Length == 0 ? null : pair.Key.Scope,
                    BroadPrincipalCatalogue.NameOf(pair.Key.Sid)!, pair.Value.Order().ToArray())).ToArray(),
            savedLinks, _input.IsComplete, SavedLimits());
        return Result(evidence);

        void Visit(ObjectAttributes groupSource, AdministrativeMembershipIdentity group, ObjectAttributes referenceSource,
            AdministrativeMembershipWitness witness)
        {
            var reference = Identity(referenceSource);
            if (reference is null) return;
            var memberSource = referenceSource;
            var member = reference;
            if (reference.ObjectClass == "foreignSecurityPrincipal" && !Special(reference.Sid))
            {
                if (_groups.GetValueOrDefault(Key(reference.Sid, reference.DomainFqdn)) is not { Count: 1 } matches)
                {
                    Limit(referenceSource, AdministrativeMembershipReason.ForeignPrincipalUnresolved);
                    return;
                }
                memberSource = matches[0];
                member = Identity(memberSource);
                if (member is null) return;
                if (!Same(reference.DomainFqdn, group.DomainFqdn))
                {
                    Limit(referenceSource, AdministrativeMembershipReason.GroupScopeUnsupported);
                    return;
                }
            }
            if (member.ObjectClass == "group" && member.GroupType is null)
            {
                Limit(memberSource, AdministrativeMembershipReason.GroupTypeUnavailable);
                return;
            }
            if (member.ObjectClass == "group"
                && ((member.GroupType!.Value & 0x0f) is not (2 or 4 or 5 or 8)
                    || ((member.GroupType.Value & 0x0f) == 5) != Sid.IsBuiltinDomain(member.Sid)))
            {
                Limit(memberSource, AdministrativeMembershipReason.GroupScopeUnsupported);
                return;
            }
            if (member.ObjectClass == "group" && (member.GroupType!.Value & 0x80000000L) == 0) return;
            var supported = Special(member.Sid)
                ? (group.GroupType!.Value & 0x0f) is 4 or 5
                : RequesterTrusteeReading.SupportsSecurityNesting(group.GroupType!.Value, member.GroupType,
                    Same(group.DomainFqdn, member.DomainFqdn), Sid.IsBuiltinDomain(group.Sid));
            if (member.ObjectClass == "group" && (member.GroupType!.Value & 0x0f) is 4 or 5
                && !Same(member.DomainFqdn, target.DomainFqdn)) supported = false;
            if (!supported)
            {
                Limit(referenceSource, AdministrativeMembershipReason.GroupScopeUnsupported);
                return;
            }
            if (member.ObjectClass is not ("group" or "foreignSecurityPrincipal"))
            {
                if (BroadPrincipalCatalogue.IsBroad(member.Sid)) Limit(memberSource, AdministrativeMembershipReason.IdentityUnverified);
                return;
            }
            principals.TryAdd(member.ObjectGuid, member);
            principals.TryAdd(reference.ObjectGuid, reference);
            var key = (group.ObjectGuid, member.ObjectGuid, reference.ObjectGuid);
            if (!links.TryGetValue(key, out var witnesses)) links[key] = witnesses = [];
            witnesses.Add(witness);
            if (BroadPrincipalCatalogue.IsBroad(member.Sid))
            {
                var identityKey = Key(member.Sid, member.DomainFqdn);
                if (!broad.TryGetValue(identityKey, out var ids)) broad[identityKey] = ids = [];
                ids.Add(member.ObjectGuid);
                return;
            }
            if (seen.Add(member.ObjectGuid)) queue.Enqueue(memberSource);
        }

        AdministrativeMembershipIdentity? Identity(ObjectAttributes source)
        {
            var sid = ReadSid(source);
            var context = NamingContext(source);
            if (!Unique(source) || sid is null || context is null || !OrderedValues(source.Find("objectClass")?.Values ?? [])
                || source.Find("objectClass")!.Values.Any(value => value.Text is null || value.Bytes is not null)
                || source.Find("isDeleted")?.Values.Any(value => !Same(value.Text, "FALSE")) == true)
            {
                Limit(source, AdministrativeMembershipReason.IdentityUnverified);
                return null;
            }
            var isStub = RequesterTrusteeReading.HasClass(source, "foreignSecurityPrincipal");
            var isGroup = RequesterTrusteeReading.HasClass(source, "group");
            var kind = isStub ? "foreignSecurityPrincipal" : isGroup ? "group"
                : RequesterTrusteeReading.HasClass(source, "computer") ? "computer"
                : RequesterTrusteeReading.HasClass(source, "user") ? "user" : null;
            if (kind is null || Special(sid) && !isStub
                || !isStub && _identities.GetValueOrDefault(Key(sid, source.DomainFqdn)) != 1
                || isStub && source.Find("groupType")?.HasValue == true)
            {
                Limit(source, AdministrativeMembershipReason.IdentityUnverified);
                return null;
            }
            var configurationIdentity = Special(sid) && isStub && _contexts[context] == NamingContextKind.Configuration
                && Same(context, _binding.ConfigurationNamingContext)
                && (source.DomainFqdn is null || Same(source.DomainFqdn, DnHelper.DnToFqdn(context)));
            if (!configurationIdentity)
            {
                if (source.DomainFqdn is not { } domain || _contexts[context] != NamingContextKind.Domain
                    || !_domains.TryGetValue(domain, out var root) || root is null || !Same(context, root.DistinguishedName)
                    || !isStub && !Sid.IsBuiltinDomain(sid) && !Same(Sid.IssuingDomain(sid), ReadSid(root)))
                {
                    Limit(source, AdministrativeMembershipReason.IdentityUnverified);
                    return null;
                }
                domains.TryAdd(domain, SavedIdentity(root, root.DistinguishedName, "domainDNS", null));
                if (root.Completeness != EvidenceCompleteness.Complete) Limit(root, AdministrativeMembershipReason.SourceIncomplete);
            }
            if (source.Completeness != EvidenceCompleteness.Complete) Limit(source, AdministrativeMembershipReason.SourceIncomplete);
            return SavedIdentity(source, context, kind, isGroup ? GroupType(source) : null);
        }

        void Limit(ObjectAttributes source, AdministrativeMembershipReason reason) => limits.Add(new(source.DistinguishedName, reason));
        AdministrativeMembershipLimitation[] SavedLimits() => limits.OrderBy(value => value.Reason)
            .ThenBy(value => value.DistinguishedName, StringComparer.OrdinalIgnoreCase).ToArray();
        Assessment Result(BroadAdministrativeMembershipEvidence? evidence) => new(evidence, [],
            limits.Select(value => new UnresolvedInput(DerivedFactKind.AdministrativeMembership, value.Reason switch
            {
                AdministrativeMembershipReason.GroupScopeUnsupported => UnresolvedReason.MembershipScopeUnsupported,
                AdministrativeMembershipReason.IdentityUnverified or AdministrativeMembershipReason.ForeignPrincipalUnresolved => UnresolvedReason.IdentityUnreadable,
                _ => UnresolvedReason.MembershipIncomplete,
            })).Distinct().OrderBy(value => value.Reason).ToArray());
    }

    private bool Unique(ObjectAttributes source) => source.ObjectGuid is { } guid && guid != Guid.Empty
        && _guids.GetValueOrDefault(guid) == 1 && _input.FindUnique(source.DistinguishedName, _token) == source;

    private string? NamingContext(ObjectAttributes source)
    {
        for (string? dn = source.DistinguishedName; dn is not null; dn = DnHelper.GetParentDn(dn))
            if (_contexts.ContainsKey(dn)) return dn;
        return null;
    }

    private static AdministrativeMembershipIdentity SavedIdentity(ObjectAttributes source, string context, string kind, long? groupType) =>
        new(source.ObjectGuid!.Value, source.DistinguishedName, context, source.DomainFqdn, ReadSid(source)!,
            Sid.IsBuiltinDomain(ReadSid(source)!) ? source.DomainFqdn : null, kind, groupType, source.CapturedUtc, source.Completeness,
            source.Attributes.Where(attribute => attribute.LdapDisplayName is "objectClass" or "objectSid" or "groupType" or "isDeleted")
                .OrderBy(attribute => attribute.LdapDisplayName, StringComparer.Ordinal)
                .SelectMany(attribute => attribute.Values.Select(value => new AdministrativeMembershipValue(attribute.LdapDisplayName, value.Ordinal, value.Stored))).ToArray());

    internal static string? ReadSid(ObjectAttributes source) => source.Find("objectSid") is { Values.Count: 1 } attribute
        && RequesterTrusteeReading.SidOf(source) is { } sid && Sid.ToBytes(sid) is not null
        && attribute.Values[0].Ordinal == 0 && (attribute.Values[0].Text is null) != (attribute.Values[0].Bytes is null) ? sid : null;

    internal static long? GroupType(ObjectAttributes source) => source.Find("groupType") is { Values.Count: 1 } attribute
        && attribute.Values[0] is { Ordinal: 0, Bytes: null }
        && RequesterTrusteeReading.Number(source, "groupType") is >= int.MinValue and <= uint.MaxValue and { } number ? number : null;

    internal static bool Special(string sid) => PrincipalClassificationRegistry.BroadSids.Contains(sid) && !Sid.IsBuiltinDomain(sid);
    private static (string Sid, string Scope) Key(string sid, string? domain) =>
        (sid.ToUpperInvariant(), Sid.IsBuiltinDomain(sid) ? domain?.ToUpperInvariant() ?? "" : "");
    private static bool Same(string? first, string? second) => string.Equals(first, second, StringComparison.OrdinalIgnoreCase);
    private static bool OrderedValues(IReadOnlyList<AttributeValue> values) => values.Count > 0
        && values.Select(value => value.Ordinal).Order().SequenceEqual(Enumerable.Range(0, values.Count));

    internal static string Describe(AdministrativeMembershipReason reason) => reason switch
    {
        AdministrativeMembershipReason.CaptureIncomplete => "Not all declared capture scope was read",
        AdministrativeMembershipReason.SourceIncomplete => "A captured source has limited completeness",
        AdministrativeMembershipReason.MembershipValuesUnavailable => "The captured member list is empty or unavailable",
        AdministrativeMembershipReason.MembershipValuesMalformed => "A captured membership value or ordinal is unusable",
        AdministrativeMembershipReason.MemberUncaptured => "A named member is absent or ambiguous in the captured evidence",
        AdministrativeMembershipReason.IdentityUnverified => "A captured principal or domain identity could not be verified",
        AdministrativeMembershipReason.GroupTypeUnavailable => "A security-group type was not captured or is unusable",
        AdministrativeMembershipReason.GroupScopeUnsupported => "A membership relationship has unsupported or contradictory group scope",
        AdministrativeMembershipReason.ForeignPrincipalUnresolved => "A foreign reference has no unique captured principal to qualify",
        _ => throw new ArgumentOutOfRangeException(nameof(reason)),
    };
}
