using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal sealed partial class CapturedGroupMembershipIndex
{
    internal static readonly string LegacyGroupSid = WellKnownSidCatalog.AllSids
        .Single(value => value.ConstantName == "ALIAS_PREW2KCOMPACC").Sid;
    private static readonly int DomainAdminsRid = WellKnownSidCatalog.AllRelativeIdentifiers
        .Single(value => value.ConstantName == "DOMAIN_ADMINS").Rid;
    private readonly CapturedMembershipInput _input;
    private readonly Tier0InputBinding _binding;
    private readonly IReadOnlyDictionary<string, NamingContextKind> _contexts;
    private readonly CancellationToken _token;
    private readonly Dictionary<Guid, int> _guids = [];
    private readonly Dictionary<(string Sid, string Scope), (int Count, bool KnownAccount)> _identities = [];
    private readonly HashSet<(string Sid, string Scope)> _historicalIdentities = [];
    private readonly List<ObjectAttributes> _foreignPrincipals = [];
    private readonly Dictionary<(string Sid, string Scope), List<ObjectAttributes>> _groups = [];
    private readonly Dictionary<string, ObjectAttributes?> _domains = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<(ObjectAttributes Source, AttributeValue Value)>> _backlinks = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<(string Dn, BroadMembershipTarget Kind), Assessment> _assessments = [];
    private readonly List<AdministrativeMembershipLimitation> _inventoryLimitations = [];
    private readonly List<AdministrativeMembershipLimitation> _legacyInventoryLimitations = [];
    private readonly List<AdministrativeMembershipLimitation> _domainAdminInventoryLimitations = [];
    private IReadOnlyList<AdministrativeMembershipLimitation>? _serviceInventoryLimitations;
    private readonly Dictionary<string, ILookup<string, AttributeValue>> _memberValues = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, AdministrativeMembershipReason?> _memberValueLimits = new(StringComparer.OrdinalIgnoreCase);

    private CapturedGroupMembershipIndex(CapturedMembershipInput input, Tier0InputBinding binding,
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
            if (sid is not null && RequesterTrusteeReading.HasClass(source, "foreignSecurityPrincipal")) _foreignPrincipals.Add(source);
            if (sid is not null && !RequesterTrusteeReading.HasClass(source, "foreignSecurityPrincipal"))
            {
                var identityKey = Key(sid, source.DomainFqdn);
                var previous = _identities.GetValueOrDefault(identityKey);
                var account = !RequesterTrusteeReading.HasClass(source, "group")
                    && (RequesterTrusteeReading.HasClass(source, "user") || RequesterTrusteeReading.HasClass(source, "computer")
                        || RequesterTrusteeReading.HasClass(source, "inetOrgPerson"))
                    && OrderedValues(source.Find("objectClass")?.Values ?? [])
                    && source.Find("objectClass")!.Values.All(value => value.Text is not null && value.Bytes is null);
                _identities[identityKey] = (previous.Count + 1, account && (previous.Count == 0 || previous.KnownAccount));
            }
            if (!RequesterTrusteeReading.HasClass(source, "foreignSecurityPrincipal"))
                foreach (var historical in AttributeReading.SidsOf(source, "sIDHistory").Sids)
                {
                    token.ThrowIfCancellationRequested();
                    _historicalIdentities.Add(Key(historical, source.DomainFqdn));
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
                _legacyInventoryLimitations.Add(new(pair.Key, AdministrativeMembershipReason.IdentityUnverified));
                _domainAdminInventoryLimitations.Add(new(pair.Key, AdministrativeMembershipReason.IdentityUnverified));
                continue;
            }
            if (_groups.GetValueOrDefault(Key(LegacyGroupSid, domain)) is not { Count: 1 } legacy
                || !Unique(legacy[0]) || !Same(legacy[0].DomainFqdn, domain) || !Same(NamingContext(legacy[0]), pair.Key))
                _legacyInventoryLimitations.Add(new(pair.Key, AdministrativeMembershipReason.IdentityUnverified));
            if (_groups.GetValueOrDefault(Key(ReadSid(root)! + "-" + DomainAdminsRid, domain)) is not { Count: 1 } administrators
                || !Unique(administrators[0]) || !Same(administrators[0].DomainFqdn, domain)
                || !Same(NamingContext(administrators[0]), pair.Key))
                _domainAdminInventoryLimitations.Add(new(pair.Key, AdministrativeMembershipReason.IdentityUnverified));
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

    internal static CapturedGroupMembershipIndex Create(CapturedMembershipInput input, Tier0InputBinding binding,
        IReadOnlyDictionary<string, NamingContextKind> contexts, CancellationToken token) => new(input, binding, contexts, token);

    internal sealed record Assessment(BroadGroupMembershipEvidence? Evidence, IReadOnlyList<string> Missing,
        IReadOnlyList<UnresolvedInput> Unresolved);

    internal (AdministrativeMembershipIdentity? Identity, IReadOnlyList<AdministrativeMembershipIdentity> Domains,
        IReadOnlyList<AdministrativeMembershipLimitation> Limitations) QualifyTarget(ObjectAttributes subject)
    {
        _token.ThrowIfCancellationRequested();
        var source = _input.FindUnique(subject.DistinguishedName, _token);
        var limits = new HashSet<AdministrativeMembershipLimitation>();
        var domains = new Dictionary<string, AdministrativeMembershipIdentity>(StringComparer.OrdinalIgnoreCase);
        if (source is null || source.ObjectGuid != subject.ObjectGuid || source.CapturedUtc != subject.CapturedUtc
            || source.Completeness != subject.Completeness || !Same(source.DomainFqdn, subject.DomainFqdn)
            || !Same(ReadSid(source), ReadSid(subject))
            || !(source.Find("objectClass")?.Values ?? []).Select(value => (value.Ordinal, value.Stored))
                .SequenceEqual((subject.Find("objectClass")?.Values ?? []).Select(value => (value.Ordinal, value.Stored))))
        {
            limits.Add(new(subject.DistinguishedName, AdministrativeMembershipReason.IdentityUnverified));
            return (null, [], limits.ToArray());
        }
        var identity = QualifiedIdentity(source, domains, limits);
        return (identity, domains.Values.ToArray(), limits.ToArray());
    }

    internal Assessment For(ObjectAttributes subject) => For(subject, BroadMembershipTarget.AdministrativeGroup);

    internal Assessment ForLegacyGroup(ObjectAttributes subject) => For(subject, BroadMembershipTarget.PreWindows2000CompatibleAccess);

    private Assessment For(ObjectAttributes subject, BroadMembershipTarget kind)
    {
        _token.ThrowIfCancellationRequested();
        var source = _input.FindUnique(subject.DistinguishedName, _token);
        if (source is null || source.ObjectGuid != subject.ObjectGuid || !Same(source.DomainFqdn, subject.DomainFqdn)
            || source.CapturedUtc != subject.CapturedUtc || !Same(ReadSid(source), ReadSid(subject))
            || GroupType(source) != GroupType(subject))
            return new(null, [], [new(DerivedFactKind.AdministrativeMembership, UnresolvedReason.IdentityUnreadable)]);
        var key = (source.DistinguishedName, kind);
        if (_assessments.TryGetValue(key, out var existing)) return WithInventory(existing, kind);
        var sid = ReadSid(source);
        if (sid is null) return new(null, ["objectSid"], []);
        var definition = PrincipalClassificationRegistry.For(sid);
        if (kind == BroadMembershipTarget.AdministrativeGroup ? !IsTarget(definition) : !Same(sid, LegacyGroupSid))
            return WithInventory(new(null, [], []), kind);
        var context = NamingContext(source);
        if (definition.Tier0Scope == Tier0IdentityScope.ForestRoot && _binding.ForestRootNamingContext is { } root
            && context is not null && !Same(context, root)) return WithInventory(new(null, [], []));
        var result = Assess(source, definition, kind);
        _assessments.Add(key, result);
        return WithInventory(result, kind);
    }

    private Assessment WithInventory(Assessment assessment, BroadMembershipTarget kind = BroadMembershipTarget.AdministrativeGroup) => assessment with
    {
        Unresolved = assessment.Unresolved
            .Concat((kind == BroadMembershipTarget.AdministrativeGroup ? _inventoryLimitations : _legacyInventoryLimitations).Count == 0
                ? [] : new[] { new UnresolvedInput(DerivedFactKind.AdministrativeMembership, UnresolvedReason.IdentityUnreadable) })
            .Concat(_input.IsComplete ? [] : new[] { new UnresolvedInput(DerivedFactKind.AdministrativeMembership, UnresolvedReason.MembershipIncomplete) })
            .Distinct().OrderBy(value => value.Reason).ToArray(),
    };

    internal sealed record ServiceAssessment(IReadOnlyList<ServiceAdministrativeMembership> Memberships,
        IReadOnlyList<string> Missing, IReadOnlyList<UnresolvedInput> Unresolved);

    internal ServiceAssessment ForServiceAccount(ObjectAttributes subject, MembershipRouteSummary routes)
    {
        _token.ThrowIfCancellationRequested();
        var limits = ServiceInventory().ToHashSet();
        var missing = new List<string>();
        var source = _input.FindUnique(subject.DistinguishedName, _token);
        // The streaming object and the saved membership source must be the same captured occurrence.
        if (source is null || source.ObjectGuid != subject.ObjectGuid || source.CapturedUtc != subject.CapturedUtc
            || source.Completeness != subject.Completeness || !Same(source.DomainFqdn, subject.DomainFqdn)
            || new[] { "objectClass", "objectSid", "userAccountControl", "primaryGroupID", "isDeleted", "sIDHistory" }.Any(name =>
                !(source.Find(name)?.Values ?? []).Select(ValueKey).SequenceEqual((subject.Find(name)?.Values ?? []).Select(ValueKey))))
        {
            return new([], [], [new(DerivedFactKind.AdministrativeMembership, UnresolvedReason.IdentityUnreadable)]);
        }
        if (QualifiedIdentity(source, new(StringComparer.OrdinalIgnoreCase), limits) is null)
            return new([], [], limits.Select(limit => new UnresolvedInput(DerivedFactKind.AdministrativeMembership, Reason(limit.Reason)))
                .Distinct().OrderBy(input => input.Reason).ToArray());
        var primary = ServiceAccountReading.ReadControl(source.Find("primaryGroupID")?.Values ?? []);
        if (primary is null)
        {
            missing.Add("primaryGroupID");
            limits.Add(new(source.DistinguishedName, AdministrativeMembershipReason.PrimaryGroupUnavailable));
        }
        if (!_input.IsComplete) limits.Add(new(source.DistinguishedName, AdministrativeMembershipReason.CaptureIncomplete));
        // These routes are saved independently of protection. The protection-exclusion mask
        // cannot change security membership, so it is not an uncertainty for this rule.
        var reasons = routes.IncompleteReasons & ~MembershipRouteIncompleteReason.ForestMaskUnreadable;
        var proofs = new Dictionary<Guid, ServiceProof>();
        foreach (var route in routes.Memberships.SelectMany(group => group.Routes))
        {
            _token.ThrowIfCancellationRequested();
            var last = route.Steps.LastOrDefault()?.Principal;
            if (last is null || !IsTarget(PrincipalClassificationRegistry.For(last.Sid))) continue;
            var definition = PrincipalClassificationRegistry.For(last.Sid);
            var targetSource = last.DistinguishedName is null ? null : _input.FindUnique(last.DistinguishedName, _token);
            var targetContext = targetSource is null ? null : NamingContext(targetSource);
            if (definition.Tier0Scope == Tier0IdentityScope.ForestRoot && _binding.ForestRootNamingContext is { } root
                && targetContext is not null && !Same(targetContext, root)) continue;
            if (route.Authorization == MembershipRouteAuthorization.DistributionGroup) continue;
            if (route.Authorization != MembershipRouteAuthorization.SecurityEnabled)
            {
                limits.Add(new(last.DistinguishedName ?? subject.DistinguishedName, AdministrativeMembershipReason.GroupTypeUnavailable));
                continue;
            }
            var domains = new Dictionary<string, AdministrativeMembershipIdentity>(StringComparer.OrdinalIgnoreCase);
            var chain = new List<(ObjectAttributes Source, AdministrativeMembershipIdentity Identity)>();
            var seen = new HashSet<Guid>();
            foreach (var step in route.Steps)
            {
                var item = step.Principal.DistinguishedName is null ? null : _input.FindUnique(step.Principal.DistinguishedName, _token);
                var identity = item is null ? null : QualifiedIdentity(item, domains, limits);
                if (identity is null || !Same(identity.Sid, step.Principal.Sid) || !Same(identity.SidScope, step.Principal.Scope)
                    || !seen.Add(identity.ObjectGuid))
                {
                    limits.Add(new(step.Principal.DistinguishedName ?? subject.DistinguishedName, AdministrativeMembershipReason.IdentityUnverified));
                    break;
                }
                chain.Add((item!, identity));
            }
            if (chain.Count != route.Steps.Count || chain.Count < 2 || route.Steps[0].IsPrimaryGroup
                || chain[0].Identity.ObjectGuid != subject.ObjectGuid || chain[^1].Identity.ObjectClass != "group") continue;
            var target = chain[^1].Identity;
            if (!TargetScopeMatches(target, definition, _binding.ForestRootNamingContext))
            {
                limits.Add(new(target.DistinguishedName, target.GroupType is null ? AdministrativeMembershipReason.GroupTypeUnavailable
                    : AdministrativeMembershipReason.GroupScopeUnsupported));
                continue;
            }
            var links = new List<AdministrativeMembershipLink>();
            var references = new List<AdministrativeMembershipIdentity>();
            for (var i = 1; i < chain.Count; i++)
            {
                var (memberSource, member) = chain[i - 1];
                var (groupSource, group) = chain[i];
                if (group.ObjectClass != "group" || group.GroupType is null
                    || member.ObjectClass == "group" && member.GroupType is null)
                {
                    limits.Add(new(group.DistinguishedName, AdministrativeMembershipReason.GroupTypeUnavailable));
                    break;
                }
                if (!RequesterTrusteeReading.SupportsSecurityNesting(group.GroupType.Value, member.GroupType,
                    Same(group.DomainFqdn, member.DomainFqdn), Sid.IsBuiltinDomain(group.Sid))
                    || (group.GroupType.Value & 0x0f) is 4 or 5 && !Same(group.DomainFqdn, target.DomainFqdn))
                {
                    limits.Add(new(group.DistinguishedName, AdministrativeMembershipReason.GroupScopeUnsupported));
                    break;
                }
                if (route.Steps[i].IsPrimaryGroup)
                {
                    var values = memberSource.Find("primaryGroupID")?.Values ?? [];
                    var rid = ServiceAccountReading.ReadControl(values);
                    if (member.ObjectClass == "group" || rid is null || !Same(member.DomainFqdn, group.DomainFqdn)
                        || !Same(group.Sid, Sid.IssuingDomain(member.Sid) + "-" + rid.Value.ToString(System.Globalization.CultureInfo.InvariantCulture)))
                    {
                        limits.Add(new(member.DistinguishedName, AdministrativeMembershipReason.PrimaryGroupUnavailable));
                        break;
                    }
                    chain[i - 1] = (memberSource, member with
                    {
                        Values = member.Values.Concat(values.Select(value => new AdministrativeMembershipValue("primaryGroupID", value.Ordinal, value.Stored))).ToArray(),
                    });
                    links.Add(new(group.ObjectGuid, member.ObjectGuid, member.ObjectGuid,
                        [new(member.ObjectGuid, "primaryGroupID", 0, values[0].Stored)]));
                    continue;
                }
                var direct = MemberWitnesses(groupSource, memberSource, limits);
                if (direct.Count > 0)
                {
                    links.Add(new(group.ObjectGuid, member.ObjectGuid, member.ObjectGuid, direct));
                    continue;
                }
                var foreign = ForeignWitnesses(groupSource, member, domains, limits).ToArray();
                if (foreign.Length == 0)
                {
                    var hasForeignReference = (groupSource.Find("member")?.Values ?? []).Where(MembershipValue)
                        .Any(value => RequesterTrusteeReading.HasClass(_input.FindUnique(value.Text!, _token), "foreignSecurityPrincipal"));
                    limits.Add(new(member.DistinguishedName, hasForeignReference ? AdministrativeMembershipReason.ForeignPrincipalUnresolved
                        : AdministrativeMembershipReason.MembershipValuesUnavailable));
                    break;
                }
                foreach (var (reference, witnesses) in foreign)
                {
                    references.Add(reference);
                    links.Add(new(group.ObjectGuid, member.ObjectGuid, reference.ObjectGuid, witnesses));
                }
            }
            if (links.Select(link => link.GroupGuid).Distinct().Count() != chain.Count - 1) continue;
            if (!proofs.TryGetValue(target.ObjectGuid, out var proof)) proofs[target.ObjectGuid] = proof = new();
            foreach (var identity in chain.Select(item => item.Identity).Concat(references))
                proof.Principals[identity.ObjectGuid] = proof.Principals.TryGetValue(identity.ObjectGuid, out var existing)
                    ? identity with { Values = existing.Values.Concat(identity.Values).Distinct().OrderBy(value => value.Attribute, StringComparer.Ordinal)
                        .ThenBy(value => value.Ordinal).ToArray() } : identity;
            foreach (var domain in domains) proof.Domains[domain.Key] = domain.Value;
            foreach (var link in links)
            {
                var key = (link.GroupGuid, link.MemberGuid, link.MemberReferenceGuid);
                if (!proof.Links.TryGetValue(key, out var witnesses)) proof.Links[key] = witnesses = [];
                witnesses.AddRange(link.Witnesses);
            }
        }
        var savedLimits = limits.OrderBy(limit => limit.Reason).ThenBy(limit => limit.DistinguishedName, StringComparer.OrdinalIgnoreCase).ToArray();
        var memberships = proofs.OrderBy(pair => pair.Key).Select(pair => new ServiceAdministrativeMembership(
            _binding.EvidenceSeal, _binding.DerivationGenerationId, _binding.DerivationSeal, PrincipalClassificationRegistry.Version,
            ServiceAccountWithAdministrativeMembership.PolicyVersion, _binding.ForestRootNamingContext, subject.ObjectGuid!.Value, pair.Key,
            pair.Value.Principals.Values.OrderBy(identity => identity.ObjectGuid).ToArray(),
            pair.Value.Domains.Values.OrderBy(identity => identity.DistinguishedName, StringComparer.OrdinalIgnoreCase).ToArray(),
            pair.Value.Links.OrderBy(link => link.Key.Group).ThenBy(link => link.Key.Member).ThenBy(link => link.Key.Reference)
                .Select(link => new AdministrativeMembershipLink(link.Key.Group, link.Key.Member, link.Key.Reference,
                    link.Value.Distinct().OrderBy(value => value.SourceObjectGuid).ThenBy(value => value.Attribute, StringComparer.Ordinal)
                        .ThenBy(value => value.Ordinal).ToArray())).ToArray(),
            _input.IsComplete, reasons, savedLimits)).ToArray();
        var unresolved = limits.Select(limit => Reason(limit.Reason)).ToHashSet();
        if (reasons.HasFlag(MembershipRouteIncompleteReason.NotDerived)) unresolved.Add(UnresolvedReason.NotDerived);
        if (reasons.HasFlag(MembershipRouteIncompleteReason.ForestIdentityUnknown)) unresolved.Add(UnresolvedReason.ForestIdentityUnreadable);
        if ((reasons & (MembershipRouteIncompleteReason.MembershipEvidenceIncomplete | MembershipRouteIncompleteReason.CycleBoundary)) != 0)
            unresolved.Add(UnresolvedReason.MembershipIncomplete);
        if ((reasons & (MembershipRouteIncompleteReason.NodeBudgetReached | MembershipRouteIncompleteReason.EdgeBudgetReached
            | MembershipRouteIncompleteReason.StorageBudgetReached | MembershipRouteIncompleteReason.TimeBudgetReached)) != 0)
            unresolved.Add(UnresolvedReason.MembershipProcessingLimit);
        return new(memberships, missing, unresolved.Order().Select(reason => new UnresolvedInput(DerivedFactKind.AdministrativeMembership, reason)).ToArray());

        static (int Ordinal, string? Text, string? Bytes) ValueKey(AttributeValue value) =>
            (value.Ordinal, value.Text, value.Bytes is null ? null : Convert.ToHexString(value.Bytes));
    }

    private sealed class ServiceProof
    {
        internal Dictionary<Guid, AdministrativeMembershipIdentity> Principals { get; } = [];
        internal Dictionary<string, AdministrativeMembershipIdentity> Domains { get; } = new(StringComparer.OrdinalIgnoreCase);
        internal Dictionary<(Guid Group, Guid Member, Guid Reference), List<AdministrativeMembershipWitness>> Links { get; } = [];
    }

    private IReadOnlyList<AdministrativeMembershipLimitation> ServiceInventory()
    {
        if (_serviceInventoryLimitations is not null) return _serviceInventoryLimitations;
        var limits = _inventoryLimitations.ToHashSet();
        foreach (var source in _foreignPrincipals)
        {
            _token.ThrowIfCancellationRequested();
            var key = Key(ReadSid(source)!, source.DomainFqdn);
            if (!_identities.ContainsKey(key) && _historicalIdentities.Contains(key))
                limits.Add(new(source.DistinguishedName, AdministrativeMembershipReason.HistoricalIdentityUnsupported));
        }
        foreach (var sources in _groups.Values)
            foreach (var source in sources)
            {
                _token.ThrowIfCancellationRequested();
                var definition = PrincipalClassificationRegistry.For(ReadSid(source)!);
                if (!IsTarget(definition)) continue;
                if (definition.Tier0Scope == Tier0IdentityScope.ForestRoot && _binding.ForestRootNamingContext is { } root
                    && !Same(NamingContext(source), root)) continue;
                var identity = QualifiedIdentity(source, new(StringComparer.OrdinalIgnoreCase), limits);
                if (identity is not null && !TargetScopeMatches(identity, definition, _binding.ForestRootNamingContext))
                    limits.Add(new(source.DistinguishedName, identity.GroupType is null ? AdministrativeMembershipReason.GroupTypeUnavailable
                        : AdministrativeMembershipReason.GroupScopeUnsupported));
            }
        return _serviceInventoryLimitations = limits.ToArray();
    }

    internal static bool TargetScopeMatches(AdministrativeMembershipIdentity target, PrincipalClassification definition, string? forestRoot) =>
        IsTarget(definition) && target.ObjectClass == "group" && target.GroupType is { } type && (type & 0x80000000L) != 0
        && (definition.Tier0Scope switch
        {
            Tier0IdentityScope.Domain => (type & 0x0f) == 2,
            Tier0IdentityScope.BuiltinDomain => (type & 0x0f) == 5,
            Tier0IdentityScope.ForestRoot => (type & 0x0f) is 2 or 8 && forestRoot is not null && Same(target.NamingContext, forestRoot),
            _ => false,
        });

    private IReadOnlyList<AdministrativeMembershipWitness> MemberWitnesses(ObjectAttributes group, ObjectAttributes member,
        HashSet<AdministrativeMembershipLimitation> limits)
    {
        if (!_memberValues.TryGetValue(group.DistinguishedName, out var values))
        {
            var captured = group.Find("member")?.Values ?? [];
            _memberValueLimits[group.DistinguishedName] = !OrderedValues(captured) || captured.Any(value => !MembershipValue(value))
                ? captured.Count == 0 ? AdministrativeMembershipReason.MembershipValuesUnavailable : AdministrativeMembershipReason.MembershipValuesMalformed : null;
            values = captured.Where(MembershipValue).ToLookup(value => value.Text!, StringComparer.OrdinalIgnoreCase);
            _memberValues.Add(group.DistinguishedName, values);
        }
        if (_memberValueLimits[group.DistinguishedName] is { } reason) limits.Add(new(group.DistinguishedName, reason));
        var backlinks = member.Find("memberOf")?.Values ?? [];
        if (backlinks.Count > 0 && (!OrderedValues(backlinks) || backlinks.Any(value => !MembershipValue(value))))
            limits.Add(new(member.DistinguishedName, AdministrativeMembershipReason.MembershipValuesMalformed));
        return values[member.DistinguishedName].Select(value => new AdministrativeMembershipWitness(group.ObjectGuid!.Value, "member", value.Ordinal, value.Text!))
            .Concat(backlinks.Where(value => MembershipValue(value) && Same(value.Text, group.DistinguishedName))
                .Select(value => new AdministrativeMembershipWitness(member.ObjectGuid!.Value, "memberOf", value.Ordinal, value.Text!)))
            .Distinct().ToArray();
    }

    private IEnumerable<(AdministrativeMembershipIdentity Identity, IReadOnlyList<AdministrativeMembershipWitness> Witnesses)> ForeignWitnesses(
        ObjectAttributes group, AdministrativeMembershipIdentity member, Dictionary<string, AdministrativeMembershipIdentity> domains,
        HashSet<AdministrativeMembershipLimitation> limits)
    {
        var candidates = (group.Find("member")?.Values ?? []).Where(MembershipValue)
            .Select(value => _input.FindUnique(value.Text!, _token))
            .Concat((_backlinks.GetValueOrDefault(group.DistinguishedName) ?? []).Select(link => link.Source))
            .Where(source => source is not null && RequesterTrusteeReading.HasClass(source, "foreignSecurityPrincipal") && Same(ReadSid(source), member.Sid))
            .Distinct();
        foreach (var source in candidates)
        {
            _token.ThrowIfCancellationRequested();
            var identity = QualifiedIdentity(source!, domains, limits);
            if (identity is null || !Same(identity.DomainFqdn, group.DomainFqdn)
                || Sid.IsBuiltinDomain(member.Sid) && !Same(identity.DomainFqdn, member.DomainFqdn))
            {
                limits.Add(new(source!.DistinguishedName, AdministrativeMembershipReason.ForeignPrincipalUnresolved));
                continue;
            }
            var witnesses = MemberWitnesses(group, source!, limits);
            if (witnesses.Count > 0) yield return (identity, witnesses);
        }
    }

    private static bool MembershipValue(AttributeValue value) => value.Ordinal >= 0 && value.Bytes is null && !string.IsNullOrWhiteSpace(value.Text);
    private static UnresolvedReason Reason(AdministrativeMembershipReason reason) => reason switch
    {
        AdministrativeMembershipReason.GroupScopeUnsupported => UnresolvedReason.MembershipScopeUnsupported,
        AdministrativeMembershipReason.IdentityUnverified or AdministrativeMembershipReason.ForeignPrincipalUnresolved => UnresolvedReason.IdentityUnreadable,
        AdministrativeMembershipReason.HistoricalIdentityUnsupported => UnresolvedReason.MembershipIdentityUnsupported,
        _ => UnresolvedReason.MembershipIncomplete,
    };

    internal static bool IsTarget(PrincipalClassification value) => value.Tier0ObjectClass == "group"
        && value.ControlPlaneScope is PrincipalAuthorityScope.Domain or PrincipalAuthorityScope.Forest or PrincipalAuthorityScope.Schema;

    private Assessment Assess(ObjectAttributes targetSource, PrincipalClassification definition, BroadMembershipTarget kind)
    {
        var limits = (kind == BroadMembershipTarget.AdministrativeGroup ? _inventoryLimitations : _legacyInventoryLimitations).ToHashSet();
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
        var expectedScope = kind == BroadMembershipTarget.PreWindows2000CompatibleAccess ? targetScope == 5 : definition.Tier0Scope switch
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
        var evidence = new BroadGroupMembershipEvidence(_binding.EvidenceSeal, _binding.DerivationGenerationId, _binding.DerivationSeal,
            PrincipalClassificationRegistry.Version, kind == BroadMembershipTarget.AdministrativeGroup
                ? BroadAdministrativeGroupMembership.PolicyVersion : BroadPreWindows2000Membership.PolicyVersion, _binding.ForestRootNamingContext,
            _binding.ConfigurationNamingContext, target.ObjectGuid, savedPrincipals,
            domains.Values.Where(domain => usedDomains.Contains(domain.DomainFqdn!)).OrderBy(domain => domain.DistinguishedName, StringComparer.OrdinalIgnoreCase).ToArray(),
            broad.OrderBy(pair => pair.Key.Sid, StringComparer.Ordinal).ThenBy(pair => pair.Key.Scope, StringComparer.Ordinal)
                .Select(pair => new AdministrativeBroadSource(pair.Key.Sid, pair.Key.Scope.Length == 0 ? null : pair.Key.Scope,
                    BroadPrincipalCatalogue.NameOf(pair.Key.Sid)!, pair.Value.Order().ToArray())).ToArray(),
            savedLinks, _input.IsComplete, SavedLimits(), kind);
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
            if (kind == BroadMembershipTarget.PreWindows2000CompatibleAccess && member.ObjectGuid == target.ObjectGuid) return;
            principals.TryAdd(member.ObjectGuid, member);
            principals.TryAdd(reference.ObjectGuid, reference);
            var key = (group.ObjectGuid, member.ObjectGuid, reference.ObjectGuid);
            if (!links.TryGetValue(key, out var witnesses)) links[key] = witnesses = [];
            witnesses.Add(witness);
            if (member.ObjectGuid != target.ObjectGuid && BroadPrincipalCatalogue.IsBroad(member.Sid))
            {
                var identityKey = Key(member.Sid, member.DomainFqdn);
                if (!broad.TryGetValue(identityKey, out var ids)) broad[identityKey] = ids = [];
                ids.Add(member.ObjectGuid);
                return;
            }
            if (seen.Add(member.ObjectGuid)) queue.Enqueue(memberSource);
        }

        AdministrativeMembershipIdentity? Identity(ObjectAttributes source) => QualifiedIdentity(source, domains, limits);

        void Limit(ObjectAttributes source, AdministrativeMembershipReason reason) => limits.Add(new(source.DistinguishedName, reason));
        AdministrativeMembershipLimitation[] SavedLimits() => limits.OrderBy(value => value.Reason)
            .ThenBy(value => value.DistinguishedName, StringComparer.OrdinalIgnoreCase).ToArray();
        Assessment Result(BroadGroupMembershipEvidence? evidence) => new(evidence, [],
            limits.Select(value => new UnresolvedInput(DerivedFactKind.AdministrativeMembership, value.Reason switch
            {
                AdministrativeMembershipReason.GroupScopeUnsupported => UnresolvedReason.MembershipScopeUnsupported,
                AdministrativeMembershipReason.IdentityUnverified or AdministrativeMembershipReason.ForeignPrincipalUnresolved => UnresolvedReason.IdentityUnreadable,
                _ => UnresolvedReason.MembershipIncomplete,
            })).Distinct().OrderBy(value => value.Reason).ToArray());
    }

    private AdministrativeMembershipIdentity? QualifiedIdentity(ObjectAttributes source,
        Dictionary<string, AdministrativeMembershipIdentity> domains, HashSet<AdministrativeMembershipLimitation> limits)
    {
        var sid = ReadSid(source);
        var context = NamingContext(source);
        if (!Unique(source) || sid is null || context is null || !OrderedValues(source.Find("objectClass")?.Values ?? [])
            || source.Find("objectClass")!.Values.Any(value => value.Text is null || value.Bytes is not null)
            || source.Find("isDeleted")?.Values.Any(value => !Same(value.Text, "FALSE")) == true)
            return Unverified();
        var isStub = RequesterTrusteeReading.HasClass(source, "foreignSecurityPrincipal");
        var isGroup = RequesterTrusteeReading.HasClass(source, "group");
        var kind = isStub ? "foreignSecurityPrincipal" : isGroup ? "group"
            : RequesterTrusteeReading.HasClass(source, "computer") ? "computer"
            : RequesterTrusteeReading.HasClass(source, "user") ? "user"
            : RequesterTrusteeReading.HasClass(source, "inetOrgPerson") ? "inetOrgPerson" : null;
        if (kind is null || Special(sid) && !isStub
            || !isStub && _identities.GetValueOrDefault(Key(sid, source.DomainFqdn)).Count != 1
            || isStub && source.Find("groupType")?.HasValue == true) return Unverified();
        var configurationIdentity = Special(sid) && isStub && _contexts[context] == NamingContextKind.Configuration
            && Same(context, _binding.ConfigurationNamingContext)
            && (source.DomainFqdn is null || Same(source.DomainFqdn, DnHelper.DnToFqdn(context)));
        if (!configurationIdentity)
        {
            if (source.DomainFqdn is not { } domain || _contexts[context] != NamingContextKind.Domain
                || !_domains.TryGetValue(domain, out var root) || root is null || !Same(context, root.DistinguishedName)
                || !isStub && !Sid.IsBuiltinDomain(sid) && !Same(Sid.IssuingDomain(sid), ReadSid(root))) return Unverified();
            domains.TryAdd(domain, SavedIdentity(root, root.DistinguishedName, "domainDNS", null));
            if (root.Completeness != EvidenceCompleteness.Complete) limits.Add(new(root.DistinguishedName, AdministrativeMembershipReason.SourceIncomplete));
        }
        if (source.Completeness != EvidenceCompleteness.Complete) limits.Add(new(source.DistinguishedName, AdministrativeMembershipReason.SourceIncomplete));
        return SavedIdentity(source, context, kind, isGroup ? GroupType(source) : null);

        AdministrativeMembershipIdentity? Unverified()
        {
            limits.Add(new(source.DistinguishedName, AdministrativeMembershipReason.IdentityUnverified));
            return null;
        }
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
        AdministrativeMembershipReason.PrimaryGroupUnavailable => "The account's primary-group identifier is absent or unusable",
        AdministrativeMembershipReason.HistoricalIdentityUnsupported => "A captured foreign reference matches SID history, which the saved membership routes do not resolve",
        _ => throw new ArgumentOutOfRangeException(nameof(reason)),
    };
}
