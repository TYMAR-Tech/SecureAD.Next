using System.Collections.Immutable;
using System.Text.Json;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Derivation;

/// <summary>Qualifies canonical principal identities and supplied same-domain membership witnesses; never expands a graph.</summary>
public static class Tier0Classifier
{
    /// <summary>The classes a captured naming-context head may legitimately be, per decision 0117.</summary>
    private static readonly string[] PartitionRootClasses = ["domainDNS", "configuration", "dMD"];

    /// <summary>Qualifies one captured object from source-bound inputs; unsupported bases remain explicitly incomplete.</summary>
    public static Tier0Classification Qualify(Tier0InputBinding binding, Tier0Target target,
        CapturedMembershipInput input, MembershipRouteSummary? routes, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(target);
        return QualifyIndexed(binding, target, input, CreateIndex(binding, input, cancellationToken), routes, cancellationToken);
    }

    /// <summary>Qualifies supplied targets using one captured-input index, without discovering new memberships.</summary>
    /// <remarks>Results preserve target order. Cancellation throws rather than publishing a partial batch.</remarks>
    public static Tier0ClassificationBatch QualifyMany(Tier0InputBinding binding, IEnumerable<Tier0Target> targets,
        CapturedMembershipInput input, Func<Tier0Target, MembershipRouteSummary?>? routes, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(targets);
        var index = CreateIndex(binding, input, cancellationToken);
        var results = ImmutableArray.CreateBuilder<Tier0Classification>();
        foreach (var target in targets)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(target);
            results.Add(QualifyIndexed(binding, target, input, index, routes?.Invoke(target), cancellationToken));
        }

        var classifications = results.ToImmutable();
        return new(classifications, Aggregate(classifications, binding, input));
    }

    /// <summary>
    /// The coverage that holds across a whole batch: every boundary only as complete as its weakest
    /// member, and every limitation any member reported.
    /// </summary>
    /// <remarks>
    /// The seed carries the two facts that survive an empty batch. A caller who offered no targets
    /// was answered in full, so that case is complete rather than silently incomplete - but not when
    /// the binding names a different derivation from the input, because then nothing could have been
    /// classified whatever was offered, and reporting an empty batch as complete would say the
    /// forest holds no Tier-0 objects when the truth is that nothing was read.
    /// </remarks>
    private static Tier0Coverage Aggregate(ImmutableArray<Tier0Classification> classifications,
        Tier0InputBinding binding, CapturedMembershipInput input) =>
        classifications.Aggregate(
            new Tier0Coverage(input.IsComplete, true, true,
                binding.DerivationGenerationId == input.DerivationGenerationId
                    ? Tier0Limitations.None
                    : Tier0Limitations.SourceMismatch),
            (total, item) => new(
                total.InputsComplete && item.Coverage.InputsComplete,
                total.AnalysisComplete && item.Coverage.AnalysisComplete,
                total.ProcessingComplete && item.Coverage.ProcessingComplete,
                total.Limitations | item.Coverage.Limitations));

    private static CapturedIndex CreateIndex(Tier0InputBinding binding, CapturedMembershipInput input, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(input);
        if (!binding.IsSupported) throw new ArgumentException(null, nameof(binding));
        cancellationToken.ThrowIfCancellationRequested();
        return binding.DerivationGenerationId == input.DerivationGenerationId
            ? input.Index(cancellationToken) : new CapturedIndex([], cancellationToken);
    }

    private static Tier0Classification QualifyIndexed(Tier0InputBinding binding, Tier0Target target,
        CapturedMembershipInput input, CapturedIndex index, MembershipRouteSummary? routes, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var limitations = Tier0Limitations.MembershipIncomplete | Tier0Limitations.AssetQualificationUnsupported
            | Tier0Limitations.ControlQualificationUnsupported | Tier0Limitations.DependencyQualificationUnsupported;
        if (!input.IsComplete) limitations |= Tier0Limitations.InputIncomplete;
        var supports = ImmutableArray.CreateBuilder<Tier0Support>();
        Tier0Classification Result() => new(binding, target, supports.ToImmutable(),
            new(input.IsComplete && (limitations & Tier0Limitations.InputIncomplete) == 0, false, true, limitations));
        if (binding.DerivationGenerationId != input.DerivationGenerationId)
        {
            limitations |= Tier0Limitations.SourceMismatch;
            return Result();
        }

        ObjectAttributes? Find(string? dn) => index.Find(dn);
        var subject = Find(target.DistinguishedName);

        // An object carrying no SID cannot have an ambiguous one. Uniqueness for it is established by
        // distinguished name, which is already the index key, so requiring a unique SID identity here
        // would reject every naming-context head before any basis is considered - and a head is
        // exactly what has no SID. The check is unchanged for anything that does carry one, where an
        // ambiguous SID must never resolve to an arbitrary object.
        if (!target.IsValid || subject is null || Tier0Target.From(subject, target.NamingContext) != target
            || Tier0Target.ReadSid(subject) is not null && !UniqueIdentity(subject))
        {
            limitations |= Tier0Limitations.IdentityUnverified;
            return Result();
        }
        if (Core(subject) is { } core) supports.Add(core);
        if (PartitionRoot(subject) is { } root) supports.Add(root);
        EnterpriseCa(binding, target, subject, index, supports, ref limitations, cancellationToken);
        if (routes is null) return Result();
        var uniqueSupports = new HashSet<string>(StringComparer.Ordinal);
        foreach (var group in routes.Memberships)
        {
            foreach (var route in group.Routes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var support = Membership(route);
                if (support is null) limitations |= Tier0Limitations.MembershipUnqualified;
                else if (uniqueSupports.Add(JsonSerializer.Serialize(support.Evidence, ProofSerialization.Options))) supports.Add(support);
            }
        }
        return Result();

        bool UniqueIdentity(ObjectAttributes item) => index.UniqueIdentity(item);

        ObjectAttributes? DomainRoot(ObjectAttributes item) => index.DomainRoot(item, cancellationToken);

        Tier0Target? Identity(ObjectAttributes item)
        {
            var domain = DomainRoot(item);
            if (domain is null || !UniqueIdentity(item)) return null;
            var identity = Tier0Target.From(item, domain.DistinguishedName);
            return identity.IsValid ? identity : null;
        }

        Tier0Support? Core(ObjectAttributes item)
        {
            var sid = Tier0Target.ReadSid(item);
            if (sid is null) return null;
            var definition = PrincipalClassificationRegistry.For(sid);
            if (definition.Tier0Scope is not { } scope) return null;
            var identity = Identity(item);
            var domain = DomainRoot(item);
            if (identity is null || domain is null || definition.Tier0ObjectClass is not { } requiredClass
                || !Tier0Target.Same(item.Find("objectClass")?.Values.LastOrDefault()?.Text, requiredClass))
            {
                limitations |= Tier0Limitations.IdentityUnverified;
                return null;
            }
            if (item == subject && identity != target)
            {
                limitations |= Tier0Limitations.IdentityUnverified;
                return null;
            }
            var domainSid = Tier0Target.ReadSid(domain);
            if (scope != Tier0IdentityScope.BuiltinDomain && !Tier0Target.Same(Sid.IssuingDomain(sid), domainSid)
                || scope == Tier0IdentityScope.ForestRoot && (Find(binding.ForestRootNamingContext) != domain))
            {
                limitations |= Tier0Limitations.IdentityUnverified;
                return null;
            }
            var evidence = ImmutableArray.CreateBuilder<Tier0Evidence>();
            AddAttribute(evidence, identity, item, "objectSid");
            AddAttribute(evidence, identity, item, "objectClass");
            AddAttribute(evidence, Tier0Target.From(domain, domain.DistinguishedName), domain, "objectSid");
            AddAttribute(evidence, Tier0Target.From(domain, domain.DistinguishedName), domain, "objectClass");
            return new(Tier0Basis.Core, identity, evidence.ToImmutable());
        }

        /// <summary>
        /// Qualifies the head of a directory partition, which holds no SID and no route can reach.
        /// </summary>
        /// <remarks>
        /// The naming context comes from the capture's own recorded contexts by way of the target,
        /// not from the shape of a distinguished name. The object class must agree with the kind the
        /// capture recorded for that context, so a mismatch is an unverified identity rather than a
        /// seed. Decision 0117.
        /// </remarks>
        Tier0Support? PartitionRoot(ObjectAttributes item)
        {
            if (!Tier0Target.Same(item.DistinguishedName, target.NamingContext)) return null;
            var objectClass = item.Find("objectClass")?.Values.LastOrDefault()?.Text;
            if (objectClass is null || !PartitionRootClasses.Contains(objectClass, StringComparer.OrdinalIgnoreCase))
            {
                limitations |= Tier0Limitations.IdentityUnverified;
                return null;
            }
            var identity = Tier0Target.From(item, target.NamingContext);
            if (!identity.IsValid || identity != target)
            {
                limitations |= Tier0Limitations.IdentityUnverified;
                return null;
            }
            var evidence = ImmutableArray.CreateBuilder<Tier0Evidence>();
            AddAttribute(evidence, identity, item, "objectClass");
            AddAttribute(evidence, identity, item, "objectSid");
            return new(Tier0Basis.PartitionRoot, identity, evidence.ToImmutable());
        }

        Tier0Support? Membership(MembershipRoute route)
        {
            if (route.Authorization != MembershipRouteAuthorization.SecurityEnabled || route.Steps.Count < 2
                || route.Steps[0].IsPrimaryGroup) return null;
            var chain = new List<(ObjectAttributes Object, Tier0Target Identity)>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var step in route.Steps)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var item = Find(step.Principal.DistinguishedName);
                var identity = item is null ? null : Identity(item);
                if (item is null || identity is null || !seen.Add(item.DistinguishedName)
                    || !Tier0Target.Same(identity.Sid, step.Principal.Sid) || !Tier0Target.Same(identity.SidScope, step.Principal.Scope)
                    || !Tier0Target.Same(identity.DomainFqdn, target.DomainFqdn)) return null;
                chain.Add((item, identity));
            }
            if (chain[0].Identity != target || HasClass(chain[0].Object, "group") && !SecurityGroup(chain[0].Object)
                || Core(chain[^1].Object) is not { } root) return null;
            var evidence = root.Evidence.ToBuilder();
            for (var i = 1; i < chain.Count; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var member = chain[i - 1];
                var container = chain[i];
                if (!SecurityGroup(container.Object)) return null;
                AddAttribute(evidence, container.Identity, container.Object, "groupType");
                AddAttribute(evidence, member.Identity, member.Object, "objectSid");
                if (route.Steps[i].IsPrimaryGroup)
                {
                    var primary = AttributeReading.UnsignedInteger(member.Object, "primaryGroupID");
                    if (primary is null || member.Identity.Sid is not { } memberSid || !Tier0Target.Same(container.Identity.Sid,
                        Sid.IssuingDomain(memberSid) + "-" + primary.Value.ToString(System.Globalization.CultureInfo.InvariantCulture))) return null;
                    AddAttribute(evidence, member.Identity, member.Object, "primaryGroupID");
                }
                else
                {
                    var link = container.Object.Find("member")?.Values.FirstOrDefault(value => Tier0Target.Same(value.Text, member.Identity.DistinguishedName));
                    if (link is not null)
                        evidence.Add(new(container.Identity, "member", link.Ordinal, link.Stored));
                    else
                    {
                        link = member.Object.Find("memberOf")?.Values.FirstOrDefault(value => Tier0Target.Same(value.Text, container.Identity.DistinguishedName));
                        if (link is null) return null;
                        evidence.Add(new(member.Identity, "memberOf", link.Ordinal, link.Stored));
                    }
                }
            }
            return new(Tier0Basis.EffectiveMembership, root.Root, evidence.ToImmutable());
        }
    }

    private static void EnterpriseCa(Tier0InputBinding binding, Tier0Target target, ObjectAttributes subject,
        CapturedIndex index, ImmutableArray<Tier0Support>.Builder supports, ref Tier0Limitations limitations,
        CancellationToken cancellationToken)
    {
        var isRegistration = HasClass(subject, "pKIEnrollmentService");
        IEnumerable<ObjectAttributes> registrations = isRegistration ? [subject]
            : HasClass(subject, "computer") ? index.RegistrationsFor(subject) : [];
        foreach (var registration in registrations.OrderBy(item => item.DistinguishedName, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var configuration = index.Find(binding.ConfigurationNamingContext);
            if (configuration is null)
            {
                limitations |= Tier0Limitations.InputIncomplete | Tier0Limitations.IdentityUnverified;
                continue;
            }
            var context = configuration.DistinguishedName;
            var container = "CN=Enrollment Services,CN=Public Key Services,CN=Services," + context;
            if (!AssetIdentity(configuration, index) || !LastClass(configuration, "configuration")
                || !AssetIdentity(registration, index) || !LastClass(registration, "pKIEnrollmentService")
                || !Tier0Target.Same(DnHelper.GetParentDn(registration.DistinguishedName), container))
            {
                limitations |= Tier0Limitations.IdentityUnverified;
                continue;
            }
            var registrationTarget = Tier0Target.From(registration, context);
            if (!registrationTarget.IsValid || isRegistration && registrationTarget != target)
            {
                limitations |= Tier0Limitations.IdentityUnverified;
                continue;
            }
            var evidence = ImmutableArray.CreateBuilder<Tier0Evidence>();
            AddAttribute(evidence, Tier0Target.From(configuration, context), configuration, "objectClass");
            AddAttribute(evidence, registrationTarget, registration, "objectClass");
            AddAttribute(evidence, registrationTarget, registration, "dNSHostName");
            AddAttribute(evidence, registrationTarget, registration, "isDeleted");

            // The registration is independently established even when its named host cannot be resolved.
            // Neither support transfers a permission between these two separate directory resources.
            if (isRegistration) supports.Add(new(Tier0Basis.EnterpriseCaRegistration, registrationTarget, evidence.ToImmutable()));
            if (registration.Find("dNSHostName")?.Values is not { Count: > 0 })
            {
                limitations |= Tier0Limitations.InputIncomplete | Tier0Limitations.AssetHostEvidenceMissing;
                continue;
            }
            var hostName = SingleHostName(registration);
            var matches = hostName is null ? [] : index.ComputersFor(hostName);
            var host = matches.Count == 1 ? matches[0] : null;
            var domain = host is null ? null : index.DomainRoot(host, cancellationToken);
            if (host is null || domain is null || !AssetIdentity(domain, index)
                || !LastClass(host, "computer") || !AssetIdentity(host, index)
                || !index.UniqueIdentity(host) || !Tier0Target.Same(SingleHostName(host), hostName)
                || !Tier0Target.Same(Sid.IssuingDomain(Tier0Target.ReadSid(host)), Tier0Target.ReadSid(domain)))
            {
                limitations |= Tier0Limitations.IdentityUnverified | Tier0Limitations.AssetHostIdentityUnresolved;
                continue;
            }
            var hostTarget = Tier0Target.From(host, domain.DistinguishedName);
            if (!hostTarget.IsValid || !isRegistration && hostTarget != target)
            {
                limitations |= Tier0Limitations.IdentityUnverified | Tier0Limitations.AssetHostIdentityUnresolved;
                continue;
            }
            if (isRegistration) continue;
            AddAttribute(evidence, Tier0Target.From(domain, domain.DistinguishedName), domain, "objectClass");
            AddAttribute(evidence, Tier0Target.From(domain, domain.DistinguishedName), domain, "objectSid");
            AddAttribute(evidence, hostTarget, host, "objectClass");
            AddAttribute(evidence, hostTarget, host, "objectSid");
            AddAttribute(evidence, hostTarget, host, "dNSHostName");
            AddAttribute(evidence, hostTarget, host, "isDeleted");
            supports.Add(new(Tier0Basis.EnterpriseCaHost, registrationTarget, evidence.ToImmutable()));
        }
    }

    private static bool LastClass(ObjectAttributes item, string name) =>
        Tier0Target.Same(item.Find("objectClass")?.Values.LastOrDefault()?.Text, name);

    private static bool AssetIdentity(ObjectAttributes item, CapturedIndex index) =>
        index.Find(item.DistinguishedName) == item && index.UniqueGuid(item)
        && (item.Find("objectSid")?.HasValue != true
            || Tier0Target.ReadSid(item) is { } sid && Sid.ToBytes(sid) is not null && index.UniqueIdentity(item))
        && (item.Find("isDeleted")?.Values is not { Count: > 0 } deleted
            || deleted.Count == 1 && Tier0Target.Same(deleted[0].Text, "FALSE"));

    // dNSHostName is a single-valued DNS name in the Microsoft schema. Match the recorded full
    // name only; shortening it or deriving a name from an SPN would turn missing identity into a guess.
    private static string? SingleHostName(ObjectAttributes item) => item.Find("dNSHostName") is
        { Cardinality: AttributeCardinality.SingleValued, Values.Count: 1 } attribute
        && attribute.Values[0] is { Text: { } name, Bytes: null, Ordinal: 0 }
        && !string.IsNullOrWhiteSpace(name) && name.Contains('.', StringComparison.Ordinal)
        && Uri.CheckHostName(name) == UriHostNameType.Dns ? name : null;

    internal sealed class CapturedIndex
    {
        private readonly Dictionary<string, List<ObjectAttributes>> objects = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, List<ObjectAttributes>> domains = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<(string Sid, string? Scope), int> identities = [];
        private readonly Dictionary<Guid, int> guids = [];
        private readonly Dictionary<string, List<ObjectAttributes>> computersByHost = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, List<ObjectAttributes>> registrationsByHost = new(StringComparer.OrdinalIgnoreCase);

        internal CapturedIndex(IEnumerable<ObjectAttributes> input, CancellationToken cancellationToken)
        {
            foreach (var item in input)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!objects.TryGetValue(item.DistinguishedName, out var matches)) objects[item.DistinguishedName] = matches = [];
                matches.Add(item);
                if (item.ObjectGuid is { } guid) guids[guid] = guids.GetValueOrDefault(guid) + 1;
                if (HasClass(item, "computer")) IndexHost(computersByHost, item);
                if (HasClass(item, "pKIEnrollmentService")) IndexHost(registrationsByHost, item);
                var sid = Tier0Target.ReadSid(item);
                if (sid is not null && Sid.ToBytes(sid) is not null)
                {
                    var key = IdentityKey(sid, item.DomainFqdn);
                    identities[key] = identities.GetValueOrDefault(key) + 1;
                }
                if (item.DomainFqdn is { } domain && !string.IsNullOrWhiteSpace(domain) && HasClass(item, "domainDNS")
                    && Tier0Target.Same(DnHelper.DnToFqdn(item.DistinguishedName), domain))
                {
                    if (!domains.TryGetValue(domain, out var roots)) domains[domain] = roots = [];
                    roots.Add(item);
                }
            }
        }

        internal ObjectAttributes? Find(string? dn) => dn is not null && objects.TryGetValue(dn, out var matches)
            && matches.Count == 1 ? matches[0] : null;

        internal bool UniqueIdentity(ObjectAttributes item) => Tier0Target.ReadSid(item) is { } sid
            && identities.GetValueOrDefault(IdentityKey(sid, item.DomainFqdn)) == 1;

        internal bool UniqueGuid(ObjectAttributes item) => item.ObjectGuid is { } guid && guid != Guid.Empty
            && guids.GetValueOrDefault(guid) == 1;

        internal IReadOnlyList<ObjectAttributes> ComputersFor(string name) => computersByHost.GetValueOrDefault(name) ?? [];

        internal IEnumerable<ObjectAttributes> RegistrationsFor(ObjectAttributes computer) =>
            (computer.Find("dNSHostName")?.Values ?? []).Where(value => value.Text is not null)
                .SelectMany(value => registrationsByHost.GetValueOrDefault(value.Text ?? "") ?? []).Distinct();

        private static void IndexHost(Dictionary<string, List<ObjectAttributes>> index, ObjectAttributes item)
        {
            // Include contradictory values in the candidate index so uniqueness cannot hide a malformed competitor.
            foreach (var value in item.Find("dNSHostName")?.Values ?? [])
            {
                if (value.Text is not { } name) continue;
                if (!index.TryGetValue(name, out var matches)) index[name] = matches = [];
                matches.Add(item);
            }
        }

        internal ObjectAttributes? DomainRoot(ObjectAttributes item, CancellationToken cancellationToken)
        {
            if (item.DomainFqdn is not { } domain || !domains.TryGetValue(domain, out var roots)) return null;
            ObjectAttributes? found = null;
            foreach (var candidate in roots)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!Tier0Target.Within(item.DistinguishedName, candidate.DistinguishedName)) continue;
                if (found is not null) return null;
                found = candidate;
            }
            var sid = found is null ? null : Tier0Target.ReadSid(found);
            return found is not null && sid is not null && PrincipalClassificationRegistry.DomainRid(sid + "-0") == 0
                && UniqueIdentity(found) ? found : null;
        }

        private static (string Sid, string? Scope) IdentityKey(string sid, string? domain) =>
            (sid.ToUpperInvariant(), Sid.IsBuiltinDomain(sid) ? domain?.ToUpperInvariant() : null);
    }

    private static bool HasClass(ObjectAttributes item, string value) => item.Find("objectClass")?.Values
        .Any(attribute => Tier0Target.Same(attribute.Text, value)) == true;

    private static bool SecurityGroup(ObjectAttributes item)
    {
        var type = AttributeReading.SignedInteger(item, "groupType");
        return HasClass(item, "group") && type is { } value && (value & int.MinValue) != 0
            && (value & 15) is 2 or 4 or 5 or 8;
    }

    private static void AddAttribute(ImmutableArray<Tier0Evidence>.Builder evidence, Tier0Target identity,
        ObjectAttributes item, string name)
    {
        foreach (var value in item.Find(name)?.Values ?? []) evidence.Add(new(identity, name, value.Ordinal, value.Stored));
    }
}
