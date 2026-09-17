using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// Builds bounded captured facts for Tier-0 discovery acceptance, extending the classifier fixture
/// with the owner and permission evidence discovery reads.
/// </summary>
/// <remarks>
/// Expected relevance is stated by each test from these captured facts and decision 0116, never by
/// running the selector under test to produce its own oracle.
/// </remarks>
internal sealed class Tier0DiscoveryEvidence
{
    internal const string Everyone = "S-1-1-0";
    internal const string AuthenticatedUsers = "S-1-5-11";
    internal const string Self = "S-1-5-10";
    internal const int WriteDacl = 0x40000;
    internal const int WriteOwner = 0x80000;

    private readonly Dictionary<string, ObjectAttributes> _objects = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ObjectPermissions> _permissions = new(StringComparer.OrdinalIgnoreCase);

    internal Guid Generation { get; } = Guid.NewGuid();

    internal ObjectAttributes Domain { get; }

    internal Tier0DiscoveryEvidence(string domainSid = "S-1-5-21-1-2-3", string domainFqdn = "contoso.com")
    {
        DomainSid = domainSid;
        DomainFqdn = domainFqdn;
        Domain = new(string.Join(',', domainFqdn.Split('.').Select(part => "DC=" + part)), Guid.NewGuid(),
            DateTimeOffset.UnixEpoch, default,
            [Attribute("objectSid", domainSid), Attribute("objectClass", "top", "domain", "domainDNS")], domainFqdn);
        _objects[Domain.DistinguishedName] = Domain;
    }

    internal string DomainSid { get; }
    internal string DomainFqdn { get; }

    internal Tier0InputBinding Binding => new(new string('A', 64), Generation, new string('B', 64),
        PrincipalClassificationRegistry.Version, PolicyVersion: 2, ContractVersion: 2,
        ForestRootNamingContext: Domain.DistinguishedName, ConfigurationNamingContext: null);

    internal IReadOnlyCollection<ObjectAttributes> Objects => _objects.Values;

    /// <summary>Every captured object, so a stream can be replayed in a stable order.</summary>
    internal IEnumerable<ObjectAttributes> Stream() =>
        _objects.Values.OrderBy(item => item.DistinguishedName, StringComparer.OrdinalIgnoreCase);

    internal CapturedMembershipInput Input(bool complete = true) => new(Generation, complete, [.. Stream()]);

    internal Tier0Target Target(ObjectAttributes subject) => Tier0Target.From(subject, Domain.DistinguishedName);

    internal ObjectAttributes? Find(string distinguishedName) =>
        _objects.GetValueOrDefault(distinguishedName);

    internal ObjectPermissions? Permissions(string distinguishedName) =>
        _permissions.GetValueOrDefault(distinguishedName);

    /// <summary>A captured principal; <paramref name="rid"/> completes this fixture's domain SID.</summary>
    internal ObjectAttributes Principal(string name, string rid, string objectClass = "group",
        params ObjectAttribute[] extras)
    {
        var subject = new ObjectAttributes($"CN={name},{Domain.DistinguishedName}", Guid.NewGuid(),
            DateTimeOffset.UnixEpoch, default,
            [Attribute("objectSid", $"{DomainSid}-{rid}"), Attribute("objectClass", "top", objectClass), .. extras],
            DomainFqdn);
        _objects[subject.DistinguishedName] = subject;
        return subject;
    }

    /// <summary>A security group holding the supplied members, as the captured member attribute.</summary>
    internal ObjectAttributes Group(string name, string rid, params ObjectAttributes[] members) =>
        Principal(name, rid, "group", Attribute("groupType", "-2147483646"),
            Attribute("member", members.Select(item => item.DistinguishedName).ToArray()));

    /// <summary>Records the descriptor discovery reads for <paramref name="subject"/>.</summary>
    internal ObjectPermissions Describe(ObjectAttributes subject, string? ownerSid = null,
        DaclState state = DaclState.Present, DaclCompleteness completeness = DaclCompleteness.Complete,
        params PermissionEntry[] entries)
    {
        var permissions = new ObjectPermissions(subject.DistinguishedName, DescriptorAvailability.Read, null,
            ownerSid is null ? null : Trustee(ownerSid), state, completeness, true, false, entries, []);
        _permissions[subject.DistinguishedName] = permissions;
        return permissions;
    }

    /// <summary>A descriptor that could not be read, which is not an empty permission set.</summary>
    internal ObjectPermissions Unreadable(ObjectAttributes subject, string reason = "AccessDenied")
    {
        var permissions = new ObjectPermissions(subject.DistinguishedName, DescriptorAvailability.Unreadable, reason,
            null, DaclState.Unreadable, DaclCompleteness.Unknown, true, false, [], [reason]);
        _permissions[subject.DistinguishedName] = permissions;
        return permissions;
    }

    /// <summary>A NULL DACL, which grants everyone everything rather than nobody anything.</summary>
    internal ObjectPermissions NullDacl(ObjectAttributes subject, string? ownerSid = null)
    {
        var permissions = new ObjectPermissions(subject.DistinguishedName, DescriptorAvailability.Read, null,
            ownerSid is null ? null : Trustee(ownerSid), DaclState.Null, DaclCompleteness.Complete, true, false, [], []);
        _permissions[subject.DistinguishedName] = permissions;
        return permissions;
    }

    /// <summary>One access control entry at a stated ordinal, which is part of the retained witness.</summary>
    internal PermissionEntry Allow(int ordinal, ObjectAttributes holder, int accessMask) =>
        new(ordinal, "AccessAllowed", Trustee(holder), accessMask, null, null, false, 0, 0, false, false, []);

    /// <summary>An entry naming a SID this fixture did not capture as an object.</summary>
    internal static PermissionEntry AllowSid(int ordinal, string sid, int accessMask, string? name = null,
        WellKnownSidRole? role = null) =>
        new(ordinal, "AccessAllowed", new(sid, name, null, null, null, role, null), accessMask,
            null, null, false, 0, 0, false, false, []);

    internal static PermissionEntry Deny(int ordinal, ObjectAttributes holder, int accessMask) =>
        new(ordinal, "AccessDenied", Trustee(holder), accessMask, null, null, false, 0, 0, false, false, []);

    internal static PermissionTrustee Trustee(ObjectAttributes holder) => new(
        holder.Find("objectSid")?.OnlyValue?.Text ?? throw new InvalidOperationException("The fixture principal has no SID."),
        holder.DistinguishedName, holder.DistinguishedName, holder.DomainFqdn, null, null, null);

    internal PermissionTrustee Trustee(string sid) => new(sid, sid, null, DomainFqdn, null,
        sid is Everyone or AuthenticatedUsers ? WellKnownSidRole.Principal : null, null);

    internal MembershipRouteSummary Routes(params ObjectAttributes[] chain) => new(
        [new(PrincipalIdentity(chain[1]), [new(0, "NameDoesNotDefineImportance", MembershipRouteAuthorization.SecurityEnabled,
            false, chain.Select(item => new MembershipRouteStep(PrincipalIdentity(item), false)).ToArray())],
            MembershipRouteIncompleteReason.None)],
        MembershipRouteIncompleteReason.None);

    internal static MembershipRoutePrincipal PrincipalIdentity(ObjectAttributes item)
    {
        var sid = item.Find("objectSid")?.OnlyValue?.Text ?? "";
        return new(sid, Sid.IsBuiltinDomain(sid) ? item.DomainFqdn : null, item.DistinguishedName);
    }

    internal static ObjectAttribute Attribute(string name, params string[] values) => new(name,
        AttributeCardinality.MultiValued, values.Select((value, index) => new AttributeValue(index, value, null)).ToArray());
}
