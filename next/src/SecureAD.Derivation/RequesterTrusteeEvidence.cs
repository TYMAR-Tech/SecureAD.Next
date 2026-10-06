using System.Globalization;
using SecureAD.Evidence;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Derivation;

/// <summary>Whether a captured trustee applies to an ordinary authenticated directory user.</summary>
public enum RequesterTrusteeState { Matches, DoesNotMatch, Unknown }

/// <summary>The evidence or limit behind one bounded requester-to-trustee answer.</summary>
public enum RequesterTrusteeReason
{
    DirectIdentity, AuthenticatedIdentity, DirectGlobalMembership, DistributionGroup,
    OtherCurrentUser, NonUserIdentity, IdentityMissing, UnsupportedIdentity,
    ResourceContextUnknown, GroupTypeMissing, UnsupportedGroupScope, MembershipNotEstablished,
    ObtainedGlobalMembership,
    NestedGlobalMembership,
    DirectSecurityMembership, NestedSecurityMembership, DomainLocalOutsideResource,
}

/// <summary>A source-backed authorization route, not an AdminSDHolder protection route or a complete token.</summary>
public sealed record RequesterTrusteeEvidence(
    string TrusteeSid,
    RequesterTrusteeState State,
    RequesterTrusteeReason Reason,
    Guid? HolderGuid,
    string? HolderDn,
    string? HolderDomain,
    long? GroupType,
    DateTimeOffset? CapturedUtc,
    string? DirectMemberDn);

/// <summary>Reads only direct identities and one explicit same-domain global-security-group membership.</summary>
public static class RequesterTrusteeReading
{
    /// <summary>Returns a bounded authorization explanation from captured objects, never a live token.</summary>
    public static RequesterTrusteeEvidence Read(ObjectAttributes requester, ObjectAttributes target,
        PermissionTrustee trustee, ObjectAttributes? holder, string forest) =>
        ReadCore(requester, target, trustee, holder, forest, null);

    /// <summary>Reads a captured trustee after the caller has bound these domains to the sealed forest declaration.</summary>
    public static RequesterTrusteeEvidence ReadSameForest(ObjectAttributes requester, ObjectAttributes target,
        PermissionTrustee trustee, ObjectAttributes? holder, string forest, IReadOnlySet<string> readDomains) =>
        ReadCore(requester, target, trustee, holder, forest, readDomains);

    private static RequesterTrusteeEvidence ReadCore(ObjectAttributes requester, ObjectAttributes target,
        PermissionTrustee trustee, ObjectAttributes? holder, string forest, IReadOnlySet<string>? readDomains)
    {
        var isSelf = trustee.Sid == "S-1-5-10";
        if (isSelf) holder = target;
        var sid = isSelf ? SidOf(target) : trustee.Sid;
        var groupType = Number(holder, "groupType");
        RequesterTrusteeEvidence Answer(RequesterTrusteeState state, RequesterTrusteeReason reason, string? member) =>
            new(trustee.Sid, state, reason, holder?.ObjectGuid, holder?.DistinguishedName,
                holder?.DomainFqdn, groupType, holder?.CapturedUtc, member);
        if (SidOf(requester) is not { } requesterSid || requester.ObjectGuid is null
            || (isSelf && (sid is null || target.ObjectGuid is null)))
            return Answer(RequesterTrusteeState.Unknown, RequesterTrusteeReason.IdentityMissing, null);
        if (!IsDomainObject(requester, forest) || !IsDomainObject(target, forest)
            || (readDomains is null ? !Same(requester.DomainFqdn, target.DomainFqdn)
                : !Declared(requester) || !Declared(target)))
            return Answer(RequesterTrusteeState.Unknown, RequesterTrusteeReason.ResourceContextUnknown, null);
        if (Same(sid, requesterSid))
            return Answer(RequesterTrusteeState.Matches, RequesterTrusteeReason.DirectIdentity, null);
        if (sid is "S-1-1-0" or "S-1-5-11")
            return Answer(RequesterTrusteeState.Matches, RequesterTrusteeReason.AuthenticatedIdentity, null);
        if (sid is "S-1-5-18" or "S-1-5-7")
            return Answer(RequesterTrusteeState.DoesNotMatch, RequesterTrusteeReason.NonUserIdentity, null);
        if (sid is null || readDomains is null && Sid.IsBuiltinDomain(sid))
            return Answer(RequesterTrusteeState.Unknown, RequesterTrusteeReason.UnsupportedIdentity, null);
        if (holder is null || holder.ObjectGuid is null || !Same(SidOf(holder), sid))
            return Answer(RequesterTrusteeState.Unknown, RequesterTrusteeReason.IdentityMissing, null);
        if (!IsDomainObject(holder, forest) || (readDomains is null ? !Same(holder.DomainFqdn, requester.DomainFqdn) : !Declared(holder)))
            return Answer(RequesterTrusteeState.Unknown, RequesterTrusteeReason.ResourceContextUnknown, null);
        // A holder's current type cannot exclude its SID when the requester carries that identity
        // historically. This is uncertainty, not support for constructing a SID-history token.
        if (requester.Find("sIDHistory")?.Values.Any(value => Same(SidValue(value), sid)) == true)
            return Answer(RequesterTrusteeState.Unknown, RequesterTrusteeReason.UnsupportedIdentity, null);
        if (HasClass(holder, "group"))
        {
            if (groupType is null)
                return Answer(RequesterTrusteeState.Unknown, RequesterTrusteeReason.GroupTypeMissing, null);
            if ((groupType.Value & 0x80000000L) == 0)
                return Answer(RequesterTrusteeState.DoesNotMatch, RequesterTrusteeReason.DistributionGroup, null);
            var scope = groupType.Value & 0x0f;
            if (readDomains is null ? scope != 2 : scope is not (2 or 4 or 5 or 8))
                return Answer(RequesterTrusteeState.Unknown, RequesterTrusteeReason.UnsupportedGroupScope, null);
            if (readDomains is not null)
            {
                if ((scope != 2 || !Same(requester.DomainFqdn, target.DomainFqdn)) && holder.Find("sIDHistory")?.HasValue == true)
                    return Answer(RequesterTrusteeState.Unknown, RequesterTrusteeReason.UnsupportedIdentity, null);
                if (scope is 4 or 5 && !Same(holder.DomainFqdn, target.DomainFqdn))
                    return Answer(RequesterTrusteeState.DoesNotMatch, RequesterTrusteeReason.DomainLocalOutsideResource, null);
            }
            var direct = holder.Find("member")?.Values.Any(value => Same(value.Text, requester.DistinguishedName)) == true;
            if (direct && readDomains is not null && !SupportsSecurityNesting(holder, requester))
                return Answer(RequesterTrusteeState.Unknown, RequesterTrusteeReason.UnsupportedGroupScope, null);
            return direct
                ? Answer(RequesterTrusteeState.Matches, scope == 2 ? RequesterTrusteeReason.DirectGlobalMembership
                    : RequesterTrusteeReason.DirectSecurityMembership, requester.DistinguishedName)
                : Answer(RequesterTrusteeState.Unknown, RequesterTrusteeReason.MembershipNotEstablished, null);
        }
        return HasClass(holder, "user")
            ? Answer(RequesterTrusteeState.DoesNotMatch, RequesterTrusteeReason.OtherCurrentUser, null)
            : Answer(RequesterTrusteeState.Unknown, RequesterTrusteeReason.UnsupportedIdentity, null);

        bool Declared(ObjectAttributes value) => value.DomainFqdn is { } domain && readDomains!.Contains(domain);
    }

    /// <summary>Qualifies one security-group hop under Microsoft's scope table; it does not discover membership or prove access.</summary>
    public static bool SupportsSecurityNesting(ObjectAttributes group, ObjectAttributes member)
    {
        if (!HasClass(group, "group") || Number(group, "groupType") is not { } type) return false;
        if (!HasClass(member, "group") && !HasClass(member, "user") && !HasClass(member, "computer")) return false;
        var memberType = HasClass(member, "group") ? Number(member, "groupType") : null;
        if (HasClass(member, "group") && memberType is null) return false;
        return SupportsSecurityNesting(type, memberType, Same(group.DomainFqdn, member.DomainFqdn),
            SidOf(group) is { } sid && Sid.IsBuiltinDomain(sid));
    }

    /// <summary>Checks the same hop rules against stored group-type witnesses; a null member type identifies the ordinary user.</summary>
    public static bool SupportsSecurityNesting(long type, long? memberType, bool sameDomain, bool builtinHolder)
    {
        if ((type & 0x80000000L) == 0) return false;
        var scope = type & 0x0f;
        if (scope is not (2 or 4 or 5 or 8)) return false;
        if (memberType is null) return scope != 2 || sameDomain;
        if ((memberType.Value & 0x80000000L) == 0) return false;
        var memberScope = memberType.Value & 0x0f;
        // BUILTIN groups are supported as resource-domain holders, not as transferable nested identities.
        if (builtinHolder && memberScope is not (2 or 8)) return false;
        return scope switch
        {
            2 => sameDomain && memberScope == 2,
            8 => memberScope is 2 or 8,
            4 => memberScope is 2 or 8 || memberScope == 4 && sameDomain,
            5 => memberScope is 2 or 8,
            _ => false,
        };
    }

    internal static bool IsDomainObject(ObjectAttributes value, string forest)
    {
        if (string.IsNullOrWhiteSpace(value.DomainFqdn) || string.IsNullOrWhiteSpace(forest)
            || !Same(DnHelper.DnToFqdn(value.DistinguishedName), value.DomainFqdn)) return false;
        var configuration = "CN=Configuration," + string.Join(',', forest.Split('.').Select(part => "DC=" + part));
        for (string? dn = value.DistinguishedName; dn is not null; dn = DnHelper.GetParentDn(dn))
            if (Same(dn, configuration)) return false;
        return true;
    }

    public static bool HasClass(ObjectAttributes? value, string name) =>
        value?.Find("objectClass")?.Values.Any(item => Same(item.Text, name)) == true;
    public static string? SidOf(ObjectAttributes? value) => SidValue(value?.Find("objectSid")?.OnlyValue);
    private static string? SidValue(AttributeValue? value) => value?.Bytes is { } bytes ? Sid.ToText(bytes) : value?.Text;
    public static long? Number(ObjectAttributes? value, string name) =>
        long.TryParse(value?.Find(name)?.OnlyValue?.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number) ? number : null;
    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}
