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
}

/// <summary>A captured authorization route, not an AdminSDHolder protection route or a complete token.</summary>
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
        PermissionTrustee trustee, ObjectAttributes? holder, string forest)
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
            || !Same(requester.DomainFqdn, target.DomainFqdn))
            return Answer(RequesterTrusteeState.Unknown, RequesterTrusteeReason.ResourceContextUnknown, null);
        if (Same(sid, requesterSid))
            return Answer(RequesterTrusteeState.Matches, RequesterTrusteeReason.DirectIdentity, null);
        if (sid is "S-1-1-0" or "S-1-5-11")
            return Answer(RequesterTrusteeState.Matches, RequesterTrusteeReason.AuthenticatedIdentity, null);
        if (sid is "S-1-5-18" or "S-1-5-7")
            return Answer(RequesterTrusteeState.DoesNotMatch, RequesterTrusteeReason.NonUserIdentity, null);
        if (sid is null || Sid.IsBuiltinDomain(sid))
            return Answer(RequesterTrusteeState.Unknown, RequesterTrusteeReason.UnsupportedIdentity, null);
        if (holder is null || holder.ObjectGuid is null || !Same(SidOf(holder), sid))
            return Answer(RequesterTrusteeState.Unknown, RequesterTrusteeReason.IdentityMissing, null);
        if (!IsDomainObject(holder, forest) || !Same(holder.DomainFqdn, requester.DomainFqdn))
            return Answer(RequesterTrusteeState.Unknown, RequesterTrusteeReason.ResourceContextUnknown, null);
        if (HasClass(holder, "group"))
        {
            if (groupType is null)
                return Answer(RequesterTrusteeState.Unknown, RequesterTrusteeReason.GroupTypeMissing, null);
            if ((groupType.Value & 0x80000000L) == 0)
                return Answer(RequesterTrusteeState.DoesNotMatch, RequesterTrusteeReason.DistributionGroup, null);
            if ((groupType.Value & 0x0f) != 2)
                return Answer(RequesterTrusteeState.Unknown, RequesterTrusteeReason.UnsupportedGroupScope, null);
            var direct = holder.Find("member")?.Values.Any(value => Same(value.Text, requester.DistinguishedName)) == true;
            return direct
                ? Answer(RequesterTrusteeState.Matches, RequesterTrusteeReason.DirectGlobalMembership, requester.DistinguishedName)
                : Answer(RequesterTrusteeState.Unknown, RequesterTrusteeReason.MembershipNotEstablished, null);
        }
        // A historical identity is not a direct current-identity route, even when it is captured.
        if (requester.Find("sIDHistory")?.Values.Any(value => Same(SidValue(value), sid)) == true)
            return Answer(RequesterTrusteeState.Unknown, RequesterTrusteeReason.UnsupportedIdentity, null);
        return HasClass(holder, "user")
            ? Answer(RequesterTrusteeState.DoesNotMatch, RequesterTrusteeReason.OtherCurrentUser, null)
            : Answer(RequesterTrusteeState.Unknown, RequesterTrusteeReason.UnsupportedIdentity, null);
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
