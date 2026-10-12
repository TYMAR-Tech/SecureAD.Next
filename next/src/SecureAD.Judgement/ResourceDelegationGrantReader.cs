using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal static class ResourceDelegationGrantReader
{
    // RBCD consumes a stored security descriptor. Generic bits in stored ACEs are not expanded.
    // MS-SFU 3.2.5.2.3 requires a requester PAC/token and a KDC access check, but does not name its mask.
    // The CONTROL_ACCESS mask is cross-checked against Samba's Windows-interoperability implementation:
    // https://github.com/samba-team/samba/blob/master/source4/kdc/pac-glue.c (samba_kdc_check_s4u2proxy_rbcd).
    internal const int ControlAccess = 0x100;
    private static readonly string Everyone = WellKnownSidCatalog.AllSids.Single(value => value.ConstantName == "EVERYONE").Sid;
    private static readonly string AuthenticatedUsers = WellKnownSidCatalog.AllSids
        .Single(value => value.ConstantName == "AUTHENTICATED_USERS").Sid;

    internal static (IReadOnlyList<ResourceDelegationGrant> Grants, IReadOnlyList<string> Limits) Read(byte[] bytes)
    {
        var descriptor = SecurityDescriptorParser.Parse(bytes);
        var limits = new HashSet<string>(StringComparer.Ordinal);
        if (descriptor.DaclCompleteness != DaclCompleteness.Complete || descriptor.Errors.Count != 0)
        {
            limits.Add("ResourceDescriptorIncomplete");
            return ([], limits.ToArray());
        }
        if (descriptor.DaclState == DaclState.Unreadable) return ([], limits.Order(StringComparer.Ordinal).ToArray());
        if (descriptor.DaclState == DaclState.Null)
            return ([new(Everyone, [], true)], limits.Order(StringComparer.Ordinal).ToArray());
        var grants = new Dictionary<string, List<int>>(StringComparer.OrdinalIgnoreCase);
        var denied = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var deniedEveryone = false;
        var unknownEarlierEntry = false;
        foreach (var entry in descriptor.DaclAces.OrderBy(entry => entry.Ordinal))
        {
            if ((entry.PropagationFlags & 0x08) != 0) continue;
            if ((entry.AccessMask & ControlAccess) == 0)
            {
                if ((entry.AccessMask & unchecked((int)0xf0000000)) != 0) limits.Add("StoredGenericRightUnsupported");
                continue;
            }
            if (entry.AceType is not (AceType.AccessAllowed or AceType.AccessDenied or AceType.AccessAllowedObject or AceType.AccessDeniedObject)
                || entry.HasObjectType || entry.HasInheritedObjectType || entry.ApplicationData.Length != 0
                || Sid.ToBytes(entry.TrusteeSid) is null || WellKnownSidCatalog.FindBySid(entry.TrusteeSid)?.NamesAPrincipal == false)
            {
                limits.Add("ResourceDelegationEntryUnsupported");
                unknownEarlierEntry = true;
                continue;
            }
            if (entry.AceType is AceType.AccessDenied or AceType.AccessDeniedObject)
            {
                // An earlier same-holder/Everyone deny blocks this stored grant. Other group
                // denials need a concrete requester token and remain a separate authorization question.
                denied.Add(entry.TrusteeSid);
                deniedEveryone |= entry.TrusteeSid.Equals(Everyone, StringComparison.OrdinalIgnoreCase)
                    || entry.TrusteeSid.Equals(AuthenticatedUsers, StringComparison.OrdinalIgnoreCase);
                continue;
            }
            if (unknownEarlierEntry || deniedEveryone || denied.Contains(entry.TrusteeSid)) continue;
            if (denied.Count != 0) limits.Add("OtherRequesterDenyMembershipUnassessed");
            if (!grants.TryGetValue(entry.TrusteeSid, out var ordinals)) grants.Add(entry.TrusteeSid, ordinals = []);
            ordinals.Add(entry.Ordinal);
        }
        return (grants.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair =>
            new ResourceDelegationGrant(pair.Key, pair.Value.ToArray(), false)).ToArray(), limits.Order(StringComparer.Ordinal).ToArray());
    }
}
