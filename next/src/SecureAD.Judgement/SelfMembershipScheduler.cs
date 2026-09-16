using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal sealed class SelfMembershipScheduler
{
    private readonly SelfMembershipDiscoveryBudget? _budget;
    private readonly bool _captureComplete;
    private readonly Func<string, ObjectAttributes?> _attributes;
    private readonly string _forest;
    private readonly CancellationToken _cancellationToken;
    private readonly Dictionary<(string Requester, string Target), (string Requester, string Target)> _pairs = [];
    private readonly HashSet<SelfMembershipDiscoveryLimitation> _limitations = [];
    private long _objects;
    private long _permissions;
    private long _members;
    private bool _stopped;

    internal SelfMembershipScheduler(SelfMembershipDiscoveryBudget? budget, bool captureComplete,
        Func<string, ObjectAttributes?> attributes, string forest, CancellationToken cancellationToken)
    {
        budget?.Validate();
        _budget = budget;
        _captureComplete = captureComplete;
        _attributes = attributes;
        _forest = forest;
        _cancellationToken = cancellationToken;
        if (!captureComplete) Limit(SelfMembershipDiscoveryReason.CaptureIncomplete, null);
        if (budget is null) Limit(SelfMembershipDiscoveryReason.ProductionBudgetNotConfigured, null);
    }

    internal void Observe(ObjectAttributes target, ObjectPermissions? permissions)
    {
        _cancellationToken.ThrowIfCancellationRequested();
        if (_budget is null || _stopped) return;
        var dn = target.DistinguishedName;
        if (_objects == _budget.Objects) { Stop(SelfMembershipDiscoveryReason.ObjectsBudgetExceeded, dn); return; }
        _objects++;
        if (target.Find("objectClass")?.HasValue != true)
        {
            Limit(SelfMembershipDiscoveryReason.TargetClassMissing, dn);
            return;
        }
        if (!RequesterTrusteeReading.HasClass(target, "group")) return;
        if (permissions is null || permissions.Availability != DescriptorAvailability.Read || permissions.DaclState == DaclState.Unreadable)
        {
            Limit(SelfMembershipDiscoveryReason.DescriptorUnavailable, dn);
            return;
        }
        if (permissions.DaclState == DaclState.Null)
        {
            Limit(SelfMembershipDiscoveryReason.BroadTrustee, dn);
            return;
        }
        if (permissions.DaclCompleteness != DaclCompleteness.Complete)
            Limit(SelfMembershipDiscoveryReason.DescriptorIncomplete, dn);
        foreach (var entry in permissions.Entries)
        {
            _cancellationToken.ThrowIfCancellationRequested();
            if (_permissions == _budget.PermissionEntries)
            {
                Stop(SelfMembershipDiscoveryReason.PermissionBudgetExceeded, dn, entry);
                return;
            }
            _permissions++;
            if ((entry.AccessMask & 0x08) == 0 || EntryReachReader.FromPropagationFlags(entry.PropagationFlags) != EntryReach.ThisObject)
                continue;
            if (entry.HasObjectType && entry.ObjectTypeGuid is { } guid
                && !string.Equals(guid, SchemaGuidCatalog.Embedded.GuidFor("Self-Membership"), StringComparison.OrdinalIgnoreCase)) continue;
            var holder = entry.Trustee.Sid == "S-1-5-10" ? target
                : entry.Trustee.DistinguishedName is { } holderDn ? _attributes(holderDn) : null;
            if (holder is null)
            {
                Limit(entry.Trustee.Sid is "S-1-1-0" or "S-1-5-11" ? SelfMembershipDiscoveryReason.BroadTrustee
                    : entry.Trustee.WellKnownRole is not null ? SelfMembershipDiscoveryReason.UnsupportedRoute
                    : SelfMembershipDiscoveryReason.UnresolvedTrustee, dn, entry);
                continue;
            }
            if (holder.ObjectGuid is null || RequesterTrusteeReading.SidOf(holder) is null)
                Limit(SelfMembershipDiscoveryReason.MissingIdentity, dn, entry);
            if (IsUser(holder))
            {
                Pair(holder, target, entry);
            }
            else if (RequesterTrusteeReading.HasClass(holder, "group"))
            {
                var groupType = RequesterTrusteeReading.Number(holder, "groupType");
                if (groupType is null)
                    Limit(SelfMembershipDiscoveryReason.GroupTypeMissing, dn, entry);
                else if ((groupType.Value & 0x8000000fL) != 0x80000002L)
                    Limit(SelfMembershipDiscoveryReason.UnsupportedRoute, dn, entry);
                var members = holder.Find("member");
                if (members?.HasValue != true)
                {
                    Limit(SelfMembershipDiscoveryReason.MembershipNotCaptured, dn, entry);
                    continue;
                }
                // Visible members establish their own links, not completeness of the entire attribute.
                Limit(SelfMembershipDiscoveryReason.MembershipCompletenessUnknown, dn, entry);
                foreach (var member in members.Values)
                {
                    _cancellationToken.ThrowIfCancellationRequested();
                    if (_members == _budget.MembershipValues)
                    {
                        Stop(SelfMembershipDiscoveryReason.MembershipBudgetExceeded, dn, entry, member.Text);
                        return;
                    }
                    _members++;
                    var memberDn = string.IsNullOrWhiteSpace(member.Text) ? null : member.Text;
                    var requester = memberDn is null ? null : _attributes(memberDn);
                    if (requester is null)
                        Limit(SelfMembershipDiscoveryReason.MissingIdentity, dn, entry, memberDn);
                    else if (!IsUser(requester))
                        Limit(SelfMembershipDiscoveryReason.UnsupportedRoute, dn, entry, memberDn);
                    else
                        Pair(requester, target, entry);
                    if (_stopped) return;
                }
            }
            else
                Limit(SelfMembershipDiscoveryReason.UnsupportedRoute, dn, entry);
            if (_stopped) return;
        }
    }

    internal IReadOnlyList<SelfMembershipRequest> Requests() => _pairs.Values
        .OrderBy(value => value.Requester, StringComparer.OrdinalIgnoreCase)
        .ThenBy(value => value.Target, StringComparer.OrdinalIgnoreCase)
        .SelectMany(value => new[]
        {
            new SelfMembershipRequest(value.Requester, value.Target, SelfMembershipOperation.Add, null),
            new SelfMembershipRequest(value.Requester, value.Target, SelfMembershipOperation.Remove, null),
        }).ToArray();

    internal SelfMembershipDiscoveryCoverage Coverage() => new(1, SelfMembershipDiscoveryMode.Automatic,
        _budget is not null && !_stopped, _captureComplete, _budget, _objects, _permissions, _members, _pairs.Count,
        _limitations.OrderBy(item => item.Reason).ThenBy(item => item.TargetDn, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.PermissionOrdinal).ThenBy(item => item.TrusteeSid, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.MemberDn, StringComparer.OrdinalIgnoreCase).ToArray());

    private void Pair(ObjectAttributes requester, ObjectAttributes target, PermissionEntry entry)
    {
        var dn = target.DistinguishedName;
        var key = (requester.DistinguishedName.ToUpperInvariant(), dn.ToUpperInvariant());
        if (_pairs.ContainsKey(key)) return;
        if (_pairs.Count == _budget!.Pairs)
        {
            Stop(SelfMembershipDiscoveryReason.PairBudgetExceeded, dn, entry, requester.DistinguishedName);
            return;
        }
        var trustee = RequesterTrusteeReading.Read(requester, target, entry.Trustee,
            entry.Trustee.Sid == "S-1-5-10" ? target : entry.Trustee.DistinguishedName is { } holderDn ? _attributes(holderDn) : null, _forest);
        if (trustee.State == RequesterTrusteeState.Unknown)
            Limit(trustee.Reason == RequesterTrusteeReason.GroupTypeMissing ? SelfMembershipDiscoveryReason.GroupTypeMissing
                : trustee.Reason is RequesterTrusteeReason.IdentityMissing or RequesterTrusteeReason.MembershipNotEstablished
                    || string.IsNullOrWhiteSpace(requester.DomainFqdn) || string.IsNullOrWhiteSpace(target.DomainFqdn)
                    || string.IsNullOrWhiteSpace(holderDomain(entry, target))
                ? SelfMembershipDiscoveryReason.MissingIdentity : SelfMembershipDiscoveryReason.UnsupportedRoute,
                dn, entry, requester.DistinguishedName);
        _pairs.Add(key, (requester.DistinguishedName, dn));

        string? holderDomain(PermissionEntry permission, ObjectAttributes subject) => permission.Trustee.Sid == "S-1-5-10"
            ? subject.DomainFqdn : permission.Trustee.DomainFqdn;
    }

    private static bool IsUser(ObjectAttributes value) => RequesterTrusteeReading.HasClass(value, "user")
        && !RequesterTrusteeReading.HasClass(value, "computer");

    private void Limit(SelfMembershipDiscoveryReason reason, string? target) =>
        Limit(reason, target, null, null);

    private void Limit(SelfMembershipDiscoveryReason reason, string? target, PermissionEntry? entry) =>
        Limit(reason, target, entry, null);

    private void Limit(SelfMembershipDiscoveryReason reason, string? target, PermissionEntry? entry, string? member) =>
        _limitations.Add(new(reason, target, entry?.Ordinal, entry?.Trustee.Sid, member));

    private void Stop(SelfMembershipDiscoveryReason reason, string? target) =>
        Stop(reason, target, null, null);

    private void Stop(SelfMembershipDiscoveryReason reason, string? target, PermissionEntry? entry) =>
        Stop(reason, target, entry, null);

    private void Stop(SelfMembershipDiscoveryReason reason, string? target, PermissionEntry? entry, string? member)
    {
        Limit(reason, target, entry, member);
        _stopped = true;
    }
}
