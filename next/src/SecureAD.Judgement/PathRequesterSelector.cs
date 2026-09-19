using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal sealed class PathRequesterSelector(BundleReader bundle, PathInputs inputs,
    IReadOnlyDictionary<string, Tier0PathNode> nodes, IReadOnlyDictionary<string, NamingContextKind> contexts,
    CancellationToken cancellationToken)
{
    internal const int Version = 1;
    private const int WriteDacl = 0x40000;
    private readonly Dictionary<string, ObjectAttributes?> _attributes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ObjectPermissions?> _permissions = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<PathRequesterSelectionLimitation> _limitations = [];
    private readonly Dictionary<string, PathRequesterCandidate> _candidates = new(StringComparer.Ordinal);

    internal PathRequesterSelection Select()
    {
        cancellationToken.ThrowIfCancellationRequested();
        Limit(PathRequesterSelectionReason.OtherPathFamiliesNotSelected, null, null, null);
        if (inputs.UncertaintyRegions.Count != 0) Limit(PathRequesterSelectionReason.CapturedInputUncertainty, null, null, null);
        if (inputs.Availability != PathInputAvailability.Recorded)
        {
            Limit(PathRequesterSelectionReason.InputsUnavailable, null, null, null);
            return Result(false, []);
        }

        var resources = ResourceScope();
        foreach (var dn in resources.Order(StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var permissions = Permissions(dn);
            if (permissions is null || permissions.Availability != DescriptorAvailability.Read
                || permissions.DaclState == DaclState.Unreadable || permissions.DaclCompleteness != DaclCompleteness.Complete)
                Limit(PathRequesterSelectionReason.DescriptorUnavailable, dn, null, null);
            if (permissions?.DaclState == DaclState.Null) Limit(PathRequesterSelectionReason.BroadIdentityNotExpanded, dn, null, null);
            if (Qualification(dn, dn) is { } resourceIssue)
            {
                Limit(resourceIssue, dn, null, null);
                continue;
            }
            foreach (var entry in permissions?.Entries ?? [])
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (EntryReachReader.FromPropagationFlags(entry.PropagationFlags) != EntryReach.ThisObject) continue;
                if ((entry.AccessMask & (WriteDacl | 0x28)) == 0)
                {
                    if ((entry.AccessMask & 0xf0000000) != 0) Limit(PathRequesterSelectionReason.PermissionUnsupported, dn, entry, null);
                    continue;
                }
                // These are questions, including uncertain and denied entries. Only the existing
                // evaluators may interpret object scopes, ordered denies or operation prerequisites.
                if (Fixed(dn) && (entry.AccessMask & WriteDacl) != 0)
                    foreach (var witness in Requesters(dn, entry, WriteDacl))
                        Add(PathRequesterFamily.RequesterDacl, witness.MemberDn ?? witness.HolderDn, dn, null, null, [witness]);
                if (!Global(dn))
                {
                    if (Group(dn) && (entry.AccessMask & 0x28) != 0) Limit(PathRequesterSelectionReason.GlobalGroupRequired, dn, entry, null);
                    continue;
                }
                foreach (var kind in new[] { OwnAccountMembershipPermissionKind.SelfMembership, OwnAccountMembershipPermissionKind.WriteMembers })
                {
                    var mask = Mask(kind);
                    if ((entry.AccessMask & mask) == 0) continue;
                    foreach (var witness in Requesters(dn, entry, mask))
                    {
                        var requester = witness.MemberDn ?? witness.HolderDn;
                        if (nodes[dn].MembershipDistance is not null)
                            Add(PathRequesterFamily.OwnAccountMembership, requester, dn, null, kind, [witness]);
                        foreach (var terminal in TerminalWitnesses(dn))
                        {
                            if (Qualification(requester, terminal.ResourceDn) is { } issue)
                                Limit(issue, terminal.ResourceDn, null, requester);
                            else Add(PathRequesterFamily.MembershipDacl, requester, terminal.ResourceDn, dn, kind, [witness, terminal]);
                        }
                    }
                }
            }
        }
        return Result(true, resources.Order(StringComparer.OrdinalIgnoreCase)
            .Select(dn => new PathRequesterSelectionSource(dn, SourceFingerprint(dn))).ToArray());
    }

    internal static RequesterDaclRequest[] Requests(PathRequesterSelection selection) => selection.Candidates
        .Where(value => value.Family == PathRequesterFamily.RequesterDacl).Select(value => new RequesterDaclRequest(value.RequesterDn, value.TargetDn))
        .OrderBy(RequesterDaclProofs.Key, StringComparer.Ordinal).ToArray();
    internal static OwnAccountMembershipRequest[] OwnAccounts(PathRequesterSelection selection) => selection.Candidates
        .Where(value => value.Family == PathRequesterFamily.OwnAccountMembership)
        .Select(value => new OwnAccountMembershipRequest(value.RequesterDn, value.TargetDn) { PermissionKind = value.PermissionKind!.Value })
        .OrderBy(OwnAccountMembershipProofs.Key, StringComparer.Ordinal).ToArray();
    internal static MembershipDaclRequest[] MembershipDacls(PathRequesterSelection selection) => selection.Candidates
        .Where(value => value.Family == PathRequesterFamily.MembershipDacl)
        .Select(value => new MembershipDaclRequest(value.RequesterDn, value.GroupDn!, value.TargetDn) { PermissionKind = value.PermissionKind!.Value })
        .OrderBy(MembershipDaclProofs.Key, StringComparer.Ordinal).ToArray();

    private HashSet<string> ResourceScope()
    {
        var result = inputs.FixedTargets.Select(value => value.DistinguishedName).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var node in nodes.Values)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (node.MembershipDistance is not null && Group(node.Subject.DistinguishedName)) result.Add(node.Subject.DistinguishedName);
        }
        foreach (var target in inputs.FixedTargets)
            foreach (var entry in Permissions(target.DistinguishedName)?.Entries ?? [])
            {
                cancellationToken.ThrowIfCancellationRequested();
                if ((entry.AccessMask & WriteDacl) != 0 && EntryReachReader.FromPropagationFlags(entry.PropagationFlags) == EntryReach.ThisObject
                    && Holder(target.DistinguishedName, entry) is { } holder && Group(holder)) result.Add(holder);
            }
        return result;
    }

    private IEnumerable<PathRequesterSelectionWitness> TerminalWitnesses(string group)
    {
        foreach (var target in inputs.FixedTargets.OrderBy(value => value.DistinguishedName, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Qualification(group, target.DistinguishedName) is not null) continue;
            foreach (var entry in Permissions(target.DistinguishedName)?.Entries ?? [])
                if ((entry.AccessMask & WriteDacl) != 0 && EntryReachReader.FromPropagationFlags(entry.PropagationFlags) == EntryReach.ThisObject
                    && Same(Holder(target.DistinguishedName, entry), group)) yield return new(target.DistinguishedName, entry.Ordinal, WriteDacl, group, null);
        }
    }

    private IEnumerable<PathRequesterSelectionWitness> Requesters(string resource, PermissionEntry entry, int mask)
    {
        var holder = Holder(resource, entry);
        if (entry.Trustee.Sid is "S-1-1-0" or "S-1-5-11")
        {
            Limit(PathRequesterSelectionReason.BroadIdentityNotExpanded, resource, entry, null);
            yield break;
        }
        if (holder is null || Qualification(holder, resource) is not null)
        {
            Limit(holder is null ? PathRequesterSelectionReason.IdentityUnresolved : Qualification(holder, resource)!.Value, resource, entry, null);
            yield break;
        }
        if (User(holder)) { yield return new(resource, entry.Ordinal, mask, holder, null); yield break; }
        if (!Global(holder))
        {
            Limit(Group(holder) ? PathRequesterSelectionReason.GlobalGroupRequired : PathRequesterSelectionReason.RequesterKindUnsupported, resource, entry, null);
            yield break;
        }
        Limit(PathRequesterSelectionReason.MembershipVisibilityUnknown, resource, entry, null);
        foreach (var member in Attributes(holder)?.Find("member")?.Values ?? [])
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(member.Text)) { Limit(PathRequesterSelectionReason.IdentityUnresolved, resource, entry, null); continue; }
            if (Qualification(member.Text, resource) is { } issue) { Limit(issue, resource, entry, member.Text); continue; }
            if (!User(member.Text)) { Limit(PathRequesterSelectionReason.RequesterKindUnsupported, resource, entry, member.Text); continue; }
            yield return new(resource, entry.Ordinal, mask, holder, member.Text);
        }
    }

    private void Add(PathRequesterFamily family, string requester, string target, string? group,
        OwnAccountMembershipPermissionKind? kind, PathRequesterSelectionWitness[] witnesses)
    {
        var candidate = new PathRequesterCandidate(family, requester, target, group, kind,
            Tier0PathCalculation.Fingerprint(Attributes(requester)), witnesses);
        var key = Key(candidate);
        if (_candidates.TryGetValue(key, out var existing)) candidate = existing with { Witnesses = existing.Witnesses.Concat(witnesses).Distinct().ToArray() };
        _candidates[key] = candidate;
    }

    private PathRequesterSelection Result(bool complete, PathRequesterSelectionSource[] sources) => new(Version, inputs.JudgementGenerationId,
        Tier0PathCalculation.Fingerprint(inputs), complete, _candidates.Values.OrderBy(Key, StringComparer.Ordinal).ToArray(), sources,
        _limitations.OrderBy(value => Tier0PathCalculation.Fingerprint(value), StringComparer.Ordinal).ToArray());
    private static string Key(PathRequesterCandidate value) => value.Family + "\0" + value.RequesterDn.ToUpperInvariant() + "\0"
        + value.TargetDn.ToUpperInvariant() + "\0" + value.GroupDn?.ToUpperInvariant() + "\0" + value.PermissionKind;
    private static int Mask(OwnAccountMembershipPermissionKind kind) => kind == OwnAccountMembershipPermissionKind.SelfMembership ? 0x08 : 0x20;
    private void Limit(PathRequesterSelectionReason reason, string? resource, PermissionEntry? entry, string? member) =>
        _limitations.Add(new(reason, resource, entry?.Ordinal, entry?.Trustee.Sid, member));
    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    private bool Fixed(string dn) => inputs.FixedTargets.Any(value => Same(value.DistinguishedName, dn));
    private bool Group(string dn) => Attributes(dn) is { } value && RequesterTrusteeReading.HasClass(value, "group");
    private bool Global(string dn) => Group(dn) && RequesterTrusteeReading.Number(Attributes(dn), "groupType") is { } type && (type & 0x8000000fL) == 0x80000002L;
    private bool User(string dn) => Attributes(dn) is { } value && RequesterTrusteeReading.HasClass(value, "user") && !RequesterTrusteeReading.HasClass(value, "computer");
    private string? Holder(string resource, PermissionEntry entry) => entry.Trustee.Sid == "S-1-5-10" ? resource : entry.Trustee.DistinguishedName;
    private ObjectAttributes? Attributes(string dn)
    {
        if (!_attributes.TryGetValue(dn, out var value)) _attributes[dn] = value = bundle.ReadObjectAttributes(dn);
        return value;
    }
    private ObjectPermissions? Permissions(string dn)
    {
        if (!_permissions.TryGetValue(dn, out var value)) _permissions[dn] = value = bundle.ReadPermissions(dn);
        return value;
    }
    private string SourceFingerprint(string dn) => Tier0PathCalculation.Fingerprint(new
    {
        Resource = Attributes(dn), Permissions = Permissions(dn),
        Holders = (Permissions(dn)?.Entries ?? []).Select(entry => Holder(dn, entry)).OfType<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).Select(Attributes).ToArray(),
    });
    private PathRequesterSelectionReason? Qualification(string dn, string resource)
    {
        var value = Attributes(dn);
        if (!nodes.TryGetValue(dn, out var node) || value is null || node.Subject.ObjectGuid is null || !node.Subject.IsValid
            || Tier0Target.From(value, node.Subject.NamingContext) != node.Subject
            || (User(dn) || Group(dn)) && node.Subject.Sid is null
            || RequesterTrusteeReading.HasClass(value, "foreignSecurityPrincipal") || Same(value.Find("isDeleted")?.OnlyValue?.Text, "TRUE")
            || node.Subject.Sid is { } sid && nodes.Values.Count(other => Same(other.Subject.Sid, sid) && Same(other.Subject.SidScope, node.Subject.SidScope)) != 1)
            return PathRequesterSelectionReason.IdentityUnresolved;
        if (!nodes.TryGetValue(resource, out var target) || !Domain(node.Subject) || !Domain(target.Subject)
            || !Same(node.Subject.DomainFqdn, target.Subject.DomainFqdn)) return PathRequesterSelectionReason.ResourceContextUnsupported;
        return null;
    }
    private bool Domain(Tier0Target identity) => contexts.TryGetValue(identity.NamingContext, out var kind) && kind == NamingContextKind.Domain
        && !string.IsNullOrWhiteSpace(identity.DomainFqdn) && Same(DnHelper.DnToFqdn(identity.NamingContext), identity.DomainFqdn);
}
