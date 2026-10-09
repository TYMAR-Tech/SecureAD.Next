using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal sealed class PathRequesterSelector(Func<string, ObjectAttributes?> readAttributes,
    Func<string, ObjectPermissions?> readPermissions, PathInputs inputs,
    IReadOnlyDictionary<string, Tier0PathNode> nodes, IReadOnlyDictionary<string, NamingContextKind> contexts,
    CancellationToken cancellationToken, PostPassDiagnostics? diagnostic, IPathRequesterSelectionSink sink)
{
    internal PathRequesterSelector(BundleReader bundle, PathInputs inputs,
        IReadOnlyDictionary<string, Tier0PathNode> nodes, IReadOnlyDictionary<string, NamingContextKind> contexts,
        CancellationToken cancellationToken, PostPassDiagnostics? diagnostic, IPathRequesterSelectionSink sink)
        : this(bundle.ReadObjectAttributes, bundle.ReadPermissions, inputs, nodes, contexts, cancellationToken, diagnostic, sink) { }

    internal const int Version = 5;
    internal RequesterMembershipContext? Memberships { get; init; }
    private const int WriteDacl = 0x40000;
    private readonly Dictionary<string, ObjectAttributes?> _attributes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ObjectPermissions?> _permissions = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<(string Sid, string? Scope), int> _identityCounts = [];
    private readonly HashSet<string> _fixedTargets = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<PathRequesterSelectionWitness>> _terminals = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _requesterFingerprints = new(StringComparer.OrdinalIgnoreCase);
    private long _questionsConsidered;
    private long _sourcesFingerprinted;
    private long _distinctQuestions;

    internal PathRequesterSelectionScan Select()
    {
        ArgumentNullException.ThrowIfNull(sink);
        cancellationToken.ThrowIfCancellationRequested();
        Limit(PathRequesterSelectionReason.OtherPathFamiliesNotSelected, null, null, null);
        if (inputs.UncertaintyRegions.Count != 0) Limit(PathRequesterSelectionReason.CapturedInputUncertainty, null, null, null);
        if (inputs.Availability != PathInputAvailability.Recorded)
        {
            Limit(PathRequesterSelectionReason.InputsUnavailable, null, null, null);
            return Result(false);
        }

        var resources = PrepareLookups();
        _permissions.Clear();
        _attributes.Clear();
        diagnostic?.Part("selecting-questions");
        diagnostic?.Counter("resourcesTotal", resources.Count);
        var processed = 0L;
        foreach (var dn in resources.Order(StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var permissions = Permissions(dn);
            SelectResource(dn, permissions);
            diagnostic?.Part("fingerprinting-sources");
            sink.Source(new(dn, SourceFingerprint(dn)));
            _permissions.Clear();
            _attributes.Clear();
            diagnostic?.Counter("resourcesProcessed", ++processed);
            diagnostic?.Part("selecting-questions");
        }
        return Result(true);

        void SelectResource(string dn, ObjectPermissions? permissions)
        {
            if (permissions is null || permissions.Availability != DescriptorAvailability.Read
                || permissions.DaclState == DaclState.Unreadable || permissions.DaclCompleteness != DaclCompleteness.Complete)
                Limit(PathRequesterSelectionReason.DescriptorUnavailable, dn, null, null);
            if (permissions?.DaclState == DaclState.Null) Limit(PathRequesterSelectionReason.BroadIdentityNotExpanded, dn, null, null);
            if (Qualification(dn, dn) is { } resourceIssue)
            {
                Limit(resourceIssue, dn, null, null);
                return;
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
                            if (Qualification(requester, terminal.ResourceDn, Memberships?.HasForestScope == true) is { } issue)
                                Limit(issue, terminal.ResourceDn, null, requester);
                            else Add(PathRequesterFamily.MembershipDacl, requester, terminal.ResourceDn, dn, kind, [witness, terminal]);
                        }
                    }
                }
            }
        }
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

    private HashSet<string> PrepareLookups()
    {
        diagnostic?.Part("indexing-identities");
        diagnostic?.Counter("identityNodesTotal", nodes.Count);
        var result = inputs.FixedTargets.Select(value => value.DistinguishedName).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var target in inputs.FixedTargets) _fixedTargets.Add(target.DistinguishedName);
        var indexed = 0L;
        foreach (var node in nodes.Values)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (node.Subject.Sid is { } sid)
            {
                var key = IdentityKey(sid, node.Subject.SidScope);
                _identityCounts[key] = _identityCounts.GetValueOrDefault(key) + 1;
            }
            if (node.MembershipDistance is not null && Group(node.Subject.DistinguishedName)) result.Add(node.Subject.DistinguishedName);
            diagnostic?.Counter("identityNodesIndexed", ++indexed);
        }
        diagnostic?.Part("indexing-target-permissions");
        var permissionsRead = 0L;
        foreach (var target in inputs.FixedTargets)
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var entry in Permissions(target.DistinguishedName)?.Entries ?? [])
            {
                cancellationToken.ThrowIfCancellationRequested();
                diagnostic?.Counter("targetPermissionsProcessed", ++permissionsRead);
                if ((entry.AccessMask & WriteDacl) != 0 && EntryReachReader.FromPropagationFlags(entry.PropagationFlags) == EntryReach.ThisObject
                    && (Memberships?.HasForestScope == true
                        ? Memberships.Holder(entry.Trustee, target)?.DistinguishedName
                        : Holder(target.DistinguishedName, entry)) is { } holder && Group(holder))
                {
                    result.Add(holder);
                    if (Qualification(holder, target.DistinguishedName, Memberships?.HasForestScope == true) is not null) continue;
                    if (RequesterTrusteeReading.Number(Attributes(holder), "groupType") is { } type
                        && (type & 0x0f) is 4 or 5 && !Same(nodes[holder].Subject.DomainFqdn, target.DomainFqdn)) continue;
                    if (!result.TryGetValue(holder, out var group)) throw Tier0PathStorage.InvalidProof();
                    if (!_terminals.TryGetValue(holder, out var witnesses)) _terminals[holder] = witnesses = [];
                    witnesses.Add(new(target.DistinguishedName, entry.Ordinal, WriteDacl, group, null));
                    if (Memberships is null) continue;
                    foreach (var route in Memberships.Groups(holder, target))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        result.Add(route.GroupDn);
                        if (!_terminals.TryGetValue(route.GroupDn, out var continuations)) _terminals[route.GroupDn] = continuations = [];
                        continuations.Add(new(target.DistinguishedName, entry.Ordinal, WriteDacl, group, null) { Membership = route.Evidence });
                    }
                }
            }
        }
        foreach (var group in _terminals.Keys)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _terminals[group] = _terminals[group].OrderBy(value => value.ResourceDn, StringComparer.OrdinalIgnoreCase).ToList();
        }
        return result;
    }

    private IReadOnlyList<PathRequesterSelectionWitness> TerminalWitnesses(string group) =>
        _terminals.TryGetValue(group, out var witnesses) ? witnesses : [];

    private IEnumerable<PathRequesterSelectionWitness> Requesters(string resource, PermissionEntry entry, int mask)
    {
        var sameForest = mask == WriteDacl && Memberships?.HasForestScope == true;
        var holder = sameForest ? Memberships!.Holder(entry.Trustee, nodes[resource].Subject)?.DistinguishedName : Holder(resource, entry);
        if (entry.Trustee.Sid is "S-1-1-0" or "S-1-5-11")
        {
            Limit(PathRequesterSelectionReason.BroadIdentityNotExpanded, resource, entry, null);
            yield break;
        }
        if (holder is null)
        {
            Limit(PathRequesterSelectionReason.IdentityUnresolved, resource, entry, null);
            yield break;
        }
        if (Qualification(holder, resource, sameForest) is { } issue)
        {
            Limit(issue, resource, entry, null);
            yield break;
        }
        if (User(holder)) { yield return new(resource, entry.Ordinal, mask, holder, null); yield break; }
        if (!Global(holder) && (!sameForest || !Group(holder)))
        {
            Limit(Group(holder) ? PathRequesterSelectionReason.GlobalGroupRequired : PathRequesterSelectionReason.RequesterKindUnsupported, resource, entry, null);
            yield break;
        }
        if (sameForest && RequesterTrusteeReading.Number(Attributes(holder), "groupType") is { } type
            && !RequesterTrusteeReading.SupportsSecurityNesting(type, null, true, Sid.IsBuiltinDomain(entry.Trustee.Sid)))
        {
            Limit(PathRequesterSelectionReason.PermissionUnsupported, resource, entry, null);
            yield break;
        }
        Limit(PathRequesterSelectionReason.MembershipVisibilityUnknown, resource, entry, null);
        foreach (var member in Global(holder) ? Attributes(holder)?.Find("member")?.Values ?? [] : [])
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(member.Text)) { Limit(PathRequesterSelectionReason.IdentityUnresolved, resource, entry, null); continue; }
            if (Qualification(member.Text, resource, sameForest) is { } memberIssue) { Limit(memberIssue, resource, entry, member.Text); continue; }
            if (!User(member.Text))
            {
                if (mask != WriteDacl || Memberships is null || !Global(member.Text))
                    Limit(PathRequesterSelectionReason.RequesterKindUnsupported, resource, entry, member.Text);
                continue;
            }
            yield return new(resource, entry.Ordinal, mask, holder, member.Text);
        }
        if (mask != WriteDacl || Memberships is null) yield break;
        var routes = sameForest ? Memberships.CapturedRequesters(holder) : Memberships.Requesters(holder);
        foreach (var nested in routes)
        {
            if (Global(holder) && nested.Evidence.Links.Count == 1) continue;
            yield return new(resource, entry.Ordinal, mask, holder, nested.RequesterDn) { Membership = nested.Evidence };
        }
        foreach (var limitation in sameForest ? Memberships.CapturedLimitations(holder) : Memberships.Limitations(holder))
            Limit(limitation.Reason, resource, entry, limitation.Dn);
    }

    private void Add(PathRequesterFamily family, string requester, string target, string? group,
        OwnAccountMembershipPermissionKind? kind, PathRequesterSelectionWitness[] witnesses)
    {
        cancellationToken.ThrowIfCancellationRequested();
        diagnostic?.Counter("questionsConsidered", ++_questionsConsidered);
        if (!_requesterFingerprints.TryGetValue(requester, out var fingerprint))
        {
            _requesterFingerprints[requester] = fingerprint = Tier0PathCalculation.Fingerprint(Attributes(requester));
            diagnostic?.Counter("accountsFingerprinted", _requesterFingerprints.Count);
        }
        if (sink.Include(new(family, requester, target, group, kind, fingerprint, witnesses)))
            diagnostic?.Counter("distinctQuestions", ++_distinctQuestions);
    }

    private PathRequesterSelectionScan Result(bool complete) => new(Version, inputs.JudgementGenerationId,
        Tier0PathCalculation.Fingerprint(inputs), complete);
    internal static string Key(PathRequesterCandidate value) => Key(value.Family, value.RequesterDn, value.TargetDn, value.GroupDn, value.PermissionKind);
    internal static string Key(PathRequesterFamily family, string requester, string target, string? group, OwnAccountMembershipPermissionKind? kind) =>
        family + "\0" + requester.ToUpperInvariant() + "\0" + target.ToUpperInvariant() + "\0" + group?.ToUpperInvariant() + "\0" + kind;
    private static (string Sid, string? Scope) IdentityKey(string sid, string? scope) => (sid.ToUpperInvariant(), scope?.ToUpperInvariant());
    private static int Mask(OwnAccountMembershipPermissionKind kind) => kind == OwnAccountMembershipPermissionKind.SelfMembership ? 0x08 : 0x20;
    private void Limit(PathRequesterSelectionReason reason, string? resource, PermissionEntry? entry, string? member) =>
        sink.Limit(new(reason, resource, entry?.Ordinal, entry?.Trustee.Sid, member));
    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    private bool Fixed(string dn) => _fixedTargets.Contains(dn);
    private bool Group(string dn) => Attributes(dn) is { } value && RequesterTrusteeReading.HasClass(value, "group");
    private bool Global(string dn) => Group(dn) && RequesterTrusteeReading.Number(Attributes(dn), "groupType") is { } type && (type & 0x8000000fL) == 0x80000002L;
    private bool User(string dn) => Attributes(dn) is { } value && RequesterTrusteeReading.HasClass(value, "user") && !RequesterTrusteeReading.HasClass(value, "computer");
    private string? Holder(string resource, PermissionEntry entry) => entry.Trustee.Sid == "S-1-5-10" ? resource : entry.Trustee.DistinguishedName;
    private ObjectAttributes? Attributes(string dn)
    {
        if (!_attributes.TryGetValue(dn, out var value)) _attributes[dn] = value = readAttributes(dn);
        return value;
    }
    private ObjectPermissions? Permissions(string dn)
    {
        if (!_permissions.TryGetValue(dn, out var value)) _permissions[dn] = value = readPermissions(dn);
        return value;
    }
    private string SourceFingerprint(string dn)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var fingerprint = Tier0PathCalculation.Fingerprint(new
        {
            Resource = Attributes(dn), Permissions = Permissions(dn),
            Holders = (Permissions(dn)?.Entries ?? []).Select(entry => Holder(dn, entry)).OfType<string>()
                .Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).Select(Attributes).ToArray(),
        });
        diagnostic?.Counter("resourcesFingerprinted", ++_sourcesFingerprinted);
        cancellationToken.ThrowIfCancellationRequested();
        return fingerprint;
    }
    private PathRequesterSelectionReason? Qualification(string dn, string resource) => Qualification(dn, resource, false);

    private PathRequesterSelectionReason? Qualification(string dn, string resource, bool sameForest)
    {
        var value = Attributes(dn);
        if (!nodes.TryGetValue(dn, out var node) || value is null || node.Subject.ObjectGuid is null || !node.Subject.IsValid
            || Tier0Target.From(value, node.Subject.NamingContext) != node.Subject
            || (User(dn) || Group(dn)) && node.Subject.Sid is null
            || RequesterTrusteeReading.HasClass(value, "foreignSecurityPrincipal") || Same(value.Find("isDeleted")?.OnlyValue?.Text, "TRUE")
            || node.Subject.Sid is { } sid && _identityCounts.GetValueOrDefault(IdentityKey(sid, node.Subject.SidScope)) != 1)
            return PathRequesterSelectionReason.IdentityUnresolved;
        if (!nodes.TryGetValue(resource, out var target) || !Domain(node.Subject) || !Domain(target.Subject)
            || (sameForest ? !Memberships!.InResourceForest(node.Subject, target.Subject)
                : !Same(node.Subject.DomainFqdn, target.Subject.DomainFqdn))) return PathRequesterSelectionReason.ResourceContextUnsupported;
        return null;
    }
    private bool Domain(Tier0Target identity) => contexts.TryGetValue(identity.NamingContext, out var kind) && kind == NamingContextKind.Domain
        && !string.IsNullOrWhiteSpace(identity.DomainFqdn) && Same(DnHelper.DnToFqdn(identity.NamingContext), identity.DomainFqdn);
}
