using System.Collections.Immutable;
using System.Globalization;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>Selected containing-group witnesses, qualified for one computer and resource domain.</summary>
internal sealed class GpoComputerMembership(BundleReader bundle, Func<Result<DerivationReader>> openDerivation,
    CapturedObjectIdentity computer, ObjectAttributes computerValues, ObjectAttributes policyValues,
    string forest, IReadOnlySet<string> readDomains, Func<string?, string?> domainSid)
{
    private readonly Dictionary<string, GpoTrusteeCheck> _matches = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<int, (CapturedObjectIdentity Identity, ObjectAttributes Values)?> _nodes = [];
    private readonly Dictionary<int, (int Parent, GpoMembershipWitness Witness)> _parents = [];
    private readonly Dictionary<string, int> _groups = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _history = new(StringComparer.OrdinalIgnoreCase);
    private bool _prepared;
    private bool _historyIncomplete;
    private string? _unavailable;

    internal GpoTrusteeCheck Match(PermissionTrustee trustee, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var sid = trustee.Sid;
        if (_matches.TryGetValue(sid, out var saved)) return saved;
        GpoTrusteeCheck Answer(bool? matches, string reason, ImmutableArray<GpoMembershipWitness> route) =>
            _matches[sid] = new(sid, matches, reason, route);
        if (Same(sid, computer.PrincipalSid)) return Answer(true, "Captured computer SID.", []);
        if (sid is "S-1-1-0" or "S-1-5-11")
            return Answer(true, "Configured authenticated computer identity, not proof of a live authentication.", []);
        Prepare(token);
        if (_groups.TryGetValue(sid, out var groupId))
            return Answer(true, "Qualified captured security-group membership.", Route(groupId));
        if (_history.Contains(sid))
            return Answer(null, "A captured current membership carries this SID historically; historical token authorization is not qualified.", []);
        if (sid is "S-1-3-0" or "S-1-3-4" or "S-1-5-10")
            return Answer(null, "The placeholder or SELF identity does not establish a computer membership here.", []);
        var holder = Resolve(sid, Sid.IsBuiltinDomain(sid) ? policyValues.DomainFqdn ?? "" : "", null);
        var read = RequesterTrusteeReading.ReadSameForest(computerValues, policyValues, trustee,
            holder?.Values, forest, readDomains);
        if (read.State == RequesterTrusteeState.DoesNotMatch)
            return _historyIncomplete
                ? Answer(null, "Unresolved captured membership/history prevents this trustee from being definitely excluded.", [])
                : Answer(false, read.Reason.ToString(), []);
        return Answer(null, _unavailable ?? "No supported captured security-membership witness establishes this trustee for the computer.", []);
    }

    private void Prepare(CancellationToken token)
    {
        if (_prepared) return;
        _nodes.Clear();
        _parents.Clear();
        _groups.Clear();
        _history.Clear();
        _historyIncomplete = false;
        _unavailable = null;
        var opened = openDerivation();
        if (!opened.IsSuccess)
        {
            _unavailable = opened.Error.Description;
            _historyIncomplete = true;
            _prepared = true;
            ReadHistory(computerValues);
            return;
        }
        DelegationMembership graph;
        try { graph = opened.Value.ReadContainingGroups(computer.PrincipalSid!, computer.DomainFqdn, token); }
        catch (Exception error) when (error is InvalidDataException or InvalidOperationException or ArgumentException)
        {
            token.ThrowIfCancellationRequested();
            _unavailable = "Saved containing-group evidence is unavailable: " + error.Message;
            _historyIncomplete = true;
            _prepared = true;
            ReadHistory(computerValues);
            return;
        }
        if (graph.GenerationId != opened.Value.Description.GenerationId || graph.EvidenceFingerprint != opened.Value.Description.EvidenceSeal)
            throw new InvalidDataException("The containing-group proof belongs to another derivation or capture.");
        var root = graph.Nodes.SingleOrDefault(value => value.Id == graph.RootId);
        if (root is null || root.ObjectGuid != computer.ObjectGuid || !Same(root.Sid, computer.PrincipalSid) || root.IsGroup != false)
        {
            _unavailable = "The saved containing-group root does not match the selected captured computer.";
            _historyIncomplete = true;
            _prepared = true;
            ReadHistory(computerValues);
            return;
        }
        _historyIncomplete = graph.Warnings.Count != 0;
        if (AttributeReading.UnsignedInteger(computerValues, "primaryGroupID") is null or 0)
        {
            _historyIncomplete = true;
            _unavailable = "The computer's primary-group identifier was not captured as a usable RID.";
        }
        _nodes.Add(root.Id, (computer, computerValues));
        ReadHistory(computerValues);
        var nodes = graph.Nodes.ToDictionary(value => value.Id);
        var edges = graph.Links.GroupBy(value => value.MemberId).ToDictionary(value => value.Key, value => value.ToArray());
        var seen = new HashSet<int> { root.Id };
        var queue = new Queue<int>();
        queue.Enqueue(root.Id);
        while (queue.TryDequeue(out var current))
        {
            token.ThrowIfCancellationRequested();
            if (!edges.TryGetValue(current, out var links)) continue;
            foreach (var link in links)
            {
                token.ThrowIfCancellationRequested();
                if (!nodes.TryGetValue(link.MemberId, out var memberNode) || !nodes.TryGetValue(link.GroupId, out var groupNode))
                    throw new InvalidDataException("The saved membership edge has no captured-identity node.");
                var member = Source(memberNode);
                var group = Source(groupNode);
                if (member is null || group is null) { _historyIncomplete = true; continue; }
                var memberValue = member.Value;
                var groupValue = group.Value;
                var type = RequesterTrusteeReading.Number(groupValue.Values, "groupType");
                if (type is null || groupNode.IsGroup != true || groupNode.IsSecurityEnabled is null)
                {
                    _historyIncomplete = true;
                    continue;
                }
                if ((type.Value & 0x80000000L) == 0) continue;
                if (groupNode.IsSecurityEnabled != true || !RequesterTrusteeReading.SupportsSecurityNesting(groupValue.Values, memberValue.Values))
                {
                    _historyIncomplete = true;
                    continue;
                }
                var scope = type.Value & 0x0f;
                if (scope is 4 or 5 && !Same(groupValue.Identity.DomainFqdn, policyValues.DomainFqdn)) continue;
                AttributeValue? witness;
                string attribute;
                if (link.IsPrimaryGroup)
                {
                    attribute = "primaryGroupID";
                    witness = memberValue.Values.Find(attribute)?.OnlyValue;
                    var primary = AttributeReading.UnsignedInteger(memberValue.Values, attribute);
                    if (scope != 2 || primary is null or 0 || witness is null || witness.Ordinal != 0
                        || !Same(memberValue.Identity.DomainFqdn, groupValue.Identity.DomainFqdn)
                        || !Same(groupNode.Sid, Sid.IssuingDomain(memberNode.Sid) + "-" + primary.Value.ToString(CultureInfo.InvariantCulture)))
                    {
                        _historyIncomplete = true;
                        continue;
                    }
                }
                else
                {
                    var observed = bundle.ReadMembershipWitness(memberValue.Identity, groupValue.Identity, token);
                    if (!observed.IsSuccess) { _historyIncomplete = true; _unavailable = observed.Error.Description; continue; }
                    attribute = observed.Value.Attribute;
                    witness = observed.Value.Value;
                }
                if (!seen.Add(link.GroupId)) continue;
                _parents.Add(link.GroupId, (link.MemberId, new(memberValue.Identity, groupValue.Identity, attribute,
                    witness.Ordinal, witness.Stored, type.Value)));
                _groups.TryAdd(groupNode.Sid, groupNode.Id);
                ReadHistory(groupValue.Values);
                queue.Enqueue(groupNode.Id);
            }
        }
        token.ThrowIfCancellationRequested();
        _prepared = true;
    }

    private (CapturedObjectIdentity Identity, ObjectAttributes Values)? Source(DelegationMemberNode node)
    {
        if (_nodes.TryGetValue(node.Id, out var existing)) return existing;
        var source = Resolve(node.Sid, node.Scope, node.ObjectGuid);
        _nodes.Add(node.Id, source);
        return source;
    }

    private (CapturedObjectIdentity Identity, ObjectAttributes Values)? Resolve(string sid, string scope, Guid? guid)
    {
        if (Sid.ToBytes(sid) is null || guid == Guid.Empty) return null;
        DelegationPrincipal? principal;
        try { principal = bundle.ResolveDelegationPrincipal(sid, scope, guid); }
        catch (InvalidDataException error)
        {
            _unavailable = error.Message;
            _historyIncomplete = true;
            return null;
        }
        if (principal is not { ObjectId: not null, DistinguishedName: not null, DomainFqdn: not null }
            || !readDomains.Contains(principal.DomainFqdn)) return null;
        var match = bundle.ReadObjectNameMatch(principal.DistinguishedName);
        if (match.Ambiguous || match.ObjectId != principal.ObjectId) return null;
        var identity = bundle.ReadObjectIdentity(principal.DistinguishedName)!;
        var values = bundle.ReadObjectAttributesAt(identity,
            ["objectClass", "objectSid", "groupType", "primaryGroupID", "sIDHistory"]).Snapshot();
        identity = GpoCapturedIdentity.Normalize(identity, values);
        if (identity.ObjectGuid is null || identity.ObjectGuid == Guid.Empty
            || !Same(identity.PrincipalSid, sid) || guid is not null && identity.ObjectGuid != guid
            || (!Sid.IsBuiltinDomain(sid) && !Same(Sid.IssuingDomain(sid), domainSid(identity.DomainFqdn))))
            return null;
        return (identity, values);
    }

    private void ReadHistory(ObjectAttributes values)
    {
        foreach (var value in values.Find("sIDHistory")?.Values ?? [])
        {
            var sid = value.Bytes is { } bytes ? Sid.ToText(bytes) : value.Text;
            if (sid is null || Sid.ToBytes(sid) is null) _historyIncomplete = true;
            else _history.Add(sid);
        }
    }

    private ImmutableArray<GpoMembershipWitness> Route(int group)
    {
        var route = new List<GpoMembershipWitness>();
        while (_parents.TryGetValue(group, out var link))
        {
            route.Add(link.Witness);
            group = link.Parent;
        }
        route.Reverse();
        return route.ToImmutableArray();
    }

    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}
