using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal sealed class MemberAttributionDeriver
{
    private readonly CapturedMembershipInput _input;
    private readonly MemberAttributionBudget _budget;
    private readonly TimeProvider _time;
    private readonly long _started;
    private readonly Dictionary<string, ObjectAttributes> _objects;
    private readonly Dictionary<string, ObjectAttributes[]> _bySid;
    private readonly Dictionary<string, List<MemberAttributionLink>> _links = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _missingPrimaryDomains = new(StringComparer.OrdinalIgnoreCase);
    private long _nodes, _traversed, _records;
    private MemberAttributionStop _stop;

    internal MemberAttributionDeriver(CapturedMembershipInput input, MemberAttributionBudget budget, TimeProvider time, CancellationToken cancellationToken)
    {
        budget.Validate();
        _input = input;
        _budget = budget;
        _time = time;
        _started = time.GetTimestamp();
        _objects = input.Objects.ToDictionary(source => source.DistinguishedName, StringComparer.OrdinalIgnoreCase);
        _bySid = input.Objects.Where(source => RequesterTrusteeReading.SidOf(source) is not null)
            .GroupBy(source => RequesterTrusteeReading.SidOf(source)!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.OrdinalIgnoreCase);
        foreach (var source in input.Objects.OrderBy(source => source.DistinguishedName, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (RequesterTrusteeReading.HasClass(source, "user") && source.Find("primaryGroupID")?.HasValue != true)
                _missingPrimaryDomains.Add(source.DomainFqdn ?? "");
            foreach (var value in source.Find("member")?.Values ?? [])
                if (!string.IsNullOrWhiteSpace(value.Text)) Add(new(source.DistinguishedName, value.Text, source.DistinguishedName, "member", value.Ordinal));
            foreach (var value in source.Find("memberOf")?.Values ?? [])
                if (!string.IsNullOrWhiteSpace(value.Text)) Add(new(value.Text, source.DistinguishedName, source.DistinguishedName, "memberOf", value.Ordinal));
            if (PrimarySid(source) is { } primary)
            {
                var group = Resolve(primary, source.DomainFqdn);
                Add(new(group?.DistinguishedName ?? "SID:" + primary, source.DistinguishedName, source.DistinguishedName, "primaryGroupID", 0));
            }
        }
        foreach (var links in _links.Values)
            links.Sort((left, right) => StringComparer.OrdinalIgnoreCase.Compare(Key(left), Key(right)));
    }

    internal ObjectAttributes? Resolve(string sid, string? scope)
    {
        if (!_bySid.TryGetValue(sid, out var matches)) return null;
        var candidates = matches.Where(source => !RequesterTrusteeReading.HasClass(source, "foreignSecurityPrincipal")
            && (!Sid.IsBuiltinDomain(sid) || Same(source.DomainFqdn, scope))).ToArray();
        return candidates.Length == 1 ? candidates[0] : null;
    }

    internal bool RequiresAssessment(string sid, string? scope) => Resolve(sid, scope) is not { } source
        || RequesterTrusteeReading.HasClass(source, "group") || source.Find("objectClass")?.HasValue != true;

    internal MemberAttribution Derive(string sid, string? scope, Guid generation, int resourceContexts, CancellationToken cancellationToken)
    {
        var holder = Resolve(sid, scope);
        var members = new Dictionary<string, MemberAttributionMember>(StringComparer.OrdinalIgnoreCase);
        var links = new List<MemberAttributionLink>();
        var linkIds = new Dictionary<MemberAttributionLink, int>();
        var routes = new List<MemberAttributionRoute>();
        var seen = new HashSet<(string, MemberAttributionState)>();
        var emitted = new HashSet<(string, string, MemberAttributionState)>();
        var limits = new SortedSet<string>(StringComparer.Ordinal);
        var queue = new Queue<(string Dn, MemberAttributionState State, int? Route)>();
        string? position = null;
        if (!_input.IsComplete) limits.Add("CaptureIncomplete");
        if (holder is null) limits.Add("HolderIdentityUnresolved");
        else if (!RequesterTrusteeReading.HasClass(holder, "group")) limits.Add("HolderIsNotDirectoryGroup");
        else if (_stop == MemberAttributionStop.None && WithinTime())
        {
            if (_nodes >= _budget.MaxNodes) _stop = MemberAttributionStop.NodeBudgetExceeded;
            else
            {
                _nodes++;
                var state = SecurityState(holder);
                queue.Enqueue((holder.DistinguishedName, state, null));
                seen.Add((holder.DistinguishedName.ToUpperInvariant(), state));
            }
        }
        while (queue.TryDequeue(out var current) && _stop == MemberAttributionStop.None)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!WithinTime()) break;
            var source = _objects.GetValueOrDefault(current.Dn);
            if (source is null || !RequesterTrusteeReading.HasClass(source, "group")) continue;
            if (source.Find("member")?.HasValue != true) limits.Add("MemberValuesNotReturned:" + current.Dn);
            if (RequesterTrusteeReading.Number(source, "groupType") is null) limits.Add("GroupTypeMissing:" + current.Dn);
            foreach (var link in _links.GetValueOrDefault(current.Dn) ?? [])
            {
                cancellationToken.ThrowIfCancellationRequested();
                position = Key(link);
                if (!WithinTime()) break;
                if (_traversed >= _budget.MaxLinks) { _stop = MemberAttributionStop.LinkBudgetExceeded; break; }
                var memberSource = ResolveDn(link.Member);
                var identity = memberSource?.DistinguishedName ?? link.Member;
                var state = Combine(current.State, SecurityState(memberSource));
                var isRoot = Same(identity, holder?.DistinguishedName);
                var newNode = !isRoot && !members.ContainsKey(identity);
                var newLink = !linkIds.ContainsKey(link);
                var routeKey = (identity.ToUpperInvariant(), current.Dn.ToUpperInvariant(), state);
                var newRoute = !isRoot && !emitted.Contains(routeKey);
                var cost = (newNode ? 1L + resourceContexts : 0) + (newLink ? 1 : 0) + (newRoute ? 1 : 0);
                if (newNode && _nodes >= _budget.MaxNodes) { _stop = MemberAttributionStop.NodeBudgetExceeded; break; }
                if (cost > _budget.MaxRecords - _records) { _stop = MemberAttributionStop.StorageBudgetExceeded; break; }
                _traversed++;
                _records += cost;
                if (newNode) _nodes++;
                if (newLink) { linkIds.Add(link, links.Count); links.Add(link); }
                if (isRoot) continue;
                var member = new MemberAttributionMember(identity, memberSource, state);
                if (!members.TryGetValue(identity, out var previous) || Rank(state) > Rank(previous.State)) members[identity] = member;
                if (!member.IsResolved) limits.Add("IdentityUnresolved:" + identity);
                if (state == MemberAttributionState.Unknown) limits.Add("MembershipUnconfirmed:" + identity);
                int? routeId = current.Route;
                if (newRoute)
                {
                    emitted.Add(routeKey);
                    routeId = routes.Count;
                    routes.Add(new(routes.Count, identity, current.Dn, state, current.Route, linkIds[link]));
                }
                if (!member.IsDeleted && seen.Add((identity.ToUpperInvariant(), state))) queue.Enqueue((identity, state, routeId));
            }
        }
        // A missing primary-group value can hide an otherwise unlinked account in this domain.
        if (holder is not null && _missingPrimaryDomains.Contains(holder.DomainFqdn ?? ""))
            limits.Add("PrimaryGroupEvidenceIncomplete");
        return new(sid, scope, holder, generation, _input.DerivationGenerationId, _budget, _stop,
            _nodes, _traversed, _records, _time.GetElapsedTime(_started), position, limits.ToArray(),
            members.Values.OrderBy(member => member.Identity, StringComparer.OrdinalIgnoreCase).ToArray(), links, routes);
    }

    private ObjectAttributes? ResolveDn(string dn)
    {
        var source = _objects.GetValueOrDefault(dn);
        return source is not null && RequesterTrusteeReading.HasClass(source, "foreignSecurityPrincipal")
            && RequesterTrusteeReading.SidOf(source) is { } sid ? Resolve(sid, source.DomainFqdn) ?? source : source;
    }

    private void Add(MemberAttributionLink link)
    {
        if (!_links.TryGetValue(link.Group, out var values)) _links.Add(link.Group, values = []);
        values.Add(link);
    }

    private static string Key(MemberAttributionLink link) => link.Group + "\0" + link.Member + "\0" + link.SourceDn + "\0" + link.Attribute + "\0" + link.Ordinal;
    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    private static int Rank(MemberAttributionState value) => value == MemberAttributionState.Established ? 2 : value == MemberAttributionState.Unknown ? 1 : 0;
    private static MemberAttributionState Combine(MemberAttributionState left, MemberAttributionState right) =>
        left == MemberAttributionState.NotEstablished || right == MemberAttributionState.NotEstablished ? MemberAttributionState.NotEstablished
        : left == MemberAttributionState.Unknown || right == MemberAttributionState.Unknown ? MemberAttributionState.Unknown : MemberAttributionState.Established;
    internal bool WithinTime()
    {
        if (_time.GetElapsedTime(_started) < _budget.MaxTime) return true;
        if (_stop == MemberAttributionStop.None) _stop = MemberAttributionStop.TimeBudgetExceeded;
        return false;
    }

    internal MemberAttribution Finish(MemberAttribution expansion) => expansion with
    {
        Stop = _stop,
        Elapsed = _time.GetElapsedTime(_started),
    };

    private MemberAttributionState SecurityState(ObjectAttributes? source)
    {
        if (source?.ObjectGuid is null || RequesterTrusteeReading.SidOf(source) is null
            || RequesterTrusteeReading.HasClass(source, "foreignSecurityPrincipal")) return MemberAttributionState.Unknown;
        if (Resolve(RequesterTrusteeReading.SidOf(source)!, source.DomainFqdn) is null) return MemberAttributionState.Unknown;
        if (!RequesterTrusteeReading.HasClass(source, "group")) return RequesterTrusteeReading.HasClass(source, "user")
            || RequesterTrusteeReading.HasClass(source, "computer") ? MemberAttributionState.Established : MemberAttributionState.Unknown;
        return RequesterTrusteeReading.Number(source, "groupType") is not { } type ? MemberAttributionState.Unknown
            : (type & 0x80000000L) != 0 ? MemberAttributionState.Established : MemberAttributionState.NotEstablished;
    }

    private static string? PrimarySid(ObjectAttributes source)
    {
        var sid = RequesterTrusteeReading.SidOf(source);
        if (sid is null || !sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) || sid.Split('-').Length != 8
            || RequesterTrusteeReading.Number(source, "primaryGroupID") is not { } rid || rid < 0 || rid > uint.MaxValue) return null;
        return sid[..sid.LastIndexOf('-')] + "-" + rid.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }
}
