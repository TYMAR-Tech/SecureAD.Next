using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>Stored usability of one member's group routes in a resource context, not a complete access check.</summary>
public sealed record MemberResourceApplicability(string Member, MemberAttributionState State, string Reason);

/// <summary>Stored attribution for a selected group-held permission, with separately recorded resource applicability.</summary>
public sealed record MemberAttributionDetail(bool WasRun, MemberAttribution? Expansion, IReadOnlyList<MemberResourceApplicability> ResourceMembers)
{
    /// <summary>The immutable judgement selected for this reading, including not-run results.</summary>
    public Guid GenerationId { get; init; }
    /// <summary>Whether both the membership expansion and resource questions are complete.</summary>
    public bool IsComplete => WasRun && Expansion?.IsComplete == true && ResourceMembers.All(member => member.State != MemberAttributionState.Unknown);
}

/// <summary>A source permission found through stored group membership; never an additional holder edge.</summary>
public sealed record MemberPermissionReference(long DisplayId, string HolderSid, string? HolderScope, string Target,
    string Capability, ControlExpectedness Expectedness, bool IsCounted, MemberAttributionState Membership,
    MemberAttributionState ResourceApplicability, string Reason)
{
    /// <summary>The source permission's evaluation, never inferred from membership or group usability.</summary>
    public ControlEvaluationState PermissionState { get; init; } = ControlEvaluationState.Unknown;
    /// <summary>Whether the original permission is supporting evidence beneath a counted full-control summary.</summary>
    public bool IncludedInFullControl { get; init; }
}

/// <summary>A bounded reverse page of persisted source permissions, not a requester assessment.</summary>
public sealed record MemberPermissionPage(bool WasRun, bool IsComplete, Guid GenerationId,
    IReadOnlyList<MemberPermissionReference> Permissions, bool HasMore, long LastId)
{
    /// <summary>Count-eligible expected source permissions in the stored member selection, including hidden ones.</summary>
    public long ExpectedCount { get; init; }
}

internal static class MemberAttributionScope
{
    internal static string ContextKey(string target, string forest, IReadOnlyDictionary<string, NamingContextKind> namingContexts)
    {
        for (string? dn = target; dn is not null; dn = DnHelper.GetParentDn(dn))
        {
            if (!namingContexts.TryGetValue(dn, out var kind)) continue;
            var domain = DnHelper.DnToFqdn(dn);
            return kind == NamingContextKind.Domain && InForest(domain, forest) ? domain.ToUpperInvariant() : "Unknown";
        }
        return "Unknown";
    }

    internal static IReadOnlyList<MemberResourceApplicability> Assess(MemberAttribution expansion, string context, string forest,
        Func<bool> withinTime, CancellationToken cancellationToken)
    {
        var objects = expansion.Members.Where(member => member.Source is not null)
            .ToDictionary(member => member.Identity, member => member.Source!, StringComparer.OrdinalIgnoreCase);
        if (expansion.Holder is { } holder) objects[holder.DistinguishedName] = holder;
        var aliases = expansion.Routes.GroupBy(route => expansion.Links[route.LinkIndex].Member, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First().Member, StringComparer.OrdinalIgnoreCase);
        var outgoing = expansion.Links.GroupBy(link => link.Group, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.OrdinalIgnoreCase);
        var states = new Dictionary<string, HashSet<MemberAttributionState>>(StringComparer.OrdinalIgnoreCase);
        var pending = new Queue<(string Identity, MemberAttributionState State)>();
        var completed = true;
        if (expansion.Holder is { } root) pending.Enqueue((root.DistinguishedName, MemberAttributionState.Established));
        while (pending.TryDequeue(out var current))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!withinTime()) { completed = false; break; }
            if (!states.TryGetValue(current.Identity, out var reached)) states.Add(current.Identity, reached = []);
            if (!reached.Add(current.State)) continue;
            var group = objects.GetValueOrDefault(current.Identity);
            foreach (var link in outgoing.GetValueOrDefault(current.Identity) ?? [])
            {
                cancellationToken.ThrowIfCancellationRequested();
                var identity = aliases.GetValueOrDefault(link.Member) ?? link.Member;
                var member = objects.GetValueOrDefault(identity);
                var state = Combine(current.State, Combine(Usability(group, context, forest), Nesting(group, member, forest)));
                pending.Enqueue((identity, state));
            }
        }
        return expansion.Members.Select(member =>
        {
            var routes = states.GetValueOrDefault(member.Identity) ?? [];
            var state = member.IsDeleted ? MemberAttributionState.NotEstablished
                : routes.Contains(MemberAttributionState.Established) && member.State == MemberAttributionState.Established ? MemberAttributionState.Established
                : routes.Count == 0 || routes.Contains(MemberAttributionState.Unknown)
                    || member.State == MemberAttributionState.Unknown
                    || (!completed || !expansion.IsComplete) && Usability(expansion.Holder, context, forest) != MemberAttributionState.NotEstablished ? MemberAttributionState.Unknown
                : MemberAttributionState.NotEstablished;
            return new MemberResourceApplicability(member.Identity, state,
                member.IsDeleted ? "CapturedDeletedPrincipal" : context == "Unknown" ? "ResourceContextUnknown"
                : state == MemberAttributionState.Established ? "CapturedGroupRouteUsable"
                : !completed ? "TimeBudgetExceeded"
                : state == MemberAttributionState.Unknown ? "AuthorizationContextUnsupported" : "GroupRouteNotUsable");
        }).ToArray();
    }

    private static MemberAttributionState Nesting(ObjectAttributes? group, ObjectAttributes? member, string forest)
    {
        if (group is null || member?.ObjectGuid is null || !InForest(member.DomainFqdn, forest)
            || RequesterTrusteeReading.HasClass(member, "foreignSecurityPrincipal")
            || RequesterTrusteeReading.SidOf(member) is null || RequesterTrusteeReading.Number(group, "groupType") is not { } type)
            return MemberAttributionState.Unknown;
        var groupScope = type & 0xf;
        if (groupScope == 2 && !Same(group.DomainFqdn, member.DomainFqdn)) return MemberAttributionState.Unknown;
        if (!RequesterTrusteeReading.HasClass(member, "group"))
            return RequesterTrusteeReading.HasClass(member, "user") || RequesterTrusteeReading.HasClass(member, "computer")
                ? MemberAttributionState.Established : MemberAttributionState.Unknown;
        if (RequesterTrusteeReading.Number(member, "groupType") is not { } memberType) return MemberAttributionState.Unknown;
        if ((memberType & 0x80000000L) == 0) return MemberAttributionState.NotEstablished;
        var memberScope = memberType & 0xf;
        if (groupScope == 2 && memberScope != 2 || groupScope == 8 && memberScope == 4
            || groupScope == 4 && memberScope == 4 && !Same(group.DomainFqdn, member.DomainFqdn)) return MemberAttributionState.Unknown;
        return memberScope is 2 or 4 or 8 ? MemberAttributionState.Established : MemberAttributionState.Unknown;
    }

    private static MemberAttributionState Usability(ObjectAttributes? group, string context, string forest)
    {
        if (context == "Unknown" || group is null || !InForest(group.DomainFqdn, forest)
            || !Same(DnHelper.DnToFqdn(group.DistinguishedName), group.DomainFqdn)
            || RequesterTrusteeReading.Number(group, "groupType") is not { } type)
            return MemberAttributionState.Unknown;
        if ((type & 0x80000000L) == 0) return MemberAttributionState.NotEstablished;
        if (RequesterTrusteeReading.SidOf(group) is { } sid && Sid.IsBuiltinDomain(sid) || (type & 0xf) == 4)
            return Same(context, group.DomainFqdn) ? MemberAttributionState.Established : MemberAttributionState.NotEstablished;
        return (type & 0xf) is 2 or 8 ? MemberAttributionState.Established : MemberAttributionState.Unknown;
    }

    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    private static bool InForest(string? domain, string forest) => domain is not null
        && (Same(domain, forest) || domain.EndsWith("." + forest, StringComparison.OrdinalIgnoreCase));
    private static MemberAttributionState Combine(MemberAttributionState left, MemberAttributionState right) =>
        left == MemberAttributionState.NotEstablished || right == MemberAttributionState.NotEstablished ? MemberAttributionState.NotEstablished
        : left == MemberAttributionState.Unknown || right == MemberAttributionState.Unknown ? MemberAttributionState.Unknown : MemberAttributionState.Established;
}
