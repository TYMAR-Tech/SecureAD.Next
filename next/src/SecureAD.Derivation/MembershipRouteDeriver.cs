using System.Diagnostics;
using System.Text;
using SecureAD.Evidence.Findings;

namespace SecureAD.Derivation;

internal sealed record MembershipRouteBudget(int MaxNodes, int MaxEdges, long MaxBytes, TimeSpan MaxTime)
{
    // Resource limits, not a statement that a forest below these sizes is safe.
    public static MembershipRouteBudget Bulk { get; } = new(500_000, 2_000_000, 64 * 1024 * 1024, TimeSpan.FromMinutes(30));
}

internal sealed record MembershipRouteRoot(int SidId, AdminSdHolderCatalogueEntry Entry, bool PropagatesProtection);

internal static class MembershipRouteDeriver
{
    public static IReadOnlyList<MembershipRouteSummary> Derive(
        NestingGraph graph,
        SidInterner sids,
        IReadOnlyList<MembershipRouteRoot> roots,
        MembershipRouteIncompleteReason inputLimits,
        MembershipRouteBudget budget,
        CancellationToken cancellationToken)
    {
        var routes = new Dictionary<int, Dictionary<int, List<MembershipRoute>>>();
        var cycleLimits = new HashSet<int>();
        var clock = Stopwatch.StartNew();
        var nodes = 0;
        var edges = 0;
        long bytes = 0;
        var limit = MembershipRouteIncompleteReason.None;

        MembershipRoutePrincipal Principal(int id) => new(sids.TextOf(id), sids.ScopeOf(id), graph.DistinguishedNameOf(id));
        string Key(int id) => sids.TextOf(id) + "\0" + (sids.ScopeOf(id)?.ToUpperInvariant() ?? string.Empty);

        foreach (var root in roots.OrderBy(r => r.Entry.Id).ThenBy(r => Key(r.SidId), StringComparer.Ordinal))
        {
            if (limit != MembershipRouteIncompleteReason.None)
                break;
            var initial = new WalkNode(root.SidId, null, false, AuthorizationOf(graph, root.SidId), false);
            var queue = new Queue<WalkNode>();
            var seen = new HashSet<(int, MembershipRouteAuthorization, bool)>();
            var emitted = new HashSet<(int Member, int Initial, MembershipRouteAuthorization Authorization, bool Primary, bool InitialPrimary)>();
            Enqueue(initial);

            while (queue.TryDequeue(out var current) && limit == MembershipRouteIncompleteReason.None)
            {
                CheckCancellationAndTime();
                if (limit != MembershipRouteIncompleteReason.None)
                    break;
                if (!graph.IsGroup(current.SidId))
                    continue;

                var members = graph.MembersOf(current.SidId).ToArray().Select(id => (Id: id, Primary: false))
                    .Concat(graph.PrimaryMembersOf(current.SidId).ToArray().Select(id => (Id: id, Primary: true)))
                    .Distinct().OrderBy(m => Key(m.Id), StringComparer.Ordinal).ThenBy(m => m.Primary);
                foreach (var member in members)
                {
                    CheckCancellationAndTime();
                    if (limit != MembershipRouteIncompleteReason.None)
                        break;
                    if (++edges > budget.MaxEdges)
                    {
                        limit = MembershipRouteIncompleteReason.EdgeBudgetReached;
                        break;
                    }
                    if (Contains(current, member.Id))
                    {
                        // A shortest supporting tree cannot prove all simple routes for a group
                        // inside a cycle. Accounts below it remain fully enumerable by initial group.
                        cycleLimits.Add(member.Id);
                        continue;
                    }

                    var authorization = Combine(current.Authorization, AuthorizationOf(graph, member.Id));
                    var next = new WalkNode(member.Id, current, member.Primary, authorization, current.HasPrimary || member.Primary);
                    if (emitted.Add((member.Id, current.SidId, authorization, next.HasPrimary, member.Primary)))
                    {
                        var steps = Steps(next, Principal);
                        var cost = steps.Sum(step => 32L + Encoding.UTF8.GetByteCount(step.Principal.Sid)
                            + Encoding.UTF8.GetByteCount(step.Principal.Scope ?? string.Empty)
                            + Encoding.UTF8.GetByteCount(step.Principal.DistinguishedName ?? string.Empty));
                        if (cost > budget.MaxBytes - bytes)
                        {
                            limit = MembershipRouteIncompleteReason.StorageBudgetReached;
                            break;
                        }
                        bytes += cost;
                        if (!routes.TryGetValue(member.Id, out var groups))
                            routes.Add(member.Id, groups = []);
                        if (!groups.TryGetValue(current.SidId, out var paths))
                            groups.Add(current.SidId, paths = []);
                        paths.Add(new MembershipRoute(root.Entry.Id, root.Entry.Name, authorization,
                            root.PropagatesProtection && !next.HasPrimary, steps));
                    }

                    // Emit before the visited check: two initial memberships can lead to the same
                    // root, even at different distances. Visiting the account just once loses one.
                    Enqueue(next);
                    if (limit != MembershipRouteIncompleteReason.None)
                        break;
                }
            }

            void Enqueue(WalkNode node)
            {
                if (!seen.Add((node.SidId, node.Authorization, node.HasPrimary)))
                    return;
                if (++nodes > budget.MaxNodes)
                    limit = MembershipRouteIncompleteReason.NodeBudgetReached;
                else
                    queue.Enqueue(node);
            }
        }

        return Enumerable.Range(0, graph.Count).Select(id => new MembershipRouteSummary(
            routes.TryGetValue(id, out var groups)
                ? groups.OrderBy(g => Key(g.Key), StringComparer.Ordinal)
                    .Select(g => new InitialMembershipRoutes(Principal(g.Key), g.Value.ToArray(),
                        inputLimits | limit | (cycleLimits.Contains(id) ? MembershipRouteIncompleteReason.CycleBoundary : MembershipRouteIncompleteReason.None))).ToArray()
                : [],
            inputLimits | limit | (cycleLimits.Contains(id) ? MembershipRouteIncompleteReason.CycleBoundary : MembershipRouteIncompleteReason.None)))
            .ToArray();

        void CheckCancellationAndTime()
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (clock.Elapsed >= budget.MaxTime)
                limit = MembershipRouteIncompleteReason.TimeBudgetReached;
        }
    }

    private static MembershipRouteAuthorization AuthorizationOf(NestingGraph graph, int sidId) =>
        !graph.IsGroup(sidId) ? MembershipRouteAuthorization.SecurityEnabled
        : graph.IsSecurityEnabled(sidId) switch
        {
            true => MembershipRouteAuthorization.SecurityEnabled,
            false => MembershipRouteAuthorization.DistributionGroup,
            null => MembershipRouteAuthorization.UnknownGroupType,
        };

    private static MembershipRouteAuthorization Combine(MembershipRouteAuthorization a, MembershipRouteAuthorization b) =>
        a == MembershipRouteAuthorization.DistributionGroup || b == MembershipRouteAuthorization.DistributionGroup
            ? MembershipRouteAuthorization.DistributionGroup
            : a == MembershipRouteAuthorization.UnknownGroupType || b == MembershipRouteAuthorization.UnknownGroupType
                ? MembershipRouteAuthorization.UnknownGroupType
                : MembershipRouteAuthorization.SecurityEnabled;

    private static bool Contains(WalkNode node, int sidId)
    {
        for (WalkNode? current = node; current is not null; current = current.Parent)
            if (current.SidId == sidId)
                return true;
        return false;
    }

    private static IReadOnlyList<MembershipRouteStep> Steps(WalkNode node, Func<int, MembershipRoutePrincipal> principal)
    {
        var steps = new List<MembershipRouteStep>();
        var primary = false;
        for (WalkNode? current = node; current is not null; current = current.Parent)
        {
            steps.Add(new MembershipRouteStep(principal(current.SidId), primary));
            primary = current.PrimaryLink;
        }
        return steps;
    }

    private sealed record WalkNode(int SidId, WalkNode? Parent, bool PrimaryLink,
        MembershipRouteAuthorization Authorization, bool HasPrimary);
}
