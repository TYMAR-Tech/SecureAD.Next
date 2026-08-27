using System.Diagnostics;

namespace SecureAD.Derivation;

/// <summary>
/// Every principal that reaches a group through membership, and what the expansion could not
/// establish.
/// </summary>
/// <param name="MembersByGroup">
/// Transitive members, indexed by the group's SID dictionary id. Empty for anything that is not a
/// group or has nobody in it.
/// </param>
/// <param name="Cycles">
/// Groups that contain one another, each cycle as the set of principals caught in it. Reportable in
/// its own right rather than merely survived: a membership loop is a fact about the directory
/// somebody should be told about.
/// </param>
/// <param name="GroupsOfUnknownType">
/// Groups whose <c>groupType</c> was not captured, so whether they carry authorization is unknown
/// and the expansion followed them anyway. Any closure that passed through one of these is
/// qualified by it.
/// </param>
/// <param name="PartialGroups">
/// Groups the expansion never reached, because it stopped at a budget first. Their entry in
/// <paramref name="MembersByGroup"/> is empty, and empty here means <i>not computed</i> rather than
/// <i>nobody is in it</i> - which is the distinction a reader cannot make without this list.
/// </param>
/// <param name="Limit">Why the expansion stopped short, when it did.</param>
/// <param name="IsComplete">
/// Whether every group was expanded in full. False means a closure read from here is a floor rather
/// than an answer, and a rule resting on it has established nothing clean.
/// </param>
public sealed record MembershipClosure(
    IReadOnlyList<int[]> MembersByGroup,
    IReadOnlyList<int[]> Cycles,
    IReadOnlyList<int> GroupsOfUnknownType,
    IReadOnlyList<int> PartialGroups,
    ExpansionLimit Limit,
    bool IsComplete)
{
    /// <summary>The transitive members of one group.</summary>
    /// <param name="groupSidId">The group.</param>
    public ReadOnlySpan<int> MembersOf(int groupSidId) => MembersByGroup[groupSidId];
}

/// <summary>
/// Expands group membership over the nesting graph, once per group rather than once per question.
/// </summary>
/// <remarks>
/// <para>
/// <b>Each group is expanded exactly once, and this is the whole of the difference from the
/// predecessor.</b> It walked every group from scratch, so a subtree beneath three groups was
/// walked three times and the work grew with the number of groups multiplied by the size of the
/// directory. Here the graph is condensed and traversed bottom-up: when a group is reached,
/// everything inside it already has an answer, so its own is the union of answers already computed.
/// The work is the size of the graph plus the size of the result, and the result is what had to be
/// written anyway.
/// </para>
/// <para>
/// <b>Cycles are condensed rather than guarded against.</b> Active Directory permits a group to
/// contain a group that contains it. Tarjan's algorithm finds those components, and - the property
/// that makes this one pass rather than two - emits them in reverse topological order, so a
/// component is always finished after everything reachable from it. No separate sort is needed and
/// no visited-set has to survive between groups.
/// </para>
/// <para>
/// <b>It is iterative because the recursion is not bounded by anything sensible.</b> Nesting depth
/// in a real directory is small, but the traversal's depth is bounded by the number of principals,
/// and a recursive implementation would exhaust the stack on a forest rather than on anything
/// pathological.
/// </para>
/// <para>
/// <b>Components are found over every edge; closures follow only the ones authorization honours.</b>
/// A cycle through a distribution group is still a cycle and still worth reporting, while a hop
/// through one carries no authorization. Ordering computed over the whole graph stays valid for any
/// part of it, so one pass serves both - but inside a component the members are settled by
/// iteration rather than by assuming they all reach each other, because two groups in a directory
/// cycle need not reach each other through followable edges alone.
/// </para>
/// </remarks>
public static class AuthorizationMembershipExpander
{
    /// <summary>
    /// Expands every group in the graph.
    /// </summary>
    /// <param name="graph">The nesting graph.</param>
    /// <param name="budget">The limits to run under.</param>
    /// <param name="cancellationToken">Stops the expansion.</param>
    /// <returns>The closure, and what it could not establish.</returns>
    public static MembershipClosure Expand(
        NestingGraph graph,
        ExpansionBudget budget,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(graph);
        ArgumentNullException.ThrowIfNull(budget);

        var count = graph.Count;
        var components = StronglyConnectedComponents.Find(graph, cancellationToken);

        var members = new HashSet<int>?[count];
        var cycles = new List<int[]>();
        var unknownType = new List<int>();
        var entries = 0;
        var limit = ExpansionLimit.None;
        var clock = Stopwatch.StartNew();

        foreach (var component in components)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (limit != ExpansionLimit.None)
                break;

            if (component.Length > 1)
                cycles.Add(component);

            foreach (var node in component)
            {
                if (graph.IsGroup(node) && graph.IsSecurityEnabled(node) is null)
                    unknownType.Add(node);
            }

            // Settled by iteration rather than in one sweep. Everything outside the component is
            // already final - that is what reverse topological order buys - but two nodes inside it
            // can each be waiting on the other, so the component is re-swept until nothing changes.
            // A component is one node in almost every directory and small in the rest.
            bool changed;
            do
            {
                changed = false;

                foreach (var node in component)
                {
                    if (!graph.IsGroup(node))
                        continue;

                    var into = members[node] ??= [];
                    var before = into.Count;

                    var edgeCount = EdgeCount(graph, node);
                    for (var i = 0; i < edgeCount; i++)
                    {
                        var member = EdgeAt(graph, node, i);

                        into.Add(member);

                        // Recurse only through a group that can carry authorization. Microsoft's
                        // guidance is explicit that an account nested through a distribution group
                        // does not receive the enclosing security group's SID in its token, so the
                        // members of a distribution group are not members of what contains it.
                        if (!graph.IsGroup(member) || !MayTraverse(graph, member))
                            continue;

                        var inner = members[member];
                        if (inner is not null)
                            into.UnionWith(inner);
                    }

                    if (into.Count != before)
                        changed = true;
                }
            }
            while (changed);

            foreach (var node in component)
            {
                entries += members[node]?.Count ?? 0;

                if (entries > budget.MaxClosureEntries)
                {
                    limit = ExpansionLimit.MaxClosureEntriesReached;
                    break;
                }
            }

            if (limit == ExpansionLimit.None && clock.Elapsed > budget.MaxTime)
                limit = ExpansionLimit.MaxTimeReached;
        }

        var frozen = new int[count][];
        var partial = new List<int>();

        for (var i = 0; i < count; i++)
        {
            var set = members[i];

            // Null rather than empty is what says the expansion never got here. A group that was
            // reached and found empty has an empty set; one the budget cut off has nothing at all,
            // and the two would be indistinguishable on the way out without this.
            if (set is null && graph.IsGroup(i))
                partial.Add(i);

            if (set is null || set.Count == 0)
            {
                frozen[i] = [];
                continue;
            }

            // Sorted so a store written from this is byte-identical between runs over one bundle.
            // A hash set's order is not a promise, and a derived file that differs run to run cannot
            // be compared or sealed meaningfully.
            var list = new int[set.Count];
            set.CopyTo(list);
            Array.Sort(list);
            frozen[i] = list;
        }

        return new MembershipClosure(
            frozen,
            cycles,
            unknownType,
            partial,
            limit,
            limit == ExpansionLimit.None);
    }

    /// <summary>
    /// Whether an expansion may pass through this group.
    /// </summary>
    /// <remarks>
    /// <b>A group whose type nobody captured is traversed, and that is a decision rather than an
    /// oversight.</b> Refusing to traverse it would mean reporting principals as not holding a
    /// privilege they may well hold, and an audit tool that under-reports privilege fails at the
    /// thing it exists for. Traversing it can only over-report, which an operator can check. The
    /// group is recorded in <see cref="MembershipClosure.GroupsOfUnknownType"/> so the uncertainty
    /// travels with the answer rather than being silently resolved here.
    /// </remarks>
    private static bool MayTraverse(NestingGraph graph, int groupSidId) =>
        graph.IsSecurityEnabled(groupSidId) is not false;

    /// <summary>
    /// How many principals are directly inside a group, counting both kinds of membership.
    /// </summary>
    /// <remarks>
    /// The two are addressed as one sequence rather than copied into one, so walking a group's
    /// members allocates nothing.
    /// </remarks>
    internal static int EdgeCount(NestingGraph graph, int node) =>
        graph.MembersOf(node).Length + graph.PrimaryMembersOf(node).Length;

    /// <summary>
    /// One of the principals directly inside a group: ordinary members first, then the accounts
    /// naming it as their primary group.
    /// </summary>
    internal static int EdgeAt(NestingGraph graph, int node, int index)
    {
        var ordinary = graph.MembersOf(node);
        return index < ordinary.Length
            ? ordinary[index]
            : graph.PrimaryMembersOf(node)[index - ordinary.Length];
    }
}
