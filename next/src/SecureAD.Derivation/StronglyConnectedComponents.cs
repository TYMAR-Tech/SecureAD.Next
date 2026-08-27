namespace SecureAD.Derivation;

/// <summary>
/// Finds the groups that contain one another, and orders them so each is finished after everything
/// inside it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Tarjan's algorithm, for the ordering as much as for the cycles.</b> It emits each strongly
/// connected component only once every component reachable from it has already been emitted - that
/// is, in reverse topological order of the condensed graph. That property is what lets membership
/// be expanded in a single pass: when a group is reached, everything it contains has an answer
/// already, so nothing has to be walked twice and no separate topological sort is needed.
/// </para>
/// <para>
/// <b>Iterative, because the recursive form would overflow the stack.</b> The traversal's depth is
/// bounded by the number of principals rather than by nesting depth, so a forest is enough to
/// exhaust it. The explicit frame carries the node and how far through its members the walk had
/// got.
/// </para>
/// </remarks>
internal static class StronglyConnectedComponents
{
    private const int Unvisited = -1;

    /// <summary>
    /// Every component, in reverse topological order.
    /// </summary>
    /// <remarks>
    /// A principal that is in no cycle comes back as a component of one, which is the ordinary case
    /// and carries no meaning beyond its position in the order.
    /// </remarks>
    /// <param name="graph">The nesting graph.</param>
    /// <param name="cancellationToken">Stops the search.</param>
    /// <returns>The components.</returns>
    internal static IReadOnlyList<int[]> Find(NestingGraph graph, CancellationToken cancellationToken)
    {
        var count = graph.Count;

        var index = new int[count];
        var lowLink = new int[count];
        var onStack = new bool[count];
        Array.Fill(index, Unvisited);

        var component = new Stack<int>();
        var work = new Stack<(int Node, int NextEdge)>();
        var found = new List<int[]>();
        var nextIndex = 0;

        for (var start = 0; start < count; start++)
        {
            if (index[start] != Unvisited)
                continue;

            work.Push((start, 0));

            while (work.Count > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var (node, nextEdge) = work.Pop();

                if (nextEdge == 0)
                {
                    index[node] = nextIndex;
                    lowLink[node] = nextIndex;
                    nextIndex++;
                    component.Push(node);
                    onStack[node] = true;
                }

                var descended = false;
                var edgeCount = AuthorizationMembershipExpander.EdgeCount(graph, node);

                for (var edge = nextEdge; edge < edgeCount; edge++)
                {
                    var member = AuthorizationMembershipExpander.EdgeAt(graph, node, edge);

                    if (index[member] == Unvisited)
                    {
                        // Stand where the walk was, then go in. The frame remembers which member
                        // was being considered so it resumes at the next one rather than the first.
                        work.Push((node, edge + 1));
                        work.Push((member, 0));
                        descended = true;
                        break;
                    }

                    if (onStack[member])
                        lowLink[node] = Math.Min(lowLink[node], index[member]);
                }

                if (descended)
                    continue;

                if (lowLink[node] == index[node])
                {
                    var members = new List<int>();
                    int popped;

                    do
                    {
                        popped = component.Pop();
                        onStack[popped] = false;
                        members.Add(popped);
                    }
                    while (popped != node);

                    found.Add([.. members]);
                }

                // Carry what this node reached back to whoever descended into it. Without this a
                // cycle discovered deeper than its entry point is never recognised as one.
                if (work.Count > 0)
                {
                    var (parent, _) = work.Peek();
                    lowLink[parent] = Math.Min(lowLink[parent], lowLink[node]);
                }
            }
        }

        return found;
    }
}
