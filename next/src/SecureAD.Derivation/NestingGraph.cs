namespace SecureAD.Derivation;

/// <summary>
/// The directory's nesting, held as integer arrays so a closure can walk it without touching the
/// database.
/// </summary>
/// <remarks>
/// <para>
/// <b>Compressed sparse rows, which is what makes holding the graph affordable.</b> Members are one
/// flat array with a per-group offset into it, rather than a list per group. A forest's nesting is
/// millions of edges: as a dictionary of lists of SID strings it is hundreds of megabytes and
/// millions of small objects for the garbage collector to trace, and as two integer arrays it is a
/// few tens of megabytes that the processor reads sequentially. The predecessor held the first
/// shape, which is part of why it re-read members from SQLite rather than keeping them.
/// </para>
/// <para>
/// <b>Primary-group membership is kept in its own arrays, not folded in with the rest.</b> It would
/// be simpler to merge them and have one list of members per group, and it would be wrong: the
/// three closures derived from this graph do not agree about which edges they may follow.
/// Authorization membership honours primary groups; the protected-principal closure may not, since
/// whether SDProp traverses them is unevidenced and gated under <c>AC-64</c>. Merging the two would
/// destroy the distinction at the moment the graph is built, and no later phase could recover it.
/// </para>
/// <para>
/// <b>Indexed by SID dictionary id, over every SID, not only the principals.</b> A SID can be
/// present because it is somebody's <c>sIDHistory</c>, or because an account named it as a primary
/// group whose object the capture did not contain. Those have no members and are not groups, and
/// asking about them is an ordinary thing for a traversal to do.
/// </para>
/// </remarks>
internal sealed class NestingGraph
{
    private readonly int[] _memberOffsets;
    private readonly int[] _members;
    private readonly int[] _containerOffsets;
    private readonly int[] _containers;
    private readonly int[] _primaryMemberOffsets;
    private readonly int[] _primaryMembers;
    private readonly bool[] _isGroup;
    private readonly int?[] _groupType;

    private NestingGraph(
        int[] memberOffsets,
        int[] members,
        int[] containerOffsets,
        int[] containers,
        int[] primaryMemberOffsets,
        int[] primaryMembers,
        bool[] isGroup,
        int?[] groupType)
    {
        _memberOffsets = memberOffsets;
        _members = members;
        _containerOffsets = containerOffsets;
        _containers = containers;
        _primaryMemberOffsets = primaryMemberOffsets;
        _primaryMembers = primaryMembers;
        _isGroup = isGroup;
        _groupType = groupType;
    }

    /// <summary>How many SIDs the graph is over.</summary>
    public int Count => _isGroup.Length;

    /// <summary>
    /// Builds the graph from what one pass over the bundle found.
    /// </summary>
    /// <param name="facts">The nesting facts.</param>
    /// <returns>The graph, ready to walk.</returns>
    public static NestingGraph Build(NestingFacts facts)
    {
        ArgumentNullException.ThrowIfNull(facts);

        var count = facts.Sids.Count;

        var isGroup = new bool[count];
        var groupType = new int?[count];
        foreach (var principal in facts.Principals)
        {
            isGroup[principal.SidId] = principal.IsGroup;
            groupType[principal.SidId] = principal.GroupType;
        }

        var (memberOffsets, members) = CompressRows(
            count,
            facts.Edges.Count,
            facts.Edges,
            static edge => edge.GroupSidId,
            static edge => edge.MemberSidId);

        // The same edges the other way round: given a principal, which groups hold it. Needed to
        // walk upward - asking what a group is nested inside, rather than what is inside it.
        var (containerOffsets, containers) = CompressRows(
            count,
            facts.Edges.Count,
            facts.Edges,
            static edge => edge.MemberSidId,
            static edge => edge.GroupSidId);

        // The reverse of primaryGroupID: given a group, which accounts name it. The attribute points
        // the other way, and expanding a group needs this direction - without it, folding primary
        // groups into an expansion is a scan of every principal per group.
        var primaryPairs = facts.Principals
            .Where(p => p.PrimaryGroupSidId is not null)
            .Select(p => (Group: p.PrimaryGroupSidId!.Value, Member: p.SidId))
            .ToList();

        var (primaryOffsets, primaryMembers) = CompressRows(
            count,
            primaryPairs.Count,
            primaryPairs,
            static pair => pair.Group,
            static pair => pair.Member);

        return new NestingGraph(
            memberOffsets, members, containerOffsets, containers,
            primaryOffsets, primaryMembers, isGroup, groupType);
    }

    /// <summary>
    /// The principals directly inside a group through <c>member</c> or <c>memberOf</c>.
    /// </summary>
    /// <remarks>
    /// <b>This does not include primary-group members.</b> A caller that wants every member Windows
    /// would recognise wants <see cref="PrimaryMembersOf"/> as well, and a caller deriving the
    /// protected-principal closure deliberately does not.
    /// </remarks>
    /// <param name="groupSidId">The group.</param>
    public ReadOnlySpan<int> MembersOf(int groupSidId) =>
        _members.AsSpan(
            _memberOffsets[groupSidId],
            _memberOffsets[groupSidId + 1] - _memberOffsets[groupSidId]);

    /// <summary>
    /// The accounts naming a group as their primary group.
    /// </summary>
    /// <remarks>
    /// Real membership that appears in neither <c>member</c> nor <c>memberOf</c>. Kept apart from
    /// <see cref="MembersOf"/> because whether it may be followed depends on which closure is
    /// asking.
    /// </remarks>
    /// <param name="groupSidId">The group.</param>
    public ReadOnlySpan<int> PrimaryMembersOf(int groupSidId) =>
        _primaryMembers.AsSpan(
            _primaryMemberOffsets[groupSidId],
            _primaryMemberOffsets[groupSidId + 1] - _primaryMemberOffsets[groupSidId]);

    /// <summary>
    /// The groups a principal is directly inside, through <c>member</c> or <c>memberOf</c>.
    /// </summary>
    /// <remarks>
    /// <b>Primary groups are deliberately absent from this direction too.</b> A principal's primary
    /// group is one value on its own row rather than something this index has to answer, and mixing
    /// it in here would reintroduce upward the distinction the forward direction keeps apart.
    /// </remarks>
    /// <param name="sidId">The principal.</param>
    public ReadOnlySpan<int> ContainingGroupsOf(int sidId) =>
        _containers.AsSpan(
            _containerOffsets[sidId],
            _containerOffsets[sidId + 1] - _containerOffsets[sidId]);

    /// <summary>Whether <c>objectClass</c> called this a group.</summary>
    /// <param name="sidId">The principal.</param>
    public bool IsGroup(int sidId) => _isGroup[sidId];

    /// <summary>
    /// The raw <c>groupType</c> flags, or null when none was captured or this is not a group.
    /// </summary>
    /// <param name="sidId">The principal.</param>
    public int? GroupType(int sidId) => _groupType[sidId];

    /// <summary>
    /// Whether this group's flags say it can carry authorization, or null when nobody knows.
    /// </summary>
    /// <remarks>
    /// Null is a third answer and not a quiet no. A group whose <c>groupType</c> the capture did not
    /// record is not thereby a distribution group, and a closure that treated it as one would drop
    /// authorization edges that exist.
    /// </remarks>
    /// <param name="sidId">The principal.</param>
    public bool? IsSecurityEnabled(int sidId) =>
        MembershipNestingPass.IsSecurityEnabled(_groupType[sidId]);

    /// <summary>
    /// Turns a list of pairs into an offset array and a flat value array, in one counting pass.
    /// </summary>
    private static (int[] Offsets, int[] Values) CompressRows<T>(
        int rowCount,
        int pairCount,
        IEnumerable<T> pairs,
        Func<T, int> rowOf,
        Func<T, int> valueOf)
    {
        // One extra so the last row's length is offsets[n + 1] - offsets[n] like every other row's,
        // rather than a special case every caller has to remember.
        var offsets = new int[rowCount + 1];

        var materialised = pairs as IReadOnlyCollection<T> ?? [.. pairs];

        foreach (var pair in materialised)
            offsets[rowOf(pair) + 1]++;

        for (var i = 0; i < rowCount; i++)
            offsets[i + 1] += offsets[i];

        var values = new int[pairCount];
        var cursor = new int[rowCount];

        foreach (var pair in materialised)
        {
            var row = rowOf(pair);
            values[offsets[row] + cursor[row]] = valueOf(pair);
            cursor[row]++;
        }

        return (offsets, values);
    }
}
