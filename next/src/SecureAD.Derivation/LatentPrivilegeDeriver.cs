namespace SecureAD.Derivation;

/// <summary>
/// One conversion away from real privilege: a distribution group that, if it were made
/// security-enabled, would hand its members the authority of a group it is nested inside.
/// </summary>
/// <param name="DistributionGroupSidId">The group that would have to be converted.</param>
/// <param name="WouldGainSidId">The group whose authority its members would then hold.</param>
/// <param name="PrincipalsWhoWouldGain">
/// Who would gain it, excluding anyone who already holds it by some other route. A path that
/// changes nothing for anybody is not worth reporting.
/// </param>
internal sealed record LatentPrivilegePath(
    int DistributionGroupSidId,
    int WouldGainSidId,
    int[] PrincipalsWhoWouldGain);

/// <summary>
/// Finds privilege that is staged rather than held.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is not a weaker form of the authorization closure; it is a statement about a change that
/// has not happened.</b> An account beneath a distribution group nested in Domain Admins holds
/// none of that group's authority today - Microsoft is explicit that it receives no such SID in its
/// token - so reporting it as privileged would be false. Converting that one group to
/// security-enabled makes it privileged at the next logon, and the conversion is a single attribute
/// change.
/// </para>
/// <para>
/// <b>Which is why it is worth deriving at all.</b> Nesting a distribution group under a privileged
/// group grants nothing, so it trips no privilege alert and looks like an untidy mailing list.
/// The change that arms it is a flag on <c>groupType</c> rather than a membership edit, and it is
/// the membership edits that are watched. The innocent explanations are more common - an
/// Exchange-era notification group, a conversion nobody finished - and all of them leave the same
/// arrangement behind.
/// </para>
/// <para>
/// <b>It does not decide which groups are worth caring about.</b> Every security-enabled ancestor
/// is reported, not only the protected ones, because whether a given group's authority matters is a
/// rule's judgement and this stage derives facts. A rule that only cares about protected groups has
/// <see cref="ProtectedGroupCatalogue"/> to filter with.
/// </para>
/// </remarks>
internal static class LatentPrivilegeDeriver
{
    /// <summary>The name this phase is recorded under.</summary>
    public const string PhaseName = "LatentPrivilegePaths";

    /// <summary>
    /// Finds every distribution group whose conversion would confer privilege.
    /// </summary>
    /// <param name="graph">The nesting graph.</param>
    /// <param name="closure">
    /// The membership closure, which already holds who is effectively inside each group - including
    /// inside a distribution group, which is exactly the set that would be promoted.
    /// </param>
    /// <param name="cancellationToken">Stops the derivation.</param>
    /// <returns>The paths, one per distribution group and group it would confer.</returns>
    public static IReadOnlyList<LatentPrivilegePath> Derive(
        NestingGraph graph,
        MembershipClosure closure,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(graph);
        ArgumentNullException.ThrowIfNull(closure);

        var paths = new List<LatentPrivilegePath>();

        for (var candidate = 0; candidate < graph.Count; candidate++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Only a group known to be distribution is a candidate. A group whose type was not
            // captured is not reported here: saying "converting this would grant Domain Admins"
            // about a group that is already security-enabled would be false, and unlike the
            // membership expansion there is no safe direction to guess in - the finding either
            // describes a real change or it does not.
            if (!graph.IsGroup(candidate) || graph.IsSecurityEnabled(candidate) is not false)
                continue;

            var wouldGain = SecurityEnabledAncestorsOf(graph, candidate, cancellationToken);
            if (wouldGain.Count == 0)
                continue;

            // Who is effectively inside the distribution group. The membership expansion computes
            // this for every group, distribution ones included, precisely so this product can ask.
            var promoted = closure.MembersOf(candidate);
            if (promoted.Length == 0)
                continue;

            foreach (var gained in wouldGain)
            {
                var already = closure.MembersOf(gained);
                var newlyPrivileged = new List<int>();

                foreach (var principal in promoted)
                {
                    if (!already.Contains(principal))
                        newlyPrivileged.Add(principal);
                }

                // Everyone beneath it already holds that authority by another route, so converting
                // the group would change nothing and there is nothing to report.
                if (newlyPrivileged.Count == 0)
                    continue;

                newlyPrivileged.Sort();
                paths.Add(new LatentPrivilegePath(candidate, gained, [.. newlyPrivileged]));
            }
        }

        return paths;
    }

    /// <summary>
    /// The security-enabled groups whose authority would flow to a converted group's members.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The walk upward is not symmetrical with the walk downward.</b> The first hop is taken as
    /// though the candidate were already converted, because that is the change being described.
    /// Every hop after it requires the group standing on to be security-enabled already: if the
    /// candidate sits inside another distribution group, converting the candidate alone changes
    /// nothing above that second group, and a path that needs two conversions is a different and
    /// much weaker claim.
    /// </para>
    /// <para>
    /// A group whose type was not captured is walked through, matching what the membership
    /// expansion does with the same uncertainty, so that a path is not lost because an attribute
    /// was missing.
    /// </para>
    /// </remarks>
    private static List<int> SecurityEnabledAncestorsOf(
        NestingGraph graph,
        int candidate,
        CancellationToken cancellationToken)
    {
        var found = new List<int>();
        var seen = new HashSet<int> { candidate };
        var pending = new Stack<int>();

        pending.Push(candidate);

        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var node = pending.Pop();

            foreach (var container in graph.ContainingGroupsOf(node))
            {
                if (!seen.Add(container))
                    continue;

                if (graph.IsSecurityEnabled(container) is not false)
                {
                    found.Add(container);

                    // Keep climbing: a security-enabled group passes its members up to whatever
                    // holds it, so the converted group's members would gain those too.
                    pending.Push(container);
                }

                // A distribution group above stops this branch. It would still not carry
                // authorization after the candidate below it was converted.
            }
        }

        found.Sort();
        return found;
    }
}
