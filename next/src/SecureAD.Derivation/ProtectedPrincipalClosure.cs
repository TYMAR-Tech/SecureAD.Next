namespace SecureAD.Derivation;

/// <summary>
/// Whether AdminSDHolder and SDProp cover a principal.
/// </summary>
/// <remarks>
/// <b>Three answers, because two would be a lie.</b> A principal that reaches a protected group only
/// through an edge nobody has established is not thereby unprotected - saying so would report a
/// genuinely protected account as unprotected, which is the direction this stage exists to avoid.
/// </remarks>
internal enum ProtectedPrincipalEvaluation
{
    /// <summary>Covered, on evidence.</summary>
    Protected,

    /// <summary>Not covered, and nothing about the question is in doubt for this principal.</summary>
    NotProtected,

    /// <summary>
    /// Reaches a protected group only through an edge whose behaviour is not established, so
    /// whether it is covered cannot be said either way.
    /// </summary>
    Unknown,
}

/// <summary>
/// Why a principal's protection could not be settled.
/// </summary>
/// <remarks>
/// A set rather than one value: a principal can sit behind more than one unestablished thing at
/// once, and reporting only the first found would understate the doubt.
/// </remarks>
[Flags]
internal enum ProtectionUnknownReason
{
    /// <summary>Nothing is in doubt.</summary>
    None = 0,

    /// <summary>
    /// It reaches a protected group only through a distribution group, and whether the protection
    /// process follows those is not established.
    /// </summary>
    /// <remarks>
    /// Not raised while the catalogue follows distribution nesting, which it does by default on
    /// Microsoft's documented statement. Kept because the catalogue can be built without it, and
    /// because a store written under such a catalogue has to be able to say why.
    /// </remarks>
    DistributionTraversalResearchBlocked = 1,

    /// <summary>
    /// It reaches a protected group only by naming it as its primary group, and whether the
    /// protection process follows that is not established.
    /// </summary>
    PrimaryGroupTraversalResearchBlocked = 2,

    /// <summary>
    /// The membership evidence underneath is incomplete, so the paths that were searched are not
    /// all the paths there are.
    /// </summary>
    PartialMembershipEvidence = 4,

    /// <summary>
    /// The set of protected principals could not be confirmed for this domain.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>dSHeuristics</c> can remove four operator groups from the protected set, and this bundle
    /// does not carry it - either because nothing read the forest's configuration object, or
    /// because the bundle was captured before the attribute was requested. Removal can only shrink
    /// the set, so the effect is to report protection that may have been turned off rather than to
    /// miss protection that is on - the safer of the two directions, and the reason this does not
    /// make every principal <see cref="ProtectedPrincipalEvaluation.Unknown"/>.
    /// </para>
    /// <para>
    /// <b>Not raised where the forest was asked and answered.</b> A forest holding no value has a
    /// documented answer - every character defaults to zero, so nothing is excluded - and reporting
    /// that as a limit would state doubt nobody has.
    /// </para>
    /// </remarks>
    ProtectedCatalogueIncomplete = 8,

    /// <summary>
    /// The forest has removed one or more operator groups from AdminSDHolder's protection.
    /// </summary>
    /// <remarks>
    /// <b>Not a doubt, and recorded beside them because a smaller answer needs an explanation.</b>
    /// Everything else here says something could not be established; this says something was
    /// established and the answer was narrower than the published catalogue. Without it an operator
    /// sees four groups missing from the protected set with nothing to say why, which reads as the
    /// product having lost them.
    /// </remarks>
    ProtectedCatalogueNarrowedByForest = 16,
}

/// <summary>
/// Which principals AdminSDHolder covers, and what could not be established about the rest.
/// </summary>
/// <param name="EvaluationBySid">One answer per SID dictionary id.</param>
/// <param name="ReasonsBySid">Why, for the ones that came back unknown.</param>
/// <param name="Seeds">The protected principals the closure started from.</param>
/// <param name="Catalogue">Which catalogue, and which edges it followed, produced this.</param>
/// <param name="StatedLimits">
/// What is in doubt about the whole derivation rather than about one principal.
/// </param>
internal sealed record ProtectedPrincipalClosure(
    IReadOnlyList<ProtectedPrincipalEvaluation> EvaluationBySid,
    IReadOnlyList<ProtectionUnknownReason> ReasonsBySid,
    IReadOnlyList<int> Seeds,
    ProtectedGroupCatalogue Catalogue,
    ProtectionUnknownReason StatedLimits)
{
    /// <summary>What is true of one principal.</summary>
    /// <param name="sidId">The principal.</param>
    public ProtectedPrincipalEvaluation EvaluationOf(int sidId) => EvaluationBySid[sidId];

    /// <summary>Why it could not be settled, when it could not.</summary>
    /// <param name="sidId">The principal.</param>
    public ProtectionUnknownReason ReasonsFor(int sidId) => ReasonsBySid[sidId];
}

/// <summary>
/// Works out which principals AdminSDHolder and SDProp cover.
/// </summary>
/// <remarks>
/// <para>
/// <b>A different question from authorization, over the same graph, and the answers differ.</b> An
/// account nested through a distribution group beneath Domain Admins is not a Domain Admin - it
/// receives none of the group's authority - and is nonetheless a protected account, with
/// inheritance disabled and AdminSDHolder's permissions applied to it. Both statements come from
/// the same Microsoft guidance, and a single closure answering both would have to be wrong about
/// one of them.
/// </para>
/// <para>
/// <b>It searches downward from the protected principals, not upward from everybody.</b> The seeds
/// are the fifteen entries of the catalogue, so the search is over the part of the graph beneath
/// them rather than over the forest. That is why this is cheap where the authorization closure is
/// not.
/// </para>
/// <para>
/// <b>Only a principal that actually meets a gated edge becomes unknown.</b> A gated edge kind must
/// not turn the whole directory into a shrug: an account that reaches a protected group by ordinary
/// nesting is protected however many other accounts sit behind something unestablished, and an
/// account that reaches nothing protected at all is simply not protected.
/// </para>
/// </remarks>
internal static class ProtectedPrincipalDeriver
{
    /// <summary>The name this phase is recorded under.</summary>
    public const string PhaseName = "ProtectedPrincipals";

    /// <summary>
    /// Evaluates every principal in the graph.
    /// </summary>
    /// <param name="graph">The nesting graph.</param>
    /// <param name="sids">The SID dictionary, for recognising the protected principals.</param>
    /// <param name="catalogue">Which principals are protected and which edges may be followed.</param>
    /// <param name="membershipEvidenceIsPartial">
    /// Whether the nesting underneath is known to be incomplete - an unresolved member, or an
    /// expansion that reached its budget.
    /// </param>
    /// <param name="cancellationToken">Stops the derivation.</param>
    /// <returns>What is true of each principal, and what could not be established.</returns>
    public static ProtectedPrincipalClosure Derive(
        NestingGraph graph,
        SidInterner sids,
        ProtectedGroupCatalogue catalogue,
        bool membershipEvidenceIsPartial,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(graph);
        ArgumentNullException.ThrowIfNull(sids);
        ArgumentNullException.ThrowIfNull(catalogue);

        var count = graph.Count;
        var seeds = new List<int>();

        for (var sidId = 0; sidId < count; sidId++)
        {
            if (catalogue.IsProtected(sids.TextOf(sidId)))
                seeds.Add(sidId);
        }

        // Everything reachable by nesting the catalogue is willing to follow. Distribution groups
        // are included here rather than excluded: nesting_edge holds member and memberOf without
        // regard to group type, which is exactly the enumeration Microsoft describes.
        var established = Reach(graph, seeds, followPrimaryGroups: false, cancellationToken);

        // Everything reachable if primary-group membership were followed as well. Whatever is in
        // here and not in the set above is reachable only through the gated edge.
        var withGatedEdge = catalogue.FollowsPrimaryGroup
            ? established
            : Reach(graph, seeds, followPrimaryGroups: true, cancellationToken);

        var evaluations = new ProtectedPrincipalEvaluation[count];
        var reasons = new ProtectionUnknownReason[count];

        // What the forest said about its own protected set, rather than a caveat stated whatever
        // the evidence. An unread dSHeuristics leaves the published catalogue in force and says so;
        // a read one either confirms it or narrows it, and both are answers rather than doubts.
        var statedLimits = catalogue.Exclusions.IsComplete
            ? ProtectionUnknownReason.None
            : ProtectionUnknownReason.ProtectedCatalogueIncomplete;

        if (catalogue.Exclusions.Excluded.Count > 0)
            statedLimits |= ProtectionUnknownReason.ProtectedCatalogueNarrowedByForest;

        if (membershipEvidenceIsPartial)
            statedLimits |= ProtectionUnknownReason.PartialMembershipEvidence;

        if (!catalogue.FollowsDistributionNesting)
            statedLimits |= ProtectionUnknownReason.DistributionTraversalResearchBlocked;

        for (var sidId = 0; sidId < count; sidId++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (established.Contains(sidId))
            {
                evaluations[sidId] = ProtectedPrincipalEvaluation.Protected;
                continue;
            }

            if (withGatedEdge.Contains(sidId))
            {
                // Reached only through primary-group membership. Microsoft's specifications make
                // that real membership and make authorization honour it; none of them says the
                // protection process follows it. Answering NotProtected here would be a boolean
                // answer to a question nobody has settled, pointing the dangerous way.
                evaluations[sidId] = ProtectedPrincipalEvaluation.Unknown;
                reasons[sidId] = ProtectionUnknownReason.PrimaryGroupTraversalResearchBlocked;
                continue;
            }

            // Partial membership evidence does NOT make this principal unknown, and resisting that
            // is the point. One member of one group failing to resolve would otherwise turn every
            // principal in the forest into a shrug, which is the failure this whole derivation is
            // shaped to avoid - and a closure that answers Unknown about everybody has told a
            // reader nothing while sounding careful. The doubt is real but unbounded: an unresolved
            // member could hide anything beneath it, so there is no set of principals to attach it
            // to. It is stated once about the derivation, in StatedLimits, and a rule reading a
            // NotProtected out of a closure carrying that limit has not established a clean result.
            evaluations[sidId] = ProtectedPrincipalEvaluation.NotProtected;
        }

        return new ProtectedPrincipalClosure(
            evaluations, reasons, seeds, catalogue, statedLimits);
    }

    /// <summary>
    /// Everything beneath the seeds, following the kinds of edge asked for.
    /// </summary>
    /// <remarks>
    /// Iterative for the reason the membership expansion is: the depth of a walk is bounded by the
    /// number of principals rather than by how deeply anyone nests groups.
    /// </remarks>
    private static HashSet<int> Reach(
        NestingGraph graph,
        IReadOnlyList<int> seeds,
        bool followPrimaryGroups,
        CancellationToken cancellationToken)
    {
        var reached = new HashSet<int>();
        var pending = new Stack<int>();

        foreach (var seed in seeds)
        {
            if (reached.Add(seed))
                pending.Push(seed);
        }

        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var group = pending.Pop();

            foreach (var member in graph.MembersOf(group))
            {
                if (reached.Add(member))
                    pending.Push(member);
            }

            if (!followPrimaryGroups)
                continue;

            foreach (var member in graph.PrimaryMembersOf(group))
            {
                if (reached.Add(member))
                    pending.Push(member);
            }
        }

        return reached;
    }
}
