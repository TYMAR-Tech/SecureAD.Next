using SecureAD.Evidence.Findings;

namespace SecureAD.Derivation;

public enum ProtectedPrincipalEvaluation
{
    Protected,
    NotProtected,
    Unknown,
}

[Flags]
public enum ProtectionUnknownReason
{
    None = 0,
    PrimaryGroupTraversalResearchBlocked = 1,
    MembershipEvidenceIncomplete = 2,
    PossibleRootReached = 4,
    PrincipalClaimDisputed = 8,
    PrincipalClaimUnverified = 16,
    ForestMaskNotRead = 32,
    ForestMaskMalformed = 64,
    ForestRootDomainUnknown = 128,

    // Temporary names retained until all existing callers have moved to the Decision 0089 vocabulary.
    DistributionTraversalResearchBlocked = 256,
    PartialMembershipEvidence = MembershipEvidenceIncomplete,
    ProtectedCatalogueIncomplete = ForestMaskNotRead,
    ProtectedCatalogueNarrowedByForest = 512,
}

public enum ProtectedPrincipalBasisKind
{
    DirectPrincipalClaim,
    MembershipRoot,
}

/// <summary>
/// Whether this product accepts a principal as an object's owner without reporting it.
/// </summary>
/// <remarks>
/// <para>
/// <b>A separate question from protection, and it must stay separate.</b> <i>Does AdminSDHolder
/// repair this principal's permissions</i> and <i>is this an owner the product stays silent
/// about</i> have different answers for the same group: Backup Operators is protected by
/// Microsoft's design and is outside the control plane by <c>0099</c>, so its ownership of an
/// object is worth reporting. Reading one as the other is what <c>P-140</c> found the product
/// doing.
/// </para>
/// <para>
/// <b>Why it cannot be filtered out of the protection answer afterwards.</b>
/// <see cref="ProtectedPrincipalBasis"/> records one root, so an account inside both Domain Admins
/// and Account Operators carries whichever the walk attributed it to. Filtering on that basis would
/// report a domain administrator as a non-administrative owner - a false statement to a customer,
/// which is the one thing this product must not produce. So the reachable set is computed again,
/// over the accepted roots alone, and carries its own evidence.
/// </para>
/// <para>
/// <b>One of the five questions <c>0101</c> requires a principal registry to answer</b>, and the
/// only one built so far. The other four keep their existing homes until that registry exists;
/// nothing here is inferred from any of them.
/// </para>
/// </remarks>
public enum OwnerAcceptance
{
    /// <summary>The product reports this principal when it owns an object.</summary>
    NotAccepted,

    /// <summary>The product accepts this principal as an owner and says nothing.</summary>
    Accepted,

    /// <summary>Nobody could say, and <c>0002</c> forbids reading that as either answer.</summary>
    Unknown,

    /// <summary>Accepted only within the captured forest's schema partition, per <c>0109</c>.</summary>
    SchemaOnly,

    /// <summary>Accepted in the schema; incomplete evidence leaves acceptance elsewhere unknown.</summary>
    SchemaOnlyOtherwiseUnknown,
}

public sealed record ProtectedPrincipalBasis(
    ProtectedPrincipalBasisKind Kind,
    int CatalogueEntryId,
    int CatalogueRid);

internal sealed record ProtectedPrincipalClosure(
    IReadOnlyList<ProtectedPrincipalEvaluation> EvaluationBySid,
    IReadOnlyList<ProtectionUnknownReason> ReasonsBySid,
    IReadOnlyList<ProtectedPrincipalBasis?> BasisBySid,
    IReadOnlyList<IReadOnlyList<int>> PathsBySid,
    IReadOnlyList<int> Seeds,
    ProtectedGroupCatalogue Catalogue,
    ProtectionUnknownReason StatedLimits,
    IReadOnlyList<OwnerAcceptance> OwnerAcceptanceBySid)
{
    public IReadOnlyList<MembershipRouteSummary> MembershipRoutesBySid { get; init; } = [];

    public ProtectedPrincipalEvaluation EvaluationOf(int sidId) => EvaluationBySid[sidId];

    public ProtectionUnknownReason ReasonsFor(int sidId) => ReasonsBySid[sidId];

    public ProtectedPrincipalBasis? BasisFor(int sidId) => BasisBySid[sidId];

    public IReadOnlyList<int> PathFor(int sidId) => PathsBySid[sidId];

    public OwnerAcceptance OwnerAcceptanceOf(int sidId) => OwnerAcceptanceBySid[sidId];
}

internal static class ProtectedPrincipalDeriver
{
    public const string PhaseName = "ProtectedPrincipals";

    public static ProtectedPrincipalClosure Derive(
        NestingGraph graph,
        SidInterner sids,
        ProtectedGroupCatalogue catalogue,
        bool membershipEvidenceIsPartial,
        CancellationToken cancellationToken,
        string? forestRootDomainSid)
    {
        ArgumentNullException.ThrowIfNull(graph);
        ArgumentNullException.ThrowIfNull(sids);
        ArgumentNullException.ThrowIfNull(catalogue);

        var count = graph.Count;
        var evaluations = Enumerable.Repeat(ProtectedPrincipalEvaluation.NotProtected, count).ToArray();
        var reasons = new ProtectionUnknownReason[count];
        var bases = new ProtectedPrincipalBasis?[count];
        var paths = Enumerable.Range(0, count).Select(_ => (IReadOnlyList<int>)Array.Empty<int>()).ToArray();
        var establishedRoots = new List<Root>();
        var possibleRoots = new List<Root>();
        var seeds = new List<int>();
        var schemaOwnerRoots = new List<int>();
        var membershipRoots = new List<MembershipRouteRoot>();

        for (var sidId = 0; sidId < count; sidId++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var entry = Match(catalogue, sids.TextOf(sidId), forestRootDomainSid);
            if (entry is null)
                continue;

            // Matched to the forest-root identity, before and independently of protection claims.
            if (entry.Rid == ProtectedGroupCatalogue.SchemaOwnerRid)
                schemaOwnerRoots.Add(sidId);

            switch (entry.PrincipalProtection.Status)
            {
                case CatalogueClaimStatus.Established:
                    ProtectDirect(sidId, entry, evaluations, bases);
                    break;
                case CatalogueClaimStatus.Disputed:
                    MakeUnknown(sidId, ProtectionUnknownReason.PrincipalClaimDisputed, evaluations, reasons);
                    break;
                case CatalogueClaimStatus.Unverified:
                    MakeUnknown(sidId, ProtectionUnknownReason.PrincipalClaimUnverified, evaluations, reasons);
                    break;
                case CatalogueClaimStatus.EstablishedNo:
                    break;
                default:
                    throw new InvalidOperationException(
                        $"Principal protection cannot be {entry.PrincipalProtection.Status} for {entry.Name}.");
            }

            if (!graph.IsGroup(sidId))
                continue;

            var propagation = catalogue.EffectiveMemberPropagation(entry).Status;
            membershipRoots.Add(new MembershipRouteRoot(sidId, entry, propagation == CatalogueClaimStatus.Established));
            if (propagation == CatalogueClaimStatus.Established)
            {
                establishedRoots.Add(new Root(sidId, entry));
                seeds.Add(sidId);
            }
            else if (propagation is CatalogueClaimStatus.Disputed or CatalogueClaimStatus.Unverified)
            {
                possibleRoots.Add(new Root(sidId, entry));
            }
        }

        Walk(graph, establishedRoots, isEstablished: true, evaluations, reasons, bases, paths, cancellationToken);
        Walk(graph, possibleRoots, isEstablished: false, evaluations, reasons, bases, paths, cancellationToken);
        WalkPrimaryGroups(graph, [.. establishedRoots, .. possibleRoots], evaluations, reasons, cancellationToken);

        // THE ACCEPTED-OWNER QUESTION, ANSWERED SEPARATELY AND NOT FILTERED OUT OF THE ONE ABOVE.
        // Walked over the accepted roots alone, so a principal reaching Domain Admins is accepted
        // whatever else it also reaches. Deriving this from the protection basis instead would read
        // the single root that walk happened to attribute, and an account in both Domain Admins and
        // Account Operators would come back not-accepted - reporting a domain administrator as a
        // non-administrative owner, which is P-140 replaced by something worse than P-140.
        var acceptedOwnerRoots = establishedRoots
            .Where(root => ProtectedGroupCatalogue.AcceptedOwnerRids.Contains(root.Entry.Rid))
            .ToArray();

        var acceptedOwners = Reachable(
            graph, acceptedOwnerRoots, followPrimaryGroups: false, cancellationToken);

        var ownerAcceptance = Enumerable.Repeat(OwnerAcceptance.NotAccepted, count).ToArray();
        foreach (var sidId in acceptedOwners)
            ownerAcceptance[sidId] = OwnerAcceptance.Accepted;

        // A group that IS an accepted principal, rather than a member of one. Reachable starts at
        // the roots so this is already covered for groups the graph knows; matching again costs
        // nothing and covers an accepted principal the nesting pass never saw as a group.
        for (var sidId = 0; sidId < count; sidId++)
        {
            if (Match(catalogue, sids.TextOf(sidId), forestRootDomainSid) is { } accepted
                && ProtectedGroupCatalogue.AcceptedOwnerRids.Contains(accepted.Rid))
            {
                ownerAcceptance[sidId] = OwnerAcceptance.Accepted;
            }
        }

        var globalReason = ProtectionUnknownReason.None;
        if (membershipEvidenceIsPartial)
            globalReason |= ProtectionUnknownReason.MembershipEvidenceIncomplete;
        if (forestRootDomainSid is null)
            globalReason |= ProtectionUnknownReason.ForestRootDomainUnknown;
        if (!catalogue.Exclusions.IsComplete)
            globalReason |= catalogue.Exclusions.Outcome == SecureAD.Kernel.Security.HeuristicReadOutcome.Malformed
                ? ProtectionUnknownReason.ForestMaskMalformed
                : ProtectionUnknownReason.ForestMaskNotRead;
        if (catalogue.Exclusions.Excluded.Count > 0)
            globalReason |= ProtectionUnknownReason.ProtectedCatalogueNarrowedByForest;

        if (globalReason != ProtectionUnknownReason.None)
        {
            for (var sidId = 0; sidId < count; sidId++)
            {
                if (evaluations[sidId] != ProtectedPrincipalEvaluation.Protected)
                    MakeUnknown(sidId, globalReason, evaluations, reasons);

                // A MEMBERSHIP WALK THAT MAY HAVE MISSED SOMETHING CANNOT SAY "NOT ACCEPTED".
                // The consequence of getting this wrong is a finding naming a domain administrator
                // as a non-administrative owner, so an incomplete walk withholds the answer rather
                // than defaulting it. An owner already found inside an accepted root is unaffected:
                // finding a path is positive evidence and a partial walk cannot invent one.
                if (ownerAcceptance[sidId] != OwnerAcceptance.Accepted)
                    ownerAcceptance[sidId] = OwnerAcceptance.Unknown;
            }
        }

        var schemaOwners = SchemaOwners(graph, schemaOwnerRoots, allowUnknownGroups: false, cancellationToken);
        var possibleSchemaOwners = SchemaOwners(graph, schemaOwnerRoots, allowUnknownGroups: true, cancellationToken);
        foreach (var sidId in possibleSchemaOwners)
        {
            if (ownerAcceptance[sidId] == OwnerAcceptance.Accepted)
                continue;

            ownerAcceptance[sidId] = !schemaOwners.Contains(sidId)
                ? OwnerAcceptance.Unknown
                : ownerAcceptance[sidId] == OwnerAcceptance.Unknown
                    ? OwnerAcceptance.SchemaOnlyOtherwiseUnknown
                    : OwnerAcceptance.SchemaOnly;
        }

        var routeLimits = MembershipRouteIncompleteReason.None;
        if (membershipEvidenceIsPartial)
            routeLimits |= MembershipRouteIncompleteReason.MembershipEvidenceIncomplete;
        if (forestRootDomainSid is null)
            routeLimits |= MembershipRouteIncompleteReason.ForestIdentityUnknown;
        if (!catalogue.Exclusions.IsComplete)
            routeLimits |= MembershipRouteIncompleteReason.ForestMaskUnreadable;

        return new ProtectedPrincipalClosure(
            evaluations, reasons, bases, paths, seeds, catalogue, globalReason, ownerAcceptance)
        {
            MembershipRoutesBySid = MembershipRouteDeriver.Derive(graph, sids, membershipRoots,
                routeLimits, MembershipRouteBudget.Bulk, cancellationToken),
        };
    }

    private static HashSet<int> SchemaOwners(
        NestingGraph graph,
        IReadOnlyList<int> roots,
        bool allowUnknownGroups,
        CancellationToken cancellationToken)
    {
        var seen = new HashSet<int>(roots);
        var queue = new Queue<int>(roots);
        while (queue.TryDequeue(out var current))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!graph.IsGroup(current)
                || graph.IsSecurityEnabled(current) is false
                || (graph.IsSecurityEnabled(current) is null && !allowUnknownGroups))
                continue;

            // Authorization includes primary groups; protection deliberately asks separately.
            foreach (var member in graph.MembersOf(current).ToArray()
                .Concat(graph.PrimaryMembersOf(current).ToArray()))
            {
                if (graph.IsGroup(member)
                    && (graph.IsSecurityEnabled(member) is false
                        || (graph.IsSecurityEnabled(member) is null && !allowUnknownGroups)))
                    continue;

                if (seen.Add(member))
                    queue.Enqueue(member);
            }
        }

        return seen;
    }

    private static void ProtectDirect(
        int sidId,
        AdminSdHolderCatalogueEntry entry,
        ProtectedPrincipalEvaluation[] evaluations,
        ProtectedPrincipalBasis?[] bases)
    {
        evaluations[sidId] = ProtectedPrincipalEvaluation.Protected;
        bases[sidId] = new ProtectedPrincipalBasis(
            ProtectedPrincipalBasisKind.DirectPrincipalClaim, entry.Id, entry.Rid);
    }

    private static void Walk(
        NestingGraph graph,
        IEnumerable<Root> roots,
        bool isEstablished,
        ProtectedPrincipalEvaluation[] evaluations,
        ProtectionUnknownReason[] reasons,
        ProtectedPrincipalBasis?[] bases,
        IReadOnlyList<int>[] paths,
        CancellationToken cancellationToken)
    {
        foreach (var root in roots.OrderBy(r => r.Entry.Id).ThenBy(r => r.SidId))
        {
            var queue = new Queue<(int SidId, int[] Path)>();
            queue.Enqueue((root.SidId, [root.SidId]));
            var seen = new HashSet<int> { root.SidId };

            while (queue.Count > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var current = queue.Dequeue();
                foreach (var member in graph.MembersOf(current.SidId).ToArray().Order())
                {
                    if (!seen.Add(member))
                        continue;

                    var path = new[] { member }.Concat(current.Path).ToArray();
                    queue.Enqueue((member, path));

                    if (isEstablished)
                    {
                        if (ShouldAttribute(member, path, root, evaluations, bases, paths))
                        {
                            evaluations[member] = ProtectedPrincipalEvaluation.Protected;
                            reasons[member] = ProtectionUnknownReason.None;
                            bases[member] = new ProtectedPrincipalBasis(
                                ProtectedPrincipalBasisKind.MembershipRoot, root.Entry.Id, root.Entry.Rid);
                            paths[member] = path;
                        }
                    }
                    else if (evaluations[member] != ProtectedPrincipalEvaluation.Protected)
                    {
                        MakeUnknown(member, ProtectionUnknownReason.PossibleRootReached, evaluations, reasons);
                    }
                }
            }
        }
    }

    /// <summary>
    /// Whether this root should become the selected protection basis, not the complete route summary.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The nearest root wins, decided 2026-09-05 and recorded as <c>0106</c>.</b> Until then
    /// each later root simply overwrote an earlier one, so the <i>last</i> root the walk happened
    /// to process was reported. On <c>ad.lab</c> that meant three accounts sitting directly in
    /// Enterprise Admins were each reported under <c>BUILTIN\Administrators</c>, because Enterprise
    /// Admins is itself nested there and Administrators is walked second. Both statements were
    /// true and the one shown was the wrong one to act on: the fix is to remove the account from
    /// Enterprise Admins, and nothing on the screen said so.
    /// </para>
    /// <para>
    /// <b>Nearest means the shortest supporting chain for this selected basis.</b> It is not a
    /// removal plan. Other initial memberships, including longer ones, can reach the same root.
    /// </para>
    /// <para>
    /// <b>Ties go to the lowest catalogue entry id, and that is a real limitation rather than a
    /// complete answer.</b> Roots may share an initial membership, and independent routes may have
    /// unequal lengths. <c>MembershipRouteDeriver</c> supplies the separate summary under <c>0108</c>.
    /// </para>
    /// <para>
    /// <b>A direct principal claim is never displaced.</b> A principal Microsoft names in the
    /// catalogue is protected because of what it is; that it also sits inside something else does
    /// not make its membership the reason.
    /// </para>
    /// </remarks>
    private static bool ShouldAttribute(
        int member,
        IReadOnlyList<int> path,
        Root root,
        ProtectedPrincipalEvaluation[] evaluations,
        ProtectedPrincipalBasis?[] bases,
        IReadOnlyList<int>[] paths)
    {
        if (bases[member]?.Kind == ProtectedPrincipalBasisKind.DirectPrincipalClaim)
            return false;

        if (evaluations[member] != ProtectedPrincipalEvaluation.Protected
            || bases[member] is not { } held)
        {
            return true;
        }

        // Strictly shorter only. Roots are walked in catalogue order, so declining an equal-length
        // path leaves the lowest entry id holding it - deterministic without a second comparison,
        // and it cannot depend on which root happened to be enumerated first.
        return path.Count < paths[member].Count
            || (path.Count == paths[member].Count && root.Entry.Id < held.CatalogueEntryId);
    }

    /// <summary>
    /// Flags the principals whose only route to a root runs through a primary-group edge.
    /// </summary>
    /// <remarks>
    /// <b>The difference between the two reachable sets is the whole point.</b> Walking both edge
    /// kinds together and blaming everything it reaches would stamp this reason on principals whose
    /// route is ordinary nesting, which is a reason that does not apply - and under <c>0086</c> an
    /// unknown reason is customer-visible, so a wrong one sends an operator to look at
    /// <c>primaryGroupID</c> on an account whose answer has nothing to do with it.
    /// </remarks>
    private static void WalkPrimaryGroups(
        NestingGraph graph,
        IReadOnlyCollection<Root> roots,
        ProtectedPrincipalEvaluation[] evaluations,
        ProtectionUnknownReason[] reasons,
        CancellationToken cancellationToken)
    {
        var ordinary = Reachable(graph, roots, followPrimaryGroups: false, cancellationToken);
        var withPrimary = Reachable(graph, roots, followPrimaryGroups: true, cancellationToken);

        foreach (var sidId in withPrimary.Order())
        {
            if (ordinary.Contains(sidId))
                continue;

            if (evaluations[sidId] != ProtectedPrincipalEvaluation.Protected)
            {
                MakeUnknown(
                    sidId,
                    ProtectionUnknownReason.PrimaryGroupTraversalResearchBlocked,
                    evaluations,
                    reasons);
            }
        }
    }

    /// <summary>
    /// Everything beneath the roots, by the edge kinds the caller allows.
    /// </summary>
    private static HashSet<int> Reachable(
        NestingGraph graph,
        IReadOnlyCollection<Root> roots,
        bool followPrimaryGroups,
        CancellationToken cancellationToken)
    {
        var seen = new HashSet<int>();
        var queue = new Queue<int>();

        foreach (var root in roots.OrderBy(r => r.Entry.Id).ThenBy(r => r.SidId))
        {
            if (seen.Add(root.SidId))
                queue.Enqueue(root.SidId);
        }

        while (queue.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = queue.Dequeue();

            var members = followPrimaryGroups
                ? [.. graph.MembersOf(current).ToArray(), .. graph.PrimaryMembersOf(current).ToArray()]
                : graph.MembersOf(current).ToArray();

            foreach (var member in members)
            {
                if (seen.Add(member))
                    queue.Enqueue(member);
            }
        }

        return seen;
    }

    private static AdminSdHolderCatalogueEntry? Match(
        ProtectedGroupCatalogue catalogue,
        string sid,
        string? forestRootDomainSid)
    {
        var separator = sid.LastIndexOf('-');
        if (separator < 0 || !int.TryParse(sid[(separator + 1)..], out var rid))
            return null;

        return catalogue.Entries.FirstOrDefault(entry => entry.Rid == rid && entry.Scope switch
        {
            CataloguePrincipalScope.BuiltinPerDomain =>
                string.Equals(sid, $"S-1-5-32-{rid}", StringComparison.Ordinal),
            CataloguePrincipalScope.PerDomainRid => sid.StartsWith("S-1-5-21-", StringComparison.Ordinal),
            CataloguePrincipalScope.ForestRootRid => forestRootDomainSid is not null
                && string.Equals(sid[..separator], forestRootDomainSid, StringComparison.Ordinal),
            _ => false,
        });
    }

    private static void MakeUnknown(
        int sidId,
        ProtectionUnknownReason reason,
        ProtectedPrincipalEvaluation[] evaluations,
        ProtectionUnknownReason[] reasons)
    {
        if (evaluations[sidId] == ProtectedPrincipalEvaluation.Protected)
            return;
        evaluations[sidId] = ProtectedPrincipalEvaluation.Unknown;
        reasons[sidId] |= reason;
    }

    private sealed record Root(int SidId, AdminSdHolderCatalogueEntry Entry);
}
