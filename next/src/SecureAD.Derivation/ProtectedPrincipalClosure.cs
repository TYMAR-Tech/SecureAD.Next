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
    ProtectionUnknownReason StatedLimits)
{
    public ProtectedPrincipalEvaluation EvaluationOf(int sidId) => EvaluationBySid[sidId];

    public ProtectionUnknownReason ReasonsFor(int sidId) => ReasonsBySid[sidId];

    public ProtectedPrincipalBasis? BasisFor(int sidId) => BasisBySid[sidId];

    public IReadOnlyList<int> PathFor(int sidId) => PathsBySid[sidId];
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

        for (var sidId = 0; sidId < count; sidId++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var entry = Match(catalogue, sids.TextOf(sidId), forestRootDomainSid);
            if (entry is null)
                continue;

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
            }
        }

        return new ProtectedPrincipalClosure(evaluations, reasons, bases, paths, seeds, catalogue, globalReason);
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
                        if (evaluations[member] != ProtectedPrincipalEvaluation.Protected
                            || bases[member]?.Kind != ProtectedPrincipalBasisKind.DirectPrincipalClaim)
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
