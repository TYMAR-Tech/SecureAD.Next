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

    /// <summary>
    /// This principal's own domain was not read in full, so nothing was established about it.
    /// </summary>
    /// <remarks>
    /// <b>The only reason here that is about one principal rather than the whole forest.</b> Every
    /// other value is a fact about the run or the forest and is applied to everything; this names
    /// the accounts the capture did not cover. Adding it to the forest-wide set would make one
    /// deliberately excluded domain turn every protection answer in a nine-domain forest
    /// <c>Unknown</c> and stop ownership findings being reported anywhere - judging discards the
    /// findings of an object with unresolved inputs, which turned two real findings into none on
    /// 2026-09-03. P-163.
    /// </remarks>
    PrincipalDomainNotReadInFull = 1024,
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

    /// <param name="domainSidsNotReadInFull">
    /// Domain SID prefixes the run did not read in full. Empty where every declared domain was read.
    /// </param>
    /// <param name="stubOnlyPrincipals">
    /// Principals only a <c>foreignSecurityPrincipal</c> stub ever answered for.
    /// </param>
    public static ProtectedPrincipalClosure Derive(
        NestingGraph graph,
        SidInterner sids,
        ProtectedGroupCatalogue catalogue,
        bool membershipEvidenceIsPartial,
        CancellationToken cancellationToken,
        string? forestRootDomainSid,
        IReadOnlySet<string> domainSidsNotReadInFull,
        IReadOnlyCollection<int> stubOnlyPrincipals)
    {
        ArgumentNullException.ThrowIfNull(graph);
        ArgumentNullException.ThrowIfNull(sids);
        ArgumentNullException.ThrowIfNull(catalogue);
        ArgumentNullException.ThrowIfNull(domainSidsNotReadInFull);
        ArgumentNullException.ThrowIfNull(stubOnlyPrincipals);

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

        // NO THIRD WALK FOR PRIMARY-GROUP EDGES, PER 0118. A principal reachable only through
        // primaryGroupID was marked Unknown here until 2026-09-11, because Microsoft establishes
        // that the attribute IS membership and that authorization honours it, and establishes
        // nothing about whether AdminSDHolder's protected-member enumeration follows the same edge.
        //
        // The laboratory answered it where the documentation would not. In ba.ad.lab on 2026-09-10
        // the Domain Controllers group was itself stamped, held no explicit member entries so the
        // primary-group edge was the only route into it, and dSHeuristics excluded nothing - and its
        // domain controller carried neither adminCount nor a DACL refusing inheritance, eighteen
        // months after creation, while Domain Admins was stamped and Domain Users was not in the
        // same run. SDProp does not follow the edge, so these principals keep the NotProtected they
        // already hold. tools/Observe-Ac64PrimaryGroupTraversal.ps1 reproduces the observation.
        //
        // LAB-VERIFIED, NOT SPECIFIED. One forest, one domain, one domain controller, one Windows
        // version. If a forest ever contradicts it the answer reverts to Unknown, which is why
        // PrimaryGroupTraversalResearchBlocked and UnresolvedReason.PrimaryGroupRoute both remain.

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
            graph, acceptedOwnerRoots, cancellationToken);

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

        // BESIDE THE LOOP ABOVE AND NEVER INSIDE IT, WHICH IS THE WHOLE OF P-163. Every reason
        // gathered into globalReason is a fact about the run or the forest and rightly applies to
        // every principal. This one is a fact about particular accounts - the ones the capture did
        // not cover - and folding it into globalReason would make a single deliberately excluded
        // domain turn every protection answer in a nine-domain forest Unknown. Judging counts an
        // object with unresolved inputs as not judged and discards its findings, so that would stop
        // ownership findings being reported anywhere: the trap that turned two real findings into
        // none on 2026-09-03.
        //
        // TWO SIGNALS, COVERING DISJOINT CASES, AND BOTH ARE NEEDED. A domain read in part
        // establishes a domain SID, so its principals are found by prefix. A domain excluded
        // outright establishes none - it contributed no objects to attribute one from - and its
        // principals reach the graph only as foreignSecurityPrincipal stubs. A stub resolves, so it
        // never lands in UnresolvedTrustees and the forest-wide safety net does not see it.
        if (domainSidsNotReadInFull.Count > 0 || stubOnlyPrincipals.Count > 0)
        {
            var stubs = stubOnlyPrincipals as IReadOnlySet<int>
                ?? new HashSet<int>(stubOnlyPrincipals);

            for (var sidId = 0; sidId < count; sidId++)
            {
                var ownDomainWasNotRead = stubs.Contains(sidId)
                    || (DomainRelativeSid.DomainOf(sids.TextOf(sidId)) is { } domainSid
                        && domainSidsNotReadInFull.Contains(domainSid));

                if (!ownDomainWasNotRead)
                    continue;

                // Protected survives for the same reason it survives above: finding a route to a
                // protected root is positive evidence, and not having read the principal's own
                // domain cannot unmake a path that was actually walked.
                if (evaluations[sidId] != ProtectedPrincipalEvaluation.Protected)
                {
                    MakeUnknown(
                        sidId,
                        ProtectionUnknownReason.PrincipalDomainNotReadInFull,
                        evaluations,
                        reasons);
                }

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
    /// Everything beneath the roots, following ordinary nesting alone.
    /// </summary>
    /// <remarks>
    /// <b>Primary-group edges are not followed, and there is no longer a switch to follow them.</b>
    /// This took a <c>followPrimaryGroups</c> parameter until 0118, so the deriver could difference
    /// the two reachable sets and mark the difference <c>Unknown</c>. With that gate gone the only
    /// caller passed <c>false</c>, and a parameter with one possible value is a branch nothing
    /// exercises. <see cref="SchemaOwners"/> still walks both edge kinds, because ownership
    /// acceptance is an authorization question and authorization does honour primary groups.
    /// </remarks>
    private static HashSet<int> Reachable(
        NestingGraph graph,
        IReadOnlyCollection<Root> roots,
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

            foreach (var member in graph.MembersOf(current).ToArray())
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
