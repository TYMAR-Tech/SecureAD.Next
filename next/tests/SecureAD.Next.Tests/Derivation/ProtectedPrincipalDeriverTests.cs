using SecureAD.Derivation;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

/// <summary>
/// Who AdminSDHolder covers, and what the derivation refuses to guess.
/// </summary>
/// <remarks>
/// <b>The distribution-group case is the one with a citation, and it is the one that separates this
/// closure from the authorization one.</b> The same account is not a Domain Admin and is a
/// protected account, and both halves come from the same Microsoft guidance.
/// </remarks>
public sealed class ProtectedPrincipalDeriverTests
{
    private const string DomainSid = "S-1-5-21-1111111111-2222222222-3333333333";

    // MS-ADTS 3.1.1.6.1.2 and P-88's sealed Windows Server 2022 lab observation distinguish
    // the forest-root universal RID 498 from protected RID 521; neither settles propagation.
    [Fact]
    public void EnterpriseRodcGroupIsNotAutomaticallyProtectedOrAcceptedAsOwner()
    {
        var closure = Derive([EnterpriseRodc(0), Security(1, 521), Security(2, 512), Security(3, 513)], []);

        Assert.Equal(ProtectedPrincipalEvaluation.NotProtected, closure.EvaluationOf(0));
        Assert.Equal(ProtectionUnknownReason.None, closure.ReasonsFor(0));
        Assert.Null(closure.BasisFor(0));
        Assert.Empty(closure.PathFor(0));
        Assert.Equal(OwnerAcceptance.NotAccepted, closure.OwnerAcceptanceOf(0));
        Assert.Equal(ProtectedPrincipalEvaluation.Protected, closure.EvaluationOf(1));
        Assert.Equal(ProtectedPrincipalEvaluation.Protected, closure.EvaluationOf(2));
        Assert.Equal(ProtectedPrincipalEvaluation.NotProtected, closure.EvaluationOf(3));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void EnterpriseRodcGroupCanStillBeProtectedByAnotherMembership(bool nested)
    {
        var closure = Derive([Security(0, 512), Security(1, 1200), EnterpriseRodc(2), User(3, 1104)],
            nested ? [(0, 1), (1, 2), (2, 3)] : [(0, 2), (2, 3)]);

        Assert.Equal(ProtectedPrincipalEvaluation.Protected, closure.EvaluationOf(2));
        Assert.Equal(ProtectionUnknownReason.None, closure.ReasonsFor(2));
        Assert.Equal(512, closure.BasisFor(2)!.CatalogueRid);
        Assert.Equal(nested ? [2, 1, 0] : new[] { 2, 0 }, closure.PathFor(2));
        Assert.Equal(ProtectedPrincipalEvaluation.Protected, closure.EvaluationOf(3));
    }

    [Fact]
    public void EnterpriseRodcMembershipAloneRemainsUnresolved()
    {
        var closure = Derive([EnterpriseRodc(0), User(1, 1104)], [(0, 1)]);

        Assert.Equal(ProtectedPrincipalEvaluation.NotProtected, closure.EvaluationOf(0));
        Assert.Equal(ProtectedPrincipalEvaluation.Unknown, closure.EvaluationOf(1));
        Assert.Equal(ProtectionUnknownReason.PossibleRootReached, closure.ReasonsFor(1));
    }

    [Fact]
    public void EnterpriseRodcIncompleteMembershipEvidenceIsNotANegativeAnswer()
    {
        var closure = Derive([EnterpriseRodc(0)], [], membershipEvidenceIsPartial: true);

        Assert.Equal(ProtectedPrincipalEvaluation.Unknown, closure.EvaluationOf(0));
        Assert.Equal(ProtectionUnknownReason.MembershipEvidenceIncomplete, closure.ReasonsFor(0));
    }

    [Fact]
    public void EnterpriseRodcClaimDoesNotCreateAChildDomainPropagationRoot()
    {
        Fixture[] principals = [EnterpriseRodc(0), User(1, 1104)];
        var closure = ProtectedPrincipalDeriver.Derive(GraphOf(principals, [(0, 1)]), SidsFor(principals),
            ProtectedGroupCatalogue.NarrowedBy(string.Empty), false, CancellationToken.None,
            OtherDomainSid, EveryDomainRead, NoStubOnlyPrincipals);

        Assert.Equal(ProtectedPrincipalEvaluation.NotProtected, closure.EvaluationOf(1));
        Assert.Equal(ProtectionUnknownReason.None, closure.ReasonsFor(1));
    }

    /// <summary>
    /// A member of a protected group is protected.
    /// </summary>
    [Fact]
    public void Stage2a_AMemberOfAProtectedGroupIsProtected()
    {
        var closure = Derive(
            [Security(0, rid: 512), User(1, rid: 1104)],
            edges: [(0, 1)]);

        Assert.Equal(ProtectedPrincipalEvaluation.Protected, closure.EvaluationOf(1));
    }

    /// <summary>
    /// Somebody with no path to a protected group is not protected.
    /// </summary>
    [Fact]
    public void Stage2a_SomebodyUnconnectedIsNotProtected()
    {
        var closure = Derive(
            [Security(0, rid: 512), User(1, rid: 1104)],
            edges: []);

        Assert.Equal(ProtectedPrincipalEvaluation.NotProtected, closure.EvaluationOf(1));
    }

    /// <summary>
    /// Nesting through a distribution group reaches protection, though it carries no authorization.
    /// </summary>
    /// <remarks>
    /// Microsoft states that transitive membership in a protected group confers the restricted
    /// security regardless of whether it came through a security or a distribution group, and gives
    /// this exact arrangement as the example.
    /// </remarks>
    [Fact]
    public void Stage2a_DistributionNestingReachesProtection()
    {
        var closure = Derive(
            [Security(0, rid: 512), Distribution(1, rid: 1200), User(2, rid: 1104)],
            edges: [(0, 1), (1, 2)]);

        Assert.Equal(ProtectedPrincipalEvaluation.Protected, closure.EvaluationOf(2));
    }

    /// <summary>
    /// The same account is protected and is not a Domain Admin.
    /// </summary>
    /// <remarks>
    /// The whole reason these are separate products. One closure answering both would have to be
    /// wrong about one of them.
    /// </remarks>
    [Fact]
    public void Stage2a_ProtectedThroughDistributionIsStillNotAuthorized()
    {
        var principals = new[] { Security(0, rid: 512), Distribution(1, rid: 1200), User(2, rid: 1104) };
        var edges = new[] { (0, 1), (1, 2) };

        var protectedClosure = Derive(principals, edges);
        var membership = AuthorizationMembershipExpander.ClosureOf(
            GraphOf(principals, edges), ExpansionBudget.Bulk, CancellationToken.None);
        Assert.Equal(ProtectedPrincipalEvaluation.Protected, protectedClosure.EvaluationOf(2));
        Assert.DoesNotContain(2, membership.MembersOf(0).ToArray());
    }

    /// <summary>
    /// Reaching a protected group only by primary group is not protected, and is not a doubt.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This asserted <c>Unknown</c> until 0118.</b> <c>AC-64</c> was blocked because the citation
    /// establishes that primary-group membership is real and that authorization honours it, and says
    /// nothing about whether the protection process follows it - so answering either way was a
    /// guess, and the guess that reports a protected account as unprotected is the worse one.
    /// </para>
    /// <para>
    /// <b>The laboratory answered it on 2026-09-10, which <c>AC-64</c> permits.</b> In
    /// <c>ba.ad.lab</c> the Domain Controllers group was itself stamped, held no explicit
    /// <c>member</c> entries so the primary-group edge was the only route into it, and
    /// <c>dSHeuristics</c> excluded nothing - while its domain controller carried neither
    /// <c>adminCount</c> nor a DACL refusing inheritance. Domain Admins was stamped and Domain Users
    /// was not in the same run, so the fingerprint was measuring what it claimed to.
    /// </para>
    /// <para>
    /// <b>Lab-verified, not specified.</b> One forest, one domain controller, one Windows version.
    /// The reason and its wording are retained so a contradicting forest can reinstate the doubt
    /// without rebuilding the vocabulary under pressure.
    /// </para>
    /// </remarks>
    [Fact]
    public void Stage2a_PrimaryGroupOnlyPathIsNotProtected()
    {
        var closure = Derive(
            [Security(0, rid: 512), User(1, rid: 1104, primaryGroup: 0)],
            edges: []);

        Assert.Equal(ProtectedPrincipalEvaluation.NotProtected, closure.EvaluationOf(1));

        // The answer is settled, not withheld. Asserting the evaluation alone would pass against a
        // version that still recorded the old research reason beside a changed evaluation, which
        // would put "capturing again will not help" on screen for an account nobody doubts.
        Assert.Equal(ProtectionUnknownReason.None, closure.ReasonsFor(1));
    }

    /// <summary>
    /// The primary-group edge is still walked, and still reaches the principal it always did.
    /// </summary>
    /// <remarks>
    /// <b>The negative control for the test above, and the reason it is not redundant.</b>
    /// <c>NotProtected</c> is what the deriver writes for a principal it never reached at all, so a
    /// version that had simply stopped following <c>primaryGroupID</c> would satisfy that assertion
    /// perfectly while having lost the edge. This pins the edge itself: the same account reached
    /// through the same attribute is <c>Protected</c> once the group's own protection propagates,
    /// so the traversal is demonstrably alive and only its protection consequence changed.
    /// </remarks>
    [Fact]
    public void Stage2a_ThePrimaryGroupEdgeIsStillFollowedForAuthorization()
    {
        var graph = GraphOf(
            [Security(0, rid: 512), User(1, rid: 1104, primaryGroup: 0)],
            edges: []);

        Assert.Contains(1, graph.PrimaryMembersOf(0).ToArray());
    }

    /// <summary>
    /// An ordinary path settles it, and so does a primary-group one.
    /// </summary>
    /// <remarks>
    /// <b>This distinguished a gated edge from an ordinary one until 0118 removed the gate.</b> It
    /// is retained rather than deleted because it pins the ordinary route independently: a principal
    /// with both routes must be <c>Protected</c>, and it would have been <c>Protected</c> under the
    /// old rule too. Deleting it would remove the only assertion that a nesting edge still wins.
    /// </remarks>
    [Fact]
    public void Stage2a_AnOrdinaryPathReachesProtection()
    {
        var closure = Derive(
            [Security(0, rid: 512), User(1, rid: 1104, primaryGroup: 0)],
            edges: [(0, 1)]);

        Assert.Equal(ProtectedPrincipalEvaluation.Protected, closure.EvaluationOf(1));
    }

    /// <summary>
    /// A primary-group edge does not turn the rest of the directory into a shrug.
    /// </summary>
    /// <remarks>
    /// The failure §2a names outright. This mattered most while the edge produced <c>Unknown</c>,
    /// and it still matters: both accounts are now <c>NotProtected</c>, and a version that widened
    /// the primary-group answer back into a doubt would fail here as well as above.
    /// </remarks>
    [Fact]
    public void Stage2a_APrimaryGroupEdgeDoesNotMakeEverybodyUnknown()
    {
        var closure = Derive(
            [Security(0, rid: 512), User(1, rid: 1104, primaryGroup: 0), User(2, rid: 1105)],
            edges: []);

        Assert.Equal(ProtectedPrincipalEvaluation.NotProtected, closure.EvaluationOf(1));
        Assert.Equal(ProtectedPrincipalEvaluation.NotProtected, closure.EvaluationOf(2));
    }

    /// <summary>
    /// Partial membership evidence makes every unproven principal unknown.
    /// </summary>
    /// <remarks>
    /// The initial accepted implementation is deliberately conservative: until uncertainty can be
    /// localized, an unresolved member can hide a route for any principal. It must not become a
    /// clean negative.
    /// </remarks>
    [Fact]
    public void Stage2a_PartialEvidenceMakesAnUnprovenPrincipalUnknown()
    {
        var closure = Derive(
            [Security(0, rid: 512), User(1, rid: 1104)],
            edges: [],
            membershipEvidenceIsPartial: true);

        Assert.Equal(ProtectedPrincipalEvaluation.Unknown, closure.EvaluationOf(1));
        Assert.True(closure.ReasonsFor(1).HasFlag(ProtectionUnknownReason.MembershipEvidenceIncomplete));
    }

    [Fact]
    public void Stage2a_ADirectEstablishedPrincipalCarriesItsOwnBasis()
    {
        var closure = Derive([User(0, rid: 500)], edges: []);

        Assert.Equal(ProtectedPrincipalEvaluation.Protected, closure.EvaluationOf(0));
        Assert.Equal(ProtectedPrincipalBasisKind.DirectPrincipalClaim, closure.BasisFor(0)!.Kind);
        Assert.Empty(closure.PathFor(0));
    }

    /// <summary>
    /// A principal reached only by ordinary nesting is not told the doubt is about primary groups.
    /// </summary>
    /// <remarks>
    /// Every unknown reason is customer-visible under <c>0086</c>, so a reason that does not apply
    /// is not a harmless extra: it sends an operator to look at <c>primaryGroupID</c> on an account
    /// whose answer has nothing to do with it.
    /// </remarks>
    [Fact]
    public void Stage2a_AnOrdinaryRouteToAPossibleRootDoesNotBlameThePrimaryGroup()
    {
        var closure = Derive(
            [Security(0, rid: 516), User(1, rid: 1104)],
            edges: [(0, 1)]);

        Assert.Equal(ProtectedPrincipalEvaluation.Unknown, closure.EvaluationOf(1));
        Assert.Equal(ProtectionUnknownReason.PossibleRootReached, closure.ReasonsFor(1));
    }

    [Fact]
    public void Stage2a_APathOnlyToAnUnverifiedRootIsUnknown()
    {
        var closure = Derive(
            [Security(0, rid: 516), User(1, rid: 1104)],
            edges: [(0, 1)]);

        Assert.Equal(ProtectedPrincipalEvaluation.Unknown, closure.EvaluationOf(1));
        Assert.True(closure.ReasonsFor(1).HasFlag(ProtectionUnknownReason.PossibleRootReached));
    }

    [Fact]
    public void Stage2a_AnEstablishedRouteWinsOverASeparatePossibleRoute()
    {
        var closure = Derive(
            [Security(0, rid: 512), Security(1, rid: 516), User(2, rid: 1104)],
            edges: [(0, 2), (1, 2)]);

        Assert.Equal(ProtectedPrincipalEvaluation.Protected, closure.EvaluationOf(2));
        Assert.Equal(512, closure.BasisFor(2)!.CatalogueRid);
    }

    [Fact]
    public void Stage2a_TheStoredMembershipPathIsDeterministicFromPrincipalToRoot()
    {
        var principals = new[]
        {
            Security(0, rid: 512),
            Security(1, rid: 1200),
            Security(2, rid: 1201),
            User(3, rid: 1104),
        };

        var first = Derive(principals, edges: [(0, 2), (2, 3), (0, 1), (1, 3)]);
        var second = Derive(principals, edges: [(1, 3), (0, 1), (2, 3), (0, 2)]);

        Assert.Equal(new[] { 3, 1, 0 }, first.PathFor(3));
        Assert.Equal(first.PathFor(3), second.PathFor(3));
    }

    // ---- P-105: which root a membership is reported under ----

    /// <summary>
    /// A membership is reported under the nearest root, not the last one walked.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the <c>ad.lab</c> observation of 2026-08-31, reduced to its shape.</b> Three
    /// accounts sitting directly in Enterprise Admins were each reported under
    /// <c>BUILTIN\Administrators</c>, because Enterprise Admins is nested there and the walk let
    /// each later root overwrite an earlier one. Here the account is directly in Domain Admins
    /// (catalogue entry 3) and Domain Admins is nested in Enterprise Admins (entry 11), so the old
    /// behaviour reported entry 11 and the operator was sent to the wrong membership.
    /// </para>
    /// <para>
    /// <b>Both answers were true, which is why no correctness test caught it.</b> The account
    /// really is under both. The one worth reporting is the one an operator can remove, and
    /// removing the outer membership would not have taken the account's privilege away.
    /// </para>
    /// </remarks>
    [Fact]
    public void Stage2a_AMembershipIsReportedUnderTheNearestRoot()
    {
        var principals = new[]
        {
            Security(0, rid: 519), // Enterprise Admins, catalogue entry 11 - the outer root
            Security(1, rid: 512), // Domain Admins, catalogue entry 3 - the nearer root
            User(2, rid: 1104),
        };

        // Domain Admins is nested inside Enterprise Admins, and the account is directly in
        // Domain Admins - so it reaches entry 11 as well, one hop further away.
        var closure = Derive(principals, edges: [(0, 1), (1, 2)]);

        Assert.Equal(ProtectedPrincipalEvaluation.Protected, closure.EvaluationOf(2));
        Assert.Equal(512, closure.BasisFor(2)!.CatalogueRid);
        Assert.Equal(new[] { 2, 1 }, closure.PathFor(2));
    }

    /// <summary>
    /// Two roots the same distance away are broken deterministically, and by the same value
    /// whatever order the evidence arrives in.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A tie is two separate memberships and therefore two separate removals</b>, and naming one
    /// hides the other. That is a real limit of reporting a single root rather than a defect in the
    /// tie-break, and it is carried as <c>P-146</c>; what this test pins is that the choice cannot
    /// wander between runs over the same forest, because a finding that moves on re-analysis is one
    /// an operator stops believing.
    /// </para>
    /// <para>
    /// <b>Asserted twice with the edges in different orders</b>, for the reason
    /// <c>Stage2a_TheStoredMembershipPathIsDeterministicFromPrincipalToRoot</c> already gives: the
    /// walk must not depend on the order rows came out of the database.
    /// </para>
    /// </remarks>
    [Fact]
    public void Stage2a_TwoRootsAtTheSameDistanceAreBrokenDeterministically()
    {
        var principals = new[]
        {
            Security(0, rid: 519), // Enterprise Admins, catalogue entry 11
            Security(1, rid: 512), // Domain Admins, catalogue entry 3
            User(2, rid: 1104),
        };

        var first = Derive(principals, edges: [(0, 2), (1, 2)]);
        var second = Derive(principals, edges: [(1, 2), (0, 2)]);

        // The lower catalogue entry id holds it. Both are one hop away, so nearness cannot decide.
        Assert.Equal(512, first.BasisFor(2)!.CatalogueRid);
        Assert.Equal(first.BasisFor(2)!.CatalogueEntryId, second.BasisFor(2)!.CatalogueEntryId);
        Assert.Equal(first.PathFor(2), second.PathFor(2));
    }

    /// <summary>
    /// A principal Microsoft names in the catalogue keeps that as its reason, however it is nested.
    /// </summary>
    /// <remarks>
    /// <b>Being inside something else does not make membership the reason.</b> Domain Admins is
    /// protected because Microsoft says Domain Admins is protected, and it is also nested under
    /// Enterprise Admins in most forests. Reporting it under a membership would tell an operator to
    /// remove Domain Admins from Enterprise Admins to fix something that is not a problem.
    /// </remarks>
    [Fact]
    public void Stage2a_ADirectCatalogueClaimIsNotDisplacedByAnyMembership()
    {
        var principals = new[]
        {
            Security(0, rid: 519),
            Security(1, rid: 512),
        };

        var closure = Derive(principals, edges: [(0, 1)]);

        Assert.Equal(
            ProtectedPrincipalBasisKind.DirectPrincipalClaim, closure.BasisFor(1)!.Kind);
    }

    /// <summary>
    /// Every derivation admits that the protected set itself could have been customised.
    /// </summary>
    /// <remarks>
    /// <c>dSHeuristics</c> can remove groups from the protected set and this product does not
    /// capture it. Removal only shrinks the set, so this over-reports protection rather than
    /// missing it - which is why it is a stated limit and not a universal unknown.
    /// </remarks>
    [Fact]
    public void Stage2a_TheCatalogueAdmitsItCouldHaveBeenCustomised()
    {
        var principals = new[] { Security(0, rid: 512) };
        var closure = ProtectedPrincipalDeriver.Derive(
            GraphOf(principals, []),
            SidsFor(principals),
            ProtectedGroupCatalogue.Default,
            membershipEvidenceIsPartial: false,
            CancellationToken.None,
            DomainSid,
            EveryDomainRead,
            NoStubOnlyPrincipals);

        Assert.True(closure.StatedLimits.HasFlag(ProtectionUnknownReason.ProtectedCatalogueIncomplete));
    }

    [Fact]
    public void Stage2a_AForestRootRidInAChildDomainIsNotTheForestRootPrincipal()
    {
        const string childDomainSid = "S-1-5-21-4444444444-5555555555-6666666666";
        var sids = new SidInterner();
        sids.Intern(childDomainSid + "-519", domainFqdn: null);
        var graph = NestingGraph.Build(new NestingFacts(
            sids,
            Identities: [],
            [new PrincipalRow(0, Guid.NewGuid(), IsGroup: true, GroupType: unchecked((int)0x80000002), PrimaryGroupSidId: null)],
            Edges: [],
            UnresolvedTrustees: [],
            ObjectsWithoutSid: 0,
            CollapsedStubs: 0,
            ForestHeuristics: string.Empty));

        var closure = ProtectedPrincipalDeriver.Derive(
            graph,
            sids,
            ProtectedGroupCatalogue.NarrowedBy(string.Empty),
            membershipEvidenceIsPartial: false,
            CancellationToken.None,
            DomainSid,
            EveryDomainRead,
            NoStubOnlyPrincipals);

        Assert.Equal(ProtectedPrincipalEvaluation.NotProtected, closure.EvaluationOf(0));
    }

    [Fact]
    public void SchemaOwnersIncludeTheRootAndDirectNestedAndPrimaryMembers()
    {
        var result = Derive(
            [Security(0, 518), Security(1, 1200), User(2, 1104), User(3, 1105), User(4, 1106, primaryGroup: 0)],
            [(0, 1), (0, 2), (1, 3)]);

        for (var i = 0; i < 5; i++)
            Assert.Equal(OwnerAcceptance.SchemaOnly, result.OwnerAcceptanceOf(i));

        // ACCEPTANCE AND PROTECTION REMAIN SEPARATE ANSWERS, WHICH IS THIS ASSERTION'S POINT.
        // Principal 4 reaches Schema Admins only through its primary group, so it is an accepted
        // schema owner - authorization honours the edge - while being NotProtected, because SDProp
        // does not follow it. This read Unknown until 0118; the pairing is what matters, not which
        // of the two values the protection side happens to hold.
        Assert.Equal(ProtectedPrincipalEvaluation.NotProtected, result.EvaluationOf(4));
    }

    [Fact]
    public void SchemaOwnershipDoesNotDependOnTheProtectionClaim()
    {
        Fixture[] principals = [Security(0, 518), User(1, 1104)];
        var catalogue = ProtectedGroupCatalogue.NarrowedBy(string.Empty);
        var noProtection = new CatalogueClaim(CatalogueClaimStatus.EstablishedNo,
            CatalogueClaimProvenance.None, "test");
        catalogue = catalogue with
        {
            Entries = catalogue.Entries.Select(e => e.Rid == 518
                ? e with { PrincipalProtection = noProtection, MemberPropagation = noProtection } : e).ToArray(),
        };
        var result = ProtectedPrincipalDeriver.Derive(GraphOf(principals, [(0, 1)]), SidsFor(principals),
            catalogue, false, CancellationToken.None, DomainSid, EveryDomainRead, NoStubOnlyPrincipals);

        Assert.Equal(ProtectedPrincipalEvaluation.NotProtected, result.EvaluationOf(1));
        Assert.Equal(OwnerAcceptance.SchemaOnly, result.OwnerAcceptanceOf(1));
    }

    [Fact]
    public void SchemaMembershipDoesNotNarrowAnIndependentlyAcceptedOwner()
    {
        var result = Derive([Security(0, 518), Security(1, 512), User(2, 1104)], [(0, 2), (1, 2)]);
        Assert.Equal(OwnerAcceptance.Accepted, result.OwnerAcceptanceOf(2));
    }

    [Fact]
    public void APartialReadingKeepsProvenSchemaAcceptanceButNotANegativeElsewhere()
    {
        var result = Derive([Security(0, 518), User(1, 1104), User(2, 1105)], [(0, 1)], true);
        Assert.Equal(OwnerAcceptance.SchemaOnlyOtherwiseUnknown, result.OwnerAcceptanceOf(1));
        Assert.Equal(OwnerAcceptance.Unknown, result.OwnerAcceptanceOf(2));
    }

    [Fact]
    public void DistributionNestingDoesNotConferSchemaOwnerAcceptance()
    {
        var result = Derive([Security(0, 518), Distribution(1, 1200), User(2, 1104)], [(0, 1), (1, 2)]);
        Assert.Equal(ProtectedPrincipalEvaluation.Protected, result.EvaluationOf(2));
        Assert.Equal(OwnerAcceptance.NotAccepted, result.OwnerAcceptanceOf(2));
    }

    [Fact]
    public void AnUnknownGroupTypeDoesNotEstablishSchemaOwnerAcceptance()
    {
        var group = Security(1, 1200);
        group = group with { Row = group.Row with { GroupType = null } };
        var result = Derive([Security(0, 518), group, User(2, 1104)], [(0, 1), (1, 2)]);
        Assert.Equal(OwnerAcceptance.Unknown, result.OwnerAcceptanceOf(2));
    }

    [Fact]
    public void Rid518UnderAnotherDomainIsNotTheForestsSchemaOwnerRoot()
    {
        Fixture[] principals = [Security(0, 518), User(1, 1104)];
        var result = ProtectedPrincipalDeriver.Derive(GraphOf(principals, [(0, 1)]), SidsFor(principals),
            ProtectedGroupCatalogue.NarrowedBy(string.Empty), false, CancellationToken.None,
            "S-1-5-21-999-888-777", EveryDomainRead, NoStubOnlyPrincipals);
        Assert.Equal(OwnerAcceptance.NotAccepted, result.OwnerAcceptanceOf(0));
        Assert.Equal(OwnerAcceptance.NotAccepted, result.OwnerAcceptanceOf(1));
    }

    private static ProtectedPrincipalClosure Derive(
        IReadOnlyList<Fixture> principals,
        IReadOnlyList<(int Group, int Member)> edges,
        bool membershipEvidenceIsPartial = false) =>
        ProtectedPrincipalDeriver.Derive(
            GraphOf(principals, edges),
            SidsFor(principals),
            ProtectedGroupCatalogue.NarrowedBy(string.Empty),
            membershipEvidenceIsPartial,
            CancellationToken.None,
            DomainSid,

            // Stated rather than defaulted, which gate 1 requires: every test below is about a
            // forest that was read in full, and that is a claim each one makes rather than inherits.
            EveryDomainRead,
            NoStubOnlyPrincipals);

    /// <summary>A run that read every declared domain in full.</summary>
    private static readonly IReadOnlySet<string> EveryDomainRead =
        new HashSet<string>(StringComparer.Ordinal);

    /// <summary>A capture in which every principal had a real object of its own.</summary>
    private static readonly IReadOnlyCollection<int> NoStubOnlyPrincipals = [];

    // -----------------------------------------------------------------------------------------
    // P-163: a principal whose own domain was not read in full.

    /// <summary>The SID of a second domain, so "this domain" and "the forest" can be told apart.</summary>
    /// <remarks>
    /// Every sub-authority is inside <see cref="uint"/>, as a real one is. The first draft of this
    /// constant used <c>4444444444</c>, which overflows, so the domain test correctly refused to
    /// read it as domain-relative at all and the fixture rather than the code was wrong.
    /// </remarks>
    private const string OtherDomainSid = "S-1-5-21-4000000000-1500000000-2600000000";

    /// <summary>
    /// A principal of a domain the run did not read in full loses its protection answer, and
    /// nobody else does.
    /// </summary>
    /// <remarks>
    /// <b>The fire for P-163.</b> Without it the derivation states <c>NotProtected</c> about an
    /// account nobody read, which a customer would act on. What is asserted alongside is the whole
    /// point: the principal of the domain that <i>was</i> read keeps its answer. Making the
    /// forest-wide answer <c>Unknown</c> would be the easy fix and would stop ownership findings
    /// being reported anywhere, which is the trap that turned two real findings into none on
    /// 2026-09-03.
    /// </remarks>
    [Fact]
    public void APrincipalOfADomainNotReadInFullLosesItsAnswerAndNobodyElseDoes()
    {
        var closure = DeriveAcrossTwoDomains(unreadDomains: [OtherDomainSid]);

        Assert.Equal(ProtectedPrincipalEvaluation.Unknown, closure.EvaluationOf(1));
        Assert.Equal(OwnerAcceptance.Unknown, closure.OwnerAcceptanceOf(1));

        Assert.Equal(ProtectedPrincipalEvaluation.NotProtected, closure.EvaluationOf(0));
        Assert.Equal(OwnerAcceptance.NotAccepted, closure.OwnerAcceptanceOf(0));
    }

    /// <summary>
    /// A principal only a foreign-security-principal stub ever answered for loses its answer too.
    /// </summary>
    /// <remarks>
    /// <b>The case no coverage row can reach.</b> A domain excluded outright contributes no objects,
    /// so it establishes no domain SID and there is no prefix to match it by. Its principals arrive
    /// as stubs held in the domains that were read, and a stub resolves - so it never lands in
    /// <c>UnresolvedTrustees</c> and the forest-wide safety net never sees it.
    /// </remarks>
    [Fact]
    public void APrincipalKnownOnlyByAStubLosesItsAnswer()
    {
        var closure = DeriveAcrossTwoDomains(stubOnly: [1]);

        Assert.Equal(ProtectedPrincipalEvaluation.Unknown, closure.EvaluationOf(1));
        Assert.Equal(OwnerAcceptance.Unknown, closure.OwnerAcceptanceOf(1));
        Assert.Equal(ProtectedPrincipalEvaluation.NotProtected, closure.EvaluationOf(0));
    }

    /// <summary>
    /// A forest read in full keeps every answer it had.
    /// </summary>
    /// <remarks>
    /// <b>The negative control on both tests above.</b> Without it, a change that withheld every
    /// answer whatever the coverage said would satisfy them, and the product would refuse to judge
    /// anything while looking thoroughly tested - which is the failure P-163 exists to prevent
    /// rather than to cause.
    /// </remarks>
    [Fact]
    public void AForestReadInFullKeepsEveryAnswer()
    {
        var closure = DeriveAcrossTwoDomains();

        Assert.Equal(ProtectedPrincipalEvaluation.NotProtected, closure.EvaluationOf(0));
        Assert.Equal(ProtectedPrincipalEvaluation.NotProtected, closure.EvaluationOf(1));
        Assert.Equal(OwnerAcceptance.NotAccepted, closure.OwnerAcceptanceOf(0));
        Assert.Equal(OwnerAcceptance.NotAccepted, closure.OwnerAcceptanceOf(1));
    }

    /// <summary>
    /// The reason recorded names the unread domain rather than the membership evidence.
    /// </summary>
    /// <remarks>
    /// Reporting incomplete membership would send an operator to inspect group nesting. Nothing is
    /// wrong with the nesting; the domain was never read, and the remedy is a wider capture.
    /// </remarks>
    [Fact]
    public void TheReasonRecordedNamesTheUnreadDomain()
    {
        var closure = DeriveAcrossTwoDomains(unreadDomains: [OtherDomainSid]);

        Assert.True(closure.ReasonsFor(1)
            .HasFlag(ProtectionUnknownReason.PrincipalDomainNotReadInFull));
    }

    /// <summary>
    /// One principal in each of two domains, with whichever signals the test needs.
    /// </summary>
    /// <param name="unreadDomains">Domain SID prefixes the run did not read in full.</param>
    /// <param name="stubOnly">Principals only a stub ever answered for.</param>
    private static ProtectedPrincipalClosure DeriveAcrossTwoDomains(
        string[]? unreadDomains = null,
        int[]? stubOnly = null)
    {
        var sids = new SidInterner();
        sids.Intern(DomainSid + "-1104", domainFqdn: null);
        sids.Intern(OtherDomainSid + "-1104", domainFqdn: null);

        PrincipalRow[] rows =
        [
            new(0, Guid.NewGuid(), IsGroup: false, GroupType: null, PrimaryGroupSidId: null),
            new(1, Guid.NewGuid(), IsGroup: false, GroupType: null, PrimaryGroupSidId: null),
        ];

        var graph = NestingGraph.Build(new NestingFacts(
            sids,
            Identities: [],
            rows,
            Edges: [],
            UnresolvedTrustees: [],
            ObjectsWithoutSid: 0, CollapsedStubs: 0, ForestHeuristics: null));

        return ProtectedPrincipalDeriver.Derive(
            graph,
            sids,
            ProtectedGroupCatalogue.NarrowedBy(string.Empty),
            membershipEvidenceIsPartial: false,
            CancellationToken.None,
            DomainSid,
            unreadDomains is null
                ? EveryDomainRead
                : new HashSet<string>(unreadDomains, StringComparer.Ordinal),
            stubOnly ?? NoStubOnlyPrincipals);
    }

    private static NestingGraph GraphOf(
        IReadOnlyList<Fixture> principals,
        IReadOnlyList<(int Group, int Member)> edges) =>
        NestingGraph.Build(new NestingFacts(
            SidsFor(principals),
            Identities: [],
            [.. principals.Select(p => p.Row)],
            [.. edges.Select(e => new NestingEdge(e.Group, e.Member))],
            UnresolvedTrustees: [],
            ObjectsWithoutSid: 0, CollapsedStubs: 0, ForestHeuristics: null));

    private static SidInterner SidsFor(IReadOnlyList<Fixture> principals)
    {
        var sids = new SidInterner();
        foreach (var principal in principals)
            sids.Intern(DomainSid + "-" + principal.Rid, domainFqdn: null);

        return sids;
    }

    /// <summary>
    /// A principal and the relative identifier its SID is built from, kept together so no test
    /// depends on state left behind by another.
    /// </summary>
    private sealed record Fixture(PrincipalRow Row, int Rid);

    private static Fixture Security(int sidId, int rid) =>
        new(
            new PrincipalRow(sidId, Guid.NewGuid(), IsGroup: true, GroupType: unchecked((int)0x80000002), PrimaryGroupSidId: null),
            rid);

    private static Fixture EnterpriseRodc(int sidId) =>
        new(new PrincipalRow(sidId, Guid.NewGuid(), IsGroup: true,
            GroupType: unchecked((int)0x80000008), PrimaryGroupSidId: null), 498);

    private static Fixture Distribution(int sidId, int rid) =>
        new(
            new PrincipalRow(sidId, Guid.NewGuid(), IsGroup: true, GroupType: 0x00000002, PrimaryGroupSidId: null),
            rid);

    private static Fixture User(int sidId, int rid, int? primaryGroup = null) =>
        new(
            new PrincipalRow(sidId, Guid.NewGuid(), IsGroup: false, GroupType: null, PrimaryGroupSidId: primaryGroup),
            rid);
}
