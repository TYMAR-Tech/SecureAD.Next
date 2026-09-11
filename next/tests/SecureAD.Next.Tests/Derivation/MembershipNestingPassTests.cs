using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

/// <summary>
/// The one pass over a bundle: what it makes of nesting, identity and primary groups.
/// </summary>
/// <remarks>
/// <b>Two of these are about relationships that are invisible to a naive reading.</b> Primary-group
/// membership appears in neither <c>member</c> nor <c>memberOf</c>, and a member named by a
/// distinguished name the capture never covered is a gap rather than an absence of membership.
/// Getting either wrong produces a closure that is quietly short, which no rule resting on it can
/// detect.
/// </remarks>
public sealed class MembershipNestingPassTests
{
    private const string DomainSid = "S-1-5-21-1111111111-2222222222-3333333333";

    /// <summary>
    /// A group's <c>member</c> becomes an edge.
    /// </summary>
    [Fact]
    public void Stage2a_AMemberBecomesAnEdge()
    {
        var facts = Read(
            Group("CN=Domain Admins,DC=x", 512, ["CN=Alice,DC=x"]),
            User("CN=Alice,DC=x", 1104, primaryGroupId: null, memberOf: []));

        var edge = Assert.Single(facts.Edges);
        Assert.Equal(SidOf(facts, 512), facts.Sids.TextOf(edge.GroupSidId));
        Assert.Equal(SidOf(facts, 1104), facts.Sids.TextOf(edge.MemberSidId));
    }

    /// <summary>
    /// An account's <c>memberOf</c> describes the same relationship and produces the same edge.
    /// </summary>
    [Fact]
    public void Stage2a_MemberOfProducesTheSameEdgeAsMember()
    {
        var facts = Read(
            Group("CN=Domain Admins,DC=x", 512, []),
            User("CN=Alice,DC=x", 1104, primaryGroupId: null, memberOf: ["CN=Domain Admins,DC=x"]));

        var edge = Assert.Single(facts.Edges);
        Assert.Equal(SidOf(facts, 512), facts.Sids.TextOf(edge.GroupSidId));
        Assert.Equal(SidOf(facts, 1104), facts.Sids.TextOf(edge.MemberSidId));
    }

    /// <summary>
    /// A member named before its object is streamed still resolves.
    /// </summary>
    /// <remarks>
    /// The reason edges are resolved after the pass rather than during it. Streaming order is the
    /// bundle's, not the graph's.
    /// </remarks>
    [Fact]
    public void Stage2a_AForwardReferenceStillResolves()
    {
        var facts = Read(
            Group("CN=Domain Admins,DC=x", 512, ["CN=Alice,DC=x"]),
            User("CN=Alice,DC=x", 1104, primaryGroupId: null, memberOf: []));

        Assert.Single(facts.Edges);
        Assert.Empty(facts.UnresolvedTrustees);
    }

    /// <summary>
    /// Where both ends of a link are unidentifiable, both names are recorded.
    /// </summary>
    /// <remarks>
    /// <b>The fire for P-185.</b> The resolution loop used to stop at the group end, so the member's
    /// name never reached the forest-wide list and the coverage the run prints and stores was short
    /// by an unknown amount. The case is reachable: a group whose own <c>objectSid</c> was withheld
    /// or never captured has no identity to resolve to, and the members it lists may be uncaptured
    /// as well.
    /// </remarks>
    [Fact]
    public void Stage2a_BothEndsOfAnUnidentifiableLinkAreRecorded()
    {
        var facts = Read(
            Object(
                "CN=Unreadable,DC=ad,DC=lab",
                [
                    Text("objectClass", AttributeCardinality.MultiValued, ["top", "group"]),
                    Text("member", AttributeCardinality.MultiValued, ["CN=Ghost,DC=elsewhere"]),
                ]));

        Assert.Equal(
            ["CN=Ghost,DC=elsewhere", "CN=Unreadable,DC=ad,DC=lab"],
            facts.UnresolvedTrustees.OrderBy(n => n, StringComparer.Ordinal));
    }

    /// <summary>
    /// Neither end resolving leaves no principal to attribute the link to, and none is invented.
    /// </summary>
    /// <remarks>
    /// <b>The negative control on the fix above, and it guards P-164 rather than P-185.</b> The
    /// per-group attribution exists so a group can be marked short by evidence about itself; a link
    /// with no surviving end names no such group, and inventing one would mark the wrong object
    /// incomplete.
    /// </remarks>
    [Fact]
    public void Stage2a_ALinkWithNeitherEndResolvedIsAttributedToNobody()
    {
        var facts = Read(
            Object(
                "CN=Unreadable,DC=ad,DC=lab",
                [
                    Text("objectClass", AttributeCardinality.MultiValued, ["top", "group"]),
                    Text("member", AttributeCardinality.MultiValued, ["CN=Ghost,DC=elsewhere"]),
                ]));

        Assert.Empty(facts.UnresolvedLinks);
        Assert.Equal(0, facts.GroupsWithUnidentifiedMembers);
    }

    /// <summary>
    /// A member the capture never covered is recorded as unresolved, not dropped.
    /// </summary>
    [Fact]
    public void Stage2a_AMemberOutsideTheCaptureIsRecordedAsUnresolved()
    {
        var facts = Read(
            Group("CN=Domain Admins,DC=x", 512, ["CN=Ghost,DC=elsewhere"]));

        Assert.Empty(facts.Edges);
        Assert.Equal("CN=Ghost,DC=elsewhere", Assert.Single(facts.UnresolvedTrustees));
    }

    /// <summary>
    /// The group that claimed an unidentifiable member keeps a record of having claimed it.
    /// </summary>
    /// <remarks>
    /// <b>The fire for P-164.</b> Before this the link was dropped and nothing above the pass could
    /// tell a group whose members could not be identified from a group with none, so the LAPS rules
    /// reported such machines clean. The forest-wide list asserted in the test above is not enough
    /// on its own: it says some name somewhere went unmatched, which in a nine-domain forest is
    /// almost always true and would silence judging everywhere if read as an answer about any one
    /// group.
    /// </remarks>
    [Fact]
    public void Stage2a_AnUnidentifiableMemberIsAttributedToTheGroupThatClaimedIt()
    {
        var facts = Read(
            Group("CN=Domain Admins,DC=x", 512, ["CN=Ghost,DC=elsewhere"]));

        var link = Assert.Single(facts.UnresolvedLinks);

        Assert.Equal(NestingLinkDirection.Member, link.Direction);
        Assert.Equal("CN=Ghost,DC=elsewhere", link.DistinguishedName);
        Assert.Equal(SidOf(facts, 512), facts.Sids.InIdOrder().ElementAt(link.SidId));
    }

    /// <summary>
    /// A group named by a member's <c>memberOf</c> that nothing answers to is attributed to the
    /// member, in the other direction.
    /// </summary>
    /// <remarks>
    /// <b>The asymmetry P-164 asks to preserve.</b> This thins what <i>contains</i> the account,
    /// not what is inside it, so recording it in the same direction as the test above would let an
    /// expansion mark a group short on the strength of evidence about something else entirely.
    /// </remarks>
    [Fact]
    public void Stage2a_AnUnidentifiableContainingGroupIsAttributedToTheMember()
    {
        var facts = Read(
            User("CN=Alice,DC=x", 1104, primaryGroupId: null, memberOf: ["CN=Gone,DC=elsewhere"]));

        var link = Assert.Single(facts.UnresolvedLinks);

        Assert.Equal(NestingLinkDirection.ContainingGroup, link.Direction);
        Assert.Equal("CN=Gone,DC=elsewhere", link.DistinguishedName);
        Assert.Equal(SidOf(facts, 1104), facts.Sids.InIdOrder().ElementAt(link.SidId));
    }

    /// <summary>
    /// Where both ends of a membership resolve, nothing is recorded as unidentified.
    /// </summary>
    /// <remarks>
    /// <b>The negative control.</b> A guard that fired on every membership would mark the whole
    /// forest incomplete and silence judging, which is the failure P-164 warns is worse than the
    /// defect it fixes.
    /// </remarks>
    [Fact]
    public void Stage2a_AMembershipThatResolvesRecordsNoUnidentifiedLink()
    {
        var facts = Read(
            Group("CN=Domain Admins,DC=x", 512, ["CN=Alice,DC=x"]),
            User("CN=Alice,DC=x", 1104, primaryGroupId: null, memberOf: []));

        Assert.Single(facts.Edges);
        Assert.Empty(facts.UnresolvedLinks);
        Assert.Equal(0, facts.GroupsWithUnidentifiedMembers);
    }

    /// <summary>
    /// The count is of groups, not of the names they could not identify.
    /// </summary>
    /// <remarks>
    /// What an operator needs from the run log and the dashboard is how many answers are short. One
    /// group missing three members is one group whose membership cannot be vouched for, and
    /// counting the names would make a single badly-covered group read as a wider problem.
    /// </remarks>
    [Fact]
    public void Stage2a_TheUnidentifiedCountIsOfGroupsRatherThanNames()
    {
        var facts = Read(
            Group("CN=Domain Admins,DC=x", 512,
                ["CN=One,DC=elsewhere", "CN=Two,DC=elsewhere", "CN=Three,DC=elsewhere"]));

        Assert.Equal(3, facts.UnresolvedLinks.Count);
        Assert.Equal(1, facts.GroupsWithUnidentifiedMembers);
    }

    /// <summary>
    /// Primary-group membership is read, though it appears in neither <c>member</c> nor
    /// <c>memberOf</c>.
    /// </summary>
    /// <remarks>
    /// The relationship a naive traversal loses. An account whose primary group is a privileged one
    /// has no backlink anywhere to give it away.
    /// </remarks>
    [Fact]
    public void Stage2a_PrimaryGroupMembershipIsRead()
    {
        var facts = Read(
            User("CN=Alice,DC=x", 1104, primaryGroupId: 512, memberOf: []));

        var alice = Assert.Single(facts.Principals);
        Assert.NotNull(alice.PrimaryGroupSidId);
        Assert.Equal(SidOf(facts, 512), facts.Sids.TextOf(alice.PrimaryGroupSidId!.Value));
    }

    /// <summary>
    /// Primary-group membership is not an edge.
    /// </summary>
    /// <remarks>
    /// Nearly every account names Domain Users, so materialising these would add one edge per
    /// account, all pointing at the largest group in the domain.
    /// </remarks>
    [Fact]
    public void Stage2a_PrimaryGroupMembershipIsNotAnEdge()
    {
        var facts = Read(
            User("CN=Alice,DC=x", 1104, primaryGroupId: 513, memberOf: []));

        Assert.Empty(facts.Edges);
    }

    /// <summary>
    /// SIDHistory becomes another identity for the same principal.
    /// </summary>
    [Fact]
    public void Stage2a_SidHistoryBecomesAnotherIdentity()
    {
        var old = "S-1-5-21-999999999-888888888-777777777-1104";
        var facts = Read(
            User("CN=Alice,DC=x", 1104, primaryGroupId: null, memberOf: [], sidHistory: [old]));

        var history = Assert.Single(facts.Identities, i => i.Kind == SidIdentityKind.History);
        Assert.Equal(old, facts.Sids.TextOf(history.SidId));
        Assert.Equal(SidOf(facts, 1104), facts.Sids.TextOf(history.PrincipalSidId));
    }

    /// <summary>
    /// SIDHistory is never a membership edge.
    /// </summary>
    /// <remarks>
    /// It is an identity the principal carries, not a group it is in. Treated as an edge, a closure
    /// would walk through it and report memberships nobody has.
    /// </remarks>
    [Fact]
    public void Stage2a_SidHistoryIsNotAnEdge()
    {
        var facts = Read(
            User(
                "CN=Alice,DC=x",
                1104,
                primaryGroupId: null,
                memberOf: [],
                sidHistory: ["S-1-5-21-999999999-888888888-777777777-1104"]));

        Assert.Empty(facts.Edges);
    }

    /// <summary>
    /// A group whose <c>groupType</c> was not captured has a type nobody knows, not a false one.
    /// </summary>
    [Fact]
    public void Stage2a_AnUncapturedGroupTypeIsUnknownRatherThanDistribution()
    {
        Assert.Null(MembershipNestingPass.IsSecurityEnabled(null));
        Assert.True(MembershipNestingPass.IsSecurityEnabled(unchecked((int)0x80000002)));
        Assert.False(MembershipNestingPass.IsSecurityEnabled(0x00000002));
    }

    /// <summary>
    /// An object with no SID is counted rather than ignored.
    /// </summary>
    [Fact]
    public void Stage2a_AnObjectWithoutASidIsCounted()
    {
        var facts = Read(Container("OU=People,DC=x"));

        Assert.Equal(1, facts.ObjectsWithoutSid);
        Assert.Empty(facts.Principals);
    }

    /// <summary>
    /// Every domain's copy of a built-in group is a principal of its own, and their memberships do
    /// not run together.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the defect that ended the first multi-domain derivation.</b> A three-domain lab
    /// forest carried 84 objects sharing a built-in SID, and keying them by SID alone unioned the
    /// members of every domain's <c>BUILTIN\Administrators</c> into one set - so the forest root's
    /// Administrators appeared to contain the child domains' Domain Admins. An audit tool inventing
    /// a cross-domain privilege path is the one failure this product exists to prevent.
    /// </para>
    /// <para>
    /// Microsoft's <i>Security identifiers</i> is explicit that the built-in domain is "local in
    /// scope". See <c>docs/decisions/0087-a-sid-is-unique-within-its-scope.md</c>.
    /// </para>
    /// </remarks>
    [Fact]
    public void EachDomainsBuiltinGroupIsAPrincipalOfItsOwn()
    {
        var facts = Read(
            BuiltinAdministrators("ad.lab", "CN=Administrators,CN=Builtin,DC=ad,DC=lab", "CN=Root Admin,DC=ad,DC=lab"),
            User("CN=Root Admin,DC=ad,DC=lab", 500, primaryGroupId: null, memberOf: []),
            BuiltinAdministrators("ba.ad.lab", "CN=Administrators,CN=Builtin,DC=ba,DC=ad,DC=lab", "CN=Child Admin,DC=ba,DC=ad,DC=lab"),
            User("CN=Child Admin,DC=ba,DC=ad,DC=lab", 1001, primaryGroupId: null, memberOf: []));

        var administrators = facts.Principals
            .Where(p => string.Equals(facts.Sids.TextOf(p.SidId), BuiltinAdministratorsSid, StringComparison.Ordinal))
            .ToList();

        Assert.Equal(2, administrators.Count);

        // The membership of one must not contain the other domain's account.
        var rootAdministrators = administrators.Single(
            p => facts.Sids.ScopeOf(p.SidId) == "ad.lab");

        var membersOfRoot = facts.Edges
            .Where(e => e.GroupSidId == rootAdministrators.SidId)
            .Select(e => facts.Sids.TextOf(e.MemberSidId))
            .ToList();

        Assert.Equal([DomainSid + "-500"], membersOfRoot);
    }

    /// <summary>
    /// One SID captured in several places is one principal, not several rows.
    /// </summary>
    /// <remarks>
    /// <b>A universal well-known SID is held once in the configuration partition and again as a
    /// stub in every domain.</b> Four objects for <c>S-1-5-11</c> in a three-domain forest, all the
    /// same principal - and a row per object is what raised
    /// <c>UNIQUE constraint failed: sid_identity.sid_id</c> on the first real capture. Scoping
    /// alone does not fix this one, because a well-known SID is deliberately not scoped.
    /// </remarks>
    [Fact]
    public void OneSidCapturedInSeveralPlacesIsOnePrincipal()
    {
        var facts = Read(
            ForeignSecurityPrincipal("ad.lab", "CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=ad,DC=lab"),
            ForeignSecurityPrincipal("ba.ad.lab", "CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=ba,DC=ad,DC=lab"),
            ForeignSecurityPrincipal("ph.ad.lab", "CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=ph,DC=ad,DC=lab"));

        Assert.Single(facts.Identities);
        Assert.Single(facts.Principals);

        // The two that were folded are counted rather than passed over.
        Assert.Equal(2, facts.CollapsedStubs);
    }

    /// <summary>
    /// A real object beats a stub standing in for it, so the facts kept are the ones worth having.
    /// </summary>
    /// <remarks>
    /// A <c>foreignSecurityPrincipal</c> carries no <c>objectClass</c> of its own worth reading, no
    /// <c>groupType</c> and no useful GUID. Where both were captured, keeping the stub's row would
    /// lose the real object's - and a group recorded as not being a group takes part in no closure.
    /// </remarks>
    [Fact]
    public void ARealObjectBeatsAStubStandingInForIt()
    {
        var facts = Read(
            ForeignSecurityPrincipal("ba.ad.lab", "CN=" + DomainSid + "-512,CN=ForeignSecurityPrincipals,DC=ba,DC=ad,DC=lab", DomainSid + "-512"),
            Group("CN=Domain Admins,DC=ad,DC=lab", 512, []));

        var domainAdmins = Assert.Single(facts.Principals);

        Assert.True(domainAdmins.IsGroup);
        Assert.Equal(1, facts.CollapsedStubs);
    }

    /// <summary>
    /// A built-in SID with no domain to scope it by is counted rather than passed over.
    /// </summary>
    /// <remarks>
    /// It cannot be told apart from the same SID elsewhere in the forest, so it is interned as it
    /// was before <c>0087</c> - and the count is what stops that reading as a clean result. A
    /// derivation reporting none of these and one that never looked are different facts.
    /// </remarks>
    [Fact]
    public void ABuiltinSidWithNoDomainIsCounted()
    {
        var facts = Read(
            BuiltinAdministrators(domainFqdn: null, "CN=Administrators,CN=Builtin,DC=ad,DC=lab", "CN=A,DC=ad,DC=lab"));

        Assert.Equal(1, facts.Sids.UnscopedBuiltins);
    }

    private const string BuiltinAdministratorsSid = "S-1-5-32-544";

    /// <summary>
    /// A domain's own principals establish the SID that domain's identifiers are prefixed with.
    /// </summary>
    /// <remarks>
    /// <b>What lets an unresolvable identifier be attributed to a domain at all.</b> There is no
    /// single object to read this from - the domain object carrying the bare domain SID is not
    /// among the classes this product captures, confirmed against the sealed <c>ad.lab</c> bundle
    /// of 2026-09-04 - so it comes from the ordinary principals that share it.
    /// </remarks>
    [Fact]
    public void ADomainsOwnPrincipalsEstablishItsDomainSid()
    {
        var facts = Read(
            Group("CN=Readers,DC=ad,DC=lab", 1101, []),
            User("CN=Alice,DC=ad,DC=lab", 1102, primaryGroupId: null, memberOf: []));

        Assert.Equal(DomainSid, facts.DomainSidsByFqdn["ad.lab"]);
    }

    /// <summary>
    /// A stub standing in for a foreign principal does not speak for the domain holding it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The negative control on the domain SID map, and the one way it could attribute a whole
    /// range of identifiers to the wrong domain.</b> A <c>foreignSecurityPrincipal</c> lives in one
    /// domain and carries an identifier issued by another. Letting it establish the prefix would
    /// give this domain its neighbour's SID - and then every unresolvable identifier of that
    /// neighbour would be judged against the wrong domain's coverage, which is how a delegation in
    /// an unread domain would come to be reported as inert.
    /// </para>
    /// <para>
    /// The stub here carries a different domain's prefix from every real object beside it, so a
    /// pass that counted stubs would either record the wrong SID or record a conflict and drop the
    /// domain. Both are wrong and this asserts the right answer rather than merely a safe one.
    /// </para>
    /// </remarks>
    [Fact]
    public void AStubDoesNotEstablishTheDomainSidOfTheDomainHoldingIt()
    {
        const string foreignSid = "S-1-5-21-7-7-7-1234";

        var facts = Read(
            Group("CN=Readers,DC=ad,DC=lab", 1101, []),
            ForeignSecurityPrincipal(
                "ad.lab",
                "CN=" + foreignSid + ",CN=ForeignSecurityPrincipals,DC=ad,DC=lab",
                foreignSid));

        Assert.Equal(DomainSid, facts.DomainSidsByFqdn["ad.lab"]);
    }

    /// <summary>
    /// A domain whose own principals disagree about its SID is left out rather than resolved.
    /// </summary>
    /// <remarks>
    /// <b>Refusing beats guessing here, and a majority vote would always produce an answer.</b> A
    /// domain absent from the map makes every unresolvable identifier of it stay unknown, which is
    /// the behaviour that existed before this product could tell an orphan from a gap. Electing a
    /// winner would instead conclude absence from evidence that contradicts itself, and the way
    /// that fails is by reporting a live delegation as harmless.
    /// </remarks>
    [Fact]
    public void ADomainWhosePrincipalsDisagreeAboutItsSidIsLeftOut()
    {
        var facts = Read(
            Group("CN=Readers,DC=ad,DC=lab", 1101, []),
            Object(
                "CN=Odd,DC=ad,DC=lab",
                [
                    Binary("objectSid", SidBytes("S-1-5-21-4-5-6-1102")),
                    Text("objectClass", AttributeCardinality.MultiValued, ["top", "group"]),
                ]));

        Assert.False(facts.DomainSidsByFqdn.ContainsKey("ad.lab"));
    }

    /// <summary>
    /// A principal only a stub ever answered for is recorded as one whose own domain went unread.
    /// </summary>
    /// <remarks>
    /// <b>The signal P-163 uses where no coverage row can help.</b> A domain excluded outright
    /// contributes no objects, so it establishes no domain SID and cannot be matched by prefix - but
    /// its principals still reach the graph through stubs held in the domains that were read, and a
    /// stub resolves, so it never lands in <see cref="NestingFacts.UnresolvedTrustees"/>. Without
    /// this the protection derivation states <c>NotProtected</c> about it.
    /// </remarks>
    [Fact]
    public void Stage2a_APrincipalOnlyAStubAnsweredForIsRecordedAsSuch()
    {
        var facts = Read(
            ForeignSecurityPrincipal("ad.lab", "CN=S-1-5-21-9-9-9-1500,CN=ForeignSecurityPrincipals,DC=ad,DC=lab",
                sid: "S-1-5-21-9-9-9-1500"));

        var sidId = Assert.Single(facts.StubOnlyPrincipals);
        Assert.Equal("S-1-5-21-9-9-9-1500", facts.Sids.InIdOrder().ElementAt(sidId));
    }

    /// <summary>
    /// A real object displaces the stub standing in for it, so nothing is recorded.
    /// </summary>
    /// <remarks>
    /// <b>The negative control.</b> A stub exists for a principal whose domain <i>was</i> read
    /// whenever that principal is referenced across a trust, so a signal that fired on every stub
    /// would withhold answers for principals nothing is missing about.
    /// </remarks>
    [Fact]
    public void Stage2a_AStubDisplacedByItsRealObjectIsNotRecorded()
    {
        var facts = Read(
            ForeignSecurityPrincipal("other.lab", "CN=S-1-5-21-1-2-3-1104,CN=ForeignSecurityPrincipals,DC=other,DC=lab",
                sid: DomainSid + "-1104"),
            User("CN=Alice,DC=ad,DC=lab", 1104, primaryGroupId: null, memberOf: []));

        Assert.Empty(facts.StubOnlyPrincipals);
    }

    /// <summary>
    /// A well-known identifier held only as a stub is not treated as an unread domain's principal.
    /// </summary>
    /// <remarks>
    /// <b>The filter that keeps this from firing across the forest.</b> A universal well-known
    /// identifier is held once in the configuration partition and again as a stub in every domain,
    /// so an ordinary capture can leave one stub-only. It belongs to no domain, so there is no
    /// domain of its own to have gone unread, and withholding the answer for <i>Authenticated
    /// Users</i> would silence a principal nothing is actually missing about.
    /// </remarks>
    [Fact]
    public void Stage2a_AWellKnownIdentifierHeldOnlyAsAStubIsNotRecorded()
    {
        var facts = Read(
            ForeignSecurityPrincipal("ad.lab", "CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=ad,DC=lab"));

        Assert.Empty(facts.StubOnlyPrincipals);
    }

    /// <summary>One domain's <c>BUILTIN\Administrators</c>, holding one member.</summary>
    private static ObjectAttributes BuiltinAdministrators(
        string? domainFqdn, string dn, string memberDn) =>
        Object(
            dn,
            [
                Binary("objectSid", SidBytes(BuiltinAdministratorsSid)),
                Text("objectClass", AttributeCardinality.MultiValued, ["top", "group"]),
                Text("groupType", AttributeCardinality.SingleValued, [unchecked((int)0x80000004).ToString()]),
                Text("member", AttributeCardinality.MultiValued, [memberDn]),
            ],
            domainFqdn);

    /// <summary>A stub standing in for a principal from somewhere else.</summary>
    private static ObjectAttributes ForeignSecurityPrincipal(
        string domainFqdn, string dn, string sid = "S-1-5-11") =>
        Object(
            dn,
            [
                Binary("objectSid", SidBytes(sid)),
                Text("objectClass", AttributeCardinality.MultiValued, ["top", "foreignSecurityPrincipal"]),
            ],
            domainFqdn);

    private static NestingFacts Read(params ObjectAttributes[] objects) =>
        MembershipNestingPass.Read(objects, "example.com", CancellationToken.None);

    private static string SidOf(NestingFacts facts, int rid) =>
        DomainSid + "-" + rid;

    private static ObjectAttributes Group(string dn, int rid, IReadOnlyList<string> members)
    {
        var attributes = new List<ObjectAttribute>
        {
            Binary("objectSid", SidBytes(DomainSid + "-" + rid)),
            Text("objectClass", AttributeCardinality.MultiValued, ["top", "group"]),
            Text("groupType", AttributeCardinality.SingleValued, [unchecked((int)0x80000002).ToString()]),
        };

        if (members.Count > 0)
            attributes.Add(Text("member", AttributeCardinality.MultiValued, members));

        return Object(dn, attributes);
    }

    private static ObjectAttributes User(
        string dn,
        int rid,
        int? primaryGroupId,
        IReadOnlyList<string> memberOf,
        IReadOnlyList<string>? sidHistory = null)
    {
        var attributes = new List<ObjectAttribute>
        {
            Binary("objectSid", SidBytes(DomainSid + "-" + rid)),
            Text("objectClass", AttributeCardinality.MultiValued, ["top", "person", "user"]),
        };

        if (primaryGroupId is not null)
        {
            attributes.Add(Text(
                "primaryGroupID", AttributeCardinality.SingleValued, [primaryGroupId.Value.ToString()]));
        }

        if (memberOf.Count > 0)
            attributes.Add(Text("memberOf", AttributeCardinality.MultiValued, memberOf));

        if (sidHistory is { Count: > 0 })
        {
            attributes.Add(new ObjectAttribute(
                "sIDHistory",
                AttributeCardinality.MultiValued,
                [.. sidHistory.Select((s, i) => new AttributeValue(i, null, SidBytes(s)))]));
        }

        return Object(dn, attributes);
    }

    private static ObjectAttributes Container(string dn) =>
        Object(dn, [Text("objectClass", AttributeCardinality.MultiValued, ["top", "organizationalUnit"])]);

    /// <summary>
    /// One captured object, from <paramref name="domainFqdn"/>.
    /// </summary>
    /// <remarks>
    /// The domain is defaulted because most tests here are about nesting rather than scope, and
    /// naming one in every call would bury what each test is actually saying. The tests that turn
    /// on scope pass it explicitly.
    /// </remarks>
    private static ObjectAttributes Object(
        string dn,
        IReadOnlyList<ObjectAttribute> attributes,
        string? domainFqdn = "ad.lab") =>
        new(dn, Guid.NewGuid(), DateTimeOffset.UnixEpoch, EvidenceCompleteness.Complete, attributes, domainFqdn);

    private static ObjectAttribute Text(
        string name, AttributeCardinality cardinality, IReadOnlyList<string> values) =>
        new(name, cardinality, [.. values.Select((v, i) => new AttributeValue(i, v, null))]);

    private static ObjectAttribute Binary(string name, byte[] bytes) =>
        new(name, AttributeCardinality.SingleValued, [new AttributeValue(0, null, bytes)]);

    /// <summary>
    /// Encodes a SID for a fixture, refusing one the encoder will not accept.
    /// </summary>
    /// <remarks>
    /// Without this a fixture SID with a sub-authority too large for a 32-bit unsigned value
    /// silently becomes a value carrying no bytes, and the test fails as though the pass had
    /// dropped it. That is a fixture defect wearing a product defect's clothes, and it cost a
    /// debugging cycle before this helper existed.
    /// </remarks>
    private static byte[] SidBytes(string text) =>
        Sid.ToBytes(text)
        ?? throw new InvalidOperationException(
            $"'{text}' is not a SID this product will encode, so it cannot stand in for one in a "
            + "fixture. Sub-authorities must fit in a 32-bit unsigned value.");
}
