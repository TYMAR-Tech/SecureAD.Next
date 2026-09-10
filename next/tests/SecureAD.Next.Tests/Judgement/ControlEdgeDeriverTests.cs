using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class ControlEdgeDeriverTests
{
    internal const string Holder = "S-1-5-21-1-2-3-1200";
    internal static ObjectAttributes Subject => new("OU=Test,DC=contoso,DC=com", Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        DateTimeOffset.UnixEpoch, default,
        [new("objectClass", AttributeCardinality.MultiValued, [new(0, "organizationalUnit", null)])], "contoso.com");
    internal static PermissionEntry Ace(int ordinal, string sid, int mask, string type = "AccessAllowed", byte propagation = 0) =>
        new(ordinal, type, new(sid, sid, "CN=Holder,DC=contoso,DC=com", "contoso.com", null, null, null),
            mask, null, null, false, 0, propagation, false, false, []);
    internal static ObjectPermissions Permissions(params PermissionEntry[] entries) => new(Subject.DistinguishedName,
        DescriptorAvailability.Read, null, null, DaclState.Present, DaclCompleteness.Complete, true, false, entries, []);
    internal static ControlObjectEvaluation Derive(ObjectPermissions? permissions) => ControlEdgeDeriver.Derive(Subject, permissions,
        JudgingContext.At(DateTimeOffset.UnixEpoch) with { ForestFqdn = "contoso.com" }, Guid.Empty, null, DomainSid);

    /// <summary>
    /// Derives the control edges and then the owner transitions, the way a run does.
    /// </summary>
    /// <remarks>
    /// <see cref="ControlEdgeDeriver"/> does not produce the compound takeover edge; it is derived
    /// afterwards by <see cref="OwnershipAuditRun"/> from each stored <c>CanSetOwner</c> edge, and
    /// only for objects discovery admitted under decision 0114. Tests about how that edge is stored,
    /// counted and presented need a fixture that reaches it the same way, rather than through a
    /// deriver flag no production caller selected - which is what they used until 2026-09-11.
    /// </remarks>
    internal static ControlObjectEvaluation DeriveWithTransitions(ObjectPermissions permissions) =>
        DeriveWithTransitions(Subject, permissions);

    /// <inheritdoc cref="DeriveWithTransitions(ObjectPermissions)"/>
    internal static ControlObjectEvaluation DeriveWithTransitions(ObjectAttributes subject, ObjectPermissions permissions)
    {
        var context = JudgingContext.At(DateTimeOffset.UnixEpoch) with { ForestFqdn = "contoso.com" };
        var evaluation = ControlEdgeDeriver.Derive(subject, permissions, context, Guid.Empty, null, DomainSid);
        var transitions = evaluation.Edges.Where(edge => edge.Capability == ControlCapability.CanSetOwner)
            .Select(edge => OwnershipControlDeriver.Transition(edge, subject, permissions, context,
                permissions.Entries.First(entry => entry.Trustee.Sid == edge.HolderSid).Trustee, DomainSid));
        return evaluation with { Edges = [.. evaluation.Edges, .. transitions] };
    }

    internal static string? DomainSid(string domain) => domain == "contoso.com" ? "S-1-5-21-1-2-3" : null;

    [Theory]
    [InlineData("DC=contoso,DC=com", "contoso.com", "contoso.com", true, true)]
    [InlineData("OU=Test,DC=contoso,DC=com", "contoso.com", "contoso.com", true, true)]
    [InlineData("CN=Configuration,DC=contoso,DC=com", "contoso.com", "contoso.com", true, false)]
    [InlineData("CN=Schema,CN=Configuration,DC=contoso,DC=com", "contoso.com", "contoso.com", true, false)]
    [InlineData("DC=DomainDnsZones,DC=contoso,DC=com", "contoso.com", "contoso.com", true, false)]
    [InlineData("DC=DomainDnsZones,DC=contoso,DC=com", "DomainDnsZones.contoso.com", "contoso.com", true, false)]
    [InlineData("OU=Test,DC=other,DC=com", "contoso.com", "contoso.com", true, false)]
    [InlineData("OU=Test,DC=contoso,DC=com", "contoso.com", null, true, false)]
    [InlineData("OU=Test,DC=contoso,DC=com", null, "contoso.com", true, false)]
    [InlineData("OU=Test,DC=contoso,DC=com", "contoso.com", "contoso.com", false, false)]
    public void DomainlessBuiltinAdministratorsRequiresVerifiedTargetDomain(string dn, string? domain, string? forest, bool rootCaptured, bool expected)
    {
        var holder = new PermissionTrustee("S-1-5-32-544", "BUILTIN\\Administrators", null, null, null, WellKnownSidRole.Principal, null);
        var result = ControlEdgeDeriver.Expected(holder, Subject with { DistinguishedName = dn, DomainFqdn = domain },
            forest, new([], MembershipRouteIncompleteReason.None), true, true, name => rootCaptured ? DomainSid(name) : null);
        Assert.Equal(expected ? ControlExpectedness.Expected : ControlExpectedness.Unknown, result.State);
        Assert.Equal(expected ? ControlExpectednessReason.ExpectedSameDomainControlPlane : ControlExpectednessReason.UnknownAuthorityScope, result.Reason);
    }

    [Fact]
    public void BuiltinMembershipRootDoesNotAdoptTheTargetsDomain()
    {
        var member = new MembershipRoutePrincipal(Holder, null, "CN=Holder,DC=contoso,DC=com");
        var root = new MembershipRoutePrincipal("S-1-5-32-544", "child.contoso.com", "CN=Administrators,CN=Builtin,DC=child,DC=contoso,DC=com");
        var route = new MembershipRoute(544, "Administrators", MembershipRouteAuthorization.SecurityEnabled, false, [new(member, false), new(root, false)]);
        var routes = new MembershipRouteSummary([new(root, [route], MembershipRouteIncompleteReason.None)], MembershipRouteIncompleteReason.None);
        var result = ControlEdgeDeriver.Expected(Ace(0, Holder, 0x40000).Trustee, Subject, "contoso.com", routes, true, true, DomainSid);
        Assert.Equal(ControlExpectedness.Unexpected, result.State);
    }

    [Theory]
    [InlineData("S-1-5-21-1-2-3-500", "OU=Test,DC=contoso,DC=com", true)]
    [InlineData("S-1-5-21-1-2-3-512", "OU=Test,DC=contoso,DC=com", true)]
    [InlineData("S-1-5-21-1-2-3-519", "CN=Configuration,DC=contoso,DC=com", true)]
    [InlineData("S-1-5-21-1-2-3-518", "CN=Schema,CN=Configuration,DC=contoso,DC=com", true)]
    [InlineData("S-1-5-21-1-2-3-518", "OU=Test,DC=contoso,DC=com", false)]
    [InlineData("S-1-5-21-9-9-9-518", "CN=Schema,CN=Configuration,DC=contoso,DC=com", false)]
    public void ExpectednessHonorsIndependentAuthorityScopes(string sid, string dn, bool expected)
    {
        var result = ControlEdgeDeriver.Expected(Ace(0, sid, 0x40000).Trustee, Subject with { DistinguishedName = dn },
            "contoso.com", new([], MembershipRouteIncompleteReason.None), true, true, DomainSid);
        Assert.Equal(expected, result.State == ControlExpectedness.Expected);
    }

    [Theory]
    [InlineData(MembershipRouteAuthorization.SecurityEnabled, true)]
    [InlineData(MembershipRouteAuthorization.DistributionGroup, false)]
    [InlineData(MembershipRouteAuthorization.UnknownGroupType, false)]
    public void OnlyProvenCurrentAuthorizationRoutesCanEstablishExpectedness(MembershipRouteAuthorization authorization, bool expected)
    {
        var member = new MembershipRoutePrincipal(Holder, null, "CN=Holder,DC=contoso,DC=com");
        var root = new MembershipRoutePrincipal("S-1-5-21-1-2-3-512", null, "CN=RenamedAdmins,DC=contoso,DC=com");
        var route = new MembershipRoute(9, "Domain Admins", authorization, false, [new(member, false), new(root, true)]);
        var routes = new MembershipRouteSummary([new(root, [route], MembershipRouteIncompleteReason.NodeBudgetReached)], MembershipRouteIncompleteReason.NodeBudgetReached);
        var result = ControlEdgeDeriver.Expected(Ace(0, Holder, 0x40000).Trustee, Subject, "contoso.com", routes, true, true, DomainSid);
        Assert.Equal(expected, result.State == ControlExpectedness.Expected);
        var historical = Ace(0, "S-1-5-21-1-2-3-1300", 0x40000).Trustee;
        Assert.NotEqual(ControlExpectedness.Expected, ControlEdgeDeriver.Expected(historical, Subject, "contoso.com", routes, true, true, DomainSid).State);
    }

    /// <summary>
    /// <c>WRITE_OWNER</c> produces the owner-setting edge and nothing else.
    /// </summary>
    /// <remarks>
    /// <b>The compound takeover edge this asserted until 2026-09-11 was never produced in a run.</b>
    /// The fixture reached it through <c>includeOwnerTransitions</c>, whose <c>true</c> default no
    /// production caller selected, so the assertion described the deriver's capability rather than
    /// the product's behaviour. Where the transition is genuinely derived - for objects discovery
    /// admitted, per 0114 - it is asserted by <c>OwnershipAuditIntegrationTests</c>, and
    /// <c>OwnershipWorkflowTests</c> asserts its absence for an object outside that scope.
    /// </remarks>
    [Fact]
    public void OwnerSettingIsEstablishedWithoutDerivingTheTakeoverItWouldAllow()
    {
        var result = Derive(Permissions(Ace(0, Holder, 0x80000)));

        var primitive = Assert.Single(result.Edges);
        Assert.Equal(ControlCapability.CanSetOwner, primitive.Capability);
        Assert.Equal(ControlEvaluationState.Established, primitive.EvaluationState);
        Assert.True(primitive.IsCounted);
    }

    [Fact]
    public void EveryContributingEntrySurvivesWithoutCountingDuplicateGrants()
    {
        var edge = Assert.Single(Derive(Permissions(Ace(0, Holder, 0x40000), Ace(1, Holder, 0x40000))).Edges);
        Assert.Equal(2, edge.Evidence.Count);
        Assert.True(edge.IsCounted);
    }

    [Theory]
    [InlineData(true, 0)]
    [InlineData(false, 1)]
    public void StoredOrderIsNotReplacedByBlanketDenySubtraction(bool denyFirst, int count)
    {
        var allow = Ace(denyFirst ? 1 : 0, Holder, 0x40000);
        var deny = Ace(denyFirst ? 0 : 1, Holder, 0x40000, "AccessDenied");
        Assert.Equal(count, Derive(Permissions(denyFirst ? [deny, allow] : [allow, deny])).Edges.Count);
    }

    [Fact]
    public void InheritOnlyAndGenericWriteDoNotGrantWholeObjectControl()
    {
        Assert.Empty(Derive(Permissions(Ace(0, Holder, 0x40000, propagation: 0x08))).Edges);
        Assert.Empty(Derive(Permissions(Ace(0, Holder, 0x20028))).Edges);
    }

    [Fact]
    public void ScopedStandardRightIsRetainedAsUnevaluatedRatherThanAbsent()
    {
        var entry = Ace(0, Holder, 0x40000, "AccessAllowedObject") with { HasObjectType = true, ObjectTypeGuid = Guid.NewGuid().ToString() };
        var result = Derive(Permissions(entry));
        var edge = Assert.Single(result.Edges);
        Assert.Equal(ControlEvaluationState.Unknown, edge.EvaluationState);
        Assert.Equal(entry.ObjectTypeGuid, Assert.Single(edge.Evidence).ObjectTypeGuid);
        Assert.False(result.IsComplete);
    }

    [Fact]
    public void ForeignAdministratorSidCannotUseTheLocalCapturedDomainLabel()
    {
        var holder = Ace(0, "S-1-5-21-9-9-9-512", 0x40000).Trustee;
        var answer = ControlEdgeDeriver.Expected(holder, Subject, "contoso.com", new([], MembershipRouteIncompleteReason.None), true, true, DomainSid);
        Assert.NotEqual(ControlExpectedness.Expected, answer.State);
    }

    [Fact]
    public void CrossTrusteeDenyAndCallbackDoNotBecomeUnconditionalGrants()
    {
        var denied = Assert.Single(Derive(Permissions(Ace(0, "S-1-1-0", 0x40000, "AccessDenied"), Ace(1, Holder, 0x40000))).Edges);
        Assert.Equal(ControlEvaluationState.Unknown, denied.EvaluationState);
        Assert.True(denied.Uncertainty.HasFlag(ControlUncertainty.CrossTrusteeDeny));
        var callback = Assert.Single(Derive(Permissions(Ace(0, Holder, 0x40000, "AccessAllowedCallback"))).Edges);
        Assert.Equal(ControlEvaluationState.Unknown, callback.EvaluationState);
    }

    [Fact]
    public void NullEmptyAndUnreadDescriptorsDoNotCollapse()
    {
        Assert.False(Derive(null).IsComplete);
        Assert.Empty(Derive(Permissions() with { DaclState = DaclState.Empty }).Edges);
        var open = Derive(Permissions() with { DaclState = DaclState.Null });
        Assert.Equal(2, open.Edges.Count(edge => edge.IsCounted));
        Assert.All(open.Edges, edge => Assert.Equal(ControlExpectedness.Unexpected, edge.Expectedness));
    }

    [Fact]
    public void SystemExpectednessRequiresACompleteApplicableDescriptor()
    {
        var system = Permissions(Ace(0, "S-1-5-18", 0x40000));
        Assert.Equal(ControlExpectedness.Expected, Assert.Single(Derive(system).Edges).Expectedness);
        var incomplete = system with { DaclCompleteness = DaclCompleteness.Incomplete };
        Assert.Equal(ControlExpectedness.Unknown, Assert.Single(Derive(incomplete).Edges).Expectedness);
        Assert.NotEqual(ControlExpectedness.Expected, Assert.Single(Derive(Permissions(Ace(0, Holder, 0x40000))).Edges).Expectedness);
    }

    /// <summary>
    /// SYSTEM holding <c>WRITE_OWNER</c> is expected, and the deriver does not turn that into a
    /// second edge about what SYSTEM could then become.
    /// </summary>
    /// <remarks>
    /// <b>This asserted a compound edge until 2026-09-11, and production never produced one.</b>
    /// <c>ControlEdgeDeriver.Derive</c> took an <c>includeOwnerTransitions</c> parameter defaulting
    /// to <c>true</c> while all three production callers passed <c>false</c>, so the only caller
    /// reaching the branch was this fixture - the test was measuring a path the product had already
    /// stopped taking. Ownership transitions belong to <see cref="OwnershipAuditRun"/>, which
    /// derives them for admitted objects under decision 0114, and
    /// <c>OwnershipAuditIntegrationTests</c> covers them there.
    /// </remarks>
    [Fact]
    public void SystemHoldingWriteOwnerIsExpectedWithoutDerivingATransition()
    {
        var edges = Derive(Permissions(Ace(0, "S-1-5-18", 0x80000))).Edges;

        Assert.Equal(ControlExpectedness.Expected, Assert.Single(edges).Expectedness);
        Assert.All(edges, edge => Assert.True(edge.IsCounted));
    }

    [Fact]
    public void OwnerAcceptanceAndProtectionCannotConferExpectedness()
    {
        var routes = MembershipRouteSummary.NotDerived;
        var trustee = Ace(0, "S-1-5-32-551", 0x40000).Trustee;
        var answer = ControlEdgeDeriver.Expected(trustee, Subject, "contoso.com", routes, true, true, DomainSid);
        Assert.NotEqual(ControlExpectedness.Expected, answer.State);
    }
}
