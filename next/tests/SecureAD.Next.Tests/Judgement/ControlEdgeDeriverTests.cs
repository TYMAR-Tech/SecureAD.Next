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

    [Fact]
    public void OwnerSettingRemainsEstablishedWhileTakeoverRemainsUnknown()
    {
        var result = Derive(Permissions(Ace(0, Holder, 0x80000)));
        var primitive = Assert.Single(result.Edges.Where(edge => edge.IsCounted));
        Assert.Equal(ControlCapability.CanSetOwner, primitive.Capability);
        Assert.Equal(ControlEvaluationState.Established, primitive.EvaluationState);
        var compound = Assert.Single(result.Edges.Where(edge => !edge.IsCounted));
        Assert.Equal(ControlEvaluationState.Unknown, compound.EvaluationState);
        Assert.Equal(3, compound.Preconditions.Count);
        Assert.Contains(compound.Preconditions, condition => condition.Name == "CanSetOwner" && condition.State == ControlEvaluationState.Established);
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

    [Fact]
    public void SystemExpectationDoesNotExtendToAnUnverifiedCompound()
    {
        var edges = Derive(Permissions(Ace(0, "S-1-5-18", 0x80000))).Edges;
        Assert.Equal(ControlExpectedness.Expected, Assert.Single(edges.Where(edge => edge.IsCounted)).Expectedness);
        Assert.Equal(ControlExpectedness.Unknown, Assert.Single(edges.Where(edge => !edge.IsCounted)).Expectedness);
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
