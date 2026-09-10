using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class FullControlEvaluatorTests
{
    // Independent anchor: MS-ADTS 6.1.3 GENERIC_ALL_MAPPING; never derive the expected mask from production constants.
    internal const int FullMask = 0x000F01FF;
    internal static FullControlSource Source(params PermissionEntry[] entries) => new(
        ControlEdgeDeriverTests.Subject.DistinguishedName, ControlEdgeDeriverTests.Subject.ObjectGuid, null, "contoso.com",
        ["organizationalUnit"], ControlEdgeDeriverTests.Ace(0, ControlEdgeDeriverTests.Holder, 0).Trustee,
        null, true, false, DescriptorAvailability.Read, DaclState.Present, DaclCompleteness.Complete, true, entries)
        { MembershipRoutes = new([], SecureAD.Evidence.Findings.MembershipRouteIncompleteReason.None) };
    internal static FullControlAssessment Evaluate(FullControlSource source) => FullControlEvaluator.AssessFullControl(source, Guid.Empty, null,
        ControlExpectedness.Unexpected, ControlExpectednessReason.UnexpectedNotControlPlane, []);
    internal static PermissionEntry Allow(int ordinal, int mask = FullMask) => ControlEdgeDeriverTests.Ace(ordinal, ControlEdgeDeriverTests.Holder, mask);
    internal static PermissionEntry Deny(int ordinal, int mask) => ControlEdgeDeriverTests.Ace(ordinal, ControlEdgeDeriverTests.Holder, mask, "AccessDenied");

    [Fact]
    public void SpecificAdFullMappingEstablishesTheSummary()
    {
        var result = Evaluate(Source(Allow(0)));
        Assert.Equal(ControlEvaluationState.Established, result.EvaluationState);
    }

    [Fact]
    public void SeveralSpecificGrantsJointlyEstablishFullControl()
    {
        var result = Evaluate(Source(Allow(0, 0xF0000), Allow(1, 0x1FF)));
        Assert.Equal(ControlEvaluationState.Established, result.EvaluationState);
    }

    [Theory]
    [InlineData(1)] [InlineData(2)] [InlineData(4)] [InlineData(8)] [InlineData(16)]
    [InlineData(32)] [InlineData(64)] [InlineData(128)] [InlineData(256)]
    [InlineData(0x10000)] [InlineData(0x20000)] [InlineData(0x40000)] [InlineData(0x80000)]
    public void EveryMappedRightIsRequired(int missing)
    {
        Assert.Equal(ControlEvaluationState.NotEstablished, Evaluate(Source(Allow(0, FullMask & ~missing))).EvaluationState);
    }

    [Theory]
    [InlineData(1)] [InlineData(2)] [InlineData(4)] [InlineData(8)] [InlineData(16)]
    [InlineData(32)] [InlineData(64)] [InlineData(128)] [InlineData(256)]
    [InlineData(0x10000)] [InlineData(0x20000)] [InlineData(0x40000)] [InlineData(0x80000)]
    public void AnEffectiveDenyOfAnyMappedRightBreaksFullControl(int denied)
    {
        Assert.Equal(ControlEvaluationState.NotEstablished, Evaluate(Source(Deny(0, denied), Allow(1))).EvaluationState);
    }

    [Fact]
    public void DenyingWriteDaclLeavesWriteOwnerEvidence()
    {
        var result = Evaluate(Source(Deny(0, 0x40000), Allow(1)));
        Assert.Equal(ControlEvaluationState.Established, result.Rights.Single(right => right.Mask == 0x80000).State);
    }

    [Theory]
    [InlineData(0x10000000)] [InlineData(0x10040000)] [InlineData(0x40000000)] [InlineData(0x20028)]
    public void RawGenericBitsAndGenericWriteDoNotManufactureFullControl(int mask)
    {
        Assert.Equal(ControlEvaluationState.NotEstablished, Evaluate(Source(Allow(0, mask))).EvaluationState);
    }

    [Fact]
    public void AllowBeforeDenyRetainsFullControlInNoncanonicalOrder()
    {
        Assert.Equal(ControlEvaluationState.Established, Evaluate(Source(Allow(0), Deny(1, FullMask)) with { DaclWasCanonical = false }).EvaluationState);
    }

    [Fact]
    public void AGrantAfterADenyIsNotAnIndependentRoute()
    {
        var result = Evaluate(Source(Allow(0), Deny(1, FullMask), Allow(2)));
        Assert.All(result.Rights, right => Assert.Equal(new[] { 0 }, right.GrantOrdinals));
    }

    [Fact]
    public void RemovingTheEarlierGrantDoesNotLetTheLaterGrantBypassTheDeny()
    {
        Assert.Equal(ControlEvaluationState.NotEstablished, Evaluate(Source(Deny(1, FullMask), Allow(2))).EvaluationState);
    }

    [Fact]
    public void TwoCompleteGrantsRetainIndependentRoutes()
    {
        Assert.True(Evaluate(Source(Allow(0), Allow(1))).HasIndependentGrantRoutes);
    }

    [Fact]
    public void RemovingOneCompleteGrantLeavesTheOther()
    {
        Assert.Equal(ControlEvaluationState.Established, Evaluate(Source(Allow(1))).EvaluationState);
    }

    [Fact]
    public void TwoSplitGrantSetsRetainIndependentRoutes()
    {
        Assert.True(Evaluate(Source(Allow(0, 0xF0000), Allow(1, 0x1FF), Allow(2, 0xF0000), Allow(3, 0x1FF))).HasIndependentGrantRoutes);
    }

    [Fact]
    public void SharedNecessaryGrantsAreNotReportedAsSourceDisjointRoutes()
    {
        Assert.False(Evaluate(Source(Allow(0, 0xF0000), Allow(1, 0x1FF), Allow(2, 0x1FF))).HasIndependentGrantRoutes);
    }

    [Fact]
    public void InheritOnlyFullMaskDoesNotGrantAnythingHere()
    {
        Assert.Equal(ControlEvaluationState.NotEstablished, Evaluate(Source(Allow(0) with { PropagationFlags = 8 })).EvaluationState);
    }

    [Fact]
    public void InheritedApplicableFullMaskCanEstablishTheSummary()
    {
        Assert.Equal(ControlEvaluationState.Established, Evaluate(Source(Allow(0) with { IsInherited = true })).EvaluationState);
    }

    [Fact]
    public void ScopedFullMasksAreNotUnionedIntoWholeObjectRights()
    {
        Assert.Equal(ControlEvaluationState.NotEstablished, Evaluate(Source(Scoped(Allow(0)), Scoped(Allow(1)))).EvaluationState);
    }

    [Fact]
    public void KnownMemberDenyBreaksWholeObjectFullControl()
    {
        Assert.Equal(ControlEvaluationState.NotEstablished, Evaluate(Source(Scoped(Deny(0, 0x20)), Allow(1)) with { Classes = ["group"] }).EvaluationState);
    }

    [Fact]
    public void MemberScopeGrantBeforeDenyCanSupportLaterWholeObjectGrant()
    {
        Assert.Equal(ControlEvaluationState.Established, Evaluate(Source(Scoped(Allow(0, 0x20)), Scoped(Deny(1, 0x20)), Allow(2)) with { Classes = ["group"] }).EvaluationState);
    }

    [Fact]
    public void RemovingNecessaryScopedGrantBreaksTheLaterFullMaskRoute()
    {
        Assert.Equal(ControlEvaluationState.NotEstablished, Evaluate(Source(Scoped(Deny(1, 0x20)), Allow(2)) with { Classes = ["group"] }).EvaluationState);
    }

    [Theory]
    [InlineData(null)] [InlineData("not-a-guid")] [InlineData("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")]
    public void UnresolvedScopedDenyPreventsAnEstablishedSummary(string? scope)
    {
        var entry = Scoped(Deny(0, 0x20)) with { ObjectTypeGuid = scope };
        Assert.Equal(ControlEvaluationState.Unknown, Evaluate(Source(entry, Allow(1))).EvaluationState);
    }

    [Fact]
    public void LaterUnresolvedScopedDenyDoesNotUndoAnEarlierCompletedGrant()
    {
        Assert.Equal(ControlEvaluationState.Established, Evaluate(Source(Allow(0), Scoped(Deny(1, 0x20)) with { ObjectTypeGuid = null })).EvaluationState);
    }

    [Fact]
    public void MissingClassEvidenceDoesNotEstablishScopeApplicability()
    {
        Assert.Equal(ControlEvaluationState.Unknown, Evaluate(Source(Scoped(Deny(0, 0x20)), Allow(1)) with { Classes = [] }).EvaluationState);
    }

    [Fact]
    public void CallbackGrantIsUnknownRatherThanOrdinaryAccess()
    {
        Assert.Equal(ControlEvaluationState.Unknown, Evaluate(Source(Allow(0) with { AceType = "AccessAllowedCallback" })).EvaluationState);
    }

    [Fact]
    public void CrossTrusteeDenyRequiresAuthorizationContext()
    {
        Assert.Equal(ControlEvaluationState.Unknown, Evaluate(Source(ControlEdgeDeriverTests.Ace(0, "S-1-1-0", FullMask, "AccessDenied"), Allow(1))).EvaluationState);
    }

    [Fact]
    public void GrantsToDifferentHoldersAreNotCombined()
    {
        Assert.Equal(ControlEvaluationState.NotEstablished, Evaluate(Source(Allow(0, 0xF0000), ControlEdgeDeriverTests.Ace(1, "S-1-5-21-1-2-3-1201", 0x1FF))).EvaluationState);
    }

    [Fact]
    public void SelfResolvesOnlyToTheCapturedTargetSid()
    {
        Assert.Equal(ControlEvaluationState.Established, Evaluate(Source(ControlEdgeDeriverTests.Ace(0, "S-1-5-10", FullMask)) with { TargetSid = ControlEdgeDeriverTests.Holder }).EvaluationState);
    }

    [Fact]
    public void MissingSelfTargetDoesNotInventTheHolder()
    {
        Assert.Equal(ControlEvaluationState.NotEstablished, Evaluate(Source(ControlEdgeDeriverTests.Ace(0, "S-1-5-10", FullMask))).EvaluationState);
    }

    [Theory]
    [InlineData(DaclCompleteness.Incomplete)] [InlineData(DaclCompleteness.Unknown)]
    public void IncompleteDescriptorRemainsUnknown(DaclCompleteness completeness)
    {
        Assert.Equal(ControlEvaluationState.Unknown, Evaluate(Source(Allow(0)) with { Completeness = completeness }).EvaluationState);
    }

    [Theory]
    [InlineData(DescriptorAvailability.Unreadable)] [InlineData(DescriptorAvailability.NotAttempted)]
    public void UnreadDescriptorIsNotANegativeAnswer(DescriptorAvailability availability)
    {
        Assert.Equal(ControlEvaluationState.Unknown, Evaluate(Source() with { Availability = availability }).EvaluationState);
    }

    [Fact]
    public void EmptyDaclIsNotFullControl()
    {
        Assert.Equal(ControlEvaluationState.NotEstablished, Evaluate(Source() with { Dacl = DaclState.Empty }).EvaluationState);
    }

    [Fact]
    public void NullDaclEstablishesEveryoneWithoutInventedEntries()
    {
        var source = Source() with { Dacl = DaclState.Null, Holder = new("S-1-1-0", "Everyone", null, null, null, WellKnownSidRole.Principal, null) };
        Assert.All(Evaluate(source).Rights, right => Assert.Equal((ControlEvaluationState.Established, 0), (right.State, right.GrantOrdinals.Count)));
    }

    [Fact]
    public void UnresolvedHolderIsNotAnEstablishedActingIdentity()
    {
        var source = Source(Allow(0));
        Assert.Equal(ControlEvaluationState.Unknown, Evaluate(source with { Holder = source.Holder with { DistinguishedName = null } }).EvaluationState);
    }

    [Fact]
    public void PlaceholderCannotBecomeAnActingHolder()
    {
        var ace = ControlEdgeDeriverTests.Ace(0, "S-1-3-0", FullMask);
        Assert.Equal(ControlEvaluationState.Unknown, Evaluate(Source(ace) with { Holder = ace.Trustee with { WellKnownRole = WellKnownSidRole.Placeholder } }).EvaluationState);
    }

    [Fact]
    public void UnverifiedResourceContextPreventsFullControl()
    {
        Assert.Equal(ControlEvaluationState.Unknown, Evaluate(Source(Allow(0)) with { ResourceContextEstablished = false }).EvaluationState);
    }

    [Fact]
    public void FullControlDoesNotPromoteTheOwnerTransition()
    {
        var result = ControlEdgeDeriverTests.DeriveWithTransitions(ControlEdgeDeriverTests.Permissions(Allow(0)));
        Assert.Equal((ControlEvaluationState.Unknown, false), result.Edges.Where(edge => edge.Capability == ControlCapability.CanBecomeOwnerAndRewriteDacl)
            .Select(edge => (edge.EvaluationState, edge.IsCounted)).Single());
    }

    [Fact]
    public void SchemaExpectednessDoesNotBecomeUnrestrictedFullControlExpectation()
    {
        var subject = ControlEdgeDeriverTests.Subject with { DistinguishedName = "CN=Schema,CN=Configuration,DC=contoso,DC=com" };
        var expected = ControlEdgeDeriver.Expected(ControlEdgeDeriverTests.Ace(0, "S-1-5-21-1-2-3-518", FullMask).Trustee,
            subject, "contoso.com", new([], SecureAD.Evidence.Findings.MembershipRouteIncompleteReason.None), true, true,
            ControlEdgeDeriverTests.DomainSid, fullControl: true);
        Assert.Equal(ControlExpectedness.Unknown, expected.State);
    }

    [Fact]
    public void DirectSystemFullControlCanBeExpected()
    {
        var result = ControlEdgeDeriverTests.Derive(ControlEdgeDeriverTests.Permissions(ControlEdgeDeriverTests.Ace(0, "S-1-5-18", FullMask)));
        Assert.Equal(ControlExpectedness.Expected, Assert.Single(result.FullControlAssessments).Expectedness);
    }

    [Fact]
    public void AnAlteredIndependentRouteClaimIsRejected()
    {
        var value = Evaluate(Source(Allow(0), Deny(1, FullMask), Allow(2))) with { HasIndependentGrantRoutes = true };
        Assert.Throws<InvalidOperationException>(() => FullControlEvaluator.Validate(value, []));
    }

    private static PermissionEntry Scoped(PermissionEntry entry) => entry with
    {
        AceType = FullControlEvaluator.IsDeny(entry) ? "AccessDeniedObject" : "AccessAllowedObject",
        HasObjectType = true,
        ObjectTypeGuid = "bf9679c0-0de6-11d0-a285-00aa003049e2",
    };
}
