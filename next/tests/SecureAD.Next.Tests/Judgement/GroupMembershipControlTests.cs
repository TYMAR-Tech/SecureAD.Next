using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using Xunit;
using static SecureAD.Next.Tests.Judgement.ControlEdgeDeriverTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class GroupMembershipControlTests
{
    internal static string MemberGuid => SchemaGuidCatalog.Embedded.GuidFor("member")!;
    private static string MembershipSet => SchemaGuidCatalog.Embedded.GuidFor("Membership")!;
    internal static ObjectAttributes Group => Subject with
    {
        Attributes = [new("objectClass", AttributeCardinality.MultiValued, [new(0, "top", null), new(1, "group", null)])],
    };
    internal static PermissionEntry Scoped(int ordinal, int mask, string? guid = null, string type = "AccessAllowedObject") =>
        Ace(ordinal, Holder, mask, type) with { HasObjectType = true, ObjectTypeGuid = guid ?? MemberGuid };
    internal static ControlObjectEvaluation Membership(ObjectPermissions? permissions, SchemaGuidCatalog? catalogue = null, ObjectAttributes? subject = null) =>
        ControlEdgeDeriver.Derive(subject ?? Group, permissions,
            JudgingContext.At(DateTimeOffset.UnixEpoch) with { ForestFqdn = "contoso.com", SchemaGuids = catalogue }, Guid.Empty, null, DomainSid);
    private static SchemaGuidCatalog PropertySet(params string[] members) => SchemaGuidCatalog.CapturedOver([], SchemaGuidCatalog.Embedded,
        new Dictionary<string, IReadOnlyList<string>> { [MembershipSet] = members });

    [Theory]
    [InlineData(0x20, ControlCapability.CanModifyGroupMembership, ControlEvaluationState.Established)]
    [InlineData(0x08, ControlCapability.CanAddSelfToGroup, ControlEvaluationState.Unknown)]
    public void SameGuidDoesNotMergeDifferentRights(int mask, ControlCapability capability, ControlEvaluationState state)
    {
        var ace = Scoped(3, mask);
        var edge = Assert.Single(Membership(Permissions(ace)).Edges);
        Assert.Equal(capability, edge.Capability);
        Assert.Equal(state, edge.EvaluationState);
        Assert.Equal(ControlEdgeClass.MembershipEscalation, edge.EdgeClass);
        Assert.True(edge.IsCounted);
        Assert.Equal(ace, Assert.Single(edge.Evidence));
    }

    [Fact]
    public void SelfMembershipKeepsTheRightSeparateFromTheUnverifiedRequester()
    {
        var result = Membership(Permissions(Scoped(0, 0x08)));
        var edge = Assert.Single(result.Edges);
        Assert.Equal(ControlCapability.CanAddSelfToGroup, edge.Capability);
        Assert.Contains(edge.Preconditions, condition => condition.Name == "HoldsSelfMembershipValidatedWrite" && condition.State == ControlEvaluationState.Established);
        Assert.Contains(edge.Preconditions, condition => condition.Name == "AddedMemberSid == RequesterSid" && condition.State == ControlEvaluationState.Unknown);
        Assert.True(edge.Uncertainty.HasFlag(ControlUncertainty.SelfMembershipRequesterNotEvaluated));
        Assert.Equal("ResearchBlocked", edge.ResearchStatus);
        Assert.False(result.IsComplete);
    }

    [Fact]
    public void UnknownSelfMembershipDoesNotWeakenIndependentGeneralMembership()
    {
        var edges = Membership(Permissions(Scoped(0, 0x28))).Edges;
        Assert.Equal(2, edges.Count);
        Assert.True(edges.Single(edge => edge.Capability == ControlCapability.CanModifyGroupMembership).IsComplete);
        Assert.Equal(ControlEvaluationState.Unknown, edges.Single(edge => edge.Capability == ControlCapability.CanAddSelfToGroup).EvaluationState);
    }

    [Theory]
    [InlineData("user")]
    [InlineData("computer")]
    [InlineData("organizationalUnit")]
    public void KnownNonGroupsNeverAcquireMembershipCapabilities(string objectClass)
    {
        var target = Group with { Attributes = [new("objectClass", AttributeCardinality.MultiValued, [new(0, objectClass, null)])] };
        Assert.Empty(Membership(Permissions(Scoped(0, 0x28)), subject: target).Edges);
    }

    [Fact]
    public void MissingTargetClassCannotBecomeACleanEmptyAnswer()
    {
        var result = Membership(Permissions(Scoped(0, 0x20)), subject: Subject with { Attributes = [] });
        Assert.False(result.IsComplete);
        Assert.Equal(ControlEvaluationState.Unknown, Assert.Single(result.Edges).EvaluationState);
        Assert.True(result.Uncertainty.HasFlag(ControlUncertainty.TargetClassNotRead));
    }

    [Theory]
    [InlineData(0x10)]
    [InlineData(0x100)]
    public void ReadPropertyAndExtendedRightDoNotGrantMembership(int mask) =>
        Assert.Empty(Membership(Permissions(Scoped(0, mask))).Edges);

    [Theory]
    [InlineData("memberOf")]
    [InlineData("servicePrincipalName")]
    public void UnrelatedAttributesDoNotGrantMembership(string name) =>
        Assert.Empty(Membership(Permissions(Scoped(0, 0x28, SchemaGuidCatalog.Embedded.GuidFor(name)!))).Edges);

    [Fact]
    public void InheritOnlyDoesNotApplyButInheritedApplicableEntriesDo()
    {
        var ace = Scoped(0, 0x20) with { PropagationFlags = 0x08, IsInherited = true };
        Assert.Empty(Membership(Permissions(ace)).Edges);
        Assert.True(Assert.Single(Membership(Permissions(ace with { PropagationFlags = 0 })).Edges).IsComplete);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AttributeAndPropertySetAreEvaluatedTogetherInStoredOrder(bool setGrants)
    {
        var allow = Scoped(1, 0x20, setGrants ? MembershipSet : MemberGuid);
        var deny = Scoped(0, 0x20, setGrants ? MemberGuid : MembershipSet, "AccessDeniedObject");
        Assert.Empty(Membership(Permissions(deny, allow), PropertySet("member")).Edges);
        var edge = Assert.Single(Membership(Permissions(allow with { Ordinal = 0 }, deny with { Ordinal = 1 }), PropertySet("member")).Edges);
        Assert.True(edge.IsComplete);
        Assert.Equal(2, edge.Evidence.Count);
    }

    [Fact]
    public void PropertySetReachRequiresCapturedMembershipNotItsFamiliarName()
    {
        var ace = Scoped(0, 0x20, MembershipSet);
        var missing = Assert.Single(Membership(Permissions(ace)).Edges);
        Assert.Equal(ControlEvaluationState.Unknown, missing.EvaluationState);
        Assert.True(missing.Uncertainty.HasFlag(ControlUncertainty.MembershipScopeNotEvaluated));
        Assert.Equal(ControlEvaluationState.Unknown, Assert.Single(Membership(Permissions(ace), PropertySet()).Edges).EvaluationState);
        var proven = Assert.Single(Membership(Permissions(ace), PropertySet("member")).Edges);
        Assert.True(proven.IsComplete);
        Assert.Contains(proven.Preconditions, condition => condition.EvidenceSource.Contains("Captured property set") && condition.EvidenceSource.Contains("member"));
        Assert.Empty(Membership(Permissions(ace with { AccessMask = 0x08 }), PropertySet("member")).Edges);
    }

    [Fact]
    public void MissingPropertySetDenyScopeDoesNotLeaveAnEstablishedDirectAllow()
    {
        var result = Membership(Permissions(Scoped(0, 0x20, MembershipSet, "AccessDeniedObject"), Scoped(1, 0x20)));
        Assert.Equal(ControlEvaluationState.Unknown, Assert.Single(result.Edges).EvaluationState);
        Assert.False(result.IsComplete);
    }

    [Fact]
    public void PartialPropertySetDenyDoesNotEstablishGeneralMembership()
    {
        var result = Membership(Permissions(Scoped(0, 0x20, MembershipSet, "AccessDeniedObject"), Scoped(1, 0x20)), PropertySet("displayName"));
        Assert.Equal(ControlEvaluationState.Unknown, Assert.Single(result.Edges).EvaluationState);
    }

    [Fact]
    public void AProvenDifferentPropertySetDoesNotReachMember()
    {
        var catalogue = SchemaGuidCatalog.CapturedOver([], SchemaGuidCatalog.Embedded,
            new Dictionary<string, IReadOnlyList<string>> { ["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"] = ["member"] });
        Assert.Empty(Membership(Permissions(Scoped(0, 0x20, MembershipSet)), catalogue).Edges);
    }

    [Theory]
    [InlineData(0x20)]
    [InlineData(0x08)]
    public void ADefinitiveDenyDoesNotBecomeAnUnknownGrant(int mask) =>
        Assert.Empty(Membership(Permissions(Scoped(0, mask, type: "AccessDeniedObject"), Scoped(1, mask))).Edges);

    [Fact]
    public void CrossTrusteeDeniesCallbacksAndIncompleteDescriptorsRemainUnknown()
    {
        var allow = Scoped(1, 0x20);
        var crossDeny = Ace(0, "S-1-1-0", 0x20, "AccessDenied");
        var cross = Assert.Single(Membership(Permissions(crossDeny, allow)).Edges);
        Assert.True(cross.Uncertainty.HasFlag(ControlUncertainty.CrossTrusteeDeny));
        var callback = Assert.Single(Membership(Permissions(allow with { AceType = "AccessAllowedCallbackObject", ApplicationData = [1, 2] })).Edges);
        Assert.True(callback.Uncertainty.HasFlag(ControlUncertainty.ConditionalOrUnsupportedAce));
        Assert.Equal(new byte[] { 1, 2 }, Assert.Single(callback.Evidence).ApplicationData);
        var incomplete = Assert.Single(Membership(Permissions(allow) with { DaclCompleteness = DaclCompleteness.Incomplete }).Edges);
        Assert.True(incomplete.Uncertainty.HasFlag(ControlUncertainty.DescriptorIncomplete));
        Assert.All(new[] { cross, callback, incomplete }, edge => Assert.Equal(ControlEvaluationState.Unknown, edge.EvaluationState));
    }

    [Fact]
    public void MissingObjectGuidScopeIsUnknownButAbsentScopeFlagIsUnrestricted()
    {
        var malformed = Scoped(0, 0x20) with { ObjectTypeGuid = null };
        Assert.Equal(ControlEvaluationState.Unknown, Assert.Single(Membership(Permissions(malformed)).Edges).EvaluationState);
        Assert.True(Assert.Single(Membership(Permissions(malformed with { HasObjectType = false })).Edges).IsComplete);
    }

    [Fact]
    public void SelfTrusteeIsResolvedToTheTargetWithoutRewritingStoredEvidence()
    {
        const string sid = "S-1-5-21-1-2-3-2200";
        var target = Group with { Attributes = [.. Group.Attributes, new("objectSid", AttributeCardinality.SingleValued, [new(0, null, Sid.ToBytes(sid)!)])] };
        var ace = Scoped(0, 0x08);
        ace = ace with { Trustee = ace.Trustee with { Sid = "S-1-5-10", WellKnownRole = WellKnownSidRole.Placeholder } };
        var edge = Assert.Single(Membership(Permissions(ace), subject: target).Edges);
        Assert.Equal(sid, edge.HolderSid);
        Assert.Equal("S-1-5-10", Assert.Single(edge.Evidence).Trustee.Sid);
        Assert.Equal(ControlEvaluationState.Unknown, edge.EvaluationState);
    }

    [Fact]
    public void NullEmptyUnreadAndUnparsedDescriptorsRemainDistinct()
    {
        Assert.False(Membership(null).IsComplete);
        Assert.False(Membership(Permissions() with { DaclState = DaclState.Unreadable }).IsComplete);
        var empty = Membership(Permissions() with { DaclState = DaclState.Empty,
            Owner = new("S-1-5-18", "SYSTEM", null, null, null, WellKnownSidRole.Principal, null) });
        Assert.True(empty.IsComplete);
        Assert.Empty(empty.Edges);
        var open = Membership(Permissions() with { DaclState = DaclState.Null });
        var membership = Assert.Single(open.Edges.Where(edge => edge.Capability == ControlCapability.CanModifyGroupMembership));
        Assert.True(membership.IsComplete);
        Assert.Equal("GrantsEveryoneEverything", membership.DescriptorOutcome);
        Assert.Empty(membership.Evidence);
        Assert.Equal(ControlExpectedness.Unexpected, membership.Expectedness);
        Assert.Equal(ControlEvaluationState.Unknown, open.Edges.Single(edge => edge.Capability == ControlCapability.CanAddSelfToGroup).EvaluationState);
    }

    [Fact]
    public void MembershipUsesExistingScopedExpectednessWithoutChangingTheCatalogue()
    {
        var ace = Scoped(0, 0x20);
        var builtin = Assert.Single(Membership(Permissions(ace with { Trustee = ace.Trustee with { Sid = "S-1-5-32-544", DomainFqdn = null } })).Edges);
        Assert.Equal("contoso.com", builtin.HolderScope);
        Assert.Equal(ControlExpectedness.Expected, builtin.Expectedness);
        Assert.Equal(2, builtin.PrincipalCatalogueVersion);
        var broad = Assert.Single(Membership(Permissions(ace with { Trustee = ace.Trustee with { Sid = "S-1-1-0" } })).Edges);
        Assert.Equal(ControlExpectedness.Unexpected, broad.Expectedness);
    }

    [Fact]
    public void SystemRequesterUncertaintyIsNotMislabelledAsAnUnreadDescriptor()
    {
        var ace = Scoped(0, 0x28);
        var edges = Membership(Permissions(ace with { Trustee = ace.Trustee with { Sid = "S-1-5-18" } })).Edges;
        Assert.Equal(ControlExpectedness.Expected, edges.Single(edge => edge.Capability == ControlCapability.CanModifyGroupMembership).Expectedness);
        var self = edges.Single(edge => edge.Capability == ControlCapability.CanAddSelfToGroup);
        Assert.Equal(ControlExpectedness.Unknown, self.Expectedness);
        Assert.Equal(ControlExpectednessReason.UnknownCapabilityScope, self.ExpectednessReason);
        Assert.False(self.Uncertainty.HasFlag(ControlUncertainty.DescriptorIncomplete));
    }

    [Fact]
    public void DuplicateGrantsDoNotMultiplyTheNamedHolderOrInvokeMemberExpansion()
    {
        var context = JudgingContext.At(DateTimeOffset.UnixEpoch) with
        {
            ForestFqdn = "contoso.com",
            MembersOfPrincipal = (_, _) => throw new InvalidOperationException("Member expansion is outside this slice."),
        };
        var result = ControlEdgeDeriver.Derive(Group, Permissions(Scoped(0, 0x28), Scoped(1, 0x28)),
            context, Guid.Empty, null, DomainSid);
        Assert.Equal(2, result.Edges.Count);
        Assert.All(result.Edges, edge =>
        {
            Assert.Equal(Holder, edge.HolderSid);
            Assert.True(edge.IsCounted);
            Assert.Equal(2, edge.Evidence.Count);
        });
    }
}
