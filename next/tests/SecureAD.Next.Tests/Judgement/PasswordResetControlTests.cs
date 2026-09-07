using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using Xunit;
using static SecureAD.Next.Tests.Judgement.ControlEdgeDeriverTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class PasswordResetControlTests
{
    internal const string ResetGuid = "00299570-246d-11d0-a768-00aa006e0529";
    internal static ObjectAttributes Account => Subject with
    {
        DistinguishedName = "CN=Account,DC=contoso,DC=com",
        Attributes = [new("objectClass", AttributeCardinality.MultiValued, [new(0, "user", null)])],
    };

    [Fact]
    public void DirectResetGrantProducesTheDocumentedCredentialCapability()
    {
        var result = Evaluate(Permissions(Reset(0)));

        Assert.Contains(result.Edges, edge => edge.Capability.ToString() == "CanResetPassword"
            && edge.EdgeClass == ControlEdgeClass.CredentialExposure
            && edge.EvaluationState == ControlEvaluationState.Established);
    }

    [Theory]
    [InlineData("user")]
    [InlineData("computer")]
    [InlineData("inetOrgPerson")]
    [InlineData("msDS-ManagedServiceAccount")]
    [InlineData("msDS-GroupManagedServiceAccount")]
    public void DocumentedAccountClassesReceiveResetPermission(string objectClass)
    {
        var subject = Account with { Attributes = [new("objectClass", AttributeCardinality.MultiValued, [new(0, objectClass, null)])] };
        Assert.Equal(ControlEvaluationState.Established, Single(Evaluate(Permissions(Reset(0)), subject)).EvaluationState);
    }

    [Theory]
    [InlineData("group")]
    [InlineData("organizationalUnit")]
    [InlineData("domainDNS")]
    public void KnownNonAccountsDoNotAcquireResetCapabilities(string objectClass)
    {
        var subject = Account with { Attributes = [new("objectClass", AttributeCardinality.MultiValued, [new(0, objectClass, null)])] };
        Assert.Empty(Resets(Evaluate(Permissions(Reset(0)), subject)));
    }

    [Fact]
    public void MissingClassKeepsAPossibleResetUnknown()
    {
        var edge = Single(Evaluate(Permissions(Reset(0)), Account with { Attributes = [] }));
        Assert.True(edge.EvaluationState == ControlEvaluationState.Unknown && edge.Uncertainty.HasFlag(ControlUncertainty.TargetClassNotRead));
    }

    [Theory]
    [InlineData(true, true, true, 0)]
    [InlineData(true, false, true, 0)]
    [InlineData(false, true, true, 0)]
    [InlineData(false, false, true, 0)]
    [InlineData(true, true, false, 1)]
    [InlineData(true, false, false, 1)]
    [InlineData(false, true, false, 1)]
    [InlineData(false, false, false, 1)]
    public void BroadAndSpecificEntriesShareOneOrderedOperation(bool allowScoped, bool denyScoped, bool denyFirst, int count)
    {
        var allow = Reset(0) with { HasObjectType = allowScoped, ObjectTypeGuid = allowScoped ? ResetGuid : null };
        var deny = Reset(1, "AccessDeniedObject") with { HasObjectType = denyScoped, ObjectTypeGuid = denyScoped ? ResetGuid : null };
        var entries = denyFirst ? new[] { deny, allow } : new[] { allow, deny };
        Assert.Equal(count, Resets(Evaluate(Permissions(entries))).Count());
    }

    [Theory]
    [InlineData("ab721a53-1e2f-11d0-9819-00aa0040529b", 0x100)]
    [InlineData("bf9679c0-0de6-11d0-a285-00aa003049e2", 0x08)]
    [InlineData(ResetGuid, 0x20)]
    [InlineData(ResetGuid, 0x40000)]
    public void OtherRightsDoNotBecomePasswordReset(string guid, int mask)
    {
        var entry = Reset(0) with { ObjectTypeGuid = guid, AccessMask = mask };
        Assert.Empty(Resets(Evaluate(Permissions(entry))));
    }

    [Fact]
    public void APropertySetCannotSupplyAnExtendedRight()
    {
        var catalogue = SchemaGuidCatalog.CapturedOver([], SchemaGuidCatalog.Embedded,
            new Dictionary<string, IReadOnlyList<string>> { ["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"] = ["User-Force-Change-Password"] });
        Assert.Empty(Resets(Evaluate(Permissions(Reset(0) with { ObjectTypeGuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" }), catalogue: catalogue)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("invalid")]
    public void UnavailableOrMalformedScopeDoesNotBecomeADefiniteGrant(string? guid)
    {
        var edge = Single(Evaluate(Permissions(Reset(0) with { ObjectTypeGuid = guid })));
        Assert.True(edge.EvaluationState == ControlEvaluationState.Unknown && edge.Uncertainty.HasFlag(ControlUncertainty.PasswordResetScopeNotEvaluated));
    }

    [Fact]
    public void MissingRightCatalogueRetainsTheScopedCandidateAsUnknown()
    {
        var edge = Single(Evaluate(Permissions(Reset(0)), catalogue: new SchemaGuidCatalog([])));
        Assert.Equal(ControlEvaluationState.Unknown, edge.EvaluationState);
    }

    [Theory]
    [InlineData("AccessAllowedCallbackObject")]
    [InlineData("UnsupportedCapturedType")]
    public void UnsupportedAllowEntriesRemainUnknown(string type)
    {
        Assert.Equal(ControlEvaluationState.Unknown, Single(Evaluate(Permissions(Reset(0, type)))).EvaluationState);
    }

    [Fact]
    public void ARelevantCrossTrusteeDenyDoesNotImplyCompleteTokenAuthorization()
    {
        var edge = Single(Evaluate(Permissions(Reset(0, "AccessDeniedObject", "S-1-1-0"), Reset(1))));
        Assert.True(edge.EvaluationState == ControlEvaluationState.Unknown && edge.Uncertainty.HasFlag(ControlUncertainty.CrossTrusteeDeny));
    }

    [Fact]
    public void AnUnrelatedDenyDoesNotContaminateResetPermission()
    {
        var deny = Reset(0, "AccessDeniedObject", "S-1-1-0") with { ObjectTypeGuid = "ab721a53-1e2f-11d0-9819-00aa0040529b" };
        Assert.Equal(ControlEvaluationState.Established, Single(Evaluate(Permissions(deny, Reset(1)))).EvaluationState);
    }

    [Fact]
    public void InheritOnlyEntriesDoNotApplyToThisAccount()
    {
        Assert.Empty(Resets(Evaluate(Permissions(Reset(0) with { PropagationFlags = 0x08 }))));
    }

    [Fact]
    public void InheritedEntriesThatReachTheAccountRemainEvidence()
    {
        var entry = Reset(7) with { IsInherited = true, InheritanceFlags = 2 };
        Assert.Equal(entry, Assert.Single(Single(Evaluate(Permissions(entry))).Evidence));
    }

    [Fact]
    public void DuplicateGrantEntriesDoNotMultiplyTheCountedCapability()
    {
        Assert.True(Single(Evaluate(Permissions(Reset(0), Reset(1)))).IsCounted);
    }

    [Fact]
    public void IncompleteDescriptorKeepsPermissionUnknown()
    {
        Assert.Equal(ControlEvaluationState.Unknown, Single(Evaluate(Permissions(Reset(0)) with { DaclCompleteness = DaclCompleteness.Incomplete })).EvaluationState);
    }

    [Fact]
    public void EmptyDaclDoesNotGrantResetPermission()
    {
        Assert.Empty(Resets(Evaluate(Permissions())));
    }

    [Fact]
    public void NullDaclRetainsItsBroadResetCapabilityWithoutInventingAnAce()
    {
        var edge = Single(Evaluate(Permissions() with { DaclState = DaclState.Null }));
        Assert.Equal(("S-1-1-0", ControlEvaluationState.Established, ControlExpectedness.Unexpected, 0),
            (edge.HolderSid, edge.EvaluationState, edge.Expectedness, edge.Evidence.Count));
    }

    [Fact]
    public void MissingDescriptorIsNotCompleteEmptyCoverage()
    {
        Assert.False(Evaluate(null).IsComplete);
    }

    [Fact]
    public void UnreadDescriptorIsNotCompleteEmptyCoverage()
    {
        Assert.False(Evaluate(Permissions() with { Availability = DescriptorAvailability.Unreadable }).IsComplete);
    }

    [Fact]
    public void UnresolvedHolderCannotBecomeAnEstablishedGrant()
    {
        var entry = Reset(0);
        entry = entry with { Trustee = entry.Trustee with { DistinguishedName = null } };
        Assert.True(Single(Evaluate(Permissions(entry))).Uncertainty.HasFlag(ControlUncertainty.HolderUnresolved));
    }

    [Fact]
    public void SelfResolvesToTheAccountButKeepsTheOriginalTrustee()
    {
        var account = Account with { Attributes = [.. Account.Attributes,
            new("objectSid", AttributeCardinality.SingleValued, [new(0, Holder, null)])] };
        var edge = Single(Evaluate(Permissions(Reset(0, sid: "S-1-5-10")), account));
        Assert.Equal((Holder, "S-1-5-10"), (edge.HolderSid, Assert.Single(edge.Evidence).Trustee.Sid));
    }

    [Fact]
    public void DirectSystemResetGrantUsesTheAcceptedDescriptorPolicy()
    {
        Assert.Equal(ControlExpectednessReason.ExpectedPlatformIdentityDirectAce,
            Single(Evaluate(Permissions(Reset(0, sid: "S-1-5-18")))).ExpectednessReason);
    }

    [Fact]
    public void IncompleteSystemEvidenceDoesNotBecomeExpected()
    {
        Assert.Equal(ControlExpectedness.Unknown, Single(Evaluate(Permissions(Reset(0, sid: "S-1-5-18"))
            with { DaclCompleteness = DaclCompleteness.Incomplete })).Expectedness);
    }

    [Fact]
    public void DomainBuiltinResetAuthorityKeepsTheVerifiedResourceScope()
    {
        var entry = Reset(0, sid: "S-1-5-32-544");
        entry = entry with { Trustee = entry.Trustee with { DomainFqdn = null, DistinguishedName = null } };
        var edge = Single(Evaluate(Permissions(entry)));
        Assert.Equal(("contoso.com", ControlExpectedness.Expected), (edge.HolderScope, edge.Expectedness));
    }

    private static IEnumerable<ControlEdge> Resets(ControlObjectEvaluation result) =>
        result.Edges.Where(edge => edge.Capability == ControlCapability.CanResetPassword);

    private static ControlEdge Single(ControlObjectEvaluation result) => Assert.Single(Resets(result));

    internal static PermissionEntry Reset(int ordinal, string type = "AccessAllowedObject", string? sid = null) =>
        Ace(ordinal, sid ?? Holder, 0x100, type) with { HasObjectType = true, ObjectTypeGuid = ResetGuid };

    internal static ControlObjectEvaluation Evaluate(ObjectPermissions? permissions, ObjectAttributes? subject = null,
        SchemaGuidCatalog? catalogue = null) => ControlEdgeDeriver.Derive(subject ?? Account, permissions,
            JudgingContext.At(DateTimeOffset.UnixEpoch) with { ForestFqdn = "contoso.com", SchemaGuids = catalogue },
            Guid.Empty, null, DomainSid);
}
