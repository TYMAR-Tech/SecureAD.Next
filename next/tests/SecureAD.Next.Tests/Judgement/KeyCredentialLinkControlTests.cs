using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using Xunit;
using static SecureAD.Next.Tests.Judgement.ControlEdgeDeriverTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class KeyCredentialLinkControlTests
{
    internal const string AttributeName = "msDS-KeyCredentialLink";
    internal const string AttributeGuid = "5b47d60f-6090-40b2-9f37-2a4de88f3063";
    internal const string SetGuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    [Fact]
    public void DirectPropertyWriteProducesTheDocumentedCredentialCapability()
    {
        var result = Evaluate(Permissions(Write(0)));

        Assert.Contains(result.Edges, edge => edge.Capability.ToString() == "CanWriteKeyCredentialLink"
            && edge.EdgeClass == ControlEdgeClass.CredentialExposure
            && edge.EvaluationState == ControlEvaluationState.Established);
    }

    [Fact]
    public void PartialPropertySetDenyCannotLeaveAnEstablishedAttributeGrant()
    {
        var catalogue = SchemaGuidCatalog.CapturedOver([], SchemaGuidCatalog.Embedded,
            new Dictionary<string, IReadOnlyList<string>> { [SetGuid] = ["displayName"] });
        var deny = Write(0, "AccessDeniedObject") with { ObjectTypeGuid = SetGuid };

        var edge = Assert.Single(Evaluate(Permissions(deny, Write(1)), catalogue: catalogue).Edges);

        Assert.Equal(ControlEvaluationState.Unknown, edge.EvaluationState);
    }

    [Theory]
    [InlineData("user")]
    [InlineData("computer")]
    [InlineData("inetOrgPerson")]
    [InlineData("msDS-ManagedServiceAccount")]
    [InlineData("msDS-GroupManagedServiceAccount")]
    public void AccountClassesReceivePropertyWritePermission(string objectClass)
    {
        var subject = Account(objectClass);
        Assert.Equal(ControlEvaluationState.Established, Single(Evaluate(Permissions(Write(0)), subject)).EvaluationState);
    }

    [Fact]
    public void CapturedUserAncestryIncludesAnExtendedAccountClass()
    {
        var subject = Account("user", "contosoAccount");
        Assert.Equal(ControlEvaluationState.Established, Single(Evaluate(Permissions(Write(0)), subject)).EvaluationState);
    }

    [Theory]
    [InlineData("group")]
    [InlineData("organizationalUnit")]
    [InlineData("container")]
    [InlineData("domainDNS")]
    public void KnownNonAccountsDoNotAcquireKeyCredentialCapabilities(string objectClass)
    {
        Assert.Empty(Keys(Evaluate(Permissions(Write(0)), Account(objectClass))));
    }

    [Fact]
    public void MissingClassRetainsUnknownCoverage()
    {
        var result = Evaluate(Permissions(Write(0)), Account());
        Assert.Equal((ControlEvaluationState.Unknown, false), (Single(result).EvaluationState, result.IsComplete));
    }

    [Theory]
    [InlineData(null, null, true, 0)]
    [InlineData(null, AttributeGuid, true, 0)]
    [InlineData(null, SetGuid, true, 0)]
    [InlineData(AttributeGuid, null, true, 0)]
    [InlineData(AttributeGuid, AttributeGuid, true, 0)]
    [InlineData(AttributeGuid, SetGuid, true, 0)]
    [InlineData(SetGuid, null, true, 0)]
    [InlineData(SetGuid, AttributeGuid, true, 0)]
    [InlineData(SetGuid, SetGuid, true, 0)]
    [InlineData(null, null, false, 1)]
    [InlineData(null, AttributeGuid, false, 1)]
    [InlineData(null, SetGuid, false, 1)]
    [InlineData(AttributeGuid, null, false, 1)]
    [InlineData(AttributeGuid, AttributeGuid, false, 1)]
    [InlineData(AttributeGuid, SetGuid, false, 1)]
    [InlineData(SetGuid, null, false, 1)]
    [InlineData(SetGuid, AttributeGuid, false, 1)]
    [InlineData(SetGuid, SetGuid, false, 1)]
    public void BroadAttributeAndPropertySetEntriesShareCapturedOrder(string? allowScope, string? denyScope, bool denyFirst, int count)
    {
        var entries = OrderedEntries(allowScope, denyScope, denyFirst);
        Assert.Equal(count, Keys(Evaluate(Permissions(entries), catalogue: AssignedTo(SetGuid))).Count());
    }

    [Theory]
    [InlineData(0x10, AttributeGuid)]
    [InlineData(0x08, AttributeGuid)]
    [InlineData(0x08, "9b026da6-0d3c-465c-8bee-5199d7165cba")]
    [InlineData(0x100, AttributeGuid)]
    [InlineData(0x100, PasswordResetControlTests.ResetGuid)]
    [InlineData(0x40000, AttributeGuid)]
    [InlineData(0x80000, AttributeGuid)]
    [InlineData(0x20, "bf9679c0-0de6-11d0-a285-00aa003049e2")]
    public void OtherOperationsDoNotGrantKeyCredentialWrites(int mask, string guid)
    {
        Assert.Empty(Keys(Evaluate(Permissions(Write(0) with { AccessMask = mask, ObjectTypeGuid = guid }))));
    }

    [Fact]
    public void CertificateMappingIsNotKeyCredentialWriting()
    {
        var catalogue = new SchemaGuidCatalog([.. SchemaGuidCatalog.Embedded.Entries,
            new("bbbbbbbb-1111-2222-3333-444444444444", "altSecurityIdentities", SchemaGuidKind.Attribute, SchemaGuidSource.Captured)]);
        Assert.Empty(Keys(Evaluate(Permissions(Write(0) with { ObjectTypeGuid = catalogue.GuidFor("altSecurityIdentities") }), catalogue: catalogue)));
    }

    [Fact]
    public void ExtendedRightsAloneDoNotGrantPropertyWrites()
    {
        Assert.Empty(Keys(Evaluate(Permissions(Ace(0, Holder, 0x100)))));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("invalid")]
    public void MissingOrMalformedAttributeScopeStaysUnknown(string? guid)
    {
        var edge = Single(Evaluate(Permissions(Write(0) with { ObjectTypeGuid = guid })));
        Assert.True(edge.Uncertainty.HasFlag(ControlUncertainty.KeyCredentialLinkScopeNotEvaluated));
    }

    [Fact]
    public void MissingAttributeIdentityStaysUnknown()
    {
        Assert.Equal(ControlEvaluationState.Unknown, Single(Evaluate(Permissions(Write(0)), catalogue: new SchemaGuidCatalog([]))).EvaluationState);
    }

    [Fact]
    public void CapturedAttributeIdentityWinsOverTheShippedName()
    {
        var catalogue = SchemaGuidCatalog.CapturedOver([new(SetGuid, AttributeName, SchemaGuidKind.Attribute, SchemaGuidSource.Captured)],
            SchemaGuidCatalog.Embedded, new Dictionary<string, IReadOnlyList<string>>());
        var edge = Single(Evaluate(Permissions(Write(0) with { ObjectTypeGuid = SetGuid }), catalogue: catalogue));
        Assert.Contains(edge.Preconditions, condition => condition.EvidenceSource.Contains("Captured", StringComparison.Ordinal));
    }

    [Fact]
    public void AProvenDifferentPropertySetDenyDoesNotWeakenTheGrant()
    {
        var deny = Write(0, "AccessDeniedObject") with { ObjectTypeGuid = SetGuid };
        var edge = Single(Evaluate(Permissions(deny, Write(1)), catalogue: AssignedTo("bbbbbbbb-1111-2222-3333-444444444444")));
        Assert.Equal(ControlEvaluationState.Established, edge.EvaluationState);
    }

    [Fact]
    public void APartialPropertySetAllowStaysUnknown()
    {
        var catalogue = SchemaGuidCatalog.CapturedOver([], SchemaGuidCatalog.Embedded,
            new Dictionary<string, IReadOnlyList<string>> { [SetGuid] = ["displayName"] });
        Assert.Equal(ControlEvaluationState.Unknown, Single(Evaluate(Permissions(Write(0) with { ObjectTypeGuid = SetGuid }), catalogue: catalogue)).EvaluationState);
    }

    [Theory]
    [InlineData("user", "user", ControlEvaluationState.Established)]
    [InlineData("contosoAccount", "user", ControlEvaluationState.Unknown)]
    public void ClassRootScopeRequiresTheActualCapturedClass(string targetClass, string scopeClass, ControlEvaluationState expected)
    {
        var subject = Account("user", targetClass);
        var entry = Write(0) with { ObjectTypeGuid = SchemaGuidCatalog.Embedded.GuidFor(scopeClass) };
        Assert.Equal(expected, Single(Evaluate(Permissions(entry), subject)).EvaluationState);
    }

    [Fact]
    public void AComputerClassScopedWriteDoesNotGrantAUserAttribute()
    {
        Assert.Empty(Keys(Evaluate(Permissions(Write(0) with { ObjectTypeGuid = SchemaGuidCatalog.Embedded.GuidFor("computer") }))));
    }

    [Theory]
    [InlineData("AccessAllowedCallbackObject")]
    [InlineData("UnsupportedCapturedType")]
    public void UnsupportedEntriesRemainUnknown(string type)
    {
        Assert.Equal(ControlEvaluationState.Unknown, Single(Evaluate(Permissions(Write(0, type)))).EvaluationState);
    }

    [Fact]
    public void RelevantCrossTrusteeDenyDoesNotImplyTokenAuthorization()
    {
        var edge = Single(Evaluate(Permissions(Write(0, "AccessDeniedObject", "S-1-1-0"), Write(1))));
        Assert.True(edge.Uncertainty.HasFlag(ControlUncertainty.CrossTrusteeDeny));
    }

    [Fact]
    public void UnrelatedAttributeDenyDoesNotContaminateTheOperation()
    {
        var deny = Write(0, "AccessDeniedObject", "S-1-1-0") with { ObjectTypeGuid = SchemaGuidCatalog.Embedded.GuidFor("member") };
        Assert.Equal(ControlEvaluationState.Established, Single(Evaluate(Permissions(deny, Write(1)))).EvaluationState);
    }

    [Fact]
    public void InheritOnlyDoesNotGrantOnTheCurrentObject()
    {
        Assert.Empty(Keys(Evaluate(Permissions(Write(0) with { PropagationFlags = 0x08 }))));
    }

    [Fact]
    public void InheritedOriginalScopeAndOrdinalRemainEvidence()
    {
        var entry = Write(7) with { IsInherited = true, InheritanceFlags = 2, HasInheritedObjectType = true,
            InheritedObjectTypeGuid = SchemaGuidCatalog.Embedded.GuidFor("user") };
        Assert.Equal(entry, Assert.Single(Single(Evaluate(Permissions(entry))).Evidence));
    }

    [Fact]
    public void SelfResolvesToTheAccountWithoutReplacingOriginalEvidence()
    {
        var account = Account("computer") with { Attributes = [.. Account("computer").Attributes,
            new("objectSid", AttributeCardinality.SingleValued, [new(0, Holder, null)])] };
        var edge = Single(Evaluate(Permissions(Write(0, sid: "S-1-5-10")), account));
        Assert.Equal((Holder, "S-1-5-10"), (edge.HolderSid, Assert.Single(edge.Evidence).Trustee.Sid));
    }

    [Theory]
    [InlineData("S-1-5-10")]
    [InlineData("S-1-3-0")]
    public void UnresolvedPlaceholdersDoNotBecomeEstablishedHolders(string sid)
    {
        var entry = Write(0, sid: sid);
        entry = entry with { Trustee = entry.Trustee with { WellKnownRole = WellKnownSidRole.Placeholder } };
        Assert.Equal(ControlEvaluationState.Unknown, Single(Evaluate(Permissions(entry))).EvaluationState);
    }

    [Fact]
    public void UnresolvedNamedHolderRemainsUnknown()
    {
        var entry = Write(0);
        entry = entry with { Trustee = entry.Trustee with { DistinguishedName = null } };
        Assert.True(Single(Evaluate(Permissions(entry))).Uncertainty.HasFlag(ControlUncertainty.HolderUnresolved));
    }

    [Fact]
    public void DuplicateGrantsDoNotMultiplyTheHolderCapability()
    {
        Assert.True(Single(Evaluate(Permissions(Write(0), Write(1)))).IsCounted);
    }

    [Fact]
    public void EmptyDaclGrantsNothing()
    {
        Assert.Empty(Keys(Evaluate(Permissions())));
    }

    [Fact]
    public void NullDaclGrantsEveryoneWithoutInventingAnAce()
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
    public void UnparsedDescriptorIsNotCompleteEmptyCoverage()
    {
        Assert.False(Evaluate(Permissions() with { DaclState = DaclState.Unreadable }).IsComplete);
    }

    [Fact]
    public void IncompleteDescriptorDoesNotEstablishPermission()
    {
        Assert.Equal(ControlEvaluationState.Unknown, Single(Evaluate(Permissions(Write(0)) with { DaclCompleteness = DaclCompleteness.Incomplete })).EvaluationState);
    }

    [Fact]
    public void DirectSystemGrantRetainsDescriptorNativeExpectedness()
    {
        Assert.Equal(ControlExpectednessReason.ExpectedPlatformIdentityDirectAce, Single(Evaluate(Permissions(Write(0, sid: "S-1-5-18")))).ExpectednessReason);
    }

    [Fact]
    public void IncompleteSystemGrantIsNotExpected()
    {
        Assert.Equal(ControlExpectedness.Unknown, Single(Evaluate(Permissions(Write(0, sid: "S-1-5-18")) with { DaclCompleteness = DaclCompleteness.Incomplete })).Expectedness);
    }

    [Fact]
    public void BuiltinAuthorityRetainsItsVerifiedDomainScope()
    {
        var edge = Single(Evaluate(Permissions(Write(0, sid: "S-1-5-32-544"))));
        Assert.Equal(("contoso.com", ControlExpectedness.Expected), (edge.HolderScope, edge.Expectedness));
    }

    [Theory]
    [InlineData("S-1-5-21-1-2-3-526")]
    [InlineData("S-1-5-21-1-2-3-527")]
    [InlineData("S-1-5-21-1-2-3-518")]
    [InlineData("S-1-5-21-1-2-3-1001")]
    [InlineData("S-1-1-0")]
    public void CredentialCapabilityDoesNotMakeExcludedHoldersExpected(string sid)
    {
        var result = ControlEdgeDeriver.Expected(Write(0, sid: sid).Trustee, Account("user"), "contoso.com",
            new([], MembershipRouteIncompleteReason.None), true, true, DomainSid);
        Assert.Equal(ControlExpectedness.Unexpected, result.State);
    }

    internal static IEnumerable<ControlEdge> Keys(ControlObjectEvaluation result) =>
        result.Edges.Where(edge => edge.Capability == ControlCapability.CanWriteKeyCredentialLink);

    private static ControlEdge Single(ControlObjectEvaluation result) => Assert.Single(Keys(result));

    private static ObjectAttributes Account(params string[] classes) => PasswordResetControlTests.Account with
    {
        Attributes = [new("objectClass", AttributeCardinality.MultiValued,
            classes.Select((name, index) => new AttributeValue(index, name, null)).ToArray())],
    };

    private static SchemaGuidCatalog AssignedTo(string guid) => SchemaGuidCatalog.CapturedOver([], SchemaGuidCatalog.Embedded,
        new Dictionary<string, IReadOnlyList<string>> { [guid] = [AttributeName] });

    private static PermissionEntry[] OrderedEntries(string? allowScope, string? denyScope, bool denyFirst)
    {
        var allow = Write(denyFirst ? 1 : 0) with { HasObjectType = allowScope is not null, ObjectTypeGuid = allowScope };
        var deny = Write(denyFirst ? 0 : 1, "AccessDeniedObject") with { HasObjectType = denyScope is not null, ObjectTypeGuid = denyScope };
        return denyFirst ? [deny, allow] : [allow, deny];
    }

    internal static PermissionEntry Write(int ordinal, string type = "AccessAllowedObject", string? sid = null) =>
        Ace(ordinal, sid ?? Holder, 0x20, type) with { HasObjectType = true, ObjectTypeGuid = AttributeGuid };

    internal static ControlObjectEvaluation Evaluate(ObjectPermissions? permissions, ObjectAttributes? subject = null,
        SchemaGuidCatalog? catalogue = null) => PasswordResetControlTests.Evaluate(permissions, subject, catalogue);
}
