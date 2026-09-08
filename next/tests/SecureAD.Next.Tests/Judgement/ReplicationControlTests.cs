using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Xunit;
using static SecureAD.Next.Tests.Judgement.ControlEdgeDeriverTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class ReplicationControlTests
{
    internal const string Root = "DC=contoso,DC=com";
    internal const string ChangesGuid = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
    internal const string AllGuid = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";
    internal const string FilteredGuid = "89e95b76-444d-4c62-991a-0facbeda640c";
    private static ObjectAttributes Target => Subject with
    {
        DistinguishedName = Root,
        Attributes = [new("objectClass", AttributeCardinality.MultiValued, [new(0, "domainDNS", null)])],
    };

    [Theory]
    [InlineData(false, false, false, 0)]
    [InlineData(true, false, false, 0)]
    [InlineData(false, true, false, 0)]
    [InlineData(false, false, true, 0)]
    [InlineData(false, true, true, 0)]
    [InlineData(true, true, false, 2)]
    [InlineData(true, false, true, 1)]
    [InlineData(true, true, true, 2)]
    public void RequiredRightsProduceExactlyTheDocumentedCapabilities(bool changes, bool all, bool filtered, int count)
    {
        var entries = new[] { (changes, ChangesGuid), (all, AllGuid), (filtered, FilteredGuid) }
            .Where(item => item.Item1).Select((item, index) => Right(index, item.Item2)).ToArray();
        Assert.Equal(count, Evaluate(Permissions(entries)).Edges.Count(edge => edge.EdgeClass == ControlEdgeClass.ReplicationControl));
    }

    [Fact]
    public void FilteredSetAloneWithChangesDoesNotClaimSecretDomainData()
    {
        Assert.Equal(ControlCapability.CanReplicateFilteredAttributes,
            Assert.Single(Edges(Permissions(Right(0, ChangesGuid), Right(1, FilteredGuid)))).Capability);
    }

    [Theory]
    [InlineData(ChangesGuid, 0)]
    [InlineData(AllGuid, 1)]
    [InlineData(FilteredGuid, 2)]
    public void DenyingOneComponentDoesNotEraseAnIndependentAlternative(string denied, int count)
    {
        var entries = new[] { Right(0, denied, "AccessDeniedObject"), Right(1, ChangesGuid), Right(2, AllGuid), Right(3, FilteredGuid) };
        Assert.Equal(count, Edges(Permissions(entries)).Count);
    }

    [Theory]
    [InlineData(true, true, true, 0)]
    [InlineData(true, false, true, 0)]
    [InlineData(false, true, true, 0)]
    [InlineData(false, false, true, 0)]
    [InlineData(true, true, false, 2)]
    [InlineData(true, false, false, 0)]
    [InlineData(false, true, false, 2)]
    [InlineData(false, false, false, 2)]
    public void BroadAndScopedChangesEntriesShareCapturedOrder(bool allowScoped, bool denyScoped, bool denyFirst, int count)
    {
        var allow = Right(0, ChangesGuid) with { HasObjectType = allowScoped, ObjectTypeGuid = allowScoped ? ChangesGuid : null };
        var deny = Right(1, ChangesGuid, "AccessDeniedObject") with { HasObjectType = denyScoped, ObjectTypeGuid = denyScoped ? ChangesGuid : null };
        var ordered = denyFirst ? new[] { deny, allow, Right(2, AllGuid) } : [allow, deny, Right(2, AllGuid)];
        Assert.Equal(count, Edges(Permissions(ordered)).Count);
    }

    [Theory]
    [InlineData(true, ControlEvaluationState.Unknown)]
    [InlineData(false, ControlEvaluationState.Established)]
    public void EarlierUnknownDenyCannotBeLostButLaterDenyCannotUndoACompletedCheck(bool unknownFirst, ControlEvaluationState state)
    {
        var unknown = Right(0, ChangesGuid, "AccessDeniedCallbackObject");
        var entries = unknownFirst ? new[] { unknown, Right(1, ChangesGuid), Right(2, AllGuid) }
            : [Right(1, ChangesGuid), unknown, Right(2, AllGuid)];
        Assert.Equal(new[] { state, state }, Edges(Permissions(entries)).Select(edge => edge.EvaluationState));
    }

    [Fact]
    public void UnknownAllRightDoesNotTaintTheEstablishedFilteredAlternative()
    {
        var edges = Edges(Permissions(Right(0, AllGuid, "AccessDeniedCallbackObject"),
            Right(1, ChangesGuid), Right(2, AllGuid), Right(3, FilteredGuid)));
        Assert.Equal(new[] { ControlEvaluationState.Unknown, ControlEvaluationState.Established }, edges.Select(edge => edge.EvaluationState));
    }

    [Fact]
    public void AScopedCrossTrusteeDenyKeepsItsOwnComponentUnknown()
    {
        var deny = Right(0, AllGuid, "AccessDeniedObject") with { Trustee = Ace(0, "S-1-1-0", 0x100).Trustee };
        Assert.Equal(ControlEvaluationState.Unknown,
            Edges(Permissions(deny, Right(1, ChangesGuid), Right(2, AllGuid)))[0].EvaluationState);
    }

    [Fact]
    public void RightsOnDifferentHoldersAreNeverCombined()
    {
        var other = Right(1, AllGuid) with { Trustee = Ace(1, "S-1-5-21-1-2-3-1300", 0x100).Trustee };
        Assert.Empty(Edges(Permissions(Right(0, ChangesGuid), other)));
    }

    [Theory]
    [InlineData(0x20)]
    [InlineData(0x08)]
    [InlineData(0x10)]
    [InlineData(0x40000)]
    [InlineData(0x80000)]
    public void OtherAccessMaskKindsDoNotEstablishReplication(int mask)
    {
        Assert.Empty(Edges(Permissions(Right(0, ChangesGuid) with { AccessMask = mask }, Right(1, AllGuid))));
    }

    [Fact]
    public void InheritOnlyChangesDoesNotApplyAtTheRoot()
    {
        Assert.Empty(Edges(Permissions(Right(0, ChangesGuid) with { PropagationFlags = 0x08 }, Right(1, AllGuid))));
    }

    [Fact]
    public void NullDaclEstablishesBothCapabilitiesForEveryoneWithoutInventingAces()
    {
        var edges = Edges(Permissions() with { DaclState = DaclState.Null });
        Assert.Equal(new[] { ("S-1-1-0", 0), ("S-1-1-0", 0) }, edges.Select(edge => (edge.HolderSid, edge.Evidence.Count)));
    }

    [Fact]
    public void EmptyDaclDoesNotEstablishReplication() => Assert.Empty(Edges(Permissions()));

    [Fact]
    public void UnreadDescriptorRetainsUnansweredObjectCoverage()
    {
        Assert.False(Evaluate(null).IsComplete);
    }

    [Fact]
    public void MissingRootMetadataKeepsCandidatesUnknown()
    {
        var result = Evaluate(Permissions(Right(0, ChangesGuid), Right(1, AllGuid)), roots: false);
        Assert.Collection(result.Edges,
            edge => Assert.True(edge.Uncertainty.HasFlag(ControlUncertainty.ReplicationRootNotEstablished)),
            edge => Assert.True(edge.Uncertainty.HasFlag(ControlUncertainty.ReplicationRootNotEstablished)));
    }

    [Theory]
    [InlineData("CN=Child,DC=contoso,DC=com")]
    [InlineData("DC=lookalike,DC=contoso,DC=com")]
    public void RootClassOrDnSuffixDoesNotMakeAChildAReplicationTarget(string dn)
    {
        Assert.Empty(Evaluate(Permissions(Right(0, ChangesGuid), Right(1, AllGuid)), Target with { DistinguishedName = dn }).Edges);
    }

    [Fact]
    public void MissingRootClassKeepsTheCapturedRootUnknown()
    {
        var result = Evaluate(Permissions(Right(0, ChangesGuid), Right(1, AllGuid)), Target with { Attributes = [] });
        Assert.Equal(new[] { ControlEvaluationState.Unknown, ControlEvaluationState.Unknown },
            result.Edges.Select(edge => edge.EvaluationState));
        Assert.All(result.Edges, ReplicationControlDeriver.ValidateStored);
    }

    [Fact]
    public void IncompleteDescriptorRemainsUnknownThroughProofValidation()
    {
        var edges = Edges(Permissions(Right(0, ChangesGuid), Right(1, AllGuid)) with { DaclCompleteness = DaclCompleteness.Incomplete });
        Assert.Equal(new[] { ControlEvaluationState.Unknown, ControlEvaluationState.Unknown }, edges.Select(edge => edge.EvaluationState));
        Assert.All(edges, ReplicationControlDeriver.ValidateStored);
    }

    [Fact]
    public void MissingObjectTypeGuidIsRetainedAsUnknownRatherThanAWholeObjectGrant()
    {
        var edges = Edges(Permissions(Right(0, ChangesGuid) with { ObjectTypeGuid = null }, Right(1, AllGuid)));
        Assert.Equal(new[] { ControlEvaluationState.Unknown, ControlEvaluationState.Unknown }, edges.Select(edge => edge.EvaluationState));
        Assert.All(edges, ReplicationControlDeriver.ValidateStored);
    }

    [Theory]
    [InlineData(NamingContextKind.Configuration, "CN=Configuration,DC=contoso,DC=com", "configuration")]
    [InlineData(NamingContextKind.Schema, "CN=Schema,CN=Configuration,DC=contoso,DC=com", "dMD")]
    public void NonDomainTargetsKeepTheirExactPartitionAndUnverifiedResourceContext(NamingContextKind kind, string dn, string objectClass)
    {
        var target = Target with { DistinguishedName = dn, Attributes = [new("objectClass", AttributeCardinality.MultiValued, [new(0, objectClass, null)])] };
        var context = Context with { NamingContexts = new Dictionary<string, NamingContextKind> { [dn] = kind } };
        var result = ControlEdgeDeriver.Derive(target, Permissions(Right(0, ChangesGuid), Right(1, AllGuid)), context, Guid.Empty, null, DomainSid);
        Assert.Equal(new[] { (dn, kind.ToString(), ControlEvaluationState.Unknown), (dn, kind.ToString(), ControlEvaluationState.Unknown) },
            result.Edges.Select(edge => (edge.Target, edge.ReplicationNamingContextKind, edge.EvaluationState)));
    }

    [Fact]
    public void SchemaAdministrationDoesNotAutomaticallyMakeReplicationExpected()
    {
        var result = ControlEdgeDeriver.Expected(Ace(0, "S-1-5-21-1-2-3-518", 0x100).Trustee,
            Target with { DistinguishedName = "CN=Schema,CN=Configuration,DC=contoso,DC=com" }, "contoso.com",
            new([], MembershipRouteIncompleteReason.None), true, true, DomainSid, replication: true);
        Assert.Equal((ControlExpectedness.Unknown, ControlExpectednessReason.UnknownCapabilityScope), result);
    }

    [Theory]
    [InlineData("S-1-1-0", ControlExpectedness.Unexpected)]
    [InlineData("S-1-5-18", ControlExpectedness.Expected)]
    [InlineData("S-1-5-9", ControlExpectedness.Unknown)]
    public void PlatformExpectednessRemainsIndependentOfReplication(string sid, ControlExpectedness expected)
    {
        var entries = new[] { Right(0, ChangesGuid), Right(1, AllGuid) }.Select(entry => entry with { Trustee = Ace(0, sid, 0x100).Trustee }).ToArray();
        Assert.Equal(new[] { expected, expected }, Edges(Permissions(entries)).Select(edge => edge.Expectedness));
    }

    [Theory]
    [InlineData(null, ControlEvaluationState.Unknown)]
    [InlineData("other.contoso.com", ControlEvaluationState.Unknown)]
    [InlineData("contoso.com", ControlEvaluationState.Established)]
    public void BuiltinReplicationRequiresVerifiedTargetDomainContext(string? domain, ControlEvaluationState expected)
    {
        var entries = new[] { Right(0, ChangesGuid), Right(1, AllGuid) }
            .Select(entry => entry with { Trustee = Ace(0, "S-1-5-32-544", 0x100).Trustee }).ToArray();
        var result = Evaluate(Permissions(entries), Target with { DomainFqdn = domain });
        Assert.Equal(new[] { expected, expected }, result.Edges.Select(edge => edge.EvaluationState));
        Assert.All(result.Edges, ReplicationControlDeriver.ValidateStored);
    }

    internal static PermissionEntry Right(int ordinal, string guid, string type = "AccessAllowedObject") =>
        Ace(ordinal, Holder, 0x100, type) with { HasObjectType = true, ObjectTypeGuid = guid };
    private static JudgingContext Context => JudgingContext.At(DateTimeOffset.UnixEpoch) with
    {
        ForestFqdn = "contoso.com",
        NamingContexts = new Dictionary<string, NamingContextKind>(StringComparer.OrdinalIgnoreCase) { [Root] = NamingContextKind.Domain },
    };
    internal static ControlObjectEvaluation Evaluate(ObjectPermissions? permissions, ObjectAttributes? target = null, bool roots = true) =>
        ControlEdgeDeriver.Derive(target ?? Target, permissions, roots ? Context : Context with { NamingContexts = null }, Guid.Empty, null, DomainSid);
    private static List<ControlEdge> Edges(ObjectPermissions permissions) =>
        Evaluate(permissions).Edges.Where(edge => edge.EdgeClass == ControlEdgeClass.ReplicationControl).ToList();
}
