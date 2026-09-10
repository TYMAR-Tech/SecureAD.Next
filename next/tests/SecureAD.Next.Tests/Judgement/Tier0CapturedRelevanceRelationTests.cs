using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// Covers relations discovered from captured facts before any control edge exists, per decision 0116.
/// </summary>
public sealed class Tier0CapturedRelevanceRelationTests
{
    [Fact]
    public void ACapturedCandidateNamesItsSourceWithoutRequiringAStoredEdge()
    {
        var fixture = new Tier0DiscoveryEvidence();
        var affected = fixture.Principal("Affected", "1399", "user");
        var relation = Candidate(fixture, affected, ordinal: 4);
        Assert.Equal((null, affected.DistinguishedName, (int?)4, false),
            (relation.ControlEdgeId, relation.Witness?.TargetDn, relation.Witness?.PermissionOrdinal, relation.Witness?.IsOwner));
    }

    [Fact]
    public void ANamedCapturedPermissionIsNotAnEstablishedControlOperation()
    {
        var fixture = new Tier0DiscoveryEvidence();
        var relation = Candidate(fixture, fixture.Principal("Affected", "1399", "user"));
        Assert.Equal((Tier0State.Unknown, ControlEvaluationState.Unknown,
            Tier0Limitations.ControlQualificationUnsupported | Tier0Limitations.ConditionalOperation),
            (relation.State, relation.PermissionState, relation.Limitations));
    }

    [Fact]
    public void AnOwnerWitnessCarriesNoAceOrdinalBecauseOwnershipIsNotAnEntry()
    {
        var fixture = new Tier0DiscoveryEvidence();
        var controller = fixture.Principal("Controller", "1301", "user");
        var affected = fixture.Principal("Affected", "1302", "user");
        var relation = Tier0RelevanceRelation.FromCapturedPermission(fixture.Binding, fixture.Target(controller),
            fixture.Target(affected), ControlCapability.IsOwnerAndCanRewriteDacl,
            new(affected.DistinguishedName, null, $"{fixture.DomainSid}-1301", IsOwner: true));
        Assert.True(relation.Witness!.IsOwner && relation.Witness.PermissionOrdinal is null);
    }

    [Fact]
    public void AnOwnerWitnessGivenAnAceOrdinalIsRefusedRatherThanInventingAnEntry()
    {
        var fixture = new Tier0DiscoveryEvidence();
        var controller = fixture.Principal("Controller", "1303", "user");
        var affected = fixture.Principal("Affected", "1304", "user");
        Assert.Throws<ArgumentException>(() => Tier0RelevanceRelation.FromCapturedPermission(fixture.Binding,
            fixture.Target(controller), fixture.Target(affected), ControlCapability.IsOwnerAndCanRewriteDacl,
            new(affected.DistinguishedName, 0, $"{fixture.DomainSid}-1303", IsOwner: true)));
    }

    [Fact]
    public void AWitnessNamingAnotherObjectCannotStandForThisRelation()
    {
        var fixture = new Tier0DiscoveryEvidence();
        var controller = fixture.Principal("Controller", "1305", "user");
        var affected = fixture.Principal("Affected", "1306", "user");
        var other = fixture.Principal("Other", "1307", "user");
        Assert.Throws<ArgumentException>(() => Tier0RelevanceRelation.FromCapturedPermission(fixture.Binding,
            fixture.Target(controller), fixture.Target(affected), ControlCapability.CanWriteDacl,
            new(other.DistinguishedName, 0, $"{fixture.DomainSid}-1305")));
    }

    [Fact]
    public void AnUnresolvedHolderIsRetainedWithItsUncertaintyRatherThanDropped()
    {
        var fixture = new Tier0DiscoveryEvidence();
        var relation = Candidate(fixture, fixture.Principal("Affected", "1399", "user"),
            uncertainty: ControlUncertainty.HolderUnresolved);
        Assert.Equal(ControlUncertainty.HolderUnresolved, relation.PermissionUncertainty);
    }

    /// <summary>
    /// The dedup identity must separate capabilities, because a discovered candidate has no edge id
    /// to keep it distinct. Without capability in the comparer these two collapse into one route.
    /// </summary>
    [Fact]
    public void TwoCapabilitiesFromOneHolderRemainSeparateRoutes()
    {
        var fixture = new Tier0DiscoveryEvidence();
        var root = fixture.Principal("DomainAdmins", "512");
        var controller = fixture.Principal("Controller", "1310", "user");
        var writeDacl = Tier0RelevanceRelation.FromCapturedPermission(fixture.Binding, fixture.Target(controller),
            fixture.Target(root), ControlCapability.CanWriteDacl,
            new(root.DistinguishedName, 0, $"{fixture.DomainSid}-1310"));
        var writeOwner = Tier0RelevanceRelation.FromCapturedPermission(fixture.Binding, fixture.Target(controller),
            fixture.Target(root), ControlCapability.CanSetOwner,
            new(root.DistinguishedName, 1, $"{fixture.DomainSid}-1310"));
        var result = Select(fixture, root, controller, writeDacl, writeOwner);
        Assert.Equal(2, result.For(fixture.Target(controller)).Reasons.Length);
    }

    /// <summary>
    /// Two entries granting the same right differ only by their position in the stored DACL, so the
    /// ordinal is part of the retained witness and part of the dedup identity.
    /// </summary>
    [Fact]
    public void TwoEntriesGrantingOneRightRemainSeparateRoutes()
    {
        var fixture = new Tier0DiscoveryEvidence();
        var root = fixture.Principal("DomainAdmins", "512");
        var controller = fixture.Principal("Controller", "1311", "user");
        var first = Tier0RelevanceRelation.FromCapturedPermission(fixture.Binding, fixture.Target(controller),
            fixture.Target(root), ControlCapability.CanWriteDacl,
            new(root.DistinguishedName, 0, $"{fixture.DomainSid}-1311"));
        var second = Tier0RelevanceRelation.FromCapturedPermission(fixture.Binding, fixture.Target(controller),
            fixture.Target(root), ControlCapability.CanWriteDacl,
            new(root.DistinguishedName, 7, $"{fixture.DomainSid}-1311"));
        var result = Select(fixture, root, controller, first, second);
        Assert.Equal(new int?[] { 0, 7 },
            result.For(fixture.Target(controller)).Reasons.Select(item => item.Witness?.PermissionOrdinal).ToArray());
    }

    [Fact]
    public void TheSameCapturedFactSuppliedTwiceDoesNotMultiplyWork()
    {
        var fixture = new Tier0DiscoveryEvidence();
        var root = fixture.Principal("DomainAdmins", "512");
        var controller = fixture.Principal("Controller", "1312", "user");
        var relation = Tier0RelevanceRelation.FromCapturedPermission(fixture.Binding, fixture.Target(controller),
            fixture.Target(root), ControlCapability.CanWriteDacl,
            new(root.DistinguishedName, 0, $"{fixture.DomainSid}-1312"));
        var result = Select(fixture, root, controller, relation, relation);
        Assert.Equal((1, 1), (result.Relations.Length, result.ExaminedRelations));
    }

    [Fact]
    public void ADiscoveredCandidateAdmitsItsHolderWithoutRelabellingItTier0()
    {
        var fixture = new Tier0DiscoveryEvidence();
        var root = fixture.Principal("DomainAdmins", "512");
        var controller = fixture.Principal("Controller", "1313", "user");
        var relation = Tier0RelevanceRelation.FromCapturedPermission(fixture.Binding, fixture.Target(controller),
            fixture.Target(root), ControlCapability.CanWriteDacl,
            new(root.DistinguishedName, 0, $"{fixture.DomainSid}-1313"));
        var decision = Select(fixture, root, controller, relation).For(fixture.Target(controller));
        Assert.Equal((OwnershipScopeState.Included, Tier0State.Unknown), (decision.State, decision.Classification?.State));
    }

    private static Tier0RelevanceRelation Candidate(Tier0DiscoveryEvidence fixture, ObjectAttributes affected,
        int ordinal = 0, ControlUncertainty uncertainty = ControlUncertainty.None)
    {
        var holder = fixture.Principal("Controller", "1300", "user");
        return Tier0RelevanceRelation.FromCapturedPermission(fixture.Binding, fixture.Target(holder),
            fixture.Target(affected), ControlCapability.CanWriteDacl,
            new(affected.DistinguishedName, ordinal, $"{fixture.DomainSid}-1300"), uncertainty);
    }

    private static OwnershipScopeSelection Select(Tier0DiscoveryEvidence fixture, ObjectAttributes root,
        ObjectAttributes controller, params Tier0RelevanceRelation[] relations)
    {
        var input = fixture.Input();
        var classifications = new[] { root, controller }
            .Select(item => Tier0Classifier.Classify(fixture.Binding, fixture.Target(item), input)).ToArray();
        return OwnershipScopeSelector.Select(fixture.Binding, Guid.NewGuid(), classifications, relations,
            new(true, true, true, Tier0Limitations.None));
    }
}
