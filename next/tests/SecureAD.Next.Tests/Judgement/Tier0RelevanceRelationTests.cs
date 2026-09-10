using SecureAD.Derivation;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Derivation;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class Tier0RelevanceRelationTests
{
    [Fact]
    public void DirectionFollowsTheAffectedObjectNotEverythingAControllerManages()
    {
        var (input, controller, affected, edge) = Source();
        var relation = Tier0RelevanceRelation.FromControlEdge(input, controller, affected, edge);
        Assert.Equal((true, false), (relation.IsIncomingTo(affected), relation.IsIncomingTo(controller)));
    }

    [Theory]
    [InlineData(ControlCapability.CanSetOwner)]
    [InlineData(ControlCapability.CanWriteDacl)]
    [InlineData(ControlCapability.CanResetPassword)]
    [InlineData(ControlCapability.CanBecomeOwnerAndRewriteDacl)]
    public void AnEstablishedNamedPermissionDoesNotAutomaticallyQualifyOperationalTier0(ControlCapability capability)
    {
        var (input, controller, affected, edge) = Source();
        var relation = Tier0RelevanceRelation.FromControlEdge(input, controller, affected, edge with { Capability = capability });
        Assert.Equal((Tier0State.Unknown, ControlEvaluationState.Established), (relation.State, relation.PermissionState));
    }

    [Fact]
    public void ExpectednessDoesNotChangeRelevance()
    {
        var (input, controller, affected, edge) = Source();
        var original = Tier0RelevanceRelation.FromControlEdge(input, controller, affected, edge);
        var expected = Tier0RelevanceRelation.FromControlEdge(input, controller, affected, edge with { Expectedness = ControlExpectedness.Expected });
        Assert.Equal(original, expected);
    }

    [Fact]
    public void AHolderMismatchCannotAttachProofToAnotherController()
    {
        var (input, controller, affected, edge) = Source();
        Assert.Throws<ArgumentException>(() => Tier0RelevanceRelation.FromControlEdge(input, controller, affected,
            edge with { HolderSid = "S-1-5-21-1-2-3-1300" }));
    }

    [Fact]
    public void AResourceScopeMismatchCannotAttachProofToTheController()
    {
        var (input, controller, affected, edge) = Source();
        Assert.Throws<ArgumentException>(() => Tier0RelevanceRelation.FromControlEdge(input, controller, affected,
            edge with { HolderScope = "another.com" }));
    }

    [Fact]
    public void ATargetGuidMismatchCannotAttachProofToAnotherObject()
    {
        var (input, controller, affected, edge) = Source();
        Assert.Throws<ArgumentException>(() => Tier0RelevanceRelation.FromControlEdge(input, controller, affected,
            edge with { TargetGuid = Guid.NewGuid() }));
    }

    [Fact]
    public void ARelationCannotMixDerivationGenerations()
    {
        var (input, controller, affected, edge) = Source();
        Assert.Throws<ArgumentException>(() => Tier0RelevanceRelation.FromControlEdge(input, controller, affected,
            edge with { DerivationGenerationId = Guid.NewGuid() }));
    }

    [Fact]
    public void AnUnpersistedEdgeDoesNotBecomeAStoredProofReference()
    {
        var (input, controller, affected, edge) = Source();
        Assert.Throws<ArgumentException>(() => Tier0RelevanceRelation.FromControlEdge(input, controller, affected, edge with { Id = 0 }));
    }

    [Theory]
    [InlineData(1)] [InlineData(4)]
    public void UnsupportedSourceCataloguesAreRejected(int version)
    {
        var (input, controller, affected, edge) = Source();
        Assert.Throws<ArgumentException>(() => Tier0RelevanceRelation.FromControlEdge(input, controller, affected,
            edge with { PrincipalCatalogueVersion = version }));
    }

    [Fact]
    public void ACompatibleHistoricalPermissionKeepsItsOriginalCatalogueIdentity()
    {
        var (input, controller, affected, edge) = Source();
        var relation = Tier0RelevanceRelation.FromControlEdge(input, controller, affected, edge with { PrincipalCatalogueVersion = 2 });
        Assert.Equal(2, relation.EdgeCatalogueVersion);
    }

    [Fact]
    public void AQualifiedMembershipSupportCreatesADirectedRelationWithoutExpansion()
    {
        var evidence = new Tier0TestEvidence();
        var member = evidence.Principal("Member", "S-1-5-21-1-2-3-1200", "user");
        var root = evidence.Principal("Root", "S-1-5-21-1-2-3-512", "group",
            Tier0TestEvidence.Attribute("groupType", "-2147483646"), Tier0TestEvidence.Attribute("member", member.DistinguishedName));
        var classification = Tier0Classifier.Classify(evidence.Binding, evidence.Target(member), evidence.Input(member, root), evidence.Routes(member, root));
        var relation = Tier0RelevanceRelation.FromMembership(classification, 0);
        Assert.Equal((evidence.Target(member), evidence.Target(root), Tier0State.Established), (relation.Controller, relation.Affected, relation.State));
    }

    [Fact]
    public void ACoreIdentityCannotBePresentedAsAMembershipWitness()
    {
        var evidence = new Tier0TestEvidence();
        var root = evidence.Principal("Root", "S-1-5-21-1-2-3-512");
        var classification = Tier0Classifier.Classify(evidence.Binding, evidence.Target(root), evidence.Input(root));
        Assert.Throws<ArgumentException>(() => Tier0RelevanceRelation.FromMembership(classification, 0));
    }

    internal static (Tier0InputBinding Input, Tier0Target Controller, Tier0Target Affected, ControlEdge Edge) Source()
    {
        var evidence = new Tier0TestEvidence();
        var controller = evidence.Target(evidence.Principal("Controller", "S-1-5-21-1-2-3-1200", "user"));
        var affected = evidence.Target(evidence.Principal("Root", "S-1-5-21-1-2-3-512"));
        var edge = new ControlEdge(1, affected.ObjectGuid, affected.DistinguishedName, "group", "S-1-5-21-1-2-3-1200",
            "Controller", null, ControlCapability.CanSetOwner, ControlEvaluationState.Established, ControlUncertainty.None,
            ControlExpectedness.Unexpected, ControlExpectednessReason.UnexpectedNotControlPlane, 3, Guid.NewGuid(),
            evidence.Generation, true, [], [], MembershipRouteSummary.NotDerived);
        return (evidence.Binding, controller, affected, edge);
    }
}
