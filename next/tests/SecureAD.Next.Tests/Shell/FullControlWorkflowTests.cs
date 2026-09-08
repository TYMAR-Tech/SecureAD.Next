using SecureAD.Judgement;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class FullControlWorkflowTests
{
    [Fact]
    public void SealedEvidenceFlowsThroughJudgingIntoAFullControlSummary()
    {
        var directory = OwnershipWorkflowTests.Prepared($"O:SYG:SYD:(A;;0x000F0000;;;{UserSid})(A;;0x000001FF;;;{UserSid})");
        using var reader = Judgement.FullControlStorageTests.Open(directory);
        var page = reader.ReadControlEdges(TargetDn, null, null, true, 0);
        Assert.Equal(ControlEvaluationState.Established, Assert.Single(page.FullControlAssessments).EvaluationState);
    }

    [Fact]
    public void ExistingOwnerControlKeepsItsIndependentCountBesideFullControl()
    {
        var directory = OwnershipWorkflowTests.Prepared($"O:{UserSid}G:SYD:(A;;0x000F01FF;;;{UserSid})");
        using var reader = Judgement.FullControlStorageTests.Open(directory);
        var page = reader.ReadControlEdges(TargetDn, null, null, true, 0);
        var owner = Assert.Single(page.Edges.Where(edge => edge.Capability == ControlCapability.IsOwnerAndCanRewriteDacl));
        Assert.Equal((ControlEvaluationState.Established, true, false), (owner.EvaluationState, owner.IsCounted, page.FullControlSupports.ContainsKey(owner.Id)));
    }

    [Fact]
    public void FullControlDoesNotDischargeTheLiveOwnerChangeGate()
    {
        var directory = OwnershipWorkflowTests.Prepared($"O:{UserSid}G:SYD:(A;;0x000F01FF;;;{UserSid})");
        using var reader = Judgement.FullControlStorageTests.Open(directory);
        var page = reader.ReadControlEdges(TargetDn, null, null, true, 0);
        var transition = Assert.Single(page.Edges.Where(edge => edge.Capability == ControlCapability.CanBecomeOwnerAndRewriteDacl));
        Assert.Equal((ControlEvaluationState.Unknown, false, false), (transition.EvaluationState, transition.IsCounted, page.FullControlSupports.ContainsKey(transition.Id)));
    }
}
