using SecureAD.Judgement;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnershipAuditIntegrationTests
{
    [Fact]
    public void AdmittedControlAndOwnershipPrepareTheirResourceOncePerPass()
    {
        var directory = Captured($"O:SYG:SYD:(A;;0x000F01FF;;;{UserSid})");
        Derive(directory);
        using var counts = new ControlEvidencePreparationTests.Counts();
        JudgeGated(directory);
        using var reader = Open(directory);
        var page = reader.ReadControlEdges(CoreDn, null, null, true, 0);
        Assert.Equal(2L, counts.For("control.route_preparations", reader.Description.GenerationId));
        Assert.Single(page.FullControlAssessments);
        Assert.Equal((ControlEvaluationState.Unknown, false), (
            page.Edges.Single(edge => edge.Capability == ControlCapability.CanBecomeOwnerAndRewriteDacl).EvaluationState,
            page.Edges.Single(edge => edge.Capability == ControlCapability.CanBecomeOwnerAndRewriteDacl).IsCounted));
        Assert.Empty(reader.ReadControlEdges(TargetDn, null, null, true, 0).Edges);
    }
}
