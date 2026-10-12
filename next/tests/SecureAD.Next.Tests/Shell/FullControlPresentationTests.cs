using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Judgement.FullControlEvaluatorTests;
using static SecureAD.Next.Tests.Judgement.FullControlStorageTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class FullControlPresentationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void BothDirectionsShowSummaryAndIncludedPermissions(bool byHolder)
    {
        using var reader = Open(Store([Evaluation(Allow(0))]));
        var vm = Model(reader);
        vm.ByHolder = byHolder;
        Assert.Equal(new[] { "Counted once", "Included in full-control count — not counted again", "Included in full-control count — not counted again", "Not counted" },
            vm.Rows.Select(row => row.CountStatus));
    }

    [Fact]
    public void SummaryShowsPermissionOnlyCaveatAndOriginalProof()
    {
        using var reader = Open(Store([Evaluation(Allow(0))]));
        var row = Model(reader).Rows[0];
        Assert.Contains("Permission evidence only. No directory operation was performed.", row.Evidence);
    }

    [Fact]
    public void IndependentRouteWarningComesFromStoredProof()
    {
        using var reader = Open(Store([Evaluation(Allow(0), Allow(1))]));
        Assert.Contains("Removing one complete grant route alone leaves another route to full-control permissions.", Model(reader).Rows[0].Evidence);
    }

    [Fact]
    public void DenyDependentLaterGrantDoesNotProduceIndependentRouteWarning()
    {
        using var reader = Open(Store([Evaluation(Allow(0), Deny(1, FullMask), Allow(2))]));
        Assert.DoesNotContain("Removing one complete grant route alone", Model(reader).Rows[0].Evidence);
    }

    [Fact]
    public void UnknownSummaryStatesWhyItAddsNoCount()
    {
        var deny = Deny(0, 0x10000) with { AceType = "AccessDeniedObject", HasObjectType = true };
        using var reader = Open(Store([Evaluation(deny, Allow(1))]));
        Assert.Contains("Available permissions remain visible; no full-control summary is counted.", Model(reader).Rows[0].Evidence);
    }

    [Fact]
    public void BrokenSummaryExplainsSurvivingCounts()
    {
        using var reader = Open(Store([Evaluation(Deny(0, 0x10000), Allow(1))]));
        Assert.Contains("Surviving permissions are shown and counted separately.", Model(reader).Rows[0].Evidence);
    }

    [Fact]
    public void CountExplanationDoesNotConfuseExpectednessWithEstablishment()
    {
        using var reader = Open(Store([Evaluation(Allow(0))]));
        Assert.Contains("Unknown full-control assessments add no count. Other unknown candidates retain their existing counting behavior.", Model(reader).Counts);
    }

    [Fact]
    public void ReplicationCapabilitiesKeepTheirVisibleCategoryGroup()
    {
        var result = Judgement.ReplicationControlTests.Evaluate(Judgement.ControlEdgeDeriverTests.Permissions(Allow(0)));
        using var reader = Open(Store([result]));
        var page = reader.ReadControlEdges(null, null, null, true, 0);
        var rows = page.Edges.Where(edge => edge.EdgeClass == ControlEdgeClass.ReplicationControl)
            .Select(edge => new ControlEdgeRowViewModel(edge, page.FullControlSupports.ContainsKey(edge.Id))).ToArray();
        Assert.All(rows, row => Assert.Equal((true, "Included in full-control count — not counted again"),
            (row.Group.StartsWith("Replication permissions", StringComparison.Ordinal), row.CountStatus)));
        Assert.Equal(2, rows.Length);
    }

    [Fact]
    public void CredentialCapabilitiesRemainVisibleAndIncluded()
    {
        var result = Judgement.PasswordResetControlTests.Evaluate(Judgement.ControlEdgeDeriverTests.Permissions(Allow(0)));
        using var reader = Open(Store([result]));
        var page = reader.ReadControlEdges(null, null, null, true, 0);
        var credentials = page.Edges.Where(edge => edge.EdgeClass == ControlEdgeClass.CredentialExposure).ToArray();
        Assert.Equal(new[] { ControlCapability.CanResetPassword, ControlCapability.CanWriteKeyCredentialLink, ControlCapability.CanWriteServicePrincipalName }.Order(),
            credentials.Select(edge => edge.Capability).Order());
        Assert.All(credentials, edge => Assert.True(page.FullControlSupports.ContainsKey(edge.Id)));
    }

    [Fact]
    public void OwnAccountCandidateRemainsSeparateFromGeneralMembershipSupport()
    {
        var result = Judgement.GroupMembershipControlTests.Membership(Judgement.ControlEdgeDeriverTests.Permissions(Allow(0)));
        using var reader = Open(Store([result]));
        var page = reader.ReadControlEdges(null, null, null, true, 0);
        var own = Assert.Single(page.Edges.Where(edge => edge.Capability == ControlCapability.CanAddSelfToGroup));
        Assert.Equal((ControlEvaluationState.Unknown, true, false), (own.EvaluationState, own.IsCounted, page.FullControlSupports.ContainsKey(own.Id)));
    }

    internal static ControlEdgesSectionViewModel Model(JudgementReader reader)
    {
        var vm = new ControlEdgesSectionViewModel(new(ObjectSectionCatalog.ControlEdges, "Control edges", []));
        vm.Configure(true, false, (holder, expected, after) => Result<ControlEdgePage>.Success(reader.ReadControlEdges(
            holder ? null : Judgement.ControlEdgeDeriverTests.Subject.DistinguishedName,
            holder ? Judgement.ControlEdgeDeriverTests.Holder : null, null, expected, after)),
            _ => Result<SelfMembershipAssessmentSet>.Success(new([], true, reader.Description.GenerationId)));
        return vm;
    }
}
