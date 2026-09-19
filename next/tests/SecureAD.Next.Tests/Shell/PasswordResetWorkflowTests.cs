using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class PasswordResetWorkflowTests
{
    [Theory]
    [InlineData(UserDn, false)]
    [InlineData(TargetDn, true)]
    public async Task ResetPermissionAndProofReachBothRealScreenDirections(string dn, bool byHolder)
    {
        var directory = Prepared($"O:SYG:SYD:(OA;;CR;{PasswordResetControlTests.ResetGuid};;{TargetSid})");
        var hash = Hash(directory);
        Judge(directory, null);
        using var source = new BundleAssetSource();

        var section = await MemberAttributionPresentationTests.OpenAsync(source, directory, dn, byHolder);

        // The reset permission is this test's subject. The holder view also carries the existing-owner
        // edge from the fixture's Tier-0 route, which is a real captured fact rather than noise, so
        // the row is selected by capability instead of by being the only one present.
        var row = Assert.Single(section.Rows, item => item.Capability == "Password-reset permission");
        Assert.Same(row, section.SelectedEdge);
        Assert.Equal("Established", row.Evaluation);
        Assert.Contains("Category: CredentialExposure", row.Evidence);
        Assert.Contains(PasswordResetControlTests.ResetGuid, row.Evidence);
        Assert.Contains(TargetSid, row.Evidence);
        Assert.Contains("Permission evidence only. A password reset and subsequent sign-in have not been tested.", row.Evidence);
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Contains(reader.Description.GenerationId.ToString(), row.Evidence);
        Assert.Equal("NotStarted", reader.ReadSelfMembershipSummary()!.Verdict);
        Assert.Equal(hash, Hash(directory));
    }

    [Theory]
    [InlineData("0x000f01ff", 1)]
    [InlineData("GA", 0)]
    [InlineData("CR", 1)]
    [InlineData("GW", 0)]
    public void RealPermissionReaderUsesStoredBitsForTheResetOperation(string rights, int expected)
    {
        var directory = Prepared($"O:SYG:SYD:(A;;{rights};;;{TargetSid})");
        Judge(directory, null);

        using var reader = JudgementReader.Open(directory).Value;
        Assert.Equal(expected, reader.ReadControlEdges(UserDn, null, null, true, 0).Edges.Count(edge => edge.Capability == ControlCapability.CanResetPassword));
    }

    [Fact]
    public async Task EnablingSyntheticRequesterDiscoveryDoesNotChangeResetHolderCounts()
    {
        // The requester answers link to self-membership edges on the target group, so the group has
        // to be assessed for those links to exist.
        var directory = Prepared($"O:SYG:SYD:(OA;;CR;{PasswordResetControlTests.ResetGuid};;{TargetSid})",
            tier0RouteFromTarget: true);
        Judge(directory, null);
        using var source = new BundleAssetSource();
        var section = await MemberAttributionPresentationTests.OpenAsync(source, directory, UserDn, false);
        Assert.Single(section.Rows);
        var counts = section.Counts;

        Judge(directory, TestBudget);
        source.SelectRun(directory);
        section = await MemberAttributionPresentationTests.OpenAsync(source, directory, UserDn, false);

        Assert.Single(section.Rows);
        Assert.Equal(counts, section.Counts);
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Equal(2, reader.ReadSelfMembershipAssessments(TargetDn, null).Assessments.Count);
        Assert.All(reader.ReadSelfMembershipAssessments(TargetDn, null).Assessments,
            assessment => Assert.Single(assessment.HolderEdgeIds));
    }

    [Theory]
    [InlineData("UPDATE control_product SET engine_version = 2", "not derived")]
    [InlineData("UPDATE control_edge SET edge_class = 'DirectoryControl' WHERE capability = 'CanResetPassword'", "could not be read")]
    public async Task UnsupportedOrContradictoryProductClearsOldScreenProof(string mutation, string notice)
    {
        var directory = Prepared($"O:SYG:SYD:(OA;;CR;{PasswordResetControlTests.ResetGuid};;{TargetSid})");
        Judge(directory, null);
        using var source = new BundleAssetSource();
        var section = await MemberAttributionPresentationTests.OpenAsync(source, directory, UserDn, false);
        Assert.NotNull(section.SelectedEdge);
        Assert.Single(section.Rows);

        source.CloseRun();
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = mutation;
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        source.SelectRun(directory);
        section.FirstPageCommand.Execute(null);
        await section.ReadCompletion;

        Assert.Empty(section.Rows);
        Assert.Null(section.SelectedEdge);
        section = await MemberAttributionPresentationTests.OpenAsync(source, directory, UserDn, false);
        Assert.Contains(notice, section.Coverage);
    }

    [Fact]
    public void Schema18CannotBeReadAsAnEvaluatedResetProduct()
    {
        var directory = Prepared($"O:SYG:SYD:(OA;;CR;{PasswordResetControlTests.ResetGuid};;{TargetSid})");
        Judge(directory, null);
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE judgement SET schema_version = 18";
            Assert.Equal(1, command.ExecuteNonQuery());
        });

        var result = JudgementReader.Open(directory);

        Assert.False(result.IsSuccess);
    }

    private static string Prepared(string descriptor, bool tier0RouteFromTarget = false)
    {
        // Resetting an account's password is a route to using that account, so a target reachable
        // from Tier 0 is what makes the grant worth assessing.
        var directory = Bundle(userDescriptor: descriptor, tier0Route: true, tier0RouteFromTarget: tier0RouteFromTarget);
        Derive(directory);
        return directory;
    }

    private static void Judge(string directory, SelfMembershipDiscoveryBudget? budget)
    {
        var result = JudgingRun.Judge(directory, [], budget, Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }

}
