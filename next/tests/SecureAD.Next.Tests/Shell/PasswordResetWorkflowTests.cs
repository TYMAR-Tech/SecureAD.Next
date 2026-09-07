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
    public void ResetPermissionAndProofReachBothRealScreenDirections(string dn, bool byHolder)
    {
        var directory = Prepared($"O:SYG:SYD:(OA;;CR;{PasswordResetControlTests.ResetGuid};;{TargetSid})");
        var hash = Hash(directory);
        Judge(directory, null);
        using var source = new BundleAssetSource();

        var section = Open(source, directory, dn, byHolder);

        var row = Assert.Single(section.Rows);
        Assert.Same(row, section.SelectedEdge);
        Assert.Equal("Password-reset permission", row.Capability);
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
    [InlineData("GA", 1)]
    [InlineData("CR", 1)]
    [InlineData("GW", 0)]
    public void RealPermissionReaderUsesGenericMappingsForTheResetOperation(string rights, int expected)
    {
        var directory = Prepared($"O:SYG:SYD:(A;;{rights};;;{TargetSid})");
        Judge(directory, null);

        using var reader = JudgementReader.Open(directory).Value;
        Assert.Equal(expected, reader.ReadControlEdges(UserDn, null, null, true, 0).Edges.Count(edge => edge.Capability == ControlCapability.CanResetPassword));
    }

    [Fact]
    public void EnablingSyntheticRequesterDiscoveryDoesNotChangeResetHolderCounts()
    {
        var directory = Prepared($"O:SYG:SYD:(OA;;CR;{PasswordResetControlTests.ResetGuid};;{TargetSid})");
        Judge(directory, null);
        using var source = new BundleAssetSource();
        var section = Open(source, directory, UserDn, false);
        Assert.Single(section.Rows);
        var counts = section.Counts;

        Judge(directory, TestBudget);
        section.FirstPageCommand.Execute(null);

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
    public void UnsupportedOrContradictoryProductClearsOldScreenProof(string mutation, string notice)
    {
        var directory = Prepared($"O:SYG:SYD:(OA;;CR;{PasswordResetControlTests.ResetGuid};;{TargetSid})");
        Judge(directory, null);
        using var source = new BundleAssetSource();
        var section = Open(source, directory, UserDn, false);
        Assert.NotNull(section.SelectedEdge);
        Assert.Single(section.Rows);

        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = mutation;
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        section.FirstPageCommand.Execute(null);

        Assert.Empty(section.Rows);
        Assert.Null(section.SelectedEdge);
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

    private static string Prepared(string descriptor)
    {
        var directory = Bundle(userDescriptor: descriptor);
        Derive(directory);
        return directory;
    }

    private static void Judge(string directory, SelfMembershipDiscoveryBudget? budget)
    {
        var result = JudgingRun.Judge(directory, [], budget, Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }

    private static ControlEdgesSectionViewModel Open(BundleAssetSource source, string directory, string dn, bool byHolder)
    {
        var screen = new AssetsViewModel(source);
        screen.Show(directory, false);
        var attributes = Assert.IsType<ObjectAttributes>(source.ReadObjectAttributes(directory, dn).Value);
        var objectClass = Assert.IsType<string>(attributes.Find("objectClass")?.Values.Last().Text);
        screen.OpenObject(new(new(dn, dn, attributes.ObjectGuid, objectClass, "DC=contoso,DC=com")));
        var opened = Assert.IsType<ObjectViewModel>(screen.Opened);
        opened.Show(ObjectSectionCatalog.ControlEdges);
        var section = Assert.IsType<ControlEdgesSectionViewModel>(opened.Selected);
        section.ByHolder = byHolder;
        return section;
    }
}
