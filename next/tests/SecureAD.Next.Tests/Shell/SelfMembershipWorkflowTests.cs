using SecureAD.Cli;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class SelfMembershipWorkflowTests
{
    [Theory]
    [InlineData(TargetDn)]
    [InlineData(UserDn)]
    public async Task StoredRequesterAnswersReachBothRealObjectViews(string dn)
    {
        var directory = Bundle();
        Derive(directory);
        Judge(directory, TestBudget);
        using var source = new BundleAssetSource();
        var screen = new AssetsViewModel(source);
        screen.Show(directory, false);

        var section = await OpenAsync(screen, source, directory, dn);

        Assert.Equal(new[]
        {
            ("Add to group", "Authorized", "Own account only", "Not ready"),
            ("Remove from group", "Authorized", "Own account only", "Ready from capture"),
        }, section.RequesterAssessments.Select(row => (row.Operation, row.Authorization, row.OwnAccount, row.Readiness)));
    }

    [Theory]
    [InlineData(UserSid, "The permission names the requester's current identity directly.")]
    [InlineData(TargetSid, "same-domain global security group with the requester explicitly listed as a member")]
    [InlineData("S-1-5-10", "same-domain global security group with the requester explicitly listed as a member")]
    public async Task SelectedProofKeepsTheCapturedTrusteeAndResolvedRoute(string trustee, string explanation)
    {
        var directory = Bundle($"O:SYG:SYD:(OA;;SW;bf9679c0-0de6-11d0-a285-00aa003049e2;;{trustee})");
        var originalSeal = Hash(directory);
        Derive(directory);
        Judge(directory, TestBudget);
        using var source = new BundleAssetSource();
        var screen = new AssetsViewModel(source);
        screen.Show(directory, false);
        var section = await OpenAsync(screen, source, directory, TargetDn);
        Assert.Equal(2, section.RequesterAssessments.Count);

        section.SelectedRequesterAssessment = section.RequesterAssessments[1];

        var selected = Assert.IsType<SelfMembershipAssessmentRowViewModel>(section.SelectedRequesterAssessment);
        Assert.Contains("Operation: Remove from group", selected.Evidence);
        Assert.Contains($"Original trustee SID: {trustee}; access mask: 0x00000008", selected.Evidence);
        Assert.Contains(explanation, selected.Evidence);
        Assert.Contains($"Evidence fingerprint: {Summary(directory).EvidenceSeal}", selected.Evidence);
        Assert.Contains($"Judgement generation: {Summary(directory).GenerationId}", selected.Evidence);
        Assert.Equal(originalSeal, Hash(directory));
    }

    [Fact]
    public async Task RequesterAnswersDoNotIncreaseTheRealScreenHolderCounts()
    {
        // Adding yourself to a group is a route to whatever that group can reach.
        var directory = Bundle(tier0Route: true, tier0RouteFromTarget: true);
        Derive(directory);
        Judge(directory, null);
        using var source = new BundleAssetSource();
        var screen = new AssetsViewModel(source);
        screen.Show(directory, false);
        var section = await OpenAsync(screen, source, directory, TargetDn);
        Assert.Empty(section.RequesterAssessments);
        Assert.Single(section.Rows);
        var counts = section.Counts;

        Judge(directory, TestBudget);
        source.SelectRun(directory);
        screen.Show(directory, false);
        section = await OpenAsync(screen, source, directory, TargetDn);

        Assert.Equal(2, section.RequesterAssessments.Count);
        Assert.Single(section.Rows);
        Assert.Equal(counts, section.Counts);
    }

    [Fact]
    public async Task RejudgingWithoutDiscoveryCannotRetainAnOlderSelectedAnswer()
    {
        var directory = Bundle();
        Derive(directory);
        Judge(directory, TestBudget);
        var originalGeneration = Summary(directory).GenerationId;
        using var source = new BundleAssetSource();
        var screen = new AssetsViewModel(source);
        screen.Show(directory, false);
        var section = await OpenAsync(screen, source, directory, UserDn);
        Assert.Equal(2, section.RequesterAssessments.Count);
        Assert.NotNull(section.SelectedRequesterAssessment);

        Judge(directory, null);
        source.SelectRun(directory);
        screen.Show(directory, false);
        section = await OpenAsync(screen, source, directory, UserDn);

        Assert.NotEqual(originalGeneration, Summary(directory).GenerationId);
        Assert.Empty(section.RequesterAssessments);
        Assert.Null(section.SelectedRequesterAssessment);
        Assert.Contains("No concrete requester request was scheduled", section.RequesterCoverage);
        Assert.Contains("This is not a refusal result", section.RequesterCoverage);
    }

    [Fact]
    public async Task UnreadableStoredCoverageClearsTheActualScreenWithoutHidingValidHolderEdges()
    {
        var directory = Bundle(tier0Route: true, tier0RouteFromTarget: true);
        Derive(directory);
        Judge(directory, TestBudget);
        using var source = new BundleAssetSource();
        var screen = new AssetsViewModel(source);
        screen.Show(directory, false);
        var section = await OpenAsync(screen, source, directory, TargetDn);
        Assert.Equal(2, section.RequesterAssessments.Count);
        Assert.NotNull(section.SelectedRequesterAssessment);
        var counts = section.Counts;

        source.CloseRun();
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE self_membership_discovery SET coverage_json = 'null'";
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        source.SelectRun(directory);
        screen.Show(directory, false);
        section = await OpenAsync(screen, source, directory, TargetDn);

        Assert.Empty(section.RequesterAssessments);
        Assert.Null(section.SelectedRequesterAssessment);
        Assert.Contains("requester assessments could not be read", section.RequesterCoverage);
        Assert.Single(section.Rows);
        Assert.Equal(counts, section.Counts);
    }

    [Fact]
    public async Task UnconfiguredShellReportsNoScanRatherThanNoAuthorizedRequestersAsync()
    {
        var directory = Bundle();

        var completion = await RunShellAsync(directory, null);

        var summary = Summary(directory);
        Assert.Equal("NotStarted", summary.Verdict);
        Assert.Equal(0, summary.AssessmentsStored);
        Assert.Equal(0, summary.Discovery.ObjectsVisited);
        Assert.Equal(SelfMembershipDiscoveryReason.ProductionBudgetNotConfigured, Assert.Single(summary.Discovery.Limitations).Reason);
        Assert.Contains("Own-account membership questions were not scheduled: no processing limit is configured", completion.JudgingReport);
        Assert.Contains("This is not a finding that nobody can add themselves to a group", completion.JudgingReport);
    }

    [Theory]
    [InlineData(0, "ProcessingStopped", "the scan stopped at its configured limit before reading everything captured")]
    [InlineData(1000, "CapturedInputScanFinished", "from 1 discovered account/group pair(s)")]
    public async Task ShellCompletionDistinguishesStoppedAndFinishedSyntheticScansAsync(int pairs, string verdict, string report)
    {
        var directory = Bundle();

        var completion = await RunShellAsync(directory, TestBudget with { Pairs = pairs });

        Assert.Equal(verdict, Summary(directory).Verdict);
        Assert.Contains(report, completion.JudgingReport);
    }

    [Fact]
    public async Task CliOfflineJudgingWithTheProductionNullBudgetStoresAnInactiveScanAsync()
    {
        var directory = Bundle();
        Derive(directory);
        var originalSeal = Hash(directory);
        var options = Assert.IsType<CommandLine>(CommandLine.Parse(["--judge", directory]));

        var exit = await Program.RunAsync(options, CancellationToken.None, discoveryBudget: null,
            capture: _ => throw new InvalidOperationException("Offline judging must not capture."));

        Assert.Equal(0, exit);
        var summary = Summary(directory);
        Assert.Equal("NotStarted", summary.Verdict);
        Assert.Equal(0, summary.AssessmentsStored);
        Assert.Equal(0, summary.Discovery.ObjectsVisited);
        Assert.Equal(SelfMembershipDiscoveryReason.ProductionBudgetNotConfigured, Assert.Single(summary.Discovery.Limitations).Reason);
        Assert.Equal(originalSeal, Hash(directory));
    }

    private static async Task<NewAuditViewModel> RunShellAsync(string directory, SelfMembershipDiscoveryBudget? budget)
    {
        var settings = new FakeSettingsStore { Stored = new ShellSettings(Path.GetDirectoryName(directory)!, DomainsAtOnce: null) };
        var location = new RunLibraryLocation(settings);
        location.Load();
        var capture = new FakeCaptureLauncher { Outcome = new CaptureOutcome(true, directory) };
        var screen = new NewAuditViewModel(location, capture, new FakeNewAuditDialog(), new FakeRunOpener(),
            new DerivationLauncher(), new JudgingLauncher(budget), new DomainConcurrency(settings));
        await screen.OpenAsync();
        await screen.StartAsync();
        return screen;
    }

    private static SelfMembershipSummary Summary(string directory)
    {
        var result = JudgementReader.Open(directory);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var reader = result.Value;
        return Assert.IsType<SelfMembershipSummary>(reader.ReadSelfMembershipSummary());
    }

    private static void Judge(string directory, SelfMembershipDiscoveryBudget? budget)
    {
        var result = JudgingRun.Judge(directory, [], budget, Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }

    private static async Task<ControlEdgesSectionViewModel> OpenAsync(AssetsViewModel screen, BundleAssetSource source, string directory, string dn)
    {
        await screen.ReadCompletion;
        var result = source.ReadObjectAttributes(directory, dn);
        Assert.True(result.IsSuccess, result.Error?.Description);
        var attributes = Assert.IsType<ObjectAttributes>(result.Value);
        var objectClass = Assert.IsType<string>(attributes.Find("objectClass")?.Values.Last().Text);
        screen.OpenObject(new(new(dn, dn, attributes.ObjectGuid, objectClass, "DC=contoso,DC=com")));
        await screen.ReadCompletion;
        var opened = Assert.IsType<ObjectViewModel>(screen.Opened);
        opened.Show(ObjectSectionCatalog.ControlEdges);
        await opened.ReadCompletion;
        return Assert.IsType<ControlEdgesSectionViewModel>(opened.Selected);
    }
}
