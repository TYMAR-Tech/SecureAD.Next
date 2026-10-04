using Microsoft.Data.Sqlite;
using SecureAD.Audit.Capture;
using SecureAD.Cli;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Capture;
using SecureAD.Shell.Services;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests
{
    [Fact]
    public void CoverageRecordsEverySupportedQuestionFamily()
    {
        var directory = CoverageCapture();
        Derive(directory);
        JudgeCoverage(directory);
        using var reader = Open(directory);

        Assert.Equal(new[] { (PathRequesterFamily.RequesterDacl, 1, 1), (PathRequesterFamily.OwnAccountMembership, 1, 1),
            (PathRequesterFamily.MembershipDacl, 1, 1) }, reader.ReadPathRequesterCoverage().Families
                .Select(value => (value.Family, value.SelectedQuestions, value.StoredAssessments)).ToArray());
    }

    [Theory]
    [InlineData("shell")]
    [InlineData("cli-offline")]
    [InlineData("cli-capture")]
    public async Task CoverageHostsEvaluateTheSameThreeFamiliesAsync(string host)
    {
        var directory = CoverageCapture();

        await RunCoverageHostAsync(host, directory, PathRequesterPolicy.SupportedCapturedQuestions);
        using var reader = Open(directory);

        Assert.Equal(new[] { (PathRequesterFamily.RequesterDacl, 1, 1), (PathRequesterFamily.OwnAccountMembership, 1, 1),
            (PathRequesterFamily.MembershipDacl, 1, 1) }, reader.ReadPathRequesterCoverage().Families
                .Select(value => (value.Family, value.SelectedQuestions, value.StoredAssessments)).ToArray());
    }

    [Theory]
    [InlineData("shell")]
    [InlineData("cli-offline")]
    [InlineData("cli-capture")]
    public async Task CoverageDisabledPolicyStillSchedulesNoQuestionsAsync(string host)
    {
        var directory = CoverageCapture();

        await RunCoverageHostAsync(host, directory, PathRequesterPolicy.Disabled);
        using var reader = Open(directory);
        var coverage = reader.ReadPathRequesterCoverage();

        Assert.Equal((PathRequesterCoverageState.NotRequested, 0), (coverage.Verdict, coverage.Families.Sum(value => value.StoredAssessments)));
    }

    [Theory]
    [InlineData("shell")]
    [InlineData("cli-offline")]
    [InlineData("cli-capture")]
    public async Task CoverageProductionHostsEvaluateTheSameThreeFamiliesAsync(string host)
    {
        var directory = CoverageCapture();
        switch (host)
        {
            case "shell":
                Derive(directory);
                var shell = await new JudgingLauncher(discoveryBudget: null)
                    .RunAsync(directory, JudgingRun.NobodyIsWatching, CancellationToken.None);
                Assert.True(shell.IsSuccess, shell.Error?.Description);
                break;
            case "cli-offline":
                Derive(directory);
                var offline = Assert.IsType<CommandLine>(CommandLine.Parse(["--judge", directory]));
                Assert.Equal(0, await Program.RunAsync(offline, CancellationToken.None, discoveryBudget: null,
                    capture: _ => throw new InvalidOperationException("Offline judging must not capture.")));
                break;
            case "cli-capture":
                var capture = Assert.IsType<CommandLine>(CommandLine.Parse(["--library", Path.GetDirectoryName(directory)!]));
                Assert.Equal(0, await Program.RunAsync(capture, CancellationToken.None, discoveryBudget: null,
                    capture: _ => Task.FromResult(Result<CaptureRunResult>.Success(new(RunCompletion.Sealed, directory, null)))));
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(host));
        }

        using var reader = Open(directory);
        var coverage = reader.ReadPathRequesterCoverage();
        Assert.Equal(PathRequesterCoverageState.EvaluatedSupportedQuestions, coverage.Verdict);
        Assert.Equal(new[] { (PathRequesterFamily.RequesterDacl, 1, 1), (PathRequesterFamily.OwnAccountMembership, 1, 1),
            (PathRequesterFamily.MembershipDacl, 1, 1) }, coverage.Families
                .Select(value => (value.Family, value.SelectedQuestions, value.StoredAssessments)).ToArray());
        Assert.Equal("NotStarted", reader.ReadSelfMembershipSummary()?.Verdict);
    }

    [Fact]
    public void CoverageRequesterFamiliesVerifyEachSourceOnce()
    {
        var directory = Capture(coreDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})(A;;WD;;;{UserSid})");
        Derive(directory);
        using var counts = new JudgingInputReuseTests.Verifications(directory);

        JudgeCoverage(directory);

        Assert.Equal((1L, 1L, 1L), (counts.Evidence, counts.Derivation, counts.Formats));
        using var reader = Open(directory);
        Assert.Equal(new[] { 1, 1, 1 }, reader.ReadPathRequesterCoverage().Families.Select(value => value.StoredAssessments));
        Assert.Equal(ControlEvaluationState.Established, Assert.Single(reader.ReadTier0Path(UserDn).MembershipDaclAssessments).Authorization);
    }

    [Fact]
    public void CoverageRequesterFamiliesLoadTargetsOnce()
    {
        var directory = Capture(coreDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})(A;;WD;;;{UserSid})");
        Derive(directory);
        JudgeCoverage(directory);
        using var reader = Open(directory);
        Assert.Equal(new[] { 1, 1, 1 }, reader.ReadPathRequesterCoverage().Families.Select(value => value.StoredAssessments));
        Assert.Equal(ControlEvaluationState.Established, Assert.Single(reader.ReadTier0Path(UserDn).MembershipDaclAssessments).Authorization);
        var copy = Path.Combine(directory, "requester-reuse.db");
        File.Copy(BundleLayout.AnalysisGenerationDataPath(directory, AnalysisStoreKind.Judgement, reader.Description.GenerationId), copy);
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = copy, Pooling = false }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM path_requester_risk; DELETE FROM path_risk_product; DELETE FROM tier0_path_node; DELETE FROM tier0_path_calculation";
        command.ExecuteNonQuery();
        using var sources = ControlProofVerification.OpenSources(reader);
        using var trace = new JudgingInputReuseTests.Statements(connection);

        Tier0PathStorage.Write(connection, reader.Description, sources, [], [], CancellationToken.None, [], true, _ => { }, null);

        Assert.Single(trace.Sql.Where(sql => sql.StartsWith("SELECT target,identity_json,fingerprint,", StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData("shell")]
    [InlineData("cli-offline")]
    [InlineData("cli-capture")]
    public async Task CoverageHostsDoNotActivateTheLegacyScanAsync(string host)
    {
        var directory = CoverageCapture();

        await RunCoverageHostAsync(host, directory, PathRequesterPolicy.SupportedCapturedQuestions);
        using var reader = Open(directory);

        Assert.Equal("NotStarted", reader.ReadSelfMembershipSummary()?.Verdict);
    }

    [Fact]
    public async Task CoverageShellCarriesTheSavedCoverageSeparatelyAsync()
    {
        var directory = CoverageCapture();
        Derive(directory);

        var result = await new JudgingLauncher(null, PathRequesterPolicy.SupportedCapturedQuestions)
            .RunAsync(directory, JudgingRun.NobodyIsWatching, CancellationToken.None);

        Assert.Equal((PathRequesterCoverageState.EvaluatedSupportedQuestions, 3),
            (result.Value.PathRequesters?.Verdict, result.Value.PathRequesters?.Families.Sum(value => value.SelectedQuestions)));
    }

    [Fact]
    public async Task CoverageMissingInputsAreNotACompleteShellResultAsync()
    {
        var directory = CoverageCapture();

        var result = await new JudgingLauncher(null, PathRequesterPolicy.SupportedCapturedQuestions)
            .RunAsync(directory, JudgingRun.NobodyIsWatching, CancellationToken.None);

        Assert.False(result.IsSuccess);
    }

    [Fact]
    public async Task CoverageMissingInputsAreNotASuccessfulCliResultAsync()
    {
        var directory = CoverageCapture();
        var options = Assert.IsType<CommandLine>(CommandLine.Parse(["--judge", directory]));

        var exit = await Program.RunAsync(options, CancellationToken.None, null,
            _ => throw new InvalidOperationException("Offline judging must not capture."), PathRequesterPolicy.SupportedCapturedQuestions);

        Assert.Equal(1, exit);
    }

    [Fact]
    public async Task CoverageFailedPostCaptureCheckingIsNotASuccessfulCliResultAsync()
    {
        var directory = CoverageCapture();
        File.AppendAllText(Path.Combine(directory, "evidence.db.seal"), "invalid synthetic seal");
        var options = Assert.IsType<CommandLine>(CommandLine.Parse(["--library", Path.GetDirectoryName(directory)!]));

        var exit = await Program.RunAsync(options, CancellationToken.None, null,
            _ => Task.FromResult(Result<CaptureRunResult>.Success(new(RunCompletion.Sealed, directory, null))),
            PathRequesterPolicy.SupportedCapturedQuestions);

        Assert.Equal(1, exit);
    }

    [Theory]
    [InlineData("shell")]
    [InlineData("cli-offline")]
    [InlineData("cli-capture")]
    public async Task CoverageHostsRetainOrderedDeniesAsync(string host)
    {
        var directory = Capture(descriptor: "O:SYG:SYD:", membershipTail: false,
            coreDescriptor: $"O:SYG:SYD:(D;;WD;;;{UserSid})(A;;WD;;;{UserSid})");

        await RunCoverageHostAsync(host, directory, PathRequesterPolicy.SupportedCapturedQuestions);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.NotEstablished, Assert.Single(reader.ReadTier0Path(UserDn).RequesterAssessments).Authorization);
    }

    [Fact]
    public void CoverageRemainsBoundWhenInputsAreUnavailable()
    {
        var directory = CoverageCapture();
        JudgeCoverage(directory);
        using var reader = Open(directory);
        var coverage = reader.ReadPathRequesterCoverage();

        Assert.Equal((reader.Description.EvidenceSeal, reader.Description.GenerationId, (Guid?)null, PathRequesterCoverageState.InputsUnavailable),
            (coverage.EvidenceSeal, coverage.Inputs.JudgementGenerationId, coverage.DerivationGenerationId, coverage.Verdict));
    }

    [Fact]
    public void CoverageRetainsTheExactDerivationGeneration()
    {
        var directory = CoveragePrepared();
        using var reader = Open(directory);

        Assert.Equal(AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Derivation).Value.GenerationId,
            reader.ReadPathRequesterCoverage().DerivationGenerationId);
    }

    [Fact]
    public void CoverageRefusesAChangedDerivation()
    {
        var directory = CoveragePrepared();
        using var reader = Open(directory);
        reader.ReadPathRequesterCoverage();
        Derive(directory);

        Assert.Throws<InvalidOperationException>(() => reader.ReadPathRequesterCoverage());
    }

    [Fact]
    public void CoverageEmptySelectionStillRetainsUnselectedFamilies()
    {
        var directory = Capture(descriptor: "O:SYG:SYD:", membershipTail: false);
        Derive(directory);
        JudgeCoverage(directory);
        using var reader = Open(directory);
        var coverage = reader.ReadPathRequesterCoverage();

        Assert.Equal((PathRequesterCoverageState.EvaluatedSupportedQuestions, 0, true), (coverage.Verdict,
            coverage.Families.Sum(value => value.SelectedQuestions),
            coverage.Limitations.Any(value => value.Reason == PathRequesterSelectionReason.OtherPathFamiliesNotSelected)));
    }

    [Theory]
    [InlineData("O:SYG:SYD:(A;;WD;;;WD)", false, PathRequesterSelectionReason.BroadIdentityNotExpanded)]
    [InlineData("O:SYG:SYD:(A;;WD;;;S-1-5-21-1-2-3-9999)", false, PathRequesterSelectionReason.IdentityUnresolved)]
    [InlineData(null, true, PathRequesterSelectionReason.DescriptorUnavailable)]
    public void CoverageKeepsUnidentifiedQuestionsAsLimitations(string? descriptor, bool missing, PathRequesterSelectionReason reason)
    {
        var directory = Capture(descriptor: "O:SYG:SYD:", membershipTail: false,
            coreDescriptor: descriptor, missingCoreDescriptor: missing);
        Derive(directory);
        JudgeCoverage(directory);
        using var reader = Open(directory);

        Assert.Contains(reader.ReadPathRequesterCoverage().Limitations, value => value.Reason == reason && value.ResourceDn == CoreDn);
    }

    [Theory]
    [InlineData(PathRequesterFamily.OwnAccountMembership)]
    [InlineData(PathRequesterFamily.MembershipDacl)]
    public void CoverageDoesNotMergeUnknownMembershipWithOperationReadiness(PathRequesterFamily family)
    {
        using var reader = Open(CoveragePrepared());
        var counts = reader.ReadPathRequesterCoverage().Families.Single(value => value.Family == family);

        Assert.Equal((1, 1), (counts.UnknownCurrentMembership, counts.UnknownOperationReadiness));
    }

    [Fact]
    public void CoverageRetainsUnresolvedAssessmentCounts()
    {
        var directory = Capture(userAttributes: Account(null, "513"), daclTail: true, membershipTail: false);
        Derive(directory);
        JudgeCoverage(directory);
        using var reader = Open(directory);

        Assert.Equal(1, reader.ReadPathRequesterCoverage().Families.Single(value => value.Family == PathRequesterFamily.MembershipDacl).UnresolvedResults);
    }

    [Fact]
    public void CoverageDoesNotMultiplyHolderCounts()
    {
        var directory = CoverageCapture();
        Derive(directory);
        Judge(directory, []);
        long before;
        using (var reader = Open(directory)) before = reader.ReadControlEdges(CoreDn, null, null, true, 0).Edges.Count(value => value.IsCounted);

        JudgeCoverage(directory);
        using var after = Open(directory);

        Assert.Equal(before, after.ReadControlEdges(CoreDn, null, null, true, 0).Edges.Count(value => value.IsCounted));
    }

    [Fact]
    public void CoverageReadbackDoesNotPublishOrWrite()
    {
        var directory = CoveragePrepared();
        using var reader = Open(directory);
        reader.ReadPathRequesterCoverage();
        var before = Snapshot(directory);

        reader.ReadPathRequesterCoverage();

        Assert.Equal(before, Snapshot(directory));
    }

    [Theory]
    [InlineData("$.Selection.Candidates[0].RequesterDn", "CN=Other,DC=contoso,DC=com")]
    [InlineData("$.Selection.InputFingerprint", "changed")]
    [InlineData("$.Selection.JudgementGenerationId", "11111111-1111-1111-1111-111111111111")]
    public void CoverageRejectsChangedQuestionSources(string path, string value)
    {
        var directory = CoveragePrepared();
        Mutate(directory, "UPDATE tier0_path_calculation SET proof=json_set(proof,'" + path + "','" + value + "')");
        using var reader = Open(directory);

        Assert.Throws<InvalidDataException>(() => reader.ReadPathRequesterCoverage());
    }

    [Theory]
    [InlineData(PathRequesterWorkPhase.SelectingQuestions)]
    [InlineData(PathRequesterWorkPhase.RequesterDacl)]
    [InlineData(PathRequesterWorkPhase.OwnAccountMembership)]
    [InlineData(PathRequesterWorkPhase.MembershipDacl)]
    [InlineData(PathRequesterWorkPhase.WritingProofs)]
    public void CoverageCancellationPreservesThePreviousResult(PathRequesterWorkPhase phase)
    {
        var directory = CoveragePrepared();
        var previous = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId;
        using var stopping = new CancellationTokenSource();

        var failure = Record.Exception(() => JudgeCoverage(directory, new StopCoveragePhase(phase, stopping.Cancel), stopping.Token));

        Assert.Equal((typeof(OperationCanceledException), previous),
            (failure?.GetType(), AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId));
    }

    [Fact]
    public void CoverageAttemptFailureIsSeparateFromThePreviousPublishedGeneration()
    {
        var directory = CoveragePrepared();
        var previous = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId;
        var log = new RecordingRunLog();

        var failure = Record.Exception(() => JudgeCoverage(directory,
            new StopCoveragePhase(PathRequesterWorkPhase.WritingProofs, () => throw new InvalidOperationException("Synthetic failure.")), log: log));

        Assert.Equal((typeof(InvalidOperationException), previous, "Failed", previous.ToString("D")),
            (failure?.GetType(), AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId,
                RecordingRunLog.Value(log.Saying("path-requester-attempt").Last(), "state"),
                RecordingRunLog.Value(log.Saying("path-requester-attempt").Last(), "previous-generation")));
    }

    [Fact]
    public void CoverageAttemptCancellationIsNotRecordedAsFailureOrPublication()
    {
        var directory = CoveragePrepared();
        var log = new RecordingRunLog();
        using var stopping = new CancellationTokenSource();

        Record.Exception(() => JudgeCoverage(directory, new StopCoveragePhase(PathRequesterWorkPhase.SelectingQuestions, stopping.Cancel), stopping.Token, log));

        Assert.Equal(new[] { "Started", "Cancelled" }, log.Saying("path-requester-attempt").Select(value => RecordingRunLog.Value(value, "state")).ToArray());
    }

    [Fact]
    public void CoveragePublishedAttemptNamesItsActualGeneration()
    {
        var directory = CoveragePrepared();
        var log = new RecordingRunLog();

        JudgeCoverage(directory, log: log);
        using var reader = Open(directory);
        var notes = log.Saying("path-requester-attempt");

        Assert.Equal(("Published", reader.Description.GenerationId.ToString("D"), RecordingRunLog.Value(notes[0], "attempt")),
            (RecordingRunLog.Value(notes.Last(), "state"), RecordingRunLog.Value(notes.Last(), "generation"), RecordingRunLog.Value(notes.Last(), "attempt")));
    }

    [Fact]
    public void CoverageDiagnosticsNameEveryCompletedPhase()
    {
        var directory = CoverageCapture();
        Derive(directory);
        var log = new RecordingRunLog();

        JudgeCoverage(directory, log: log);

        Assert.Equal(Enum.GetNames<PathRequesterWorkPhase>(), log.Saying("path-requester-phase")
            .Where(value => RecordingRunLog.Value(value, "completed") == "True")
            .Select(value => RecordingRunLog.Value(value, "phase")).ToArray());
    }

    private string CoverageCapture() => Capture(coreDescriptor: $"O:SYG:SYD:(A;;WD;;;{UserSid})(A;;WD;;;{TargetSid})");

    private string CoveragePrepared()
    {
        var directory = CoverageCapture();
        Derive(directory);
        JudgeCoverage(directory);
        return directory;
    }

    private static async Task RunCoverageHostAsync(string host, string directory, PathRequesterPolicy policy)
    {
        switch (host)
        {
            case "shell":
                Derive(directory);
                var result = await new JudgingLauncher(null, policy).RunAsync(directory, JudgingRun.NobodyIsWatching, CancellationToken.None);
                Assert.True(result.IsSuccess, result.Error?.Description);
                break;
            case "cli-offline":
                Derive(directory);
                var offline = Assert.IsType<CommandLine>(CommandLine.Parse(["--judge", directory]));
                Assert.Equal(0, await Program.RunAsync(offline, CancellationToken.None, null,
                    _ => throw new InvalidOperationException("Offline judging must not capture."), policy));
                break;
            case "cli-capture":
                var capture = Assert.IsType<CommandLine>(CommandLine.Parse(["--library", Path.GetDirectoryName(directory)!]));
                Assert.Equal(0, await Program.RunAsync(capture, CancellationToken.None, null,
                    _ => Task.FromResult(Result<CaptureRunResult>.Success(new(RunCompletion.Sealed, directory, null))), policy));
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(host));
        }
    }

    private sealed class StopCoveragePhase(PathRequesterWorkPhase phase, Action stop) : IProgress<JudgingRun.JudgingProgress>
    {
        public void Report(JudgingRun.JudgingProgress value)
        {
            if (value.RequesterPhase == phase) stop();
        }
    }

    private static void JudgeCoverage(string directory, IProgress<JudgingRun.JudgingProgress>? progress = null,
        CancellationToken cancellationToken = default, IRunLog? log = null) => Assert.True(JudgingRun.JudgeAudit(directory, [],
            PathRequesterPolicy.SupportedCapturedQuestions, Started, Started, progress ?? JudgingRun.NobodyIsWatching,
            log ?? RunLog.Discarded, cancellationToken, selfMembershipDiscoveryBudget: null).IsSuccess);
}
