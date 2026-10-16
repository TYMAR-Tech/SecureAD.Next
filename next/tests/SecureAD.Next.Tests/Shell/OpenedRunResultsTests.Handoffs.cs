using System.Text.Json;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Measure;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Fact]
    public async Task ProducingCompletionAndViewingShareOnlyContinuouslyProtectedExactFiles()
    {
        var directory = TempDirectories.Create("handoff-control");
        EnterpriseControlWorkload.Write(directory, CancellationToken.None);
        using var sessions = new RunProtectionSessions();
        using var counts = new ReadbackCounts(directory);
        var derived = await new DerivationLauncher(sessions).RunAsync(directory, Stage2aRun.Unwatched, CancellationToken.None);
        Assert.True(derived.IsSuccess, derived.Error?.Description);
        var judged = await new JudgingLauncher(null, PathRequesterPolicy.Disabled, sessions)
            .RunAsync(directory, JudgingRun.NobodyIsWatching, CancellationToken.None);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        Assert.Equal((1L, 1L, 1L), (counts.EvidenceVerifications, counts.DerivationVerifications, counts.JudgementVerifications));
        var root = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value;
        var output = Path.Combine(directory, root.Segment(StoreSegmentRole.Judgement).FileName);
        Assert.Throws<IOException>(() => File.Move(output, output + ".replacement"));
        using var source = new BundleAssetSource(sessions);
        source.SelectRun(directory);
        var findings = source.ReadFindings(directory, FindingsQuery.Everything());
        Assert.True(findings.IsSuccess, findings.Error?.Description);
        Assert.NotEmpty(findings.Value.Findings);
        using (var checking = sessions.Acquire(directory))
        using (var reader = JudgementReader.Open(checking.Files.Analysis(AnalysisStoreKind.Judgement,
            StoreSegmentRole.Judgement, CancellationToken.None).Value).Value)
            Assert.Equal(judged.Value.Findings.OrderBy(pair => pair.Key),
                reader.ReadSummary().Value.FindingsBySeverity.OrderBy(pair => pair.Key));
        Assert.True(source.ReadInventory(directory).IsSuccess);
        Assert.Equal((1L, 1L, 1L, 1L, 1L), (counts.EvidenceVerifications, counts.DerivationVerifications,
            counts.JudgementVerifications, counts.EvidenceFormatChecks, counts.OverviewVerifications));
        Assert.Throws<IOException>(() => File.Open(output, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite));

        await source.CloseRunAsync();

        using (File.Open(output, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite)) { }
        Assert.False(source.CaptureReadValidity()());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FailedOrCancelledProducingDoesNotReplaceAnEarlierProtectedHandoff(bool cancelled)
    {
        var completed = CreateRun();
        var failing = CreateRun();
        using var sessions = new RunProtectionSessions();
        ProtectedStoreFile? previous = null;
        Assert.True(sessions.Produce(completed, files =>
        {
            var opened = files.Capture(StoreSegmentRole.Evidence, CancellationToken.None);
            previous = opened.Value;
            return Result<bool>.Success(true);
        }).IsSuccess);
        Result<bool> Fail(ProtectedRunFiles files)
        {
            Assert.True(files.Capture(StoreSegmentRole.Evidence, CancellationToken.None).IsSuccess);
            if (cancelled) throw new OperationCanceledException();
            return Result<bool>.Failure(Failures.Any("Synthetic producer refusal."));
        }
        if (cancelled) Assert.Throws<OperationCanceledException>(() => sessions.Produce(failing, Fail));
        else Assert.False(sessions.Produce(failing, Fail).IsSuccess);
        using (File.Open(BundleLayout.EvidencePath(failing), FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite)) { }
        using var viewing = sessions.TakeForViewing(completed);
        Assert.Same(previous, viewing.Files.Capture(StoreSegmentRole.Evidence, CancellationToken.None).Value);
        Assert.Throws<IOException>(() => File.Open(BundleLayout.EvidencePath(completed), FileMode.Open,
            FileAccess.ReadWrite, FileShare.ReadWrite));
    }

    [Fact]
    public void ANewLifetimeVerifiesAgainAfterAnyUnprotectedGap()
    {
        var directory = CreateRun();
        using var counts = new ReadbackCounts(directory);
        using (var files = new ProtectedRunFiles(directory))
            Assert.True(files.Capture(StoreSegmentRole.Evidence, CancellationToken.None).IsSuccess);
        using (var files = new ProtectedRunFiles(directory))
            Assert.True(files.Capture(StoreSegmentRole.Evidence, CancellationToken.None).IsSuccess);
        Assert.Equal(2L, counts.EvidenceVerifications);
        ChangeSameLength(BundleLayout.EvidencePath(directory));
        using var reopened = new ProtectedRunFiles(directory);
        Assert.False(reopened.Capture(StoreSegmentRole.Evidence, CancellationToken.None).IsSuccess);
        Assert.Equal(3L, counts.EvidenceVerifications);
    }

    [Fact]
    public void ReplacedCaptureRootsCannotJoinAnEarlierProtectedInputToANewerView()
    {
        var directory = CreateRun();
        using var files = new ProtectedRunFiles(directory);
        Assert.True(files.Capture(StoreSegmentRole.Evidence, CancellationToken.None).IsSuccess);
        var root = AnalysisStoreLifecycle.ResolveCapture(directory).Value;
        var changed = root with { LibraryHeader = root.LibraryHeader! with { CoverageId = "another capture identity" } };
        File.WriteAllText(BundleLayout.CaptureManifestPath(directory),
            JsonSerializer.Serialize(changed with { Hash = changed.ComputeHash() }));

        Assert.False(files.Capture(StoreSegmentRole.Overview, CancellationToken.None).IsSuccess);
        Assert.False(files.Analysis(AnalysisStoreKind.Judgement, StoreSegmentRole.Judgement, CancellationToken.None).IsSuccess);
    }

    [Fact]
    public async Task ReleasingTheFinalHandoffWaitsForItsRemainingReader()
    {
        var directory = CreateRun();
        using var sessions = new RunProtectionSessions();
        sessions.Produce(directory, files => files.Capture(StoreSegmentRole.Evidence, CancellationToken.None));
        var viewing = sessions.TakeForViewing(directory);
        var file = viewing.Files.Capture(StoreSegmentRole.Evidence, CancellationToken.None).Value;
        using var reader = file.Acquire();

        var closing = viewing.DisposeAsync().AsTask();
        Assert.False(closing.IsCompleted);
        Assert.Throws<IOException>(() => File.Open(BundleLayout.EvidencePath(directory), FileMode.Open,
            FileAccess.ReadWrite, FileShare.ReadWrite));
        reader.Dispose();
        await closing;
        using (File.Open(BundleLayout.EvidencePath(directory), FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite)) { }
    }

    [Fact]
    public void CancellationDuringDerivationSealingKeepsThePreviouslyCompletedRoot()
    {
        var directory = CreateRun();
        Assert.True(Stage2aRun.Derive(directory, ExpansionBudget.Bulk, DateTimeOffset.UnixEpoch,
            Stage2aRun.Unwatched, RunLog.Discarded, CancellationToken.None).IsSuccess);
        var manifest = AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Derivation);
        var previous = File.ReadAllBytes(manifest);
        using var stopping = new CancellationTokenSource();
        var observed = false;
        var log = new JudgingStatusTests.StatusLog(line =>
        {
            if (line.Message != "file sealing") return;
            observed = true;
            stopping.Cancel();
        });

        Assert.Throws<OperationCanceledException>(() => Stage2aRun.Derive(directory, ExpansionBudget.Bulk,
            DateTimeOffset.UnixEpoch, Stage2aRun.Unwatched, log, stopping.Token));

        Assert.True(observed);
        Assert.Equal(previous, File.ReadAllBytes(manifest));
        Assert.True(AnalysisStoreLifecycle.HasUnpublishedChanges(directory, AnalysisStoreKind.Derivation));
    }
}
