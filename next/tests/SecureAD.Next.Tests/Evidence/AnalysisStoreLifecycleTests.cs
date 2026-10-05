using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>The generation manifest that atomically selects a disposable analysis store.</summary>
public sealed partial class AnalysisStoreLifecycleTests
{
    [Theory]
    [InlineData(AnalysisStoreKind.Derivation)]
    [InlineData(AnalysisStoreKind.Judgement)]
    public void BeginningAnAttemptIsVisibleBeforeItsDatabaseExists(AnalysisStoreKind kind)
    {
        var directory = NewBundle();

        AnalysisStoreLifecycle.BeginAttempt(directory, kind);

        Assert.True(AnalysisStoreLifecycle.HasUnpublishedChanges(directory, kind));
    }

    [Theory]
    [InlineData(AnalysisStoreKind.Derivation)]
    [InlineData(AnalysisStoreKind.Judgement)]
    public void SuccessfulPublicationClearsThePendingAttempt(AnalysisStoreKind kind)
    {
        var directory = NewBundle();
        AnalysisStoreLifecycle.BeginAttempt(directory, kind);
        File.WriteAllText(AnalysisStoreLifecycle.StagingPath(directory, kind), "result");

        AnalysisStoreLifecycle.Publish(directory, kind, Guid.NewGuid());

        Assert.False(AnalysisStoreLifecycle.HasUnpublishedChanges(directory, kind));
    }

    [Fact]
    public void DerivationWriterRecordsItsAttemptBeforeCompletion()
    {
        var directory = NewBundle();

        using var writer = DerivationWriter.Create(directory, "evidence", DateTimeOffset.UnixEpoch);

        Assert.True(File.Exists(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Derivation) + ".partial"));
    }

    [Fact]
    public void JudgementWriterRecordsItsAttemptBeforeCompletion()
    {
        var directory = NewBundle();

        using var writer = JudgementWriter.Create(directory, "evidence", null, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);

        Assert.True(File.Exists(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement) + ".partial"));
    }

    [Fact]
    public void FailedSealingKeepsTheUnpublishedAttemptVisible()
    {
        var directory = NewBundle();
        var generation = Guid.NewGuid();
        File.WriteAllText(AnalysisStoreLifecycle.StagingPath(directory, AnalysisStoreKind.Judgement), "new result");
        Directory.CreateDirectory(BundleLayout.AnalysisGenerationSealPath(directory, AnalysisStoreKind.Judgement, generation));

        Assert.Throws<UnauthorizedAccessException>(() => AnalysisStoreLifecycle.Publish(directory, AnalysisStoreKind.Judgement, generation));

        Assert.True(AnalysisStoreLifecycle.HasUnpublishedChanges(directory, AnalysisStoreKind.Judgement));
    }

    [Fact]
    public void PublishingSelectsACompleteImmutableGeneration()
    {
        var directory = NewBundle();
        var generationId = Guid.NewGuid();
        File.WriteAllText(
            AnalysisStoreLifecycle.StagingPath(directory, AnalysisStoreKind.Derivation),
            "derived facts");

        var published = AnalysisStoreLifecycle.Publish(
            directory, AnalysisStoreKind.Derivation, generationId);
        var resolved = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Derivation);

        Assert.Equal(published, resolved.Value);
    }

    [Fact]
    public void FailedManifestReplacementLeavesTheEarlierGenerationSelected()
    {
        var directory = NewBundle();
        var firstId = Guid.NewGuid();
        File.WriteAllText(
            AnalysisStoreLifecycle.StagingPath(directory, AnalysisStoreKind.Judgement),
            "first judgement");
        AnalysisStoreLifecycle.Publish(directory, AnalysisStoreKind.Judgement, firstId);

        var manifestPath = AnalysisStoreLifecycle.ManifestPath(
            directory, AnalysisStoreKind.Judgement);
        using (var locked = File.Open(manifestPath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            File.WriteAllText(
                AnalysisStoreLifecycle.StagingPath(directory, AnalysisStoreKind.Judgement),
                "replacement judgement");

            Assert.Throws<UnauthorizedAccessException>(() => AnalysisStoreLifecycle.Publish(
                directory, AnalysisStoreKind.Judgement, Guid.NewGuid()));
        }

        var resolved = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement);

        Assert.Equal(firstId, resolved.Value.GenerationId);
    }

    [Fact]
    public void PreCancelledPublicationPreservesTheExistingManifestAndStagingFile()
    {
        var directory = NewBundle();
        var first = Guid.NewGuid();
        var staging = AnalysisStoreLifecycle.StagingPath(directory, AnalysisStoreKind.Judgement);
        File.WriteAllText(staging, "first");
        AnalysisStoreLifecycle.Publish(directory, AnalysisStoreKind.Judgement, first);
        File.WriteAllText(staging, "replacement");
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var error = Record.Exception(() => AnalysisStoreLifecycle.Publish(directory, AnalysisStoreKind.Judgement,
            Guid.NewGuid(), cancellation.Token));
        Assert.Equal((typeof(OperationCanceledException), first, "replacement"),
            (error?.GetType(), AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId, File.ReadAllText(staging)));
    }

    [Fact]
    public void AMalformedManifestReturnsATypedFailure()
    {
        var directory = NewBundle();
        File.WriteAllText(
            AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Derivation),
            "not json");

        var resolved = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Derivation);

        Assert.Equal("Evidence.derivationManifestUnreadable", resolved.Error!.Code);
    }

    private static string NewBundle()
    {
        var directory = TempDirectories.Create("analysis-lifecycle");
        Directory.CreateDirectory(directory);
        return directory;
    }
}
