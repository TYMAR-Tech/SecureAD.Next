using SecureAD.Evidence;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>The generation manifest that atomically selects a disposable analysis store.</summary>
public sealed class AnalysisStoreLifecycleTests
{
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
