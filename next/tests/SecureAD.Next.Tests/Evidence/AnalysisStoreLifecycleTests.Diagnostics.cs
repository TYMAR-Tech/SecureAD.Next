using SecureAD.Evidence;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

public sealed partial class AnalysisStoreLifecycleTests
{
    [Fact]
    public void PublicationStageNotificationsPrecedeTheirActualFileOperations()
    {
        var directory = NewBundle();
        var generation = Guid.NewGuid();
        var manifest = AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement);
        var data = BundleLayout.AnalysisGenerationDataPath(directory, AnalysisStoreKind.Judgement, generation);
        var seal = BundleLayout.AnalysisGenerationSealPath(directory, AnalysisStoreKind.Judgement, generation);
        File.WriteAllText(data, "complete synthetic result");
        var stages = new List<AnalysisPublicationPart>();

        AnalysisStoreLifecycle.Publish(directory, AnalysisStoreKind.Judgement, generation, CancellationToken.None, part =>
        {
            stages.Add(part);
            Assert.False(File.Exists(manifest));
            switch (part)
            {
                case AnalysisPublicationPart.WritePendingManifest:
                    Assert.True(File.Exists(data));
                    Assert.False(File.Exists(manifest + ".partial"));
                    break;
                case AnalysisPublicationPart.PrepareData:
                    Assert.True(File.Exists(manifest + ".partial"));
                    Assert.True(File.Exists(data));
                    break;
                case AnalysisPublicationPart.SealData:
                    Assert.Equal("complete synthetic result", File.ReadAllText(data));
                    Assert.False(File.Exists(seal));
                    break;
                case AnalysisPublicationPart.SelectManifest:
                    Assert.True(File.Exists(manifest + ".partial"));
                    Assert.Equal(BundleSealing.HashFile(data), BundleSealing.ReadSeal(seal)!.Hash);
                    break;
                default: throw new ArgumentOutOfRangeException(nameof(part));
            }
        });

        Assert.Equal(Enum.GetValues<AnalysisPublicationPart>(), stages);
        Assert.Equal(generation, AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId);
        Assert.False(File.Exists(manifest + ".partial"));
    }

    [Fact]
    public void PublicationCancelledAtManifestSelectionLeavesThePreviousGenerationSelected()
    {
        var directory = NewBundle();
        var previous = Guid.NewGuid();
        File.WriteAllText(TestSealing.AnalysisInputPath(directory, AnalysisStoreKind.Judgement, previous), "previous result");
        AnalysisStoreLifecycle.Publish(directory, AnalysisStoreKind.Judgement, previous);
        var generation = Guid.NewGuid();
        File.WriteAllText(TestSealing.AnalysisInputPath(directory, AnalysisStoreKind.Judgement, generation), "replacement result");
        var manifest = AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement);
        var previousRoot = File.ReadAllBytes(manifest);
        using var stopping = new CancellationTokenSource();
        var reached = false;

        Assert.Throws<OperationCanceledException>(() =>
            AnalysisStoreLifecycle.Publish(directory, AnalysisStoreKind.Judgement, generation, stopping.Token, part =>
            {
                if (part != AnalysisPublicationPart.SelectManifest) return;
                reached = true;
                stopping.Cancel();
            }));

        Assert.True(reached);
        Assert.Equal(previousRoot, File.ReadAllBytes(manifest));
        Assert.Equal(previous, AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId);
        Assert.True(AnalysisStoreLifecycle.HasUnpublishedChanges(directory, AnalysisStoreKind.Judgement));
        Assert.True(File.Exists(BundleLayout.AnalysisGenerationSealPath(directory, AnalysisStoreKind.Judgement, generation)));
    }

    [Theory]
    [InlineData((int)AnalysisPublicationPart.WritePendingManifest)]
    [InlineData((int)AnalysisPublicationPart.PrepareData)]
    [InlineData((int)AnalysisPublicationPart.SealData)]
    [InlineData((int)AnalysisPublicationPart.SelectManifest)]
    public void EveryPublicationFailurePreservesTheExactPreviousSelection(int failingPart)
    {
        var directory = NewBundle();
        var kind = AnalysisStoreKind.Judgement;
        var previous = Guid.NewGuid();
        File.WriteAllText(TestSealing.AnalysisInputPath(directory, kind, previous), "previous complete result");
        AnalysisStoreLifecycle.Publish(directory, kind, previous);
        var manifest = AnalysisStoreLifecycle.ManifestPath(directory, kind);
        var previousRoot = File.ReadAllBytes(manifest);
        var data = BundleLayout.AnalysisGenerationDataPath(directory, kind, previous);
        var previousData = File.ReadAllBytes(data);
        var previousSeal = File.ReadAllBytes(data + ".seal");
        var replacement = Guid.NewGuid();
        File.WriteAllText(TestSealing.AnalysisInputPath(directory, kind, replacement), "replacement result");
        var reached = false;

        Assert.Throws<IOException>(() => AnalysisStoreLifecycle.Publish(directory, kind, replacement,
            CancellationToken.None, part =>
            {
                if (part != (AnalysisPublicationPart)failingPart) return;
                reached = true;
                throw new IOException("Injected publication failure.");
            }));

        Assert.True(reached);
        Assert.Equal(previousRoot, File.ReadAllBytes(manifest));
        Assert.Equal(previousData, File.ReadAllBytes(data));
        Assert.Equal(previousSeal, File.ReadAllBytes(data + ".seal"));
        Assert.Equal(previous, AnalysisStoreLifecycle.Resolve(directory, kind).Value.GenerationId);
    }

    [Fact]
    public void ASealingFailureDoesNotReportTheManifestSelectionStage()
    {
        var directory = NewBundle();
        var generation = Guid.NewGuid();
        File.WriteAllText(TestSealing.AnalysisInputPath(directory, AnalysisStoreKind.Judgement, generation), "synthetic result");
        Directory.CreateDirectory(BundleLayout.AnalysisGenerationSealPath(directory, AnalysisStoreKind.Judgement, generation));
        var stages = new List<AnalysisPublicationPart>();

        Assert.Throws<UnauthorizedAccessException>(() =>
            AnalysisStoreLifecycle.Publish(directory, AnalysisStoreKind.Judgement, generation, CancellationToken.None, stages.Add));

        Assert.Equal(new[] { AnalysisPublicationPart.WritePendingManifest, AnalysisPublicationPart.PrepareData, AnalysisPublicationPart.SealData }, stages);
        Assert.False(File.Exists(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement)));
        Assert.True(AnalysisStoreLifecycle.HasUnpublishedChanges(directory, AnalysisStoreKind.Judgement));
    }

    [Fact]
    public void PreCancelledPublicationDoesNotReportWorkItNeverStarted()
    {
        var directory = NewBundle();
        var generation = Guid.NewGuid();
        var staging = TestSealing.AnalysisInputPath(directory, AnalysisStoreKind.Judgement, generation);
        File.WriteAllText(staging, "synthetic result");
        using var stopping = new CancellationTokenSource();
        stopping.Cancel();
        var stages = new List<AnalysisPublicationPart>();

        Assert.Throws<OperationCanceledException>(() =>
            AnalysisStoreLifecycle.Publish(directory, AnalysisStoreKind.Judgement, generation, stopping.Token, stages.Add));

        Assert.Empty(stages);
        Assert.Equal("synthetic result", File.ReadAllText(staging));
    }
}
