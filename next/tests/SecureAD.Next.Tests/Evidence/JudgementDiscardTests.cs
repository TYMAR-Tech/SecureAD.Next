using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Shell.Services;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Evidence;

public sealed class JudgementDiscardTests
{
    [Fact]
    public void DiscardRemovesEverySavedJudgementAndPreservesAllOtherFiles()
    {
        var directory = SavedGenerations();
        var oldFiles = Directory.GetFiles(directory, "judgement.*");
        var unrelated = new[] { "evidence.db", "evidence.db.seal", "run.log", "run-notes.json",
            "judgement.notes.txt", "judgement.not-a-generation.db", $"judgement.{Guid.NewGuid():N}.db.backup" };
        foreach (var name in unrelated) File.WriteAllText(Path.Combine(directory, name), "keep " + name);
        var nested = Path.Combine(directory, "retained");
        Directory.CreateDirectory(nested);
        File.WriteAllText(Path.Combine(nested, Path.GetFileName(oldFiles[0])), "keep nested evidence");
        var preserved = Directory.GetFiles(directory, "*", SearchOption.AllDirectories)
            .Except(oldFiles).ToDictionary(path => path, File.ReadAllText);

        AnalysisStoreLifecycle.DiscardJudgement(directory);

        Assert.All(oldFiles, path => Assert.False(File.Exists(path), path));
        Assert.Equal(preserved.Keys.Order(), Directory.GetFiles(directory, "*", SearchOption.AllDirectories).Order());
        Assert.All(preserved, item => Assert.Equal(item.Value, File.ReadAllText(item.Key)));
        Assert.False(AnalysisStoreLifecycle.HasUnpublishedChanges(directory, AnalysisStoreKind.Judgement));
    }

    [Fact]
    public void AnOpenSavedResultRefusesDiscardWithoutDeletingAnyOfIt()
    {
        var directory = SavedGenerations();
        var current = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value;
        var before = Directory.GetFiles(directory).ToDictionary(path => path, File.ReadAllText);
        using var protectedResult = ProtectedStoreFile.OpenAnalysis(directory, current).Value;

        Assert.Throws<IOException>(() => AnalysisStoreLifecycle.DiscardJudgement(directory));

        Assert.Equal(current, AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value);
        Assert.All(before, item => Assert.Equal(item.Value, File.ReadAllText(item.Key)));
        Assert.False(AnalysisStoreLifecycle.HasUnpublishedChanges(directory, AnalysisStoreKind.Judgement));
    }

    [Theory]
    [InlineData(AnalysisStoreKind.Judgement)]
    [InlineData(AnalysisStoreKind.Derivation)]
    public void AnUnfinishedAnalysisIsNeverDiscarded(AnalysisStoreKind kind)
    {
        var directory = SavedGenerations();
        AnalysisStoreLifecycle.BeginAttempt(directory, kind);
        var before = Directory.GetFiles(directory).ToDictionary(path => path, File.ReadAllText);

        Assert.Throws<InvalidOperationException>(() => AnalysisStoreLifecycle.DiscardJudgement(directory));

        Assert.All(before, item => Assert.Equal(item.Value, File.ReadAllText(item.Key)));
    }

    [Fact]
    public void ARealJudgementWriterHoldsTheDiscardExclusionUntilDisposed()
    {
        var directory = TempDirectories.Create("judgement-write-exclusion");
        using (var writer = JudgementWriter.Create(directory, "evidence", null, Started, Started))
        {
            var error = Record.Exception(() =>
            {
                using var other = AnalysisStoreLifecycle.LockJudgementWrites(directory);
            });
            Assert.IsType<IOException>(error);
        }

        using var released = AnalysisStoreLifecycle.LockJudgementWrites(directory);
    }

    [Fact]
    public void AFailedWriterCreationDoesNotStrandItsExclusion()
    {
        var directory = TempDirectories.Create("judgement-write-failed");
        Directory.CreateDirectory(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement) + ".partial");

        var error = Record.Exception(() =>
        {
            using var writer = JudgementWriter.Create(directory, "evidence", null, Started, Started);
        });

        Assert.NotNull(error);
        using var released = AnalysisStoreLifecycle.LockJudgementWrites(directory);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ATerminalWriterReleasesItsExclusionBeforeDisposal(bool completed)
    {
        var directory = TempDirectories.Create("judgement-write-terminal");
        using var writer = JudgementWriter.Create(directory, "evidence", null, Started, Started);

        if (completed) writer.Complete(Started);
        else writer.Abandon(Started);

        using var released = AnalysisStoreLifecycle.LockJudgementWrites(directory);
    }

    [Fact]
    public async Task DiscardAndRejudgeUsesTheSameSealedInputsAndWritesANewReadableResult()
    {
        var directory = Bundle();
        Derive(directory);
        var launcher = new JudgingLauncher(null);
        var initial = await launcher.RunAsync(directory, JudgingRun.NobodyIsWatching, CancellationToken.None);
        Assert.True(initial.IsSuccess, initial.Error?.Description);
        var original = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value;
        var inputs = Directory.GetFiles(directory)
            .Where(path => Path.GetFileName(path).StartsWith("evidence.", StringComparison.Ordinal)
                || Path.GetFileName(path).StartsWith("derivation.", StringComparison.Ordinal))
            .ToDictionary(path => path, path => System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(path)));
        var previousLog = File.ReadAllText(BundleLayout.RunLogPath(directory));
        var catalog = new RunCatalog();

        var discarded = catalog.DiscardJudgement(directory);

        Assert.True(discarded.IsSuccess, discarded.Error?.Description);
        Assert.False(AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).IsSuccess);
        Assert.False(File.Exists(BundleLayout.AnalysisGenerationDataPath(directory, original.Kind, original.GenerationId)));
        var replacement = await launcher.RunAsync(directory, JudgingRun.NobodyIsWatching, CancellationToken.None);
        Assert.True(replacement.IsSuccess, replacement.Error?.Description);
        using var reader = JudgementReader.Open(directory).Value;
        Assert.NotEqual(original.GenerationId, reader.Description.GenerationId);
        Assert.Equal(initial.Value.ObjectsJudged, replacement.Value.ObjectsJudged);
        Assert.NotNull(reader.ReadPathRequesterCoverage());
        Assert.All(inputs, item => Assert.Equal(item.Value,
            System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(item.Key))));
        Assert.StartsWith(previousLog, File.ReadAllText(BundleLayout.RunLogPath(directory)), StringComparison.Ordinal);
        Assert.Contains("judgement discarded", File.ReadAllText(BundleLayout.RunLogPath(directory)), StringComparison.Ordinal);
    }

    [Fact]
    public void CatalogReportsADeletionFailureRatherThanReturningSuccess()
    {
        var directory = SavedGenerations();
        var current = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value;
        using var protectedResult = ProtectedStoreFile.OpenAnalysis(directory, current).Value;

        var result = new RunCatalog().DiscardJudgement(directory);

        Assert.False(result.IsSuccess);
        Assert.Equal("Shell.JudgementCannotBeDiscarded", result.Error.Code);
        Assert.Equal(current, AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value);
    }

    private static string SavedGenerations()
    {
        var directory = TempDirectories.Create("judgement-discard");
        File.WriteAllText(AnalysisStoreLifecycle.StagingPath(directory, AnalysisStoreKind.Derivation), "derived facts");
        AnalysisStoreLifecycle.Publish(directory, AnalysisStoreKind.Derivation, Guid.NewGuid());
        for (var index = 0; index < 2; index++)
        {
            var generationId = Guid.NewGuid();
            File.WriteAllText(TestSealing.AnalysisInputPath(directory, AnalysisStoreKind.Judgement, generationId), "saved judgement " + index);
            var generation = AnalysisStoreLifecycle.Publish(directory, AnalysisStoreKind.Judgement, generationId);
            var data = BundleLayout.AnalysisGenerationDataPath(directory, generation.Kind, generation.GenerationId);
            foreach (var suffix in new[] { "-wal", "-shm", "-journal" })
                File.WriteAllText(data + suffix, "saved working file");
        }
        return directory;
    }
}
