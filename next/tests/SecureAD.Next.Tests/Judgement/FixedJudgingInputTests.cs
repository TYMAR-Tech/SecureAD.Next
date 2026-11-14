using System.Text.Json;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Measure;
using Xunit;
using static SecureAD.Next.Tests.Judgement.LapsPrecedenceRun;

namespace SecureAD.Next.Tests.Judgement;

[Collection("GPO preparation diagnostics")]
public sealed class FixedJudgingInputTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(1000)]
    public void ForksAndRepeatedValidationDoNotResolveCurrentSelections(int repetitions)
    {
        var directory = GpoSecurityRun.Build(new());
        using var files = new ProtectedRunFiles(directory);
        using var counts = new Observations(directory);
        using var sources = Open(files);
        Assert.Equal(1, counts.Bindings);
        Assert.Equal(2, counts.Read("capture"));
        Assert.Equal(1, counts.Read("derivation"));
        using var first = sources.Fork(CancellationToken.None).Value;
        using var second = sources.Fork(CancellationToken.None).Value;
        var description = Description(first);
        for (var index = 0; index < repetitions; index++)
        {
            sources.RequireSameInputs(first);
            first.RequireSameInputs(second);
            first.RequireFor(description);
            Assert.True(first.OpenMembershipDerivation().IsSuccess);
        }
        Assert.Equal(1, counts.Bindings);
        Assert.Equal(2, counts.Read("capture"));
        Assert.Equal(1, counts.Read("derivation"));
    }

    [Fact]
    public void LateDerivationReaderUsesTheOriginallySelectedGeneration()
    {
        var directory = GpoSecurityRun.Build(new());
        var original = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Derivation).Value;
        using var files = new ProtectedRunFiles(directory);
        using var sources = Open(files);
        GpoSecurityRun.Derive(directory);
        var replacement = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Derivation).Value;
        Assert.NotEqual(original.GenerationId, replacement.GenerationId);
        using var counts = new Observations(directory);
        using var fork = sources.Fork(CancellationToken.None).Value;
        var opened = fork.OpenMembershipDerivation();
        Assert.True(opened.IsSuccess);
        Assert.Equal(original.GenerationId, opened.Value.Description.GenerationId);
        Assert.Equal(original.EvidenceSeal, opened.Value.Description.EvidenceSeal);
        Assert.Equal(0, counts.Read("capture"));
        Assert.Equal(0, counts.Read("derivation"));
    }

    [Fact]
    public void MissingDerivationCannotBeAdoptedHalfwayThroughAnOperation()
    {
        var directory = GpoSecurityRun.Build(new() { Derive = false });
        var missing = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Derivation).Error;
        using var files = new ProtectedRunFiles(directory);
        using var sources = Open(files);
        GpoSecurityRun.Derive(directory);
        using var fork = sources.Fork(CancellationToken.None).Value;
        var refused = fork.OpenMembershipDerivation();
        Assert.False(refused.IsSuccess);
        Assert.Equal(missing.Code, refused.Error.Code);
        using var fresh = Open(files);
        Assert.True(fresh.OpenMembershipDerivation().IsSuccess);
    }

    [Fact]
    public void LateGpoReadersUseTheParentsCaptureRatherThanTheCurrentMarker()
    {
        var directory = Build([new(1, [TextValue(Principal, GroupA)])],
            computerAttributes: GpoDirectoryWmiAssessmentTests.Platform());
        using var files = new ProtectedRunFiles(directory);
        using var sources = Open(files);
        var computer = sources.Bundle.ReadObjectIdentity(GpoSecurityRun.Computer)!;
        using var reference = LapsConfiguredPolicyReader.Open(sources, CancellationToken.None).Value;
        var expected = JsonSerializer.Serialize(reference.Read(computer, CancellationToken.None).Value);
        var other = GpoSecurityRun.Build(new());
        File.Copy(BundleLayout.CaptureManifestPath(other), BundleLayout.CaptureManifestPath(directory), true);
        using var counts = new Observations(directory);
        var opened = LapsConfiguredPolicyReader.Open(sources, CancellationToken.None);
        Assert.True(opened.IsSuccess);
        using var late = opened.Value;
        var actual = late.Read(computer, CancellationToken.None);
        Assert.True(actual.IsSuccess, actual.Error?.Description);
        Assert.Equal(expected, JsonSerializer.Serialize(actual.Value));
        Assert.Equal(0, counts.Bindings);
        Assert.Equal(0, counts.Read("capture"));
        Assert.Equal(0, counts.Read("derivation"));
    }

    [Theory]
    [InlineData("capture")]
    [InlineData("derivation")]
    public void ChangedSelectionsDoNotRetargetCalculationsButCannotPublish(string changed)
    {
        var directory = GpoSecurityRun.Build(new());
        using var files = new ProtectedRunFiles(directory);
        using var sources = Open(files);
        var description = Description(sources);
        if (changed == "capture")
            File.Copy(BundleLayout.CaptureManifestPath(GpoSecurityRun.Build(new())),
                BundleLayout.CaptureManifestPath(directory), true);
        else GpoSecurityRun.Derive(directory);
        using var counts = new Observations(directory);
        sources.RequireFor(description);
        Assert.True(sources.OpenMembershipDerivation().IsSuccess);
        Assert.Equal(description.DerivationGenerationId,
            sources.OpenMembershipDerivation().Value.Description.GenerationId);
        Assert.Equal(0, counts.Read("capture"));
        Assert.Equal(0, counts.Read("derivation"));
        Assert.Throws<InvalidOperationException>(() => sources.ProtectPublication(description));
        Assert.True(counts.Read("capture") > 0);
    }

    [Theory]
    [InlineData("capture")]
    [InlineData("derivation")]
    public void FixedInputsStillRejectForeignResultBindings(string changed)
    {
        using var files = new ProtectedRunFiles(GpoSecurityRun.Build(new()));
        using var sources = Open(files);
        var description = Description(sources);
        sources.RequireFor(description);
        var foreign = changed == "capture" ? description with { EvidenceSeal = new string('0', 64) }
            : description with { DerivationGenerationId = Guid.NewGuid() };
        Assert.Throws<InvalidOperationException>(() => sources.RequireFor(foreign));
    }

    [Fact]
    public void PublicationStillPreventsAtomicReplacementOfItsCheckedSelection()
    {
        var directory = GpoSecurityRun.Build(new());
        using var files = new ProtectedRunFiles(directory);
        using var sources = Open(files);
        var description = Description(sources);
        var manifest = AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Derivation);
        var replacement = manifest + ".fixed-input-test";
        File.Copy(manifest, replacement);
        using (sources.ProtectPublication(description))
        {
            var failure = Record.Exception(() => File.Move(replacement, manifest, true));
            Assert.True(failure is IOException or UnauthorizedAccessException, failure?.ToString());
        }
        Assert.True(File.Exists(replacement));
        File.Move(replacement, manifest, true);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void IndependentlyOpenedInputSetsCannotBeJoined(bool otherDirectory)
    {
        var directory = GpoSecurityRun.Build(new());
        using var files = new ProtectedRunFiles(directory);
        using var otherFiles = new ProtectedRunFiles(otherDirectory ? GpoSecurityRun.Build(new()) : directory);
        using var first = Open(files);
        using var second = Open(otherFiles);
        using var fork = first.Fork(CancellationToken.None).Value;
        first.RequireSameInputs(fork);
        Assert.Throws<InvalidOperationException>(() => first.RequireSameInputs(second));
    }

    [Theory]
    [InlineData("parent-disposed")]
    [InlineData("parent-cancelled")]
    [InlineData("child-disposed")]
    [InlineData("child-cancelled")]
    public void BoundReadersStillRequireTheirOwnAndParentLifetimes(string lifetime)
    {
        using var files = new ProtectedRunFiles(GpoSecurityRun.Build(new()));
        using var parentCancellation = new CancellationTokenSource();
        using var childCancellation = new CancellationTokenSource();
        using var parent = Open(files, parentCancellation.Token);
        using var child = parent.Fork(childCancellation.Token).Value;
        child.RequireActiveInputs();
        if (lifetime == "parent-disposed") parent.Dispose();
        else if (lifetime == "child-disposed") child.Dispose();
        else if (lifetime == "parent-cancelled") parentCancellation.Cancel();
        else childCancellation.Cancel();
        if (lifetime.EndsWith("disposed", StringComparison.Ordinal))
            Assert.Throws<ObjectDisposedException>(() => child.RequireActiveInputs());
        else Assert.Throws<OperationCanceledException>(() => child.RequireActiveInputs());
    }

    [Fact]
    public void BoundFilesAndSealsRemainProtectedWithoutHoldingSelectionMarkers()
    {
        var directory = GpoSecurityRun.Build(new());
        using var files = new ProtectedRunFiles(directory);
        using var sources = Open(files);
        var derived = sources.OpenMembershipDerivation().Value;
        var path = BundleLayout.AnalysisGenerationDataPath(directory, AnalysisStoreKind.Derivation,
            derived.Description.GenerationId);
        foreach (var file in new[] { BundleLayout.EvidencePath(directory), BundleLayout.SealPath(directory), path, path + ".seal" })
            Assert.Throws<IOException>(() =>
            {
                using var write = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);
            });
        using var selection = new FileStream(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Derivation),
            FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        Assert.True(selection.CanWrite);
    }

    [Theory]
    [InlineData("owner")]
    [InlineData("capture")]
    public void BoundDerivationCannotBorrowAnotherOwnerOrCapture(string changed)
    {
        var directory = GpoSecurityRun.Build(new());
        using var files = new ProtectedRunFiles(directory);
        using var other = new ProtectedRunFiles(directory);
        var evidence = files.Capture(StoreSegmentRole.Evidence, CancellationToken.None).Value;
        var root = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Derivation).Value;
        if (changed == "owner")
            evidence = other.Capture(StoreSegmentRole.Evidence, CancellationToken.None).Value;
        else
        {
            root = root with { EvidenceSeal = new string('0', 64) };
            root = root with { Hash = root.ComputeHash() };
        }
        var refused = files.BoundDerivation(evidence, root, CancellationToken.None);
        Assert.False(refused.IsSuccess);
        Assert.Equal("Evidence.ProtectedStoreGenerationChanged", refused.Error.Code);
    }

    [Theory]
    [InlineData(9)]
    [InlineData(27)]
    public void ComputerAndPolicyCountsDoNotMultiplySelectionReads(int computers)
    {
        var directory = Mixed(computers);
        using var files = new ProtectedRunFiles(directory);
        using var counts = new Observations(directory);
        using var sources = Open(files);
        using var reader = LapsConfiguredPolicyReader.Open(sources, CancellationToken.None).Value;
        var identities = sources.Bundle.StreamComputerIdentities(CancellationToken.None).ToArray();
        Assert.Equal(computers, identities.Length);
        foreach (var computer in identities)
        {
            var answer = reader.Read(computer, CancellationToken.None);
            Assert.True(answer.IsSuccess, answer.Error?.Description);
            Assert.Equal(computer.ObjectId, answer.Value.Computer.ObjectId);
        }
        Assert.Equal(1, counts.Bindings);
        Assert.Equal(2, counts.Read("capture"));
        Assert.Equal(1, counts.Read("derivation"));
    }

    [Fact]
    public void SharedCoordinatorGivesConfiguredLapsItsOriginalInputSet()
    {
        var directory = Mixed(9);
        using var counts = new Observations(directory);
        using var files = new ProtectedRunFiles(directory);
        var result = JudgingRun.JudgeAudit(directory, RuleCatalogue.All, JudgingRun.ProductionPathRequesterPolicy,
            ConfiguredLapsWorkload.When, ConfiguredLapsWorkload.When, JudgingRun.NobodyIsWatching,
            RunLog.Discarded, CancellationToken.None, null, files,
            ConfiguredLapsPolicy.AllCapturedComputers);
        Assert.True(result.IsSuccess, result.Error?.Description);
        Assert.Equal(1, counts.Bindings);
        var scope = ConfiguredLapsMeasurement.ReadScope(directory);
        Assert.Equal((9L, 9L, 0L), (scope.Considered, scope.Calculated, scope.Unassessed));
    }

    private static string Mixed(int computers)
    {
        var directory = TempDirectories.Create("fixed-input-mixed");
        ConfiguredLapsWorkload.Write(directory, new(computers, 12, 3, 0)
        {
            Profile = ConfiguredLapsWorkloadProfile.MixedLegacyWindows,
        }, CancellationToken.None);
        Assert.True(Stage2aRun.Derive(directory, ExpansionBudget.Bulk, ConfiguredLapsWorkload.When,
            Stage2aRun.Unwatched, RunLog.Discarded, CancellationToken.None).IsSuccess);
        return directory;
    }

    private static JudgingInputs Open(ProtectedRunFiles files, CancellationToken token = default)
    {
        var opened = JudgingInputs.Open(files, token);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        return opened.Value;
    }

    private static JudgementDescription Description(JudgingInputs sources)
    {
        var derived = sources.OpenMembershipDerivation();
        Assert.True(derived.IsSuccess, derived.Error?.Description);
        return new(sources.EvidenceSeal, Guid.NewGuid(), derived.Value.Description.GenerationId,
            JudgementRunState.Running, GpoSecurityRun.Captured, GpoSecurityRun.Captured, default);
    }

    private sealed class Observations : IDisposable
    {
        private readonly CancellationTokenSource _stopping = new();
        private readonly EnterpriseBaselineObservation _observer;
        internal Observations(string directory) => _observer = new(TempDirectories.Create("fixed-input-counts"),
            8L * 1024 * 1024 * 1024, _stopping, directory);
        internal long Bindings => _observer.SourceGuards.GetValueOrDefault("inputs.bindings");
        internal long Read(string kind) => _observer.SelectionManifestReads.GetValueOrDefault(kind);
        public void Dispose() { _observer.Dispose(); _stopping.Dispose(); }
    }
}
