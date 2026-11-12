using System.Diagnostics.Metrics;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Measure;
using Xunit;
using static SecureAD.Next.Tests.Judgement.LapsPrecedenceRun;

namespace SecureAD.Next.Tests.Judgement;

[Collection("GPO preparation diagnostics")]
public sealed class CurrentSelectionGuardTests
{
    [Theory]
    [InlineData("none")]
    [InlineData("first")]
    [InlineData("second")]
    [InlineData("both")]
    public void AdjacentScopesShareActualManifestReadsButValidateBothBindings(string derived)
    {
        var directory = Ready();
        using var files = new ProtectedRunFiles(directory);
        using var first = Open(files);
        using var second = Open(files);
        if (derived is "first" or "both") Assert.True(first.OpenMembershipDerivation().IsSuccess);
        if (derived is "second" or "both") Assert.True(second.OpenMembershipDerivation().IsSuccess);
        using var counts = new Observations(directory);
        first.RequireCurrentWith(second);
        Assert.Equal(2, counts.Guard("guard.logical_requests"));
        Assert.Equal(1, counts.Guard("guard.capture_resolves"));
        Assert.Equal(1, counts.Read("capture"));
        Assert.Equal(derived == "none" ? 0 : 1, counts.Guard("guard.derivation_resolves"));
        Assert.Equal(derived == "none" ? 0 : 1, counts.Read("derivation"));
        Assert.Equal(1, counts.Samples);
        Assert.True(counts.Milliseconds > 0);
    }

    [Fact]
    public void EveryScalarAndJointBoundaryReadsCurrentSelectionsAgain()
    {
        var directory = Ready();
        using var files = new ProtectedRunFiles(directory);
        using var first = Open(files);
        using var second = Open(files);
        Assert.True(first.OpenMembershipDerivation().IsSuccess);
        Assert.True(second.OpenMembershipDerivation().IsSuccess);
        using var counts = new Observations(directory);
        first.RequireCurrent();
        first.RequireCurrentWith(second);
        second.RequireCurrent();
        first.RequireCurrentWith(second);
        Assert.Equal(6, counts.Guard("guard.logical_requests"));
        Assert.Equal(4, counts.Guard("guard.capture_resolves"));
        Assert.Equal(4, counts.Guard("guard.derivation_resolves"));
        Assert.Equal(4, counts.Read("capture"));
        Assert.Equal(4, counts.Read("derivation"));
        Assert.Equal(4, counts.Samples);
    }

    [Theory]
    [InlineData("first")]
    [InlineData("second")]
    public void EitherHeldDerivationCanRefuseThePair(string stale)
    {
        var directory = Ready();
        using var files = new ProtectedRunFiles(directory);
        using var first = Open(files);
        using var second = Open(files);
        var old = stale == "first" ? first : second;
        var current = stale == "first" ? second : first;
        var original = old.OpenMembershipDerivation().Value.Description.GenerationId;
        GpoSecurityRun.Derive(directory);
        var replacement = current.OpenMembershipDerivation().Value.Description.GenerationId;
        Assert.NotEqual(original, replacement);
        current.RequireCurrent();
        Assert.Throws<InvalidOperationException>(() => old.RequireCurrent());
        Assert.Throws<InvalidOperationException>(() => first.RequireCurrentWith(second));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void IndependentProtectionOwnersCannotShareASelectionVerdict(bool differentRun)
    {
        var directory = Ready();
        using var firstFiles = new ProtectedRunFiles(directory);
        using var secondFiles = new ProtectedRunFiles(differentRun ? Ready() : directory);
        using var first = Open(firstFiles);
        using var second = Open(secondFiles);
        first.RequireCurrent();
        second.RequireCurrent();
        using var counts = new Observations(directory);
        Assert.Throws<InvalidOperationException>(() => first.RequireCurrentWith(second));
        Assert.Equal(0, counts.Read("capture"));
        Assert.Equal(0, counts.Read("derivation"));
    }

    [Theory]
    [InlineData("capture")]
    [InlineData("derivation")]
    public void AChangedSelectionBetweenJointCallsCannotReuseThePreviousSuccess(string changed)
    {
        var directory = Ready();
        using var files = new ProtectedRunFiles(directory);
        using var first = Open(files);
        using var second = Open(files);
        Assert.True(first.OpenMembershipDerivation().IsSuccess);
        Assert.True(second.OpenMembershipDerivation().IsSuccess);
        first.RequireCurrentWith(second);
        if (changed == "capture")
            File.Copy(BundleLayout.CaptureManifestPath(Ready()), BundleLayout.CaptureManifestPath(directory), true);
        else GpoSecurityRun.Derive(directory);
        using var counts = new Observations(directory);
        Assert.Throws<InvalidOperationException>(() => first.RequireCurrentWith(second));
        Assert.Equal(1, counts.Read("capture"));
        Assert.Equal(changed == "capture" ? 0 : 1, counts.Read("derivation"));
    }

    [Theory]
    [InlineData("first-disposed")]
    [InlineData("second-disposed")]
    [InlineData("first-cancelled")]
    [InlineData("second-cancelled")]
    [InlineData("first-cancel-during")]
    [InlineData("second-cancel-during")]
    [InlineData("first-dispose-during")]
    [InlineData("second-dispose-during")]
    public void BothScopeLifetimesAreRequiredBeforeAndAfterSelectionReading(string lifetime)
    {
        var directory = Ready();
        using var files = new ProtectedRunFiles(directory);
        using var firstCancellation = new CancellationTokenSource();
        using var secondCancellation = new CancellationTokenSource();
        using var first = Open(files, firstCancellation.Token);
        using var second = Open(files, secondCancellation.Token);
        first.RequireCurrentWith(second);
        var selected = lifetime.StartsWith("first", StringComparison.Ordinal) ? first : second;
        var stopping = lifetime.StartsWith("first", StringComparison.Ordinal) ? firstCancellation : secondCancellation;
        var disposed = lifetime.Contains("dispos", StringComparison.Ordinal);
        Action stop = disposed ? selected.Dispose : stopping.Cancel;
        if (lifetime.EndsWith("during", StringComparison.Ordinal))
        {
            using var interrupt = new DuringCaptureRead(directory, stop);
            if (disposed) Assert.Throws<ObjectDisposedException>(() => first.RequireCurrentWith(second));
            else Assert.Throws<OperationCanceledException>(() => first.RequireCurrentWith(second));
            Assert.True(interrupt.Observed);
        }
        else
        {
            stop();
            if (disposed) Assert.Throws<ObjectDisposedException>(() => first.RequireCurrentWith(second));
            else Assert.Throws<OperationCanceledException>(() => first.RequireCurrentWith(second));
        }
    }

    [Fact]
    public void JointCheckingProtectsPayloadsWithoutPinningMutableSelectionsBetweenCalls()
    {
        var directory = Ready();
        using var files = new ProtectedRunFiles(directory);
        using var first = Open(files);
        using var second = Open(files);
        Assert.True(first.OpenMembershipDerivation().IsSuccess);
        Assert.True(second.OpenMembershipDerivation().IsSuccess);
        first.RequireCurrentWith(second);
        foreach (var path in new[] { BundleLayout.EvidencePath(directory), BundleLayout.SealPath(directory) })
            Assert.Throws<IOException>(() =>
            {
                using var write = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);
            });
        var selectionFailure = Record.Exception(() =>
        {
            using var selection = new FileStream(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Derivation),
                FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            Assert.True(selection.CanWrite);
        });
        Assert.Null(selectionFailure);
        first.RequireCurrentWith(second);
    }

    [Fact]
    public void ConfiguredLapsUsesJointValidationWithoutDroppingLogicalBoundaries()
    {
        var directory = Build([new(1, [TextValue(Principal, GroupA)])],
            computerAttributes: GpoDirectoryWmiAssessmentTests.Platform());
        using var reader = LapsConfiguredPolicyReader.Open(directory, CancellationToken.None).Value;
        var computer = reader.Bundle.ReadObjectIdentity(GpoSecurityRun.Computer)!;
        using var counts = new Observations(directory);
        var first = reader.Read(computer, CancellationToken.None);
        var second = reader.Read(computer, CancellationToken.None);
        Assert.True(first.IsSuccess, first.Error?.Description);
        Assert.True(second.IsSuccess, second.Error?.Description);
        Assert.Equal(GroupA, second.Value.UnderDirectoryAssessment(LapsPolicySetting.ADPasswordEncryptionPrincipal).Value!.Principal);
        Assert.Equal(24, counts.Guard("guard.logical_requests"));
        Assert.Equal(16, counts.Guard("guard.capture_resolves"));
        Assert.Equal(16, counts.Read("capture"));
        Assert.Equal(0, counts.Read("derivation"));
        Assert.Equal(16, counts.Samples);
    }

    private static string Ready() => GpoSecurityRun.Build(new());
    private static JudgingInputs Open(ProtectedRunFiles files, CancellationToken token = default)
    {
        var result = JudgingInputs.Open(files, token);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return result.Value;
    }

    private sealed class Observations : IDisposable
    {
        private readonly CancellationTokenSource _stopping = new();
        private readonly EnterpriseBaselineObservation _observer;
        internal Observations(string directory) => _observer = new(TempDirectories.Create("source-guard-counts"),
            8L * 1024 * 1024 * 1024, _stopping, directory);
        internal long Guard(string name) => _observer.SourceGuards.GetValueOrDefault(name);
        internal long Read(string kind) => _observer.SelectionManifestReads.GetValueOrDefault(kind);
        internal long Samples => _observer.SourceGuardSamples;
        internal double Milliseconds => _observer.SourceGuardMilliseconds;
        public void Dispose() { _observer.Dispose(); _stopping.Dispose(); }
    }

    private sealed class DuringCaptureRead : IDisposable
    {
        private readonly MeterListener _listener = new();
        internal bool Observed { get; private set; }
        internal DuringCaptureRead(string directory, Action action)
        {
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == "SecureAD.Evidence.Readback" && instrument.Name == "store.selection_manifest_reads")
                    listener.EnableMeasurementEvents(instrument);
            };
            _listener.SetMeasurementEventCallback<long>((_, _, tags, _) =>
            {
                string? source = null;
                string? kind = null;
                foreach (var tag in tags)
                {
                    if (tag.Key == "bundle") source = tag.Value as string;
                    if (tag.Key == "kind") kind = tag.Value as string;
                }
                if (!Observed && source == directory && kind == "capture")
                {
                    Observed = true;
                    action();
                }
            });
            _listener.Start();
        }
        public void Dispose() => _listener.Dispose();
    }
}
