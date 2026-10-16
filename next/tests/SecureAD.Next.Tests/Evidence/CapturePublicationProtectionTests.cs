using System.Text.Json;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Capture;
using Xunit;
using ReadbackCounts = SecureAD.Next.Tests.Shell.OpenedRunResultsTests.ReadbackCounts;

namespace SecureAD.Next.Tests.Evidence;

public sealed class CapturePublicationProtectionTests
{
    [Theory]
    [InlineData(StoreSegmentRole.Evidence)]
    [InlineData(StoreSegmentRole.Navigation)]
    [InlineData(StoreSegmentRole.Overview)]
    [InlineData(StoreSegmentRole.Delegations)]
    public void PublicationTransfersExactProtectedFilesAndAReleasedLifetimeVerifiesAgain(StoreSegmentRole role)
    {
        using var capture = new Publication();
        using var counts = new ReadbackCounts(capture.Directory);
        var root = capture.Publish(BundleSealing.Seal, () => { });
        var selected = capture.Files.Capture(role, CancellationToken.None);
        Assert.True(selected.IsSuccess, selected.Error?.Description);
        Assert.Equal((root.GenerationId, root.Hash, root.Segment(role).Hash),
            (selected.Value.Root.GenerationId, selected.Value.Root.Hash, selected.Value.Fingerprint));
        Assert.Equal((0L, 0L, 0L, 0L), CaptureChecks(counts));
        var path = Path.Combine(capture.Directory, root.Segment(role).FileName);
        foreach (var file in new[] { path, path + ".seal" })
        {
            Assert.Throws<IOException>(() => File.Open(file, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite));
            Assert.Throws<IOException>(() => File.Move(file, file + ".replacement"));
        }

        capture.Files.Dispose();
        using var later = new ProtectedRunFiles(capture.Directory);
        Assert.True(later.Capture(role, CancellationToken.None).IsSuccess);
        Assert.Equal(1L, counts.EvidenceVerifications + counts.NavigationVerifications
            + counts.OverviewVerifications + counts.DelegationVerifications);
    }

    [Theory]
    [InlineData(StoreSegmentRole.Evidence)]
    [InlineData(StoreSegmentRole.Navigation)]
    [InlineData(StoreSegmentRole.Overview)]
    [InlineData(StoreSegmentRole.Delegations)]
    public void AChangedSealCannotBorrowTheProducerReceipt(StoreSegmentRole role)
    {
        using var capture = new Publication();
        Assert.Throws<InvalidDataException>(() => capture.Publish((data, seal, token) =>
        {
            var receipt = BundleSealing.Seal(data, seal, token);
            if (data == capture.Staged(role))
                File.WriteAllText(seal, JsonSerializer.Serialize(receipt with { Hash = new string('0', 64) }));
            return receipt;
        }, () => { }));

        Assert.False(File.Exists(BundleLayout.CaptureManifestPath(capture.Directory)));
        AssertReleased(capture.Directory);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PublicationNeverReleasesWriteProtectionDuringSealingOrItsPublicationClaim(bool atPublication)
    {
        using var capture = new Publication();
        var attempts = 0;
        void Probe(string path)
        {
            attempts++;
            Assert.Throws<IOException>(() => File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite));
        }
        var root = capture.Publish((data, seal, token) =>
        {
            var receipt = BundleSealing.Seal(data, seal, token);
            if (!atPublication) Probe(data);
            return receipt;
        }, () =>
        {
            if (atPublication)
                foreach (var role in new[] { StoreSegmentRole.Evidence, StoreSegmentRole.Navigation, StoreSegmentRole.Overview, StoreSegmentRole.Delegations })
                    Probe(capture.Staged(role));
        });
        Assert.Equal(4, attempts);
        Assert.Equal(root.Hash, AnalysisStoreLifecycle.ResolveCapture(capture.Directory).Value.Hash);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AByteIdenticalReplacementCannotBorrowAnotherFilesProtection(bool atPublication)
    {
        using var capture = new Publication();
        var replaced = false;
        void Replace(StoreSegmentRole role)
        {
            var source = capture.Staged(role);
            File.Move(source, source + ".original");
            File.Copy(source + ".original", source);
            replaced = true;
        }
        Assert.Throws<InvalidDataException>(() => capture.Publish((data, seal, token) =>
        {
            var receipt = BundleSealing.Seal(data, seal, token);
            if (!atPublication && data == capture.Staged(StoreSegmentRole.Evidence))
                Replace(StoreSegmentRole.Navigation);
            return receipt;
        }, () =>
        {
            if (atPublication) Replace(StoreSegmentRole.Evidence);
        }));

        Assert.True(replaced);
        Assert.False(File.Exists(BundleLayout.CaptureManifestPath(capture.Directory)));
        AssertReleased(capture.Directory);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FailedOwnershipOrRootSelectionCannotPublishACompletedCapture(bool closingOwner)
    {
        using var capture = new Publication();
        var error = Record.Exception(() => capture.Publish(BundleSealing.Seal, () =>
        {
            if (closingOwner) capture.Files.Dispose();
            else Directory.CreateDirectory(BundleLayout.CaptureManifestPath(capture.Directory));
        }));
        if (closingOwner) Assert.IsType<ObjectDisposedException>(error);
        else Assert.IsAssignableFrom<IOException>(error);
        Assert.False(AnalysisStoreLifecycle.ResolveCapture(capture.Directory).IsSuccess);
        Assert.False(File.Exists(BundleLayout.CaptureManifestPath(capture.Directory)));
        capture.Files.Dispose();
        AssertReleased(capture.Directory);
    }

    [Fact]
    public void AForeignRunOwnerIsRefusedBeforeCapturePreparation()
    {
        var directory = TempDirectories.Create("foreign-capture-owner");
        using var files = new ProtectedRunFiles(TempDirectories.Create("other-capture-owner"));
        using var writer = BundleWriter.Create(directory, DateTimeOffset.UnixEpoch);
        var coverage = RunCoverage.Of(CoverageId.ForDomains("example.com", ["example.com"]),
            [DomainCoverage.Read("example.com")],
            [ForestPartitionCoverage.Read("CN=Configuration,DC=example,DC=com", NamingContextKind.Configuration),
                ForestPartitionCoverage.Read("CN=Schema,CN=Configuration,DC=example,DC=com", NamingContextKind.Schema)],
            SysvolCoverage.Of([]));

        Assert.Throws<ArgumentException>(() => writer.Complete(coverage, DateTimeOffset.UnixEpoch,
            ContinuationReconciliation.NotPerformed, CaptureObjectScope.Default, CancellationToken.None,
            BundleSealing.Seal, files));
        Assert.False(File.Exists(BundleLayout.CaptureManifestPath(directory) + ".partial"));
        Assert.False(File.Exists(BundleLayout.NavigationPartialPath(directory)));
    }

    internal static (long, long, long, long) CaptureChecks(ReadbackCounts counts) =>
        (counts.EvidenceVerifications, counts.NavigationVerifications, counts.OverviewVerifications, counts.DelegationVerifications);

    internal static void AssertReleased(string directory)
    {
        foreach (var path in Directory.EnumerateFiles(directory))
        {
            using var exclusive = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            Assert.True(exclusive.CanWrite);
        }
    }

    private sealed class Publication : IDisposable
    {
        internal string Directory { get; } = TempDirectories.Create("capture-publication-protection");
        private Guid Generation { get; } = Guid.NewGuid();
        internal ProtectedRunFiles Files { get; }

        internal Publication()
        {
            Files = new(Directory);
            foreach (var role in new[] { StoreSegmentRole.Evidence, StoreSegmentRole.Navigation, StoreSegmentRole.Overview, StoreSegmentRole.Delegations })
                File.WriteAllText(Staged(role), "Synthetic publication bytes for " + role);
        }

        internal string Staged(StoreSegmentRole role) => role switch
        {
            StoreSegmentRole.Evidence => BundleLayout.PartialPath(Directory),
            StoreSegmentRole.Navigation => BundleLayout.NavigationPartialPath(Directory),
            StoreSegmentRole.Overview => BundleLayout.OverviewPartialPath(Directory),
            StoreSegmentRole.Delegations => BundleLayout.DelegationsPartialPath(Directory),
            _ => throw new ArgumentOutOfRangeException(nameof(role)),
        };

        internal StoreRootManifest Publish(Func<string, string, CancellationToken, BundleSealContents> seal, Action claim) =>
            AnalysisStoreLifecycle.PublishCapture(Directory, Staged(StoreSegmentRole.Evidence), Generation, 0,
                new("synthetic", []), CancellationToken.None, seal, claim, Files);

        public void Dispose() => Files.Dispose();
    }
}
