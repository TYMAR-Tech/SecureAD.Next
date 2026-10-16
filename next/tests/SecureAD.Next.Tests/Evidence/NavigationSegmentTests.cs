using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

public sealed class NavigationSegmentTests
{
    private const string Root = "DC=contoso,DC=com";
    private static readonly DateTimeOffset When = DateTimeOffset.UnixEpoch;

    [Fact]
    public void CaptureRootBindsEveryExactProductAndEveryPublishedByte()
    {
        var directory = Capture();
        var root = Selected(directory);
        Assert.Equal(root.Hash, root.ComputeHash());
        Assert.Equal(new[] { StoreSegmentRole.Evidence, StoreSegmentRole.Navigation, StoreSegmentRole.Overview, StoreSegmentRole.Delegations },
            root.Segments.Select(segment => segment.Role));
        Assert.Equal(8, root.CapturedObjects);
        foreach (var segment in root.Segments)
        {
            var path = Path.Combine(directory, segment.FileName);
            Assert.Equal(root.GenerationId, segment.GenerationId);
            Assert.Equal(new FileInfo(path).Length, segment.ByteLength);
            Assert.Equal(BundleSealing.HashFile(path), segment.Hash);
            Assert.Equal(segment.Hash, BundleSealing.ReadSeal(path + ".seal")!.Hash);
        }
        Assert.Equal(root.Segment(StoreSegmentRole.Evidence).Hash, root.EvidenceSeal);
    }

    [Theory]
    [InlineData("bytes")]
    [InlineData("missing")]
    [InlineData("seal")]
    [InlineData("role")]
    [InlineData("generation")]
    [InlineData("schema")]
    [InlineData("name")]
    [InlineData("count")]
    [InlineData("size")]
    [InlineData("evidence-missing")]
    [InlineData("evidence-seal")]
    [InlineData("root")]
    public void UnverifiedOrContradictoryNavigationNeverYieldsAClaim(string defect)
    {
        var directory = Capture();
        var root = Selected(directory);
        var path = BundleLayout.NavigationPath(directory, root.GenerationId);
        if (defect == "bytes")
        {
            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
                { DataSource = path, Mode = SqliteOpenMode.ReadWrite, Pooling = false }.ToString());
            connection.Open();
            using var edit = connection.CreateCommand();
            edit.CommandText = "UPDATE captured_object SET domain_fqdn='different.example'";
            edit.ExecuteNonQuery();
            edit.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)";
            edit.ExecuteNonQuery();
        }
        else if (defect == "missing") File.Delete(path);
        else if (defect == "seal") File.Delete(path + ".seal");
        else if (defect == "evidence-missing") File.Delete(BundleLayout.EvidencePath(directory));
        else if (defect == "evidence-seal") File.Delete(BundleLayout.SealPath(directory));
        else
        {
            if (defect == "name")
            {
                File.Copy(path, Path.Combine(directory, "foreign-navigation.db"));
                File.Copy(path + ".seal", Path.Combine(directory, "foreign-navigation.db.seal"));
            }
            root = root with
            {
                CapturedObjects = defect == "count" ? root.CapturedObjects + 1 : root.CapturedObjects,
                Segments = root.Segments.Select(segment => segment.Role != StoreSegmentRole.Navigation ? segment : defect switch
                {
                    "role" => segment with { Role = StoreSegmentRole.Judgement },
                    "generation" => segment with { GenerationId = Guid.NewGuid() },
                    "schema" => segment with { SchemaVersion = 999 },
                    "name" => segment with { FileName = "foreign-navigation.db" },
                    "size" => segment with { ByteLength = segment.ByteLength + 1 },
                    _ => segment,
                }).ToArray(),
            };
            File.WriteAllText(BundleLayout.CaptureManifestPath(directory),
                JsonSerializer.Serialize(root with { Hash = defect == "root" ? new string('0', 64) : root.ComputeHash() }));
        }
        var opened = BundleReader.OpenNavigation(directory);
        if (opened.IsSuccess) opened.Value.Dispose();
        Assert.False(opened.IsSuccess);
        Assert.NotNull(opened.Error);
    }

    [Fact]
    public void SubstitutedNavigationFromAnotherCaptureRefusesEvenWithItsValidSeal()
    {
        var directory = Capture();
        var other = Capture();
        var root = Selected(directory);
        var foreign = Selected(other);
        var path = BundleLayout.NavigationPath(directory, root.GenerationId);
        var foreignPath = BundleLayout.NavigationPath(other, foreign.GenerationId);
        File.Copy(foreignPath, path, overwrite: true);
        File.Copy(foreignPath + ".seal", path + ".seal", overwrite: true);
        root = root with { Segments = root.Segments.Select(segment => segment.Role == StoreSegmentRole.Navigation
            ? segment with { Hash = BundleSealing.HashFile(path), ByteLength = new FileInfo(path).Length } : segment).ToArray() };
        File.WriteAllText(BundleLayout.CaptureManifestPath(directory), JsonSerializer.Serialize(root with { Hash = root.ComputeHash() }));
        var opened = BundleReader.OpenNavigation(directory);
        Assert.False(opened.IsSuccess);
    }

    [Fact]
    public void NavigationPreservesObservedParentsEmptyContainersClassUncertaintyAndForestIdentity()
    {
        var directory = Capture();
        using var raw = BundleReader.Open(directory).Value;
        using var navigation = BundleReader.OpenNavigation(directory).Value;
        Assert.Equal(JsonSerializer.Serialize(raw.Description), JsonSerializer.Serialize(navigation.Description));
        var rawTree = raw.ReadTree();
        var tree = navigation.ReadTree();
        Assert.Equal(JsonSerializer.Serialize(rawTree), JsonSerializer.Serialize(tree));
        Assert.Equal(Root, tree.ForestRootDistinguishedName);
        var all = Flatten(tree.Roots).ToArray();
        Assert.Contains(all, node => node.DistinguishedName == "OU=Empty," + Root && node.Origin == TreeNodeOrigin.Captured);
        Assert.Contains(all, node => node.DistinguishedName == "CN=Ancestor," + Root && node.ObjectClass == "unlistedContainer");
        Assert.Contains(tree.Gaps, gap => gap.DistinguishedName == "OU=Missing,CN=Ancestor," + Root);
        Assert.Contains(all, node => node.DistinguishedName == "OU=Comma\\, name," + Root && node.Name == "Comma, name");
        Assert.Equal(JsonSerializer.Serialize(raw.ReadInventory().Value), JsonSerializer.Serialize(navigation.ReadInventory().Value));
        foreach (var scope in Enum.GetValues<ListingScope>())
            Assert.Equal(JsonSerializer.Serialize(raw.ListObjects(Root, scope, 1)), JsonSerializer.Serialize(navigation.ListObjects(Root, scope, 1)));
        var unknown = navigation.ListObjects(Root, ListingScope.OneLevel, 1).Objects.Single(row => row.DistinguishedName == "CN=Unknown," + Root);
        Assert.Null(unknown.ObjectClass);
        Assert.Null(unknown.ObjectGuid);
    }

    [Fact]
    public void DashboardTreeAndListingNeverHashThePermissionOrDerivationFiles()
    {
        var directory = Capture();
        using (var writer = DerivationWriter.Create(directory, Selected(directory).EvidenceSeal, When))
            writer.Complete(When.AddMinutes(1));
        using var counts = new Verifications(directory);
        using (var source = new BundleAssetSource())
        {
            Assert.True(source.ReadInventory(directory).IsSuccess);
            var membership = source.ReadGroupsWithUnidentifiedMembers(directory);
            Assert.True(membership.IsSuccess);
            Assert.Null(membership.Value);
            Assert.True(source.ReadTree(directory).IsSuccess);
            Assert.True(source.ListObjects(directory, Root, ListingScope.Subtree, null).IsSuccess);
            Assert.True(source.CaptureReadValidity()());
            Assert.Equal(1, counts.For("overview"));
            Assert.Equal(1, counts.For("navigation"));
            Assert.Equal(0, counts.For("evidence"));
            Assert.Equal(0, counts.For("derivation"));
        }
        using var reopened = new BundleAssetSource();
        Assert.True(reopened.ReadTree(directory).IsSuccess);
        Assert.Equal(2, counts.For("navigation"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CancellationAndFailedNavigationSealingNeverPublishACompletedCapture(bool cancel)
    {
        var directory = TempDirectories.Create("navigation-failure");
        Directory.CreateDirectory(directory);
        using var writer = BundleWriter.Create(directory, When);
        writer.WriteCoverage(Partition());
        using var stopping = new CancellationTokenSource();
        var reachedNavigation = false;
        var error = Record.Exception(() => writer.Complete(Coverage(), When.AddMinutes(1),
            ContinuationReconciliation.NotPerformed, SecureAD.Kernel.Capture.CaptureObjectScope.Default, stopping.Token,
            (data, seal, token) =>
            {
                var contents = BundleSealing.Seal(data, seal, token);
                if (!data.EndsWith("navigation.db.partial", StringComparison.Ordinal)) return contents;
                reachedNavigation = true;
                if (cancel) stopping.Cancel();
                else throw new IOException("Injected navigation sealing failure.");
                return contents;
            }));
        Assert.True(reachedNavigation);
        if (cancel) Assert.IsType<OperationCanceledException>(error);
        else Assert.IsType<IOException>(error);
        Assert.False(File.Exists(BundleLayout.CaptureManifestPath(directory)));
        Assert.False(BundleReader.OpenNavigation(directory).IsSuccess);
        Assert.False(BundleReader.Open(directory).IsSuccess);
    }

    [Fact]
    public void CaptureFinalMoveFailureNeverSelectsItsRoot()
    {
        var directory = TempDirectories.Create("capture-move-failure");
        var generation = Guid.NewGuid();
        var evidence = BundleLayout.PartialPath(directory);
        File.WriteAllText(evidence, "sealed synthetic evidence");
        File.WriteAllText(BundleLayout.NavigationPartialPath(directory), "sealed synthetic navigation");
        File.WriteAllText(BundleLayout.OverviewPartialPath(directory), "sealed synthetic overview");
        File.WriteAllText(BundleLayout.DelegationsPartialPath(directory), "sealed synthetic captured permissions");
        Directory.CreateDirectory(BundleLayout.EvidencePath(directory));
        var claimed = false;
        using var files = new ProtectedRunFiles(directory);

        Assert.Throws<IOException>(() => AnalysisStoreLifecycle.PublishCapture(directory, evidence, generation, 0,
            new("synthetic", []), CancellationToken.None, BundleSealing.Seal, () => claimed = true, files));

        Assert.True(claimed);
        Assert.True(File.Exists(BundleLayout.NavigationPath(directory, generation)));
        Assert.True(File.Exists(evidence));
        Assert.False(File.Exists(BundleLayout.CaptureManifestPath(directory)));
        Assert.True(File.Exists(BundleLayout.CaptureManifestPath(directory) + ".partial"));
        Assert.False(AnalysisStoreLifecycle.ResolveCapture(directory).IsSuccess);
    }

    [Fact]
    public void CaptureFinalCancellationNeverClaimsOrSelectsEitherProduct()
    {
        var directory = TempDirectories.Create("capture-final-cancellation");
        var generation = Guid.NewGuid();
        var evidence = BundleLayout.PartialPath(directory);
        var navigation = BundleLayout.NavigationPartialPath(directory);
        File.WriteAllText(evidence, "sealed synthetic evidence");
        File.WriteAllText(navigation, "sealed synthetic navigation");
        File.WriteAllText(BundleLayout.OverviewPartialPath(directory), "sealed synthetic overview");
        File.WriteAllText(BundleLayout.DelegationsPartialPath(directory), "sealed synthetic captured permissions");
        using var stopping = new CancellationTokenSource();
        var claimed = false;
        using var files = new ProtectedRunFiles(directory);

        Assert.Throws<OperationCanceledException>(() => AnalysisStoreLifecycle.PublishCapture(directory, evidence,
            generation, 0, new("synthetic", []), stopping.Token, (data, seal, token) =>
            {
                var contents = BundleSealing.Seal(data, seal, token);
                if (data == navigation) stopping.Cancel();
                return contents;
            }, () => claimed = true, files));

        Assert.False(claimed);
        Assert.True(File.Exists(evidence));
        Assert.True(File.Exists(navigation));
        Assert.False(File.Exists(BundleLayout.EvidencePath(directory)));
        Assert.False(File.Exists(BundleLayout.NavigationPath(directory, generation)));
        Assert.False(File.Exists(BundleLayout.CaptureManifestPath(directory)));
    }

    [Fact]
    public void AChangedCaptureRootInvalidatesAnAlreadyVerifiedSelection()
    {
        var directory = Capture();
        using var source = new BundleAssetSource();
        Assert.True(source.ReadTree(directory).IsSuccess);
        var valid = source.CaptureReadValidity();
        Assert.True(valid());
        File.WriteAllText(BundleLayout.CaptureManifestPath(directory), "{}");
        Assert.False(valid());
        Assert.False(source.ReadInventory(directory).IsSuccess);
    }

    [Fact]
    public void APartitionWithNoObservedDirectChildrenKeepsItsExistingIdentityPresentation()
    {
        var directory = TempDirectories.Create("navigation-root");
        Directory.CreateDirectory(directory);
        using (var writer = BundleWriter.Create(directory, When))
        {
            var partition = new PartitionCoverage(Root, NamingContextKind.Domain, "dc.contoso.com",
                ConnectionSecurityLevel.SignedAndSealed, 1, 1, 1, [], false);
            writer.WriteCoverage(partition);
            writer.WriteObject(new(partition, Root, Guid.NewGuid(),
                [new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("domainDNS")])], When));
            writer.Complete(Coverage(), When.AddMinutes(1));
        }
        using var raw = BundleReader.Open(directory).Value;
        using var navigation = BundleReader.OpenNavigation(directory).Value;
        Assert.Equal(JsonSerializer.Serialize(raw.ReadTree()), JsonSerializer.Serialize(navigation.ReadTree()));
    }

    [Fact]
    public void DistinctGroupCounterMatchesSavedNestingWithoutTreatingNotDerivedAsZero()
    {
        var directory = Capture();
        var evidence = Selected(directory).EvidenceSeal;
        using (var writer = DerivationWriter.Create(directory, evidence, When))
        {
            writer.WriteSids(new[] { "S-1-5-21-1-2-3-1000", "S-1-5-21-1-2-3-1001" }, new string?[] { null, null });
            writer.WriteUnresolvedNestingLinks(new[]
            {
                new UnresolvedNestingLink(0, NestingLinkDirection.Member, "CN=A," + Root),
                new UnresolvedNestingLink(0, NestingLinkDirection.Member, "CN=B," + Root),
                new UnresolvedNestingLink(1, NestingLinkDirection.Member, "CN=C," + Root),
                new UnresolvedNestingLink(1, NestingLinkDirection.ContainingGroup, "CN=D," + Root),
            });
            writer.RecordPhase(MembershipNestingPass.PhaseName, DerivationPhaseOutcome.Degraded, null);
            writer.Complete(When.AddMinutes(1));
        }
        using var source = new BundleAssetSource();
        Assert.Equal(2, source.ReadGroupsWithUnidentifiedMembers(directory).Value);
        var selected = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Derivation).Value;
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = BundleLayout.AnalysisGenerationDataPath(directory, selected.Kind, selected.GenerationId),
            Mode = SqliteOpenMode.ReadOnly, Pooling = false,
        }.ToString());
        connection.Open();
        using var count = connection.CreateCommand();
        count.CommandText = "SELECT COUNT(DISTINCT sid_id) FROM nesting_unresolved_link WHERE direction='Member'";
        Assert.Equal(Convert.ToInt32(count.ExecuteScalar()), source.ReadGroupsWithUnidentifiedMembers(directory).Value);
    }

    private static StoreRootManifest Selected(string directory)
    {
        var selected = AnalysisStoreLifecycle.ResolveCapture(directory);
        Assert.True(selected.IsSuccess, selected.Error?.Description);
        return selected.Value;
    }

    private static string Capture()
    {
        var directory = TempDirectories.Create("navigation");
        Directory.CreateDirectory(directory);
        using var writer = BundleWriter.Create(directory, When);
        var partition = Partition();
        writer.WriteCoverage(partition);
        void Write(string dn, Guid? guid, params string[] classes) => writer.WriteObject(new(partition, dn, guid,
            classes.Length == 0 ? [] : [new("objectClass", StoredAttributeCompleteness.Complete, classes.Select(EvidenceValue.OfText).ToArray())], When));
        Write(Root, Guid.NewGuid(), "top", "domainDNS");
        Write("OU=Empty," + Root, Guid.NewGuid(), "top", "organizationalUnit");
        Write("CN=Ancestor," + Root, Guid.NewGuid(), "top", "unlistedContainer");
        Write("CN=Leaf,OU=Missing,CN=Ancestor," + Root, Guid.NewGuid(), "top", "user");
        Write("OU=Comma\\, name," + Root, Guid.NewGuid(), "top", "organizationalUnit");
        Write("CN=Computer,OU=Comma\\, name," + Root, Guid.NewGuid(), "top", "user", "computer");
        Write("CN=Managed," + Root, Guid.NewGuid(), "top", "user", "computer", "msDS-GroupManagedServiceAccount");
        Write("CN=Unknown," + Root, null);
        writer.Complete(Coverage(), When.AddMinutes(1));
        return directory;
    }
    private static PartitionCoverage Partition() => new(Root, NamingContextKind.Domain, "dc.contoso.com",
        ConnectionSecurityLevel.SignedAndSealed, 1, 8, 1, [], false);
    private static RunCoverage Coverage() => RunCoverage.Of(CoverageId.ForDomains("contoso.com", ["contoso.com"]),
        [DomainCoverage.Read("contoso.com")],
        [ForestPartitionCoverage.Read("CN=Configuration," + Root, NamingContextKind.Configuration),
            ForestPartitionCoverage.Read("CN=Schema,CN=Configuration," + Root, NamingContextKind.Schema)],
        SysvolCoverage.Of([]));
    private static IEnumerable<TreeNode> Flatten(IEnumerable<TreeNode> roots) => roots.SelectMany(node =>
        new[] { node }.Concat(Flatten(node.Children)));

    private sealed class Verifications : IDisposable
    {
        private readonly MeterListener _listener = new();
        private readonly ConcurrentDictionary<string, long> _counts = new();
        internal Verifications(string directory)
        {
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Name == "store.verifications") listener.EnableMeasurementEvents(instrument);
            };
            _listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
            {
                foreach (var tag in tags)
                    if (tag.Value is string path && path.StartsWith(directory, StringComparison.OrdinalIgnoreCase))
                        _counts.AddOrUpdate(Path.GetFileName(path).Split('.')[0], value, (_, previous) => previous + value);
            });
            _listener.Start();
        }
        internal long For(string role) => _counts.GetValueOrDefault(role);
        public void Dispose() => _listener.Dispose();
    }
}
