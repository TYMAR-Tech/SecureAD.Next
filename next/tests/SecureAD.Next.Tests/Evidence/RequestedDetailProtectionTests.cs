using System.Text.Json;
using System.Diagnostics.Metrics;
using System.Text;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Capture;
using Xunit;
using ReadbackCounts = SecureAD.Next.Tests.Shell.OpenedRunResultsTests.ReadbackCounts;

namespace SecureAD.Next.Tests.Evidence;

public sealed class RequestedDetailProtectionTests
{
    [Fact]
    public void APreparedIndexCannotRelabelAnUnsupportedCaptureAsTheCurrentFormat()
    {
        using var input = new Capture();
        input.PrepareContradictoryHeader();
        using var files = new ProtectedRunFiles(input.Directory);
        var opened = files.RequestedCapture(StoreSegmentRole.Evidence, CancellationToken.None);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        using var lease = opened.Value;
        var error = Assert.Throws<InvalidDataException>(() => lease.ReadObjectAttributes(Capture.AliceDn, ["sAMAccountName"]));
        Assert.Contains("unsupported", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SelectedCapturedFieldsKeepTheOriginalAnswersWithoutReadingOtherValueFamilies()
    {
        using var input = new Capture();
        using var files = new ProtectedRunFiles(input.Directory);
        var opened = files.RequestedCapture(StoreSegmentRole.Evidence, CancellationToken.None);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        using var lease = opened.Value;
        long bytes = 0;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, owner) =>
        {
            if (instrument.Meter.Name == "SecureAD.Evidence.RequestedDetails" && instrument.Name == "requested_detail.value_bytes")
                owner.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((_, measurement, tags, _) =>
        {
            foreach (var tag in tags)
                if (tag.Key == "index" && Equals(tag.Value, lease.Reader.Manifest.Root)) bytes += measurement;
        });
        listener.Start();
        var selected = lease.ReadObjectAttributes(Capture.AliceDn, ["sAMAccountName", "description"]);
        Assert.NotNull(selected);
        Assert.Equal(["description", "sAMAccountName"], selected.Attributes.Select(attribute => attribute.LdapDisplayName));
        Assert.Equal("Alice", selected.Find("sAMAccountName")!.OnlyValue!.Text);
        Assert.Equal(Capture.Description, selected.Find("description")!.OnlyValue!.Text);
        Assert.True(bytes >= Encoding.UTF8.GetByteCount(Capture.Description));
        Assert.True(bytes < Encoding.UTF8.GetByteCount(Capture.Description) + 1000);
        using var reader = BundleReader.Open(input.Directory).Value;
        Assert.Equal(JsonSerializer.Serialize(reader.ReadObjectAttributes(Capture.AliceDn, ["sAMAccountName", "description"])),
            JsonSerializer.Serialize(selected));
    }

    [Fact]
    public void OriginalMembershipPagesReadOnlyTheirValuesAndKeepAllOriginalOccurrences()
    {
        using var input = new Capture();
        using var files = new ProtectedRunFiles(input.Directory);
        var opened = files.RequestedCapture(StoreSegmentRole.Evidence, CancellationToken.None);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        using var lease = opened.Value;
        CapturedMembershipMark? after = null;
        var sizes = new List<int>();
        var values = new List<string>();
        long bytes = 0;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, owner) =>
        {
            if (instrument.Meter.Name == "SecureAD.Evidence.RequestedDetails" && instrument.Name == "requested_detail.value_bytes")
                owner.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((_, measurement, tags, _) =>
        {
            foreach (var tag in tags)
                if (tag.Key == "index" && Equals(tag.Value, lease.Reader.Manifest.Root)) bytes += measurement;
        });
        listener.Start();
        do
        {
            var before = bytes;
            var page = lease.ReadCapturedMembership(Capture.AliceDn, false, after);
            Assert.NotNull(page);
            Assert.Equal(123, page.Total);
            sizes.Add(page.Values.Count);
            Assert.True(sizes.Count <= 3, "The original membership continuation did not make forward progress.");
            var sharedHeaderBytes = after is null
                ? Encoding.UTF8.GetByteCount(lease.Root.GenerationId.ToString("D"))
                    + Encoding.UTF8.GetByteCount(lease.Root.LibraryHeader!.CoverageId)
                : 0;
            Assert.Equal(page.Values.Sum(value => (long)Encoding.UTF8.GetByteCount(value.Text!)) + sharedHeaderBytes, bytes - before);
            values.AddRange(page.Values.Select(value => value.Text!));
            after = page.Next;
        } while (after is not null);
        Assert.Equal([50, 50, 23], sizes);
        Assert.Equal(Enumerable.Range(0, 123).Select(index => "CN=Member" + index / 2 + ",DC=example,DC=test"), values);
    }

    [Fact]
    public void ActualCapturePublishesTheIndexAndRequestedOpeningIsNotWholeFileVerification()
    {
        using var input = new Capture();
        var root = AnalysisStoreLifecycle.ResolveCapture(input.Directory);
        Assert.True(root.IsSuccess, root.Error?.Description);
        var declaration = root.Value.Segment(StoreSegmentRole.Evidence).RequestedDetails;
        Assert.NotNull(declaration);
        Assert.Equal((root.Value.GenerationId, StoreSegmentRole.Evidence, BundleSchema.Version),
            (declaration.GenerationId, declaration.Role, declaration.SchemaVersion));
        using var counts = new ReadbackCounts(input.Directory);
        using var files = new ProtectedRunFiles(input.Directory);
        var requested = files.RequestedCapture(StoreSegmentRole.Evidence, CancellationToken.None);
        Assert.True(requested.IsSuccess, requested.Error?.Description);
        using var lease = requested.Value;
        var page = lease.Reader.ReadPage("captured_object", input.Alice);
        Assert.Equal(1, page.TotalRows);
        Assert.Equal(Capture.AliceDn, Assert.Single(page.Rows).CompleteText("distinguished_name"));
        Assert.Equal(0, counts.EvidenceVerifications);
        var full = files.Capture(StoreSegmentRole.Evidence, CancellationToken.None);
        Assert.True(full.IsSuccess, full.Error?.Description);
        Assert.True(full.Value.WholeFileVerified);
        Assert.Equal(root.Value.EvidenceSeal, full.Value.Fingerprint);
        Assert.Equal(1, counts.EvidenceVerifications);
    }

    [Fact]
    public void ProtectionIsContinuousUntilTheLastRequestedLeaseCloses()
    {
        using var input = new Capture();
        var files = new ProtectedRunFiles(input.Directory);
        var requested = files.RequestedCapture(StoreSegmentRole.Evidence, CancellationToken.None);
        Assert.True(requested.IsSuccess, requested.Error?.Description);
        var lease = requested.Value;
        files.Dispose();
        var path = BundleLayout.EvidencePath(input.Directory);
        Assert.Throws<IOException>(() => File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite));
        lease.Dispose();
        using var writable = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
    }

    [Fact]
    public void AClosedRequestedLeaseCannotReadItsOldGeneration()
    {
        using var input = new Capture();
        using var files = new ProtectedRunFiles(input.Directory);
        var requested = files.RequestedCapture(StoreSegmentRole.Evidence, CancellationToken.None);
        Assert.True(requested.IsSuccess, requested.Error?.Description);
        var reader = requested.Value.Reader;
        requested.Value.Dispose();
        Assert.ThrowsAny<OperationCanceledException>(() => reader.ReadPage("captured_object", input.Alice));
    }

    [Fact]
    public void AnUnrequestedChangedObjectDoesNotTurnARequestedPageIntoAWholeFileVerdict()
    {
        using var input = new Capture();
        input.Change("UPDATE captured_object SET distinguished_name=REPLACE(distinguished_name,'Bob','Rob') WHERE object_id=" + input.Bob);
        using var files = new ProtectedRunFiles(input.Directory);
        var requested = files.RequestedCapture(StoreSegmentRole.Evidence, CancellationToken.None);
        Assert.True(requested.IsSuccess, requested.Error?.Description);
        using var lease = requested.Value;
        Assert.Equal(Capture.AliceDn, Assert.Single(lease.Reader.ReadPage("captured_object", input.Alice).Rows)
            .CompleteText("distinguished_name"));
        var unrequested = Assert.Single(lease.Reader.ReadPage("captured_object", input.Bob).Rows);
        Assert.Throws<InvalidDataException>(() => unrequested.CompleteText("distinguished_name"));
        var full = files.Capture(StoreSegmentRole.Evidence, CancellationToken.None);
        Assert.False(full.IsSuccess);
        Assert.Equal("Evidence.ProtectedStoreMismatch", full.Error.Code);
        Assert.Throws<InvalidOperationException>(() => lease.Reader.ReadPage("captured_object", input.Alice));
    }

    [Fact]
    public void AChangedSelectedRootIsRefusedEvenWhenItsFilesAreStillProtected()
    {
        using var input = new Capture();
        using var files = new ProtectedRunFiles(input.Directory);
        var requested = files.RequestedCapture(StoreSegmentRole.Evidence, CancellationToken.None);
        Assert.True(requested.IsSuccess, requested.Error?.Description);
        using var lease = requested.Value;
        Assert.Single(lease.Reader.ReadPage("captured_object", input.Alice).Rows);
        var root = AnalysisStoreLifecycle.ResolveCapture(input.Directory).Value;
        var changed = root with { CapturedObjects = root.CapturedObjects + 1 };
        File.WriteAllText(BundleLayout.CaptureManifestPath(input.Directory),
            JsonSerializer.Serialize(changed with { Hash = changed.ComputeHash() }));
        Assert.Throws<InvalidOperationException>(() => lease.Reader.ReadPage("captured_object", input.Alice));
    }

    [Fact]
    public void UncheckpointedWalCannotBeSilentlyIgnoredByARequestedOpening()
    {
        using var input = new Capture();
        File.WriteAllBytes(BundleLayout.EvidencePath(input.Directory) + "-wal", [1, 2, 3, 4]);
        using var files = new ProtectedRunFiles(input.Directory);
        var requested = files.RequestedCapture(StoreSegmentRole.Evidence, CancellationToken.None);
        Assert.False(requested.IsSuccess);
        Assert.Contains("write-ahead-log", requested.Error.Description, StringComparison.Ordinal);
    }

    private sealed class Capture : IDisposable
    {
        internal const string AliceDn = "CN=Alice,DC=example,DC=test";
        internal static string Description { get; } = new('x', 3 * 65536 + 17);
        internal string Directory { get; } = Path.Combine(Path.GetTempPath(), "r5-native-" + Guid.NewGuid().ToString("N"));
        internal long Alice { get; }
        internal long Bob { get; }

        internal Capture()
        {
            var started = new DateTimeOffset(2026, 10, 16, 12, 0, 0, TimeSpan.Zero);
            var partition = new PartitionCoverage("DC=example,DC=test", NamingContextKind.Domain,
                "dc.example.test", ConnectionSecurityLevel.SignedAndSealed, 1, 2, 0, [], false);
            using var writer = BundleWriter.Create(Directory, started);
            writer.WriteCoverage(partition);
            Alice = writer.WriteObject(new(partition, AliceDn, Guid.Parse("ddaa0000-0000-0000-0000-000000000001"),
                [
                    new("sAMAccountName", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("Alice")]),
                    new("description", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText(Description)]),
                    new("member", StoredAttributeCompleteness.Complete, Enumerable.Range(0, 123)
                        .Select(index => EvidenceValue.OfText("CN=Member" + index / 2 + ",DC=example,DC=test")).ToArray()),
                ], started));
            Bob = writer.WriteObject(new(partition, "CN=Bob,DC=example,DC=test",
                Guid.Parse("ddaa0000-0000-0000-0000-000000000002"), [], started));
            writer.Complete(RunCoverage.Of(CoverageId.ForDomains("example.test", ["example.test"]),
                [DomainCoverage.Read("example.test")],
                [
                    ForestPartitionCoverage.Read("CN=Configuration,DC=example,DC=test", NamingContextKind.Configuration),
                    ForestPartitionCoverage.Read("CN=Schema,CN=Configuration,DC=example,DC=test", NamingContextKind.Schema),
                ], SysvolCoverage.Of([])), started.AddMinutes(1));
        }

        internal void Change(string sql)
        {
            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = BundleLayout.EvidencePath(Directory), Mode = SqliteOpenMode.ReadWrite, Pooling = false,
            }.ToString());
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = sql;
            command.ExecuteNonQuery();
        }

        internal void PrepareContradictoryHeader()
        {
            var root = AnalysisStoreLifecycle.ResolveCapture(Directory).Value;
            RequestedDetailManifest declaration;
            var path = BundleLayout.EvidencePath(Directory);
            using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = path, Mode = SqliteOpenMode.ReadWrite, Pooling = false,
            }.ToString()))
            {
                connection.Open();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = $"UPDATE bundle SET schema_version={BundleSchema.Version - 1}; DROP TABLE requested_detail_node";
                    command.ExecuteNonQuery();
                }
                declaration = RequestedDetailIndex.Prepare(connection, "main", StoreSegmentRole.Evidence,
                    BundleSchema.Version, root.GenerationId, "", CancellationToken.None);
            }
            var seal = BundleSealing.Seal(path, path + ".seal");
            var segments = root.Segments.Select(segment => segment.Role != StoreSegmentRole.Evidence ? segment
                : segment with { ByteLength = new FileInfo(path).Length, Hash = seal.Hash, RequestedDetails = declaration }).ToArray();
            var changed = root with { EvidenceSeal = seal.Hash, Segments = segments };
            File.WriteAllText(BundleLayout.CaptureManifestPath(Directory),
                JsonSerializer.Serialize(changed with { Hash = changed.ComputeHash() }));
        }

        public void Dispose()
        {
            if (System.IO.Directory.Exists(Directory))
                System.IO.Directory.Delete(Directory, recursive: true);
        }
    }
}
