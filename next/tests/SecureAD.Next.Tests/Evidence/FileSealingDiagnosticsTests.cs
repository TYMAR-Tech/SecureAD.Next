using System.Globalization;
using System.Security.Cryptography;
using SecureAD.Evidence;
using SecureAD.Kernel;
using Xunit;
using static SecureAD.Next.Tests.Judgement.JudgingStatusTests;

namespace SecureAD.Next.Tests.Evidence;

public sealed class FileSealingDiagnosticsTests
{
    [Theory]
    [InlineData(0, 1)]
    [InlineData(3, 2)]
    [InlineData(81920, 2)]
    [InlineData(163857, 4)]
    public void DetailedSealingKeepsExactBytesAndCountsEveryReadIncludingEof(int length, int reads)
    {
        var directory = TempDirectories.Create("file-sealing-details");
        var path = Path.Combine(directory, "source.db");
        var bytes = Enumerable.Range(0, length).Select(index => (byte)(index % 251)).ToArray();
        File.WriteAllBytes(path, bytes);
        BundleSealing.Seal(path, path + ".control", CancellationToken.None);
        var log = new StatusLog();

        var receipt = BundleSealing.SealWithDiagnostics(path, path + ".observed", CancellationToken.None, log, null, null);

        Assert.Equal(File.ReadAllBytes(path + ".control"), File.ReadAllBytes(path + ".observed"));
        Assert.Equal(Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), BundleSealing.ReadSeal(path + ".observed")!.Hash);
        Assert.Equal(new(BundleSealing.Algorithm, Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()), receipt);
        Assert.Equal(bytes, File.ReadAllBytes(path));
        var report = Assert.Single(log.Lines);
        Assert.Equal("file sealing", report.Message);
        Assert.Equal(("Evidence", "none", "Completed", "none"),
            (report.Value("artifact"), report.Value("generation"), report.Value("outcome"), report.Value("failedPart")));
        Assert.Equal((length.ToString(CultureInfo.InvariantCulture), length.ToString(CultureInfo.InvariantCulture), reads.ToString(CultureInfo.InvariantCulture)),
            (report.Value("bytesRead"), report.Value("bytesHashed"), report.Value("readCalls")));
        Assert.Equal("81920", report.Value("readBufferBytes"));
        Assert.Equal("elapsed-operation-not-cpu", report.Value("timingKind"));
        Assert.Equal("sealing-before-log-write", report.Value("timingScope"));
        Assert.Equal("open-write-close", report.Value("sealWriteIncludes"));
        foreach (var part in new[] { "openDataMs", "readDataMs", "hashDataMs", "finishHashMs", "closeDataMs", "encodeSealMs", "writeSealMs", "maxReadMs", "maxHashMs" })
            Assert.True(Number(report, part) >= 0);
        using var exclusive = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        Assert.Equal(length, exclusive.Length);
    }

    [Fact]
    public void ReadAndHashDurationsAndLongestCallsAreMeasuredSeparately()
    {
        var clock = new StepClock();
        var bytes = new byte[81921];
        using var stream = new TimedStream(bytes, clock, () => { });
        var work = new FileSealWork(clock);

        var hash = BundleSealing.HashStream(stream, CancellationToken.None, work);

        Assert.Equal(Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), hash);
        var log = new StatusLog();
        work.Report(log, AnalysisStoreKind.Judgement, Guid.NewGuid(), "Completed");
        var report = Assert.Single(log.Lines);
        Assert.Equal((33d, 2d, 1d, 11d, 1d),
            (Number(report, "readDataMs"), Number(report, "hashDataMs"), Number(report, "finishHashMs"),
                Number(report, "maxReadMs"), Number(report, "maxHashMs")));
        Assert.Equal(("3", "81921", "81921"), (report.Value("readCalls"), report.Value("bytesRead"), report.Value("bytesHashed")));
        Assert.True(stream.CanRead);
    }

    [Fact]
    public void EverySealingIntervalIsWiredToItsFileOperation()
    {
        var directory = TempDirectories.Create("file-sealing-intervals");
        var data = Path.Combine(directory, "data");
        var seal = Path.Combine(directory, "seal");
        File.WriteAllBytes(data, [1, 2, 3]);
        var work = new FileSealWork(new StepClock());

        BundleSealing.Seal(data, seal, CancellationToken.None, work);

        var log = new StatusLog();
        work.Report(log, null, null, "Completed");
        var report = Assert.Single(log.Lines);
        Assert.Equal(2, Number(report, "readDataMs"));
        foreach (var part in new[] { "openDataMs", "hashDataMs", "finishHashMs", "closeDataMs", "encodeSealMs", "writeSealMs" })
            Assert.Equal(1, Number(report, part));
        var accounted = new[] { "openDataMs", "readDataMs", "hashDataMs", "finishHashMs", "closeDataMs", "encodeSealMs", "writeSealMs" }
            .Sum(part => Number(report, part));
        Assert.Equal(Number(report, "totalMs"), accounted + Number(report, "unaccountedMs"));
        Assert.Equal(BundleSealing.HashFile(data), BundleSealing.ReadSeal(seal)!.Hash);
    }

    [Theory]
    [InlineData("open", "OpenData")]
    [InlineData("write", "WriteSeal")]
    public void FailedSealingNamesTheFailingOperationAndPreservesTheException(string operation, string expectedPart)
    {
        var directory = TempDirectories.Create("file-sealing-failure");
        var data = Path.Combine(directory, "data");
        var seal = Path.Combine(directory, "seal");
        if (operation == "write")
        {
            File.WriteAllBytes(data, [1, 2, 3]);
            Directory.CreateDirectory(seal);
        }
        var log = new StatusLog();

        var failure = Record.Exception(() => BundleSealing.SealWithDiagnostics(data, seal, CancellationToken.None, log, null, null));

        if (operation == "open") Assert.IsType<FileNotFoundException>(failure);
        else Assert.IsType<UnauthorizedAccessException>(failure);
        var report = Assert.Single(log.Lines);
        Assert.Equal(("Failed", expectedPart), (report.Value("outcome"), report.Value("failedPart")));
        Assert.Equal(operation == "open" ? "0" : "3", report.Value("bytesRead"));
        Assert.False(File.Exists(seal));
    }

    [Fact]
    public void AReadFailureKeepsItsPartialTimingAndOriginalExceptionEvenDuringCancellation()
    {
        var clock = new StepClock();
        using var stopping = new CancellationTokenSource();
        var failure = new IOException("Synthetic data read failure");
        using var stream = new TimedStream([1], clock, () => { stopping.Cancel(); throw failure; });
        var work = new FileSealWork(clock);

        Assert.Same(failure, Assert.Throws<IOException>(() => BundleSealing.HashStream(stream, stopping.Token, work)));

        var log = new StatusLog();
        work.Report(log, null, null, "Failed");
        var report = Assert.Single(log.Lines);
        Assert.Equal(("ReadData", "1", "0", "0"), (report.Value("failedPart"), report.Value("readCalls"),
            report.Value("bytesRead"), report.Value("bytesHashed")));
        Assert.Equal(11, Number(report, "readDataMs"));
    }

    [Fact]
    public void APreCancelledObservedSealDoesNotReadOrWriteAndReportsCancellation()
    {
        var directory = TempDirectories.Create("file-sealing-cancelled");
        var data = Path.Combine(directory, "data");
        var seal = Path.Combine(directory, "seal");
        File.WriteAllBytes(data, [1, 2, 3]);
        using var stopping = new CancellationTokenSource();
        stopping.Cancel();
        var log = new StatusLog();

        var error = Assert.Throws<OperationCanceledException>(() =>
            BundleSealing.SealWithDiagnostics(data, seal, stopping.Token, log, null, null));

        Assert.Equal(stopping.Token, error.CancellationToken);
        Assert.False(File.Exists(seal));
        var report = Assert.Single(log.Lines);
        Assert.Equal(("Cancelled", "0", "0"), (report.Value("outcome"), report.Value("readCalls"), report.Value("bytesRead")));
    }

    [Fact]
    public void CancellationAfterReadingDoesNotClaimThatTheBytesWereHashed()
    {
        var clock = new StepClock();
        using var stopping = new CancellationTokenSource();
        using var stream = new TimedStream([1, 2, 3], clock, stopping.Cancel);
        var work = new FileSealWork(clock);

        Assert.Throws<OperationCanceledException>(() => BundleSealing.HashStream(stream, stopping.Token, work));

        var log = new StatusLog();
        work.Report(log, null, null, "Cancelled");
        var report = Assert.Single(log.Lines);
        Assert.Equal(("3", "0", "1"), (report.Value("bytesRead"), report.Value("bytesHashed"), report.Value("readCalls")));
        Assert.Equal(0, Number(report, "finishHashMs"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AnUnavailableDiagnosticLogDoesNotReplaceTheSealingOutcome(bool sourceMissing)
    {
        var directory = TempDirectories.Create("file-sealing-log-failure");
        var data = Path.Combine(directory, "data");
        var seal = Path.Combine(directory, "seal");
        if (!sourceMissing) File.WriteAllBytes(data, [1, 2, 3]);
        var log = new StatusLog(_ => throw new IOException("Synthetic diagnostic failure"));

        var error = Record.Exception(() => BundleSealing.SealWithDiagnostics(data, seal, CancellationToken.None, log, null, null));

        Assert.Single(log.Lines);
        if (sourceMissing) Assert.IsType<FileNotFoundException>(error);
        else
        {
            Assert.Null(error);
            Assert.Equal(BundleSealing.HashFile(data), BundleSealing.ReadSeal(seal)!.Hash);
        }
    }

    [Fact]
    public void SealingDetailsExcludeFilePathsAndDirectoryObjectData()
    {
        var directory = TempDirectories.Create("file-sealing-private-data");
        var data = Path.Combine(directory, "CN=secret-S-1-5-21-private.db");
        File.WriteAllText(data, "CN=secret,DC=private,DC=example");
        var log = new StatusLog();
        var generation = Guid.NewGuid();

        BundleSealing.SealWithDiagnostics(data, data + ".seal", CancellationToken.None, log, AnalysisStoreKind.Judgement, generation);

        var report = Assert.Single(log.Lines);
        Assert.Equal(("Judgement", generation.ToString("D")), (report.Value("artifact"), report.Value("generation")));
        foreach (var field in report.Detail)
        {
            Assert.DoesNotContain(directory, field.Value, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("CN=", field.Value, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("DC=", field.Value, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("S-1-", field.Value, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("secret", field.Value, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void DiagnosticPublicationStillSelectsOnlyTheSealedGeneration()
    {
        var directory = TempDirectories.Create("diagnostic-publication");
        var generation = Guid.NewGuid();
        var staging = TestSealing.AnalysisInputPath(directory, AnalysisStoreKind.Judgement, generation);
        File.WriteAllText(staging, "finished synthetic result");
        var log = new StatusLog(line =>
        {
            if (line.Message != "file sealing") return;
            Assert.False(File.Exists(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement)));
        });

        AnalysisStoreLifecycle.PublishWithDiagnostics(directory, AnalysisStoreKind.Judgement, generation, CancellationToken.None, log);

        Assert.Equal(generation, AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId);
        Assert.Equal("Completed", Assert.Single(log.Lines).Value("outcome"));
    }

    [Fact]
    public void CancellationFromTheSealLogStillPreventsAnalysisManifestSelection()
    {
        var directory = TempDirectories.Create("diagnostic-publication-cancel");
        var previous = Guid.NewGuid();
        File.WriteAllText(TestSealing.AnalysisInputPath(directory, AnalysisStoreKind.Judgement, previous), "previous result");
        AnalysisStoreLifecycle.Publish(directory, AnalysisStoreKind.Judgement, previous);
        var generation = Guid.NewGuid();
        var staging = TestSealing.AnalysisInputPath(directory, AnalysisStoreKind.Judgement, generation);
        File.WriteAllText(staging, "replacement result");
        using var stopping = new CancellationTokenSource();
        var log = new StatusLog(_ => stopping.Cancel());

        Assert.Throws<OperationCanceledException>(() =>
            AnalysisStoreLifecycle.PublishWithDiagnostics(directory, AnalysisStoreKind.Judgement, generation, stopping.Token, log));

        Assert.Equal("Completed", Assert.Single(log.Lines).Value("outcome"));
        Assert.Equal(previous, AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId);
        Assert.True(AnalysisStoreLifecycle.HasUnpublishedChanges(directory, AnalysisStoreKind.Judgement));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DiagnosticArtifactLabelsCannotInventOrOmitAGeneration(bool missingGeneration)
    {
        var log = new StatusLog();

        Assert.Throws<ArgumentException>(() => BundleSealing.SealWithDiagnostics("unused", "unused.seal", CancellationToken.None,
            log, missingGeneration ? AnalysisStoreKind.Judgement : null, missingGeneration ? null : Guid.NewGuid()));
        Assert.Empty(log.Lines);
    }

    [Fact]
    public void DiagnosticPublicationRequiresTheRequestedLog()
    {
        Assert.Throws<ArgumentNullException>(() =>
            AnalysisStoreLifecycle.PublishWithDiagnostics("unused", AnalysisStoreKind.Judgement, Guid.NewGuid(), CancellationToken.None, null!));
    }

    [Fact]
    public void AnUnknownArtifactKindCannotBeLoggedAsCapture()
    {
        var log = new StatusLog();
        Assert.Throws<ArgumentException>(() => BundleSealing.SealWithDiagnostics("unused", "unused.seal", CancellationToken.None,
            log, (AnalysisStoreKind)999, Guid.NewGuid()));
        Assert.Empty(log.Lines);
    }

    private static double Number(Line line, string name) => double.Parse(line.Value(name)!, CultureInfo.InvariantCulture);

    private sealed class StepClock : TimeProvider
    {
        private long _ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp()
        {
            var result = _ticks;
            _ticks += TimeSpan.TicksPerMillisecond;
            return result;
        }
        internal void AdvanceRead() => _ticks += 10 * TimeSpan.TicksPerMillisecond;
    }

    private sealed class TimedStream(byte[] bytes, StepClock clock, Action afterRead) : MemoryStream(bytes)
    {
        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = base.Read(buffer, offset, count);
            clock.AdvanceRead();
            afterRead();
            return read;
        }
    }
}
