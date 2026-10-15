using System.Collections;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Capture;
using Xunit;
using Xunit.Abstractions;

namespace SecureAD.Next.Tests.Evidence;

public sealed class BundleWriterCancellationTests(ITestOutputHelper output)
{
    [Fact]
    public void CancellationAfterSealPreparationDoesNotPublishEvidence()
    {
        var directory = NewDirectory();
        using var cancellation = new CancellationTokenSource();
        using var writer = BundleWriter.Create(directory, DateTimeOffset.UnixEpoch);

        Record.Exception(() => Complete(writer, cancellation.Token,
            (partial, seal, token) => { BundleSealing.Seal(partial, seal, token); cancellation.Cancel(); }));

        Assert.Equal((true, false),
            (File.Exists(BundleLayout.PartialPath(directory)), File.Exists(BundleLayout.EvidencePath(directory))));
    }

    [Fact]
    public void CancellationAfterSealPreparationRetainsTheCallersToken()
    {
        var directory = NewDirectory();
        using var cancellation = new CancellationTokenSource();
        using var writer = BundleWriter.Create(directory, DateTimeOffset.UnixEpoch);

        var failure = Record.Exception(() => Complete(writer, cancellation.Token,
            (partial, seal, token) => { BundleSealing.Seal(partial, seal, token); cancellation.Cancel(); }));

        Assert.Equal(cancellation.Token, Assert.IsType<OperationCanceledException>(failure).CancellationToken);
    }

    [Fact]
    public async Task AnAlreadyRequestedStopWinsEvenWhenItsCallbackIsDelayedAsync()
    {
        var directory = NewDirectory();
        using var cancellation = new CancellationTokenSource();
        using var writer = BundleWriter.Create(directory, DateTimeOffset.UnixEpoch);
        using var callbackEntered = new ManualResetEventSlim();
        using var releaseCallback = new ManualResetEventSlim();
        var cancellationWork = Task.CompletedTask;
        CancellationTokenRegistration blocker = default;
        Exception? failure;

        try
        {
            failure = Record.Exception(() => Complete(writer, cancellation.Token, (partial, seal, token) =>
            {
                BundleSealing.Seal(partial, seal, token);
                // CTS invokes callbacks in reverse registration order. Hold this newer one
                // so the token is set while the writer's earlier callback cannot run yet.
                blocker = token.Register(() =>
                {
                    callbackEntered.Set();
                    if (!releaseCallback.Wait(TimeSpan.FromSeconds(30)))
                        throw new TimeoutException("Cancellation callback was not released.");
                });
                cancellationWork = Task.Run(cancellation.Cancel);
                if (!callbackEntered.Wait(TimeSpan.FromSeconds(30)))
                    throw new TimeoutException("Cancellation callback was not entered.");
            }));
        }
        finally
        {
            releaseCallback.Set();
            await cancellationWork;
            blocker.Dispose();
        }

        Assert.IsType<OperationCanceledException>(failure);
    }

    [Fact]
    public void ACancelledPreparationReleasesEveryCreatedFile()
    {
        var directory = NewDirectory();
        using var cancellation = new CancellationTokenSource();
        using (var writer = BundleWriter.Create(directory, DateTimeOffset.UnixEpoch))
            Record.Exception(() => Complete(writer, cancellation.Token,
                (partial, seal, token) => { BundleSealing.Seal(partial, seal, token); cancellation.Cancel(); }));

        var released = Directory.GetFiles(directory).Select(path =>
        {
            using var exclusive = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            return Path.GetFileName(path);
        }).Order(StringComparer.Ordinal).ToArray();

        Assert.Equal(new[] { Path.GetFileName(BundleLayout.PartialPath(directory)),
            Path.GetFileName(BundleLayout.SealPath(directory)), Path.GetFileName(BundleLayout.AnnotationsPath(directory)),
            Path.GetFileName(BundleLayout.CaptureManifestPath(directory)) + ".partial",
            Path.GetFileName(BundleLayout.NavigationPartialPath(directory)),
            Path.GetFileName(BundleLayout.OverviewPartialPath(directory)) }
            .Order(StringComparer.Ordinal), released);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ARealSealingFailureIsNotHiddenByCancellation(bool accessDenied)
    {
        var directory = NewDirectory();
        using var cancellation = new CancellationTokenSource();
        using var writer = BundleWriter.Create(directory, DateTimeOffset.UnixEpoch);
        var failure = SealingFailure(accessDenied);

        var observed = Record.Exception(() => Complete(writer, cancellation.Token,
            (_, _, _) => { cancellation.Cancel(); throw failure; }));

        Assert.Same(failure, observed);
    }

    [Fact]
    public void AFinalRenameFailureRemainsAFailure()
    {
        var directory = NewDirectory();
        using var writer = BundleWriter.Create(directory, DateTimeOffset.UnixEpoch);

        var failure = Record.Exception(() => Complete(writer, CancellationToken.None,
            (partial, seal, token) =>
            {
                BundleSealing.Seal(partial, seal, token);
                File.WriteAllText(BundleLayout.EvidencePath(directory), "Existing synthetic destination.");
            }));

        Assert.IsType<IOException>(failure);
    }

    [Fact]
    public void CancellationDuringMetadataPreparationDoesNotReadTheNextValue()
    {
        var directory = NewDirectory();
        using var cancellation = new CancellationTokenSource();
        using var writer = BundleWriter.Create(directory, DateTimeOffset.UnixEpoch);
        var values = new CancelOnCountList(cancellation);
        var reconciliation = new ContinuationReconciliation(ContinuationReconciliationOutcome.Incomplete, values, [], []);

        Record.Exception(() => writer.Complete(Coverage(), DateTimeOffset.UnixEpoch,
            reconciliation, CaptureObjectScope.Default, cancellation.Token));

        Assert.Equal(0, values.ValuesRead);
    }

    [Fact]
    public void CancelledIndexPreparationDoesNotBuildTheIndexes()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        BundleSchema.CreateTables(connection);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        var failure = Record.Exception(() => BundleSchema.CreateDeferredIndexes(connection, cancellation.Token));

        Assert.IsType<OperationCanceledException>(failure);
    }

    private string NewDirectory()
    {
        var directory = Path.Combine(Path.GetTempPath(), "securead-p216-writer-" + Guid.NewGuid().ToString("N"));
        output.WriteLine(directory);
        return directory;
    }

    private static Exception SealingFailure(bool accessDenied) => accessDenied
        ? new UnauthorizedAccessException("Synthetic denied seal write.")
        : new IOException("Synthetic seal write failure.");

    private static BundleSealTimings Complete(BundleWriter writer, CancellationToken token,
        Action<string, string, CancellationToken> seal) =>
        writer.Complete(Coverage(), DateTimeOffset.UnixEpoch, ContinuationReconciliation.NotPerformed,
            CaptureObjectScope.Default, token, seal);

    private static RunCoverage Coverage() => RunCoverage.Of(
        CoverageId.ForDomains("example.com", ["example.com"]), [DomainCoverage.Read("example.com")],
        [ForestPartitionCoverage.Read("CN=Configuration,DC=example,DC=com", NamingContextKind.Configuration),
         ForestPartitionCoverage.Read("CN=Schema,CN=Configuration,DC=example,DC=com", NamingContextKind.Schema)],
        SysvolCoverage.Of([]));

    private sealed class CancelOnCountList(CancellationTokenSource cancellation) : IReadOnlyList<string>
    {
        public int ValuesRead { get; private set; }
        public int Count { get { cancellation.Cancel(); return 1; } }
        public string this[int index] { get { ValuesRead++; return "DC=unplanned,DC=example,DC=com"; } }
        public IEnumerator<string> GetEnumerator() => throw new NotSupportedException();
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
