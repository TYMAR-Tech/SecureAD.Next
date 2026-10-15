using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Fact]
    public async Task P248C6NavigationReadsTheSelectedSavedFindings()
    {
        var directory = CreateRun();
        using var source = new BundleAssetSource();
        source.SelectRun(directory);

        var read = await source.ReadAsync(directory,
            (reader, _) => reader.ReadFindings(directory, FindingsQuery.Everything()), CancellationToken.None);

        Assert.Equal(new[] { FirstDn, SecondDn }, read.Value.Findings.Select(value => value.DistinguishedName));
    }

    [Fact]
    public async Task P248C6NavigationSharesProtectedFilesWithoutAnalysisReplay()
    {
        var directory = CreateRun();
        using var source = new BundleAssetSource();
        using var counts = new ReadbackCounts(directory);
        source.SelectRun(directory);

        await source.ReadAsync(directory, (reader, _) => reader.ReadFindings(directory, FindingsQuery.Everything()), CancellationToken.None);
        await source.ReadAsync(directory, (reader, _) => reader.ReadRuleExecutions(directory), CancellationToken.None);

        Assert.Equal((0L, 1L, 0L, 0L),
            (counts.EvidenceVerifications, counts.JudgementVerifications, counts.EvidenceFormatChecks, counts.AnalyticalReads));
    }

    [Fact]
    public async Task P248C6NavigationCannotRebindItsReaderToAReopenedPath()
    {
        var directory = CreateRun();
        using var source = new BundleAssetSource();
        source.SelectRun(directory);
        string? readError = null;

        var failure = await Record.ExceptionAsync(() => source.ReadAsync(directory, (reader, _) =>
        {
            source.CloseRun();
            source.SelectRun(directory);
            var read = reader.ReadFindings(directory, FindingsQuery.Everything());
            readError = read.Error?.Code;
            return read;
        }, CancellationToken.None));

        Assert.Equal(("Shell.SavedResultsGenerationChanged", typeof(InvalidOperationException)), (readError, failure?.GetType()));
    }

    [Fact]
    public async Task P248C6NavigationRejectsAlreadyReadDataAfterRunSelectionChanges()
    {
        var directory = CreateRun();
        var replacement = CreateRun();
        using var source = new BundleAssetSource();
        source.SelectRun(directory);

        await Assert.ThrowsAsync<InvalidOperationException>(() => source.ReadAsync(directory, (reader, _) =>
        {
            var read = reader.ReadFindings(directory, FindingsQuery.Everything());
            source.SelectRun(replacement);
            return read;
        }, CancellationToken.None));
    }

    [Fact]
    public async Task P248C6NavigationRejectsCompletionWhenTheCallbackIgnoresCancellation()
    {
        var directory = CreateRun();
        using var source = new BundleAssetSource();
        using var stopping = new CancellationTokenSource();
        source.SelectRun(directory);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => source.ReadAsync(directory, (_, _) =>
        {
            stopping.Cancel();
            return 7;
        }, stopping.Token));
    }

    [Fact]
    public async Task P248C6NavigationPassesCancellationToTheScopedReader()
    {
        var directory = CreateRun();
        using var source = new BundleAssetSource();
        using var stopping = new CancellationTokenSource();
        source.SelectRun(directory);
        var readerCancelled = false;

        var failure = await Record.ExceptionAsync(() => source.ReadAsync(directory, (reader, _) =>
        {
            stopping.Cancel();
            readerCancelled = Record.Exception(() => reader.ReadTree(directory)) is OperationCanceledException;
            return 7;
        }, stopping.Token));

        Assert.Equal((true, true), (readerCancelled, failure is OperationCanceledException));
    }

    [Fact]
    public async Task P248C6NavigationDoesNotExecuteAPreCancelledCallback()
    {
        var directory = CreateRun();
        using var source = new BundleAssetSource();
        using var stopping = new CancellationTokenSource();
        source.SelectRun(directory);
        stopping.Cancel();
        var calls = 0;

        var failure = await Record.ExceptionAsync(() => source.ReadAsync(directory, (_, _) => ++calls, stopping.Token));

        Assert.Equal((true, 0), (failure is OperationCanceledException, calls));
    }

    [Fact]
    public void P248C6RetainedDataValidityAcceptsTheSameProtectedGeneration()
    {
        var directory = CreateRun();
        using var source = new BundleAssetSource();
        source.ReadFindings(directory, FindingsQuery.Everything());

        var valid = source.CaptureReadValidity();

        Assert.True(valid());
    }

    [Fact]
    public void P248C6RetainedDataValidityRejectsANewPublishedGeneration()
    {
        var directory = CreateRun();
        using var source = new BundleAssetSource();
        source.ReadFindings(directory, FindingsQuery.Everything());
        var valid = source.CaptureReadValidity();

        WriteJudgement(directory);

        Assert.False(valid());
    }

    [Fact]
    public void P248C6RetainedDataValidityRejectsAnUnpublishedAttempt()
    {
        var directory = CreateRun();
        using var source = new BundleAssetSource();
        source.ReadFindings(directory, FindingsQuery.Everything());
        var valid = source.CaptureReadValidity();

        AnalysisStoreLifecycle.BeginAttempt(directory, AnalysisStoreKind.Derivation);

        Assert.False(valid());
    }

    [Fact]
    public void P248C6RetainedDataValidityRejectsTheSamePathAfterReopening()
    {
        var directory = CreateRun();
        using var source = new BundleAssetSource();
        source.ReadFindings(directory, FindingsQuery.Everything());
        var valid = source.CaptureReadValidity();

        source.CloseRun();
        source.SelectRun(directory);
        source.ReadFindings(directory, FindingsQuery.Everything());

        Assert.False(valid());
    }

    [Fact]
    public void P248C6RetainedDataValidityCannotVouchForAnUnopenedRun()
    {
        using var source = new BundleAssetSource();

        var valid = source.CaptureReadValidity();

        Assert.False(valid());
    }

    [Fact]
    public void P248C6AReaderWithoutProtectionCannotVouchForRetainedData()
    {
        IAssetReader reader = new FakeAssetSource();

        var valid = reader.CaptureReadValidity();

        Assert.False(valid());
    }

    [Fact]
    public async Task P248C6NavigationDoesNotGiveRequestsRunOwnership()
    {
        var directory = CreateRun();
        using var source = new BundleAssetSource();

        var canSelectRuns = await source.ReadAsync(directory, (reader, _) => reader is IAssetSource, CancellationToken.None);

        Assert.False(canSelectRuns);
    }

    [Fact]
    public async Task P248C6RequestValidityAcceptsItsProtectedGeneration()
    {
        var directory = CreateRun();
        using var source = new BundleAssetSource();

        var valid = await source.ReadAsync(directory, (reader, _) =>
        {
            reader.ReadFindings(directory, FindingsQuery.Everything());
            return reader.CaptureReadValidity();
        }, CancellationToken.None);

        Assert.True(valid());
    }

    [Fact]
    public async Task P248C6RequestValidityRejectsSubsequentPublication()
    {
        var directory = CreateRun();
        using var source = new BundleAssetSource();
        var valid = await source.ReadAsync(directory, (reader, _) =>
        {
            reader.ReadFindings(directory, FindingsQuery.Everything());
            return reader.CaptureReadValidity();
        }, CancellationToken.None);

        WriteJudgement(directory);

        Assert.False(valid());
    }
}
