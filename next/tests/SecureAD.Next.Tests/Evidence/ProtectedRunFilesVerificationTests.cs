using System.Collections.Concurrent;
using SecureAD.Evidence;
using SecureAD.Next.Tests.Judgement;
using Xunit;
using Checks = SecureAD.Next.Tests.Evidence.VerificationChecks;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// A saved run's files are verified once, together, when the run is opened, and never again while it is read.
/// </summary>
/// <remarks>
/// Real, complete runs (capture, derivation and judgement with all four judgement parts) are verified for
/// real; nothing here fakes a file check. The checks are held in place deterministically: the product's
/// own <c>store.verifications</c> measurement runs on the thread about to hash a file, and a listener that
/// blocks there holds exactly that file's check open until the test releases it.
/// </remarks>
public sealed class ProtectedRunFilesVerificationTests
{
    private const string Descriptor = "O:SYG:SYD:(A;;WP;;;S-1-5-21-1-2-3-1200)(A;;WP;;;S-1-5-21-1-2-3-1200)";
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(30);

    [Fact]
    public async Task OpeningARunVerifiesEveryProductExactlyOnceAndReadingItVerifiesNothingMore()
    {
        var directory = Published();
        using var checks = new Checks(directory);
        using var files = new ProtectedRunFiles(directory);
        var reported = new ConcurrentBag<ProtectedFileCheck>();

        var summary = await files.VerifyAllAsync(reported.Add, CancellationToken.None);

        Assert.Equal(10, summary.Files);
        Assert.Equal(10, summary.Verified);
        Assert.Equal(0, summary.Unverified);
        Assert.Empty(summary.Problems);
        Assert.Equal(DeclaredRoles(directory).Order(), reported.Select(check => check.Role).Order());
        foreach (var check in reported)
        {
            Assert.Equal(ProtectedFileCheckOutcome.Verified, check.Outcome);
            Assert.Equal(new FileInfo(Path.Combine(directory, check.FileName)).Length, check.Bytes);
            Assert.True(check.Hashed > TimeSpan.Zero, check.FileName);
            Assert.True(check.Finished >= check.Started, check.FileName);
        }
        Assert.Equal(10, checks.Started.Count);
        Assert.Equal(10, checks.Started.Distinct(StringComparer.OrdinalIgnoreCase).Count());

        // Everything a reader asks for from here on comes from the files already verified.
        foreach (var role in new[] { StoreSegmentRole.Evidence, StoreSegmentRole.Navigation, StoreSegmentRole.Overview, StoreSegmentRole.Delegations })
            Assert.True(files.Capture(role, CancellationToken.None).IsSuccess, role.ToString());
        foreach (var role in new[] { StoreSegmentRole.Derivation, StoreSegmentRole.Membership })
            Assert.True(files.Analysis(AnalysisStoreKind.Derivation, role, CancellationToken.None).IsSuccess, role.ToString());
        var judgement = files.Analysis(AnalysisStoreKind.Judgement, StoreSegmentRole.Judgement, CancellationToken.None);
        Assert.True(judgement.IsSuccess);
        using var lease = judgement.Value.Acquire();
        foreach (var part in new[] { StoreSegmentRole.PermissionProof, StoreSegmentRole.PathProof, StoreSegmentRole.JudgementFacts })
            Assert.Equal(part.ToString(), lease.Attach(part));
        Assert.Equal(10, checks.Started.Count);
    }

    [Fact]
    public async Task AnotherPassOverAnAlreadyVerifiedRunCostsNothing()
    {
        var directory = Published();
        using var checks = new Checks(directory);
        using var files = new ProtectedRunFiles(directory);
        await files.VerifyAllAsync(null, CancellationToken.None);
        var reported = new ConcurrentBag<ProtectedFileCheck>();

        var again = await files.VerifyAllAsync(reported.Add, CancellationToken.None);

        Assert.Equal(10, again.Files);
        Assert.Equal(0, again.Verified);
        Assert.All(reported, check => Assert.Equal(ProtectedFileCheckOutcome.AlreadyVerified, check.Outcome));
        Assert.Equal(10, checks.Started.Count);
    }

    [Fact]
    public async Task AProductBeingCheckedNeverStallsAnotherProduct()
    {
        var directory = Published();
        using var checks = new Checks(directory, name => name == "evidence.db");
        using var files = new ProtectedRunFiles(directory);
        var evidence = Task.Run(() => files.Capture(StoreSegmentRole.Evidence, CancellationToken.None));
        Assert.True(checks.WaitUntilBlocked("evidence.db"), "The evidence check never started.");

        // The overview has not been asked for yet, so its check can only begin now, while the evidence check is held.
        var overview = Task.Run(() => files.Capture(StoreSegmentRole.Overview, CancellationToken.None));
        Assert.True(await Task.WhenAny(overview, Task.Delay(Patience)) == overview, "The overview waited behind the evidence check.");
        var opened = await overview;
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        Assert.False(evidence.IsCompleted);

        checks.Release();
        Assert.True((await evidence).IsSuccess);
    }

    [Fact]
    public async Task ClosingTheLifetimeStopsAProofPartCheckInProgressAndReleasesItsFile()
    {
        var directory = Published();
        var proof = Path.Combine(directory, AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value.Segment(StoreSegmentRole.PathProof).FileName);
        using var checks = new Checks(directory, name => name.Contains(".path-proof.", StringComparison.Ordinal));
        var files = new ProtectedRunFiles(directory);
        var opening = files.VerifyAllAsync(null, CancellationToken.None);
        Assert.True(checks.WaitUntilBlocked(".path-proof."), "The proof part's check never started.");

        var closing = Task.Run(files.Dispose);
        await Task.Delay(300);
        Assert.False(closing.IsCompleted, "Closing returned while a proof part's check still held its file.");
        checks.Release();
        Assert.True(await Task.WhenAny(closing, Task.Delay(Patience)) == closing, "Closing never finished.");

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => opening);
        using (new FileStream(proof, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { }
    }

    [Fact]
    public async Task EveryProductIsCheckedAtTheSameTimeWhenARunIsOpened()
    {
        var directory = Published();
        // Hold two different products open at once: both checks must be under way together.
        using var checks = new Checks(directory, name => name == "evidence.db" || name.Contains(".permission-proof.", StringComparison.Ordinal));
        using var files = new ProtectedRunFiles(directory);
        var opening = files.VerifyAllAsync(null, CancellationToken.None);

        Assert.True(checks.WaitUntilBlocked("evidence.db"), "The evidence check never started.");
        Assert.True(checks.WaitUntilBlocked(".permission-proof."), "The proof part's check never started while the evidence check was held.");
        Assert.False(opening.IsCompleted);

        checks.Release();
        Assert.Equal(10, (await opening).Verified);
    }

    [Fact]
    public async Task SeveralRequestsForOneProductShareASingleCheck()
    {
        var directory = Published();
        using var checks = new Checks(directory, name => name == "evidence.db");
        using var files = new ProtectedRunFiles(directory);
        var first = Task.Run(() => files.Capture(StoreSegmentRole.Evidence, CancellationToken.None));
        Assert.True(checks.WaitUntilBlocked("evidence.db"));
        var second = Task.Run(() => files.Capture(StoreSegmentRole.Evidence, CancellationToken.None));
        await Task.Delay(300);
        Assert.False(second.IsCompleted, "A second request was answered before the check it should share had finished.");

        checks.Release();
        var results = await Task.WhenAll(first, second);

        Assert.True(results[0].IsSuccess, results[0].Error?.Description);
        Assert.Same(results[0].Value, results[1].Value);
        Assert.Equal(1, checks.Count("evidence.db"));
    }

    [Fact]
    public async Task AReaderThatStopsWaitingDoesNotAbandonTheCheck()
    {
        var directory = Published();
        using var checks = new Checks(directory, name => name == "evidence.db");
        using var files = new ProtectedRunFiles(directory);
        using var impatient = new CancellationTokenSource();
        var waiting = Task.Run(() => files.Capture(StoreSegmentRole.Evidence, impatient.Token));
        Assert.True(checks.WaitUntilBlocked("evidence.db"));

        impatient.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
        checks.Release();
        var later = files.Capture(StoreSegmentRole.Evidence, CancellationToken.None);

        Assert.True(later.IsSuccess, later.Error?.Description);
        Assert.Equal(1, checks.Count("evidence.db"));
    }

    [Fact]
    public async Task ClosingTheLifetimeStopsACheckInProgressAndReleasesItsFiles()
    {
        var directory = Published();
        var evidence = Path.Combine(directory, "evidence.db");
        using var checks = new Checks(directory, name => name == "evidence.db");
        var files = new ProtectedRunFiles(directory);
        var waiting = Task.Run(() => files.Capture(StoreSegmentRole.Evidence, CancellationToken.None));
        Assert.True(checks.WaitUntilBlocked("evidence.db"));

        var closing = Task.Run(files.Dispose);
        await Task.Delay(300);
        Assert.False(closing.IsCompleted, "Closing returned while a check still held the file.");
        checks.Release();
        Assert.True(await Task.WhenAny(closing, Task.Delay(Patience)) == closing, "Closing never finished.");

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
        using (new FileStream(evidence, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { }
        Assert.Throws<ObjectDisposedException>(() => files.Capture(StoreSegmentRole.Evidence, CancellationToken.None));
    }

    [Fact]
    public void AFailedCheckIsNotRememberedSoALaterRequestVerifiesAgain()
    {
        var directory = Published();
        var overview = Path.Combine(directory, AnalysisStoreLifecycle.ResolveCapture(directory).Value.Segment(StoreSegmentRole.Overview).FileName);
        var original = File.ReadAllBytes(overview);
        var damaged = (byte[])original.Clone();
        damaged[damaged.Length / 2] ^= 0xFF;
        File.WriteAllBytes(overview, damaged);
        using var checks = new Checks(directory);
        using var files = new ProtectedRunFiles(directory);

        Assert.False(files.Capture(StoreSegmentRole.Overview, CancellationToken.None).IsSuccess);
        File.WriteAllBytes(overview, original);
        var repaired = files.Capture(StoreSegmentRole.Overview, CancellationToken.None);

        Assert.True(repaired.IsSuccess, repaired.Error?.Description);
        Assert.Equal(2, checks.Count(Path.GetFileName(overview)));
    }

    [Fact]
    public async Task ADamagedFileIsReportedAndDoesNotStopTheOthersBeingVerified()
    {
        var directory = Published();
        var navigation = Path.Combine(directory, AnalysisStoreLifecycle.ResolveCapture(directory).Value.Segment(StoreSegmentRole.Navigation).FileName);
        var bytes = File.ReadAllBytes(navigation);
        bytes[bytes.Length / 2] ^= 0xFF;
        File.WriteAllBytes(navigation, bytes);
        using var files = new ProtectedRunFiles(directory);
        var reported = new ConcurrentBag<ProtectedFileCheck>();

        var summary = await files.VerifyAllAsync(reported.Add, CancellationToken.None);

        Assert.Equal(10, summary.Files);
        Assert.Equal(1, summary.Unverified);
        Assert.Equal(9, summary.Verified);
        var failure = Assert.Single(reported, check => check.Outcome == ProtectedFileCheckOutcome.Failed);
        Assert.Equal(StoreSegmentRole.Navigation, failure.Role);
        Assert.False(string.IsNullOrWhiteSpace(failure.Failure));
    }

    [Fact]
    public async Task AProofPartBeingCheckedNeverStallsAnotherReaderOfTheJudgement()
    {
        var directory = Published();
        using var checks = new Checks(directory, name => name.Contains(".permission-proof.", StringComparison.Ordinal));
        using var files = new ProtectedRunFiles(directory);
        var judgement = files.Analysis(AnalysisStoreKind.Judgement, StoreSegmentRole.Judgement, CancellationToken.None).Value;
        using var first = judgement.Acquire();
        var attaching = Task.Run(() => first.Attach(StoreSegmentRole.PermissionProof));
        Assert.True(checks.WaitUntilBlocked(".permission-proof."));

        var other = Task.Run(() =>
        {
            using var lease = judgement.Acquire();
            return lease.Connection.State;
        });
        Assert.True(await Task.WhenAny(other, Task.Delay(Patience)) == other, "Another reader waited behind a proof part's check.");

        checks.Release();
        await attaching;
        Assert.Equal(1, checks.Count(".permission-proof."));
    }

    [Fact]
    public async Task AReaderAttachingAPartJoinsTheCheckTheOpeningPassAlreadyStarted()
    {
        var directory = Published();
        using var checks = new Checks(directory, name => name.Contains(".path-proof.", StringComparison.Ordinal));
        using var files = new ProtectedRunFiles(directory);
        var opening = files.VerifyAllAsync(null, CancellationToken.None);
        Assert.True(checks.WaitUntilBlocked(".path-proof."));
        var judgement = files.Analysis(AnalysisStoreKind.Judgement, StoreSegmentRole.Judgement, CancellationToken.None).Value;
        using var lease = judgement.Acquire();
        var attaching = Task.Run(() => lease.Attach(StoreSegmentRole.PathProof));
        await Task.Delay(300);
        Assert.False(attaching.IsCompleted, "The part was attached before its check finished.");

        checks.Release();
        await attaching;
        await opening;

        Assert.Equal(1, checks.Count(".path-proof."));
    }

    [Fact]
    public async Task WaitingForAPendingCheckJoinsARunningOneAndNeverStartsOne()
    {
        var directory = Published();
        using var checks = new Checks(directory, name => name == "evidence.db");
        using var files = new ProtectedRunFiles(directory);

        files.WaitForPending(StoreSegmentRole.Evidence, CancellationToken.None);
        Assert.Empty(checks.Started);

        var running = Task.Run(() => files.Capture(StoreSegmentRole.Evidence, CancellationToken.None));
        Assert.True(checks.WaitUntilBlocked("evidence.db"));
        var joined = Task.Run(() => files.WaitForPending(StoreSegmentRole.Evidence, CancellationToken.None));
        await Task.Delay(300);
        Assert.False(joined.IsCompleted, "The wait returned while the check was still running.");

        checks.Release();
        await joined;
        Assert.True((await running).IsSuccess);
        Assert.Equal(1, checks.Count("evidence.db"));
    }

    [Fact]
    public async Task ARunWithoutAJudgementOrDerivationIsOpenedWithoutComplaint()
    {
        var directory = Published();
        File.Delete(BundleLayout.AnalysisManifestPath(directory, AnalysisStoreKind.Judgement));
        File.Delete(BundleLayout.AnalysisManifestPath(directory, AnalysisStoreKind.Derivation));
        using var files = new ProtectedRunFiles(directory);

        var summary = await files.VerifyAllAsync(null, CancellationToken.None);

        Assert.Equal(4, summary.Files);
        Assert.Equal(4, summary.Verified);
        Assert.Empty(summary.Problems);
    }

    [Fact]
    public async Task ARunStillBeingCapturedIsNotReportedAsDamaged()
    {
        var directory = Published();
        File.Delete(BundleLayout.CaptureManifestPath(directory));
        File.Delete(BundleLayout.AnalysisManifestPath(directory, AnalysisStoreKind.Judgement));
        File.Delete(BundleLayout.AnalysisManifestPath(directory, AnalysisStoreKind.Derivation));
        using var files = new ProtectedRunFiles(directory);

        var summary = await files.VerifyAllAsync(null, CancellationToken.None);

        Assert.Equal(0, summary.Files);
        Assert.Empty(summary.Problems);
    }

    private static string Published() => AttributeWriteRuleTests.Published(Descriptor);

    private static IEnumerable<StoreSegmentRole> DeclaredRoles(string directory) =>
        AnalysisStoreLifecycle.ResolveCapture(directory).Value.Segments
            .Concat(AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Derivation).Value.Segments)
            .Concat(AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value.Segments)
            .Select(segment => segment.Role);
}
