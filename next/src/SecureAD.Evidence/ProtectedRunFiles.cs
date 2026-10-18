using System.Diagnostics;
using SecureAD.Kernel;

namespace SecureAD.Evidence;

/// <summary>Explicit ownership of verified immutable files across producing, completion and viewing.</summary>
/// <remarks>
/// <b>Every product is verified once for the lifetime, and the lifetime does the verifying.</b> The first
/// request for a product starts its whole-file check on a thread this lifetime owns; every other request
/// for the same product waits for that one result, and different products are checked at the same time.
/// A caller that stops waiting (a click superseded by another) does not abandon the check, so a
/// multi-gigabyte file is never hashed again because someone looked elsewhere in the meantime. Only the
/// end of the lifetime stops a check. A failed check is forgotten rather than remembered, so a later
/// request verifies again.
/// <para>
/// <see cref="VerifyAllAsync"/> requests every product of the run at once. That is how a saved run is
/// opened: the cost is paid together, up front, and nothing is hashed afterwards.
/// </para>
/// </remarks>
public sealed class ProtectedRunFiles : IDisposable, IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly CancellationTokenSource _stopping = new();
    private readonly Dictionary<(StoreSegmentRole Role, Guid Generation), Task<Result<ProtectedStoreFile>>> _files = [];
    private readonly HashSet<Task> _running = [];
    private string? _captureRootHash;
    private int _closing;

    private readonly record struct Request(Task<Result<ProtectedStoreFile>> Task, string RootHash, string CaptureHash);

    /// <summary>Starts a lifetime; no file is trusted or read until it is requested.</summary>
    public ProtectedRunFiles(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        Directory = Path.GetFullPath(directory);
    }

    /// <summary>The one run whose files this lifetime can supply.</summary>
    public string Directory { get; }

    internal void AdoptCapture(StoreRootManifest root, IReadOnlyList<ProtectedStoreFile> files)
    {
        lock (_gate)
        {
            ThrowIfClosing();
            if (_captureRootHash is not null || _files.Count != 0
                || !files.Select(file => file.Role).SequenceEqual(root.Segments.Select(segment => segment.Role))
                || files.Any(file => !string.Equals(file.BundleDirectory, Directory, StringComparison.OrdinalIgnoreCase) || file.Generation is not null
                    || file.Root.Hash != root.Hash || file.Fingerprint != root.Segment(file.Role).Hash))
                throw new InvalidOperationException("Capture publication cannot replace or join another protected lifetime.");
            foreach (var file in files)
                _files.Add((file.Role, root.GenerationId), Task.FromResult(Result<ProtectedStoreFile>.Success(file)));
            _captureRootHash = root.Hash;
        }
    }

    /// <summary>Acquires one capture product, retaining its verification only under continuous file protection.</summary>
    public Result<ProtectedStoreFile> Capture(StoreSegmentRole role, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Complete(RequestCapture(role), cancellationToken);
    }

    /// <summary>Acquires one selected analysis product without reusing a verdict from another root or generation.</summary>
    public Result<ProtectedStoreFile> Analysis(AnalysisStoreKind kind, StoreSegmentRole role, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Complete(RequestAnalysis(kind, role), cancellationToken);
    }

    /// <summary>Joins a check of this product that is already running, without starting one.</summary>
    /// <remarks>
    /// A reader calls this before it takes any lock of its own, so that a slow check holds up only the
    /// screens that need that product. The outcome is not reported here; the request that follows returns it.
    /// </remarks>
    public void WaitForPending(StoreSegmentRole role, CancellationToken cancellationToken)
    {
        Task<Result<ProtectedStoreFile>>[] pending;
        lock (_gate)
            pending = _files.Where(file => file.Key.Role == role && !file.Value.IsCompleted).Select(file => file.Value).ToArray();
        foreach (var check in pending)
        {
            try { check.WaitAsync(cancellationToken).GetAwaiter().GetResult(); }
            catch (Exception) when (!cancellationToken.IsCancellationRequested) { /* The check's own failure belongs to the request that follows. */ }
        }
    }

    /// <summary>
    /// Verifies every product of the run, all at once, reporting each as it finishes.
    /// </summary>
    /// <param name="observed">Called once per product, from whichever thread finished it.</param>
    /// <param name="cancellationToken">Stops waiting; the checks themselves stop only with the lifetime.</param>
    /// <returns>What the whole pass cost.</returns>
    /// <remarks>
    /// Products already verified (carried over from capture, or checked by an earlier request) cost nothing
    /// and are reported as such. A root that cannot be selected is reported as a problem, not thrown; a judgement or
    /// derivation that does not exist yet is simply absent.
    /// </remarks>
    public async Task<ProtectedRunVerification> VerifyAllAsync(Action<ProtectedFileCheck>? observed, CancellationToken cancellationToken)
    {
        ThrowIfClosing();
        var clock = Stopwatch.StartNew();
        var problems = new List<string>();
        var work = new List<Task<ProtectedFileCheck[]>>();

        var capture = AnalysisStoreLifecycle.ResolveCapture(Directory);
        if (capture.IsSuccess)
            foreach (var segment in capture.Value.Segments)
                work.Add(CheckAsync(segment, RequestCapture(segment.Role), clock, observed, cancellationToken));
        // A run still being captured has no root yet; that is not a damaged run.
        else if (File.Exists(BundleLayout.CaptureManifestPath(Directory))) problems.Add("capture: " + capture.Error!.Description);

        var derivation = AnalysisStoreLifecycle.ResolveRoot(Directory, AnalysisStoreKind.Derivation);
        if (derivation.IsSuccess)
            foreach (var segment in derivation.Value.Segments)
                work.Add(CheckAsync(segment, RequestAnalysis(AnalysisStoreKind.Derivation, segment.Role), clock, observed, cancellationToken));
        else if (!Absent(derivation.Error!)) problems.Add("derivation: " + derivation.Error!.Description);

        var judgement = AnalysisStoreLifecycle.ResolveRoot(Directory, AnalysisStoreKind.Judgement);
        if (judgement.IsSuccess) work.Add(CheckJudgementAsync(judgement.Value, clock, observed, cancellationToken));
        else if (!Absent(judgement.Error!)) problems.Add("judgement: " + judgement.Error!.Description);

        var checks = (await Task.WhenAll(work).ConfigureAwait(false)).SelectMany(group => group).ToArray();
        return new ProtectedRunVerification(
            checks.Length,
            checks.Count(check => check.Outcome == ProtectedFileCheckOutcome.Verified),
            checks.Count(check => check.Outcome == ProtectedFileCheckOutcome.Failed),
            checks.Sum(check => check.Bytes),
            clock.Elapsed,
            TimeSpan.FromTicks(checks.Sum(check => check.Hashed?.Ticks ?? 0)),
            problems);
    }

    private static bool Absent(AuditError error) => error.Code.EndsWith("ManifestAbsent", StringComparison.OrdinalIgnoreCase);

    private static async Task<ProtectedFileCheck[]> CheckAsync(SealedStoreSegment segment, Request request, Stopwatch clock,
        Action<ProtectedFileCheck>? observed, CancellationToken cancellationToken)
    {
        var started = clock.Elapsed;
        var already = request.Task.IsCompleted;
        ProtectedFileCheck check;
        try
        {
            var result = await request.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            check = result.IsSuccess ? Report(segment, result.Value, started, clock.Elapsed, already)
                : Refused(segment, result.Error!.Description, started, clock.Elapsed);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception error) { check = Refused(segment, error.Message, started, clock.Elapsed); }
        observed?.Invoke(check);
        return [check];
    }

    private async Task<ProtectedFileCheck[]> CheckJudgementAsync(StoreRootManifest root, Stopwatch clock,
        Action<ProtectedFileCheck>? observed, CancellationToken cancellationToken)
    {
        var request = RequestAnalysis(AnalysisStoreKind.Judgement, StoreSegmentRole.Judgement);
        var main = (await CheckAsync(root.Segment(StoreSegmentRole.Judgement), request, clock, observed, cancellationToken).ConfigureAwait(false))[0];
        if (main.Outcome == ProtectedFileCheckOutcome.Failed) return [main];
        // The proof parts belong to the verified judgement file, which is why they cannot start before it.
        var judgement = request.Task.Result.Value;
        var parts = BundleLayout.JudgementParts
            .Select(role => CheckPartAsync(judgement, root.Segment(role), clock, observed, cancellationToken)).ToArray();
        return [main, .. await Task.WhenAll(parts).ConfigureAwait(false)];
    }

    private static async Task<ProtectedFileCheck> CheckPartAsync(ProtectedStoreFile judgement, SealedStoreSegment segment,
        Stopwatch clock, Action<ProtectedFileCheck>? observed, CancellationToken cancellationToken)
    {
        var started = clock.Elapsed;
        ProtectedFileCheck check;
        try
        {
            var pending = judgement.RelatedAsync(segment.Role);
            var already = pending.IsCompleted;
            check = Report(segment, await pending.WaitAsync(cancellationToken).ConfigureAwait(false), started, clock.Elapsed, already);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception error) { check = Refused(segment, error.Message, started, clock.Elapsed); }
        observed?.Invoke(check);
        return check;
    }

    private static ProtectedFileCheck Report(SealedStoreSegment segment, ProtectedStoreFile file, TimeSpan started,
        TimeSpan finished, bool already) =>
        new(segment.Role, segment.FileName, file.VerifiedBytes, file.VerificationTime, started, finished,
            already ? ProtectedFileCheckOutcome.AlreadyVerified : ProtectedFileCheckOutcome.Verified, null);

    private static ProtectedFileCheck Refused(SealedStoreSegment segment, string reason, TimeSpan started, TimeSpan finished) =>
        new(segment.Role, segment.FileName, segment.ByteLength, null, started, finished, ProtectedFileCheckOutcome.Failed, reason);

    private Request RequestCapture(StoreSegmentRole role)
    {
        ThrowIfClosing();
        var selected = AnalysisStoreLifecycle.ResolveCapture(Directory);
        if (!selected.IsSuccess) return Refused(selected.Error!);
        return Start(role, selected.Value, selected.Value.Hash, token => role switch
        {
            StoreSegmentRole.Evidence => ProtectedStoreFile.OpenEvidence(Directory, token),
            StoreSegmentRole.Navigation => ProtectedStoreFile.OpenNavigation(Directory, token),
            StoreSegmentRole.Overview => ProtectedStoreFile.OpenOverview(Directory, token),
            StoreSegmentRole.Delegations => ProtectedStoreFile.OpenDelegations(Directory, token),
            _ => throw new ArgumentOutOfRangeException(nameof(role)),
        });
    }

    private Request RequestAnalysis(AnalysisStoreKind kind, StoreSegmentRole role)
    {
        ThrowIfClosing();
        var capture = AnalysisStoreLifecycle.ResolveCapture(Directory);
        if (!capture.IsSuccess) return Refused(capture.Error!);
        lock (_gate)
            if (_captureRootHash is not null && _captureRootHash != capture.Value.Hash)
                return Refused("The selected capture root changed during its protected lifetime.");
        var selected = AnalysisStoreLifecycle.ResolveRoot(Directory, kind);
        if (!selected.IsSuccess) return Refused(selected.Error!);
        if (selected.Value.EvidenceSeal != capture.Value.EvidenceSeal)
            return Refused("The selected analysis belongs to another capture.");
        var root = selected.Value;
        return Start(role, root, capture.Value.Hash,
            token => ProtectedStoreFile.OpenAnalysisSegment(Directory, new(kind, root.GenerationId), role, token));
    }

    private Request Start(StoreSegmentRole role, StoreRootManifest root, string captureHash,
        Func<CancellationToken, Result<ProtectedStoreFile>> open)
    {
        if (!root.Segments.Any(segment => segment.Role == role))
            return Refused("The selected root does not declare the requested product.");
        var key = (role, root.GenerationId);
        lock (_gate)
        {
            ThrowIfClosing();
            if (_captureRootHash is not null && _captureRootHash != captureHash)
                return Refused("The selected capture root changed during its protected lifetime.");
            if (_files.TryGetValue(key, out var existing)) return new(existing, root.Hash, captureHash);
            var verified = new TaskCompletionSource<Result<ProtectedStoreFile>>(TaskCreationOptions.RunContinuationsAsynchronously);
            _files.Add(key, verified.Task);
            _running.Add(verified.Task);
            // Read under the lock, while the lifetime is certainly open: the thread below must not touch the source.
            var token = _stopping.Token;
            VerificationThread.Start($"Verify {role}", () => Verify(key, root, open, verified, token));
            return new(verified.Task, root.Hash, captureHash);
        }
    }

    /// <summary>The body of one check's thread. It must complete its result whatever happens; nothing may escape it.</summary>
    private void Verify((StoreSegmentRole Role, Guid Generation) key, StoreRootManifest root,
        Func<CancellationToken, Result<ProtectedStoreFile>> open, TaskCompletionSource<Result<ProtectedStoreFile>> verified,
        CancellationToken token)
    {
        try
        {
            var result = open(token);
            if (result.IsSuccess && result.Value.Root.Hash != root.Hash)
            {
                result.Value.Dispose();
                result = Failure("The selected root changed while opening its product.");
            }
            // A failure is forgotten before anyone can see it, so the next request verifies again.
            if (!result.IsSuccess) Forget(key, verified.Task);
            verified.TrySetResult(result);
        }
        catch (Exception error)
        {
            Forget(key, verified.Task);
            if (error is OperationCanceledException) verified.TrySetCanceled(token);
            else verified.TrySetException(error);
        }
        finally { Finished(verified.Task); }
    }

    private void Forget((StoreSegmentRole Role, Guid Generation) key, Task<Result<ProtectedStoreFile>> check)
    {
        lock (_gate)
            if (_files.TryGetValue(key, out var current) && ReferenceEquals(current, check)) _files.Remove(key);
    }

    private void Finished(Task check)
    {
        lock (_gate) _running.Remove(check);
    }

    private Result<ProtectedStoreFile> Complete(Request request, CancellationToken cancellationToken)
    {
        var result = request.Task.WaitAsync(cancellationToken).GetAwaiter().GetResult();
        if (!result.IsSuccess) return result;
        if (result.Value.Root.Hash != request.RootHash)
            return Failure("The selected generation's publication root changed.");
        lock (_gate) _captureRootHash = request.CaptureHash;
        return result;
    }

    private void ThrowIfClosing() => ObjectDisposedException.ThrowIf(Volatile.Read(ref _closing) != 0, this);

    private static Request Refused(AuditError error) =>
        new(Task.FromResult(Result<ProtectedStoreFile>.Failure(error)), "", "");

    private Request Refused(string detail) => Refused(Refusal(detail));

    private AuditError Refusal(string detail) =>
        AuditError.Create(ErrorCategory.Evidence, "ProtectedStoreGenerationChanged", ErrorSeverity.Failed, detail, Directory);

    private Result<ProtectedStoreFile> Failure(string detail) => Result<ProtectedStoreFile>.Failure(Refusal(detail));

    /// <summary>Stops acquisitions and checks; readers already holding leases keep protection until their connections close.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _closing, 1) != 0) return;
        _stopping.Cancel();
        // A check owns file handles until it observes the cancellation, which it does between reads.
        Task[] running;
        lock (_gate) running = _running.ToArray();
        try { Task.WaitAll(running); }
        catch (AggregateException) { /* Cancelled or failed checks have already released their files. */ }
        foreach (var file in Verified()) file.Dispose();
        _stopping.Dispose();
    }

    /// <summary>Also waits for the final reader's protection to be released.</summary>
    public async ValueTask DisposeAsync()
    {
        Dispose();
        foreach (var file in Verified()) await file.DisposeAsync().ConfigureAwait(false);
    }

    private ProtectedStoreFile[] Verified()
    {
        lock (_gate)
            return _files.Values.Where(check => check.IsCompletedSuccessfully && check.Result.IsSuccess)
                .Select(check => check.Result.Value).ToArray();
    }
}
