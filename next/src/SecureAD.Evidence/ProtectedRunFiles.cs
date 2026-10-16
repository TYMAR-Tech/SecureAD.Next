using SecureAD.Kernel;

namespace SecureAD.Evidence;

/// <summary>Explicit ownership of verified immutable files across producing, completion and viewing.</summary>
public sealed class ProtectedRunFiles : IDisposable, IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly CancellationTokenSource _stopping = new();
    private readonly Dictionary<(StoreSegmentRole Role, Guid Generation), ProtectedStoreFile> _files = [];
    private string? _captureRootHash;
    private int _closing;

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
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _closing) != 0, this);
            if (_captureRootHash is not null || _files.Count != 0
                || !files.Select(file => file.Role).SequenceEqual(root.Segments.Select(segment => segment.Role))
                || files.Any(file => !string.Equals(file.BundleDirectory, Directory, StringComparison.OrdinalIgnoreCase) || file.Generation is not null
                    || file.Root.Hash != root.Hash || file.Fingerprint != root.Segment(file.Role).Hash))
                throw new InvalidOperationException("Capture publication cannot replace or join another protected lifetime.");
            foreach (var file in files) _files.Add((file.Role, root.GenerationId), file);
            _captureRootHash = root.Hash;
        }
    }

    /// <summary>Acquires one capture product, retaining its verification only under continuous file protection.</summary>
    public Result<ProtectedStoreFile> Capture(StoreSegmentRole role, CancellationToken cancellationToken)
    {
        using var stopping = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stopping.Token);
        var token = stopping.Token;
        lock (_gate)
        {
            token.ThrowIfCancellationRequested();
            var selected = AnalysisStoreLifecycle.ResolveCapture(Directory);
            if (!selected.IsSuccess) return Result<ProtectedStoreFile>.Failure(selected.Error);
            if (_captureRootHash is not null && _captureRootHash != selected.Value.Hash)
                return Failure("The selected capture root changed during its protected lifetime.");
            var file = Get(role, selected.Value, () => role switch
            {
                StoreSegmentRole.Evidence => ProtectedStoreFile.OpenEvidence(Directory, token),
                StoreSegmentRole.Navigation => ProtectedStoreFile.OpenNavigation(Directory, token),
                StoreSegmentRole.Overview => ProtectedStoreFile.OpenOverview(Directory, token),
                StoreSegmentRole.Delegations => ProtectedStoreFile.OpenDelegations(Directory, token),
                _ => throw new ArgumentOutOfRangeException(nameof(role)),
            });
            if (file.IsSuccess) _captureRootHash = selected.Value.Hash;
            return file;
        }
    }

    /// <summary>Acquires one selected analysis product without reusing a verdict from another root or generation.</summary>
    public Result<ProtectedStoreFile> Analysis(AnalysisStoreKind kind, StoreSegmentRole role, CancellationToken cancellationToken)
    {
        using var stopping = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stopping.Token);
        var token = stopping.Token;
        lock (_gate)
        {
            token.ThrowIfCancellationRequested();
            var capture = AnalysisStoreLifecycle.ResolveCapture(Directory);
            if (!capture.IsSuccess) return Result<ProtectedStoreFile>.Failure(capture.Error);
            if (_captureRootHash is not null && _captureRootHash != capture.Value.Hash)
                return Failure("The selected capture root changed during its protected lifetime.");
            var selected = AnalysisStoreLifecycle.ResolveRoot(Directory, kind);
            if (!selected.IsSuccess) return Result<ProtectedStoreFile>.Failure(selected.Error);
            if (selected.Value.EvidenceSeal != capture.Value.EvidenceSeal)
                return Failure("The selected analysis belongs to another capture.");
            var file = Get(role, selected.Value, () => ProtectedStoreFile.OpenAnalysisSegment(Directory,
                new(kind, selected.Value.GenerationId), role, token));
            if (file.IsSuccess) _captureRootHash = capture.Value.Hash;
            return file;
        }
    }

    private Result<ProtectedStoreFile> Get(StoreSegmentRole role, StoreRootManifest root,
        Func<Result<ProtectedStoreFile>> open)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _closing) != 0, this);
        if (!root.Segments.Any(segment => segment.Role == role))
            return Failure("The selected root does not declare the requested product.");
        var key = (role, root.GenerationId);
        if (_files.TryGetValue(key, out var existing))
            return existing.Root.Hash == root.Hash ? existing
                : Failure("The selected generation's publication root changed.");
        var file = open();
        if (!file.IsSuccess) return file;
        if (file.Value.Root.Hash != root.Hash)
        {
            file.Value.Dispose();
            return Failure("The selected root changed while opening its product.");
        }
        _files.Add(key, file.Value);
        return file;
    }

    private Result<ProtectedStoreFile> Failure(string detail) => Result<ProtectedStoreFile>.Failure(
        AuditError.Create(ErrorCategory.Evidence, "ProtectedStoreGenerationChanged", ErrorSeverity.Failed, detail, Directory));

    /// <summary>Stops acquisitions; readers already holding leases keep protection until their connections close.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _closing, 1) != 0) return;
        _stopping.Cancel();
        lock (_gate)
            foreach (var file in _files.Values) file.Dispose();
        _stopping.Dispose();
    }

    /// <summary>Also waits for the final reader's protection to be released.</summary>
    public async ValueTask DisposeAsync()
    {
        Dispose();
        ProtectedStoreFile[] files;
        lock (_gate) files = _files.Values.ToArray();
        foreach (var file in files) await file.DisposeAsync().ConfigureAwait(false);
    }
}
