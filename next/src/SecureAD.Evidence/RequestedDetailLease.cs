namespace SecureAD.Evidence;

/// <summary>A requested reader uses the existing run owner and cannot expose an unchecked SQL connection.</summary>
public sealed partial class RequestedDetailLease : IDisposable
{
    private ProtectedStoreFile.Lease? _lease;
    private readonly CancellationTokenSource _stopping;

    internal RequestedDetailLease(ProtectedStoreFile file, CancellationToken request, CancellationToken run,
        Func<bool> current)
    {
        Root = file.Root;
        _stopping = CancellationTokenSource.CreateLinkedTokenSource(request, run);
        try
        {
            _lease = file.AcquireRequested(_stopping.Token);
            Reader = RequestedDetailIndex.Open(_lease.Connection, "main",
                file.Root.Segment(file.Role).RequestedDetails ?? throw RequestedDetailMap.Invalid(), _stopping.Token);
            Reader.RequireCurrent(() => _lease is not null && current());
        }
        catch
        {
            _lease?.Dispose();
            _stopping.Dispose();
            throw;
        }
    }

    /// <summary>The source-bound page reader, not a verdict about all file bytes.</summary>
    public RequestedDetailReader Reader { get; }

    /// <summary>The exact publication selected for this lease.</summary>
    public StoreRootManifest Root { get; }

    /// <summary>Releases the connection before its existing protected-file lease.</summary>
    public void Dispose()
    {
        var lease = Interlocked.Exchange(ref _lease, null);
        if (lease is null) return;
        _stopping.Cancel();
        try { lease.Dispose(); }
        finally { _stopping.Dispose(); }
    }
}
