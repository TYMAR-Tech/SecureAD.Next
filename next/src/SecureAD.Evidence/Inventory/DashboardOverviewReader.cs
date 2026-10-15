using SecureAD.Kernel;

namespace SecureAD.Evidence.Inventory;

/// <summary>Reads only the independently verified, generation-bound saved Dashboard overview.</summary>
public sealed class DashboardOverviewReader : IDisposable
{
    private readonly ProtectedStoreFile.Lease _lease;
    private readonly ForestInventory _inventory;
    private bool _disposed;

    private DashboardOverviewReader(ProtectedStoreFile.Lease lease, ForestInventory inventory)
    {
        _lease = lease;
        _inventory = inventory;
    }

    /// <summary>Opens an independently owned reader under the selected overview's protected lifetime.</summary>
    public static Result<DashboardOverviewReader> Open(ProtectedStoreFile store, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        if (store.Generation is not null || store.Role != StoreSegmentRole.Overview)
            throw new ArgumentException("A Dashboard reader requires the captured overview product.", nameof(store));
        ProtectedStoreFile.Lease? lease = store.Acquire(cancellationToken);
        try
        {
            var inventory = DashboardOverviewStorage.Read(lease.Connection, store.Root, store.BundleDirectory, cancellationToken);
            if (!inventory.IsSuccess) return Result<DashboardOverviewReader>.Failure(inventory.Error);
            var reader = new DashboardOverviewReader(lease, inventory.Value);
            lease = null;
            return Result<DashboardOverviewReader>.Success(reader);
        }
        catch (Exception error) when (error is InvalidDataException or Microsoft.Data.Sqlite.SqliteException
            or ArgumentException or FormatException or OverflowException or InvalidOperationException)
        {
            return Result<DashboardOverviewReader>.Failure(AuditError.Create(ErrorCategory.Evidence, "DashboardOverviewUnreadable",
                ErrorSeverity.Failed, $"The saved Dashboard overview could not be read: {error.Message}", store.BundleDirectory));
        }
        finally { lease?.Dispose(); }
    }

    /// <summary>Returns authoritative saved counts and coverage, never a catalogue recount.</summary>
    public ForestInventory ReadInventory()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _inventory;
    }

    /// <summary>Releases this reader's protected file lease.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _lease.Dispose();
    }
}
