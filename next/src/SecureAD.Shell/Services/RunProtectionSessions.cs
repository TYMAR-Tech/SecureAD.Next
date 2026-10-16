using System.IO;
using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Shell.Services;

/// <summary>Shares an explicitly owned run lifetime, retaining at most one completed handoff.</summary>
internal sealed class RunProtectionSessions : IDisposable
{
    private readonly object _gate = new();
    private readonly Dictionary<string, Entry> _runs = new(StringComparer.OrdinalIgnoreCase);
    private Lease? _handoff;
    private bool _closed;
    private sealed class Entry(ProtectedRunFiles files)
    {
        internal ProtectedRunFiles Files { get; } = files;
        internal int Readers { get; set; }
    }

    internal Result<T> Produce<T>(string directory, Func<ProtectedRunFiles, Result<T>> produce)
    {
        using var operation = Acquire(directory);
        var result = produce(operation.Files);
        if (result.IsSuccess) Offer(operation);
        return result;
    }

    internal Lease Acquire(string directory)
    {
        var path = Path.GetFullPath(directory);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_closed, this);
            if (!_runs.TryGetValue(path, out var entry))
                _runs.Add(path, entry = new(new ProtectedRunFiles(path)));
            entry.Readers++;
            return new(this, entry.Files);
        }
    }

    internal void Offer(Lease completed)
    {
        Lease? previous;
        lock (_gate)
        {
            if (!completed.BelongsTo(this)) throw new InvalidOperationException("The completed lifetime is no longer owned here.");
            var next = Acquire(completed.Files.Directory);
            previous = _handoff;
            _handoff = next;
        }
        previous?.Dispose();
    }

    internal Lease TakeForViewing(string directory)
    {
        var reading = Acquire(directory);
        Lease? previous = null;
        lock (_gate)
        {
            if (string.Equals(_handoff?.Files.Directory, reading.Files.Directory, StringComparison.OrdinalIgnoreCase))
            {
                previous = _handoff;
                _handoff = null;
            }
        }
        previous?.Dispose();
        return reading;
    }

    internal void ReleaseHandoff()
    {
        Lease? previous;
        lock (_gate) { previous = _handoff; _handoff = null; }
        previous?.Dispose();
    }

    private ProtectedRunFiles? Release(ProtectedRunFiles files)
    {
        lock (_gate)
        {
            var entry = _runs[files.Directory];
            if (--entry.Readers != 0) return null;
            _runs.Remove(files.Directory);
            return files;
        }
    }

    public void Dispose()
    {
        ProtectedRunFiles[] files;
        lock (_gate)
        {
            if (_closed) return;
            _closed = true;
            files = _runs.Values.Select(entry => entry.Files).ToArray();
        }
        ReleaseHandoff();
        foreach (var file in files) file.Dispose();
    }

    internal sealed class Lease(RunProtectionSessions owner, ProtectedRunFiles files) : IDisposable, IAsyncDisposable
    {
        private RunProtectionSessions? _owner = owner;
        private readonly object _gate = new();
        private ProtectedRunFiles? _closingFiles;
        internal ProtectedRunFiles Files { get; } = files;
        internal bool BelongsTo(RunProtectionSessions value) => ReferenceEquals(_owner, value);
        public void Dispose()
        {
            lock (_gate)
            {
                var previous = Interlocked.Exchange(ref _owner, null);
                if (previous is null) return;
                _closingFiles = previous.Release(Files);
                _closingFiles?.Dispose();
            }
        }
        public async ValueTask DisposeAsync()
        {
            Dispose();
            ProtectedRunFiles? closing;
            lock (_gate) closing = _closingFiles;
            if (closing is not null) await closing.DisposeAsync().ConfigureAwait(false);
        }
    }
}
