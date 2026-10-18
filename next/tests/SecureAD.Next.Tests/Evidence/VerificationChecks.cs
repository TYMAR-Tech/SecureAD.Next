using System.Collections.Concurrent;
using System.Diagnostics.Metrics;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>Counts, and optionally holds open, the whole-file checks of one run's files.</summary>
/// <remarks>
/// The product publishes a <c>store.verifications</c> measurement on the very thread that is about to
/// hash a file. A listener that blocks inside that callback therefore holds exactly that file's check
/// open, deterministically, until <see cref="Release"/>, without any hook in the product and without
/// timing assumptions. Only files under the given run folder are seen, so parallel tests cannot
/// disturb each other.
/// </remarks>
internal sealed class VerificationChecks : IDisposable
{
    /// <summary>How long a test waits for something that should happen promptly, or should not happen at all.</summary>
    internal static readonly TimeSpan Patience = TimeSpan.FromSeconds(30);

    // A held check must outlast every wait in a test by a wide margin. Were the two equal, a reader stalled behind
    // the held check would be freed by the hold expiring a moment before the test gave up, and a defect would pass.
    private static readonly TimeSpan HoldLimit = TimeSpan.FromSeconds(90);

    private readonly MeterListener _listener = new();
    private readonly ConcurrentQueue<string> _started = new();
    private readonly ConcurrentDictionary<string, bool> _blocked = new(StringComparer.OrdinalIgnoreCase);
    private readonly ManualResetEventSlim _released = new(false);

    internal VerificationChecks(string directory, Func<string, bool>? holdWhen = null)
    {
        _listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Name == "store.verifications") listener.EnableMeasurementEvents(instrument);
        };
        _listener.SetMeasurementEventCallback<long>((_, _, tags, _) =>
        {
            foreach (var tag in tags)
            {
                if (tag.Value is not string path || !path.StartsWith(directory, StringComparison.OrdinalIgnoreCase)) continue;
                var name = Path.GetFileName(path);
                _started.Enqueue(name);
                if (holdWhen?.Invoke(name) != true) continue;
                _blocked[name] = true;
                _released.Wait(HoldLimit);
            }
        });
        _listener.Start();
    }

    /// <summary>The name of every file whose check has begun, in order, once per check.</summary>
    internal IReadOnlyCollection<string> Started => _started.ToArray();

    /// <summary>How many checks have begun on files whose name contains the text.</summary>
    internal int Count(string namePart) => _started.Count(name => name.Contains(namePart, StringComparison.Ordinal));

    /// <summary>Waits until a check on a file whose name contains the text is being held.</summary>
    internal bool WaitUntilBlocked(string namePart)
    {
        var deadline = DateTime.UtcNow + Patience;
        while (DateTime.UtcNow < deadline)
        {
            if (_blocked.Keys.Any(name => name.Contains(namePart, StringComparison.Ordinal))) return true;
            Thread.Sleep(10);
        }
        return false;
    }

    /// <summary>Lets every held check continue.</summary>
    internal void Release() => _released.Set();

    public void Dispose()
    {
        _released.Set();
        _listener.Dispose();
        _released.Dispose();
    }
}
