namespace SecureAD.Evidence;

/// <summary>Runs one whole-file check where it can neither starve the pool nor outrun the screen.</summary>
/// <remarks>
/// A check of a large store can read for minutes. It gets a dedicated thread, not a pool thread, so the
/// readers waiting on it cannot exhaust the pool, and it runs below normal priority so that hashing a
/// multi-gigabyte file never competes with drawing the window. The work must complete its own result; an
/// exception escaping a thread would end the process.
/// </remarks>
internal static class VerificationThread
{
    internal static void Start(string name, Action work)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(work);
        new Thread(() => work())
        {
            Name = name,
            IsBackground = true,
            Priority = ThreadPriority.BelowNormal,
        }.Start();
    }
}
