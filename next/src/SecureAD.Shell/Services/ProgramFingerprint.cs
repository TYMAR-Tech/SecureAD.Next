using System.IO;

namespace SecureAD.Shell.Services;

/// <summary>
/// The fingerprint of the running program file, worked out once on another thread and then read by
/// whoever needs it.
/// </summary>
/// <remarks>
/// <para>
/// Every log names the program that wrote it, so a returned log can be tied to the build that ran, and
/// that means hashing the whole program file. It is 131 MiB, which a slow disk reads in seconds: the lab
/// machine took 2.7 s. It used to be worked out when first asked for, which was the first click, on the
/// screen's own thread, so the first screen waited for a calculation no screen needs.
/// </para>
/// <para>
/// The application now starts it once the library is listed. A request that finds it finished costs
/// nothing, and one that arrives sooner waits only for what is left. Asking before anything has begun
/// works it out then, so no caller depends on <see cref="Begin"/> having been called.
/// </para>
/// <para>
/// Only a successful calculation is kept. If the program file cannot be read, that request reports it
/// unavailable and the next one tries again, because a log that cannot name its program is still a log.
/// </para>
/// </remarks>
/// <param name="calculate">Works the fingerprint out, or returns null when it cannot be.</param>
internal sealed class ProgramFingerprint(Func<string?> calculate)
{
    private readonly Lock _gate = new();
    private Task<string?>? _calculation;

    /// <summary>Starts working the fingerprint out on another thread, unless it is being or has been.</summary>
    internal void Begin()
    {
        lock (_gate) _calculation ??= Task.Run(calculate);
    }

    /// <summary>The fingerprint, or <c>unavailable</c>; waits for a calculation already under way.</summary>
    internal string Value()
    {
        Task<string?> calculation;
        lock (_gate) calculation = _calculation ??= Task.Run(calculate);

        string? fingerprint = null;
        try { fingerprint = calculation.GetAwaiter().GetResult(); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { /* Reported as unavailable below. */ }
        if (fingerprint is not null) return fingerprint;

        lock (_gate)
        {
            if (ReferenceEquals(_calculation, calculation)) _calculation = null;
        }
        return "unavailable";
    }
}
