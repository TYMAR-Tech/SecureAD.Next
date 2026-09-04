using System.Runtime.CompilerServices;
using Microsoft.Data.Sqlite;

namespace SecureAD.Next.Tests;

/// <summary>
/// Temporary directories for tests that need a real bundle on disk, cleared when the run that owns
/// them is over.
/// </summary>
/// <remarks>
/// <para>
/// <b>This exists because the suite was leaking gigabytes.</b> Measured on 2026-09-04:
/// <c>%TEMP%\securead-*</c> held 10.58 GB across 1,769 directories, the oldest from 2026-09-02.
/// <c>securead-laps-tests</c> alone held 3,848 bundles and 3.5 GB. Every run added more and nothing
/// ever removed any of them.
/// </para>
/// <para>
/// <b>The fault was not the naming - it was that nobody owned the directory.</b> Each call site
/// already built a unique <c>GUID</c> folder under a shared parent, so runs did not collide. What
/// was missing is a lifetime: the worst offender, <c>LapsBundle.Build</c>, is a static helper that
/// returns a path, so there is no instance whose <c>Dispose</c> could clean it up and no test that
/// considers itself the owner.
/// </para>
/// <para>
/// <b>Everything one run writes goes under one folder named after the process that owns it.</b>
/// That is what makes the cleanup certain rather than a guess. A starting run deletes any run
/// folder whose process is no longer alive, which needs no timer, no age threshold and no
/// assumption about how long a suite takes - and it cannot touch a run that is still going, because
/// that run's process is still there.
/// </para>
/// <para>
/// <b>Two earlier attempts were weaker, and each was caught by observation rather than review.</b>
/// Deleting only at <c>ProcessExit</c> left 88 MB in 585 files, because .NET gives exit handlers
/// roughly two seconds and several thousand bundles do not fit. Adding a sweep of anything older
/// than an hour then failed differently: two full runs inside the same hour grew the directory from
/// 107 MB to 284 MB, since nothing was ever old enough to collect. Neither was visible without
/// measuring the disk before and after.
/// </para>
/// <para>
/// <b>A directory that will not delete is ignored on purpose.</b> Reclaiming disk space must never
/// fail a test run: a file still held open would otherwise turn a green suite red for a reason that
/// has nothing to do with the product. The next run collects it instead, because by then this
/// process is gone.
/// </para>
/// </remarks>
internal static class TempDirectories
{
    private const string RunPrefix = "securead-run-";

    /// <summary>
    /// The folder holding everything this run writes, named so another run can tell whose it is.
    /// </summary>
    private static readonly string RunRoot = Path.Combine(
        Path.GetTempPath(),
        $"{RunPrefix}{Environment.ProcessId}-{Guid.NewGuid():N}");

    /// <summary>
    /// Sweeps what abandoned runs left, and arranges to clear this run's own, as the assembly
    /// loads.
    /// </summary>
    /// <remarks>
    /// <b>A module initializer rather than a static constructor, and a test proved the
    /// difference.</b> A static constructor runs only when something first touches the class, so a
    /// filtered run that happens to exercise no bundle-writing test never sweeps at all - which is
    /// exactly what was observed: a backdated marker directory survived a filtered run untouched. A
    /// module initializer runs when the test assembly is loaded, whatever is selected to run.
    /// </remarks>
    [ModuleInitializer]
    internal static void Initialize()
    {
        SweepAbandoned();

        // One recursive delete of a single root, rather than thousands of individual ones. That
        // stands a far better chance of fitting in the exit budget - and where it does not, the
        // next run collects it, because by then this process is no longer alive.
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            SqliteConnection.ClearAllPools();
            TryDelete(RunRoot);
        };
    }

    /// <summary>
    /// Creates an empty directory for one test's bundle.
    /// </summary>
    /// <param name="name">
    /// What this group of tests is called. Kept as a folder inside the run root so that a directory
    /// listing still says which tests wrote what, which is worth having when a bundle has to be
    /// opened by hand.
    /// </param>
    /// <returns>The full path of a new, empty directory.</returns>
    public static string Create(string name)
    {
        var directory = Path.Combine(RunRoot, name, Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(directory);

        return directory;
    }

    /// <summary>
    /// Deletes the run folders of test processes that are no longer running.
    /// </summary>
    private static void SweepAbandoned()
    {
        IEnumerable<string> roots;

        try
        {
            roots = Directory.EnumerateDirectories(Path.GetTempPath(), "securead-*");
        }
        catch (DirectoryNotFoundException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        foreach (var root in roots)
        {
            if (string.Equals(root, RunRoot, StringComparison.OrdinalIgnoreCase))
                continue;

            if (IsAbandoned(root))
                TryDelete(root);
        }
    }

    /// <summary>
    /// Whether a directory in the temporary folder is left over rather than in use.
    /// </summary>
    /// <remarks>
    /// <b>Anything not named as a run folder is left alone.</b> Other things in the temporary
    /// folder begin with the product's name - fixtures that already delete themselves, and whatever
    /// an operator has put there by hand - and this is not entitled to remove them.
    /// </remarks>
    private static bool IsAbandoned(string root)
    {
        var name = Path.GetFileName(root);

        if (!name.StartsWith(RunPrefix, StringComparison.Ordinal))
            return false;

        var remainder = name[RunPrefix.Length..];
        var separator = remainder.IndexOf('-', StringComparison.Ordinal);

        if (separator <= 0 || !int.TryParse(remainder[..separator], out var processId))
        {
            // Named like a run folder but not parseable as one. Nothing writes that shape, so it
            // is a leftover of some earlier scheme and is safe to remove.
            return true;
        }

        try
        {
            using var owner = System.Diagnostics.Process.GetProcessById(processId);

            // The identifier is live. It may have been reused by an unrelated process since, in
            // which case this folder survives until that one exits - which costs one run's disk
            // and never deletes anything in use.
            return owner.HasExited;
        }
        catch (ArgumentException)
        {
            // No process carries that identifier: the run that owned this is over.
            return true;
        }
        catch (InvalidOperationException)
        {
            return true;
        }
    }

    private static void TryDelete(string directory)
    {
        try
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
        catch (IOException)
        {
            // Still held open. Left for the next run rather than failing this one.
        }
        catch (UnauthorizedAccessException)
        {
            // Read-only or locked by another process. Same answer.
        }
    }
}
