using System.Globalization;
using SecureAD.Kernel;

namespace SecureAD.Evidence.Run;

/// <summary>
/// What a run cost while it was running: the peaks, and whether they were watched throughout.
/// </summary>
/// <remarks>
/// <para>
/// <b>The incompleteness is a field rather than a footnote.</b> A peak is only a peak if something
/// was watching for the whole run. If sampling stopped half way, every figure here is a floor -
/// the largest value seen before the watching stopped - and a floor presented as a peak is the
/// failure this product exists to refuse. <see cref="IsComplete"/> is the difference, and
/// <see cref="Details"/> writes it onto every line so a reader cannot see the numbers without it.
/// </para>
/// <para>
/// <b>Working set is the process's, not the run's.</b> Capture runs inside the shell, so the
/// figure includes whatever the user interface was holding. That is not a flaw to be corrected:
/// the question this answers is whether a machine survives reading nine domains at once, and the
/// machine does not care which part of the process wanted the memory.
/// <see cref="WorkingSetAtStartBytes"/> is recorded beside it so the reader can see what the run
/// itself added.
/// </para>
/// </remarks>
/// <param name="WorkingSetAtStartBytes">The process working set when the watch started.</param>
/// <param name="PeakWorkingSetBytes">The largest process working set seen.</param>
/// <param name="PeakManagedHeapBytes">The largest managed heap seen.</param>
/// <param name="PeakBundleBytes">The most bytes seen under the bundle directory at one time.</param>
/// <param name="Samples">How many readings were taken. One or more, unless nothing was watched.</param>
/// <param name="IsComplete">
/// Whether the peaks are peaks. False makes every figure a floor.
/// </param>
/// <param name="StoppedBecause">
/// Why sampling stopped early, where that is known.
/// </param>
public sealed record RunResourceReading(
    long WorkingSetAtStartBytes,
    long PeakWorkingSetBytes,
    long PeakManagedHeapBytes,
    long PeakBundleBytes,
    int Samples,
    bool IsComplete,
    string? StoppedBecause)
{
    /// <summary>
    /// The figures as log detail, with whether they can be trusted as peaks.
    /// </summary>
    /// <remarks>
    /// <b>Megabytes to one decimal, because the reader is a person.</b> An operator reading this is
    /// deciding whether a forest of 347,000 objects fits in the machine he ran it on, and bytes
    /// make that arithmetic by hand. The rounding is stated rather than hidden: a figure written
    /// as <c>0</c> megabytes means under fifty kilobytes, not nothing.
    /// </remarks>
    public IReadOnlyList<RunLogDetail> Details()
    {
        var detail = new List<RunLogDetail>
        {
            new("peakWorkingSetMb", Megabytes(PeakWorkingSetBytes)),
            new("workingSetAtStartMb", Megabytes(WorkingSetAtStartBytes)),
            new("peakManagedHeapMb", Megabytes(PeakManagedHeapBytes)),
            new("peakBundleMb", Megabytes(PeakBundleBytes)),
            new("samples", Samples.ToString(CultureInfo.InvariantCulture)),

            // Written on the complete case too, and deliberately. A reader who only ever sees the
            // word "stopped" on a broken run has to know that its absence means anything at all;
            // stating it both ways means the line says what it is without being compared to
            // another line.
            new("sampling", IsComplete ? "complete" : "stopped"),
        };

        if (!IsComplete)
        {
            detail.Add(new RunLogDetail("figuresAre", "floors, not peaks"));

            // COMPLETENESS IS ITS OWN VALUE AND IS NOT INFERRED FROM THIS REASON, which is the
            // difference between two states and three. A reading that stopped without recording
            // why is still a reading that stopped, and deriving the completeness from whether
            // there is a sentence here would report it as sound. The missing sentence is named
            // instead, because "stopped, and nobody wrote down why" is a fact worth seeing.
            detail.Add(new RunLogDetail(
                "samplingStoppedBecause",
                string.IsNullOrWhiteSpace(StoppedBecause) ? "not recorded" : StoppedBecause));
        }

        return detail;
    }

    private static string Megabytes(long bytes) =>
        (bytes / 1024d / 1024d).ToString("0.#", CultureInfo.InvariantCulture);
}

/// <summary>
/// Watches what a run costs, so the next one can be sized from evidence rather than from a guess.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists.</b> Capture is about to read domains in parallel under
/// <c>docs/decisions/0041-capture-reads-domains-in-parallel.md</c>, with a ceiling on how many at
/// once, and nothing in the product measures what one domain costs - so the ceiling could only ever
/// be a guess dressed as a number. A production run with this in place answers it from the
/// operator's own forest instead of from a laboratory of 8,383 objects or a synthetic figure.
/// </para>
/// <para>
/// <b>Disk is watched because sharding makes it the binding constraint, not memory.</b> Each domain
/// writes its own database and they are merged afterwards, so every shard file exists at once
/// alongside what has been merged so far. Peak disk is therefore well above the size of the finished
/// bundle, and it is the figure that says whether a ceiling of eight fits on the disk the operator
/// chose. Memory scales with the objects read rather than with the concurrency; disk does not.
/// </para>
/// <para>
/// <b>Sampled, because .NET keeps no peak that can be reset.</b> <c>PeakWorkingSet64</c> is a peak
/// since the process started, which in the shell means since before the run - so it answers a
/// different question. Sampling on a timer answers this one, at the cost of possibly missing a
/// spike shorter than the interval. That is stated rather than hidden: these are the peaks that
/// were <i>seen</i>.
/// </para>
/// <para>
/// <b>A failure to sample stops the watching and says so.</b> It never fails the run - losing the
/// account of what a capture cost is not a reason to lose the capture, which is the same judgement
/// <see cref="RunLogFile"/> makes about a log that will not open. What it must not do is carry on
/// reporting the peaks it had already seen as though they were the whole story.
/// </para>
/// </remarks>
public sealed class RunResourceWatch : IDisposable
{
    /// <summary>
    /// How often a reading is taken.
    /// </summary>
    /// <remarks>
    /// <b>A constant, not a setting.</b> Two seconds is short against a capture measured in hours
    /// and long against the cost of one reading, which is a directory enumeration over a handful of
    /// files. There is nothing here an operator could choose better than this, and
    /// <c>0041</c> refuses knobs whose relationship to what happens is loose.
    /// </remarks>
    public static readonly TimeSpan SampleEvery = TimeSpan.FromSeconds(2);

    private readonly string _bundleDirectory;
    private readonly Lock _gate = new();
    private readonly long _workingSetAtStart;

    private ITimer? _timer;
    private long _peakWorkingSet;
    private long _peakManagedHeap;
    private long _peakBundleBytes;
    private int _samples;

    /// <summary>
    /// Whether the watch is still taking readings.
    /// </summary>
    /// <remarks>
    /// <b>A flag of its own rather than a test on whether a reason is present.</b> Deriving it from
    /// <see cref="_stoppedBecause"/> makes an empty message a third state that means neither thing:
    /// the figures would be published as floors while nothing said why, which is worse than either
    /// honest answer. <see cref="Exception.Message"/> is not guaranteed to say anything.
    /// </remarks>
    private bool _sampling = true;

    private string? _stoppedBecause;

    private RunResourceWatch(string bundleDirectory, long workingSetAtStart)
    {
        _bundleDirectory = bundleDirectory;
        _workingSetAtStart = workingSetAtStart;
    }

    /// <summary>
    /// Starts watching <paramref name="bundleDirectory"/>, taking the first reading at once.
    /// </summary>
    /// <remarks>
    /// <b>The first reading is taken here rather than waiting for the timer.</b> A run shorter than
    /// one interval would otherwise report zero, and a zero peak reads as "this cost nothing"
    /// rather than as "nobody looked".
    /// </remarks>
    /// <param name="bundleDirectory">The run's own directory, whose size is watched.</param>
    /// <param name="time">The clock the sampling timer is taken from.</param>
    public static RunResourceWatch Start(string bundleDirectory, TimeProvider time)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentNullException.ThrowIfNull(time);

        var watch = new RunResourceWatch(bundleDirectory, Environment.WorkingSet);

        watch.Sample();
        watch._timer = time.CreateTimer(
            _ => watch.Sample(), state: null, SampleEvery, SampleEvery);

        return watch;
    }

    /// <summary>
    /// Takes one reading now, keeping it if it is larger than anything seen before.
    /// </summary>
    /// <remarks>
    /// <b>Public so that a caller can mark a moment it cares about</b> - the end of the directory
    /// read, say, before SYSVOL is touched - and so that this can be tested without a clock. Once
    /// sampling has stopped this does nothing, because a reading taken after a gap would make a
    /// floor look like a peak again.
    /// </remarks>
    public void Sample()
    {
        lock (_gate)
        {
            if (!_sampling)
                return;

            long bundleBytes;

            try
            {
                bundleBytes = BytesUnder(_bundleDirectory);
            }
            catch (Exception failure) when (
                failure is IOException or UnauthorizedAccessException)
            {
                // Not rethrown, and not swallowed either: the watching stops and the reading says
                // why, so the figures are presented as floors from here on.
                //
                // The flag is set independently of the message, because an exception carrying an
                // empty one must still stop the watching. A reason that says nothing is a poorer
                // log line; a peak that was never measured is a wrong answer.
                _sampling = false;
                _stoppedBecause = string.IsNullOrWhiteSpace(failure.Message)
                    ? failure.GetType().Name + ", which carried no message"
                    : failure.Message;

                return;
            }

            _peakWorkingSet = Math.Max(_peakWorkingSet, Environment.WorkingSet);
            _peakManagedHeap = Math.Max(
                _peakManagedHeap, GC.GetTotalMemory(forceFullCollection: false));
            _peakBundleBytes = Math.Max(_peakBundleBytes, bundleBytes);
            _samples++;
        }
    }

    /// <summary>
    /// Stops watching and hands back what was seen.
    /// </summary>
    /// <remarks>
    /// A last reading is taken first, so that whatever the run was holding at its largest - which
    /// is usually at the end, as the bundle is sealed and the shards are still on disk - is in the
    /// figures.
    /// </remarks>
    public RunResourceReading Stop()
    {
        Sample();

        lock (_gate)
        {
            _timer?.Dispose();
            _timer = null;

            return new RunResourceReading(
                _workingSetAtStart,
                _peakWorkingSet,
                _peakManagedHeap,
                _peakBundleBytes,
                _samples,
                _sampling,
                _stoppedBecause);
        }
    }

    /// <summary>Stops the timer, discarding the reading.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            _timer?.Dispose();
            _timer = null;
        }
    }

    /// <summary>
    /// Every byte under a directory, including the write-ahead log and any shard beside it.
    /// </summary>
    /// <remarks>
    /// <b>Lengths come from the enumeration rather than from a second look at each file.</b> A run
    /// is writing into this directory while it is being measured - the write-ahead log is
    /// checkpointed, the partial file is renamed at the seal - so a file named by the enumeration
    /// may be gone by the time anything asks its size. <c>EnumerateFiles</c> carries the length it
    /// found, which both avoids that race and costs one pass instead of two.
    /// </remarks>
    private static long BytesUnder(string directory)
    {
        var root = new DirectoryInfo(directory);

        if (!root.Exists)
            throw new DirectoryNotFoundException(
                $"The run's directory '{directory}' is no longer there, so nothing further can be "
                + "measured about what the run cost.");

        long total = 0;

        foreach (var file in root.EnumerateFiles("*", SearchOption.AllDirectories))
        {
            total += file.Length;
        }

        return total;
    }
}
