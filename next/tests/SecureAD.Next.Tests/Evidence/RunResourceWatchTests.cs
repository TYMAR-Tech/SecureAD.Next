using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// What a run cost, and - the part that matters - whether anyone was watching the whole time.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is worth testing at all.</b> These figures exist to size the concurrency ceiling in
/// <c>docs/decisions/0041-capture-reads-domains-in-parallel.md</c> from a real forest instead of
/// from a laboratory of 8,383 objects. A figure that is quietly wrong is worse than no figure,
/// because a guess is known to be a guess and a measurement is not.
/// </para>
/// <para>
/// <b>The two failures worth guarding.</b> Reporting the <i>last</i> reading instead of the largest,
/// which would understate a run whose memory fell before it ended; and reporting a peak that stopped
/// being measured half way as though it were the whole run. Both read as a number, and neither
/// announces itself.
/// </para>
/// </remarks>
public sealed class RunResourceWatchTests : IDisposable
{
    private const int OneMegabyte = 1024 * 1024;

    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "runwatch-" + Guid.NewGuid().ToString("N"));

    public RunResourceWatchTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
    }

    /// <summary>
    /// The largest size seen is kept after the files that made it are gone.
    /// </summary>
    /// <remarks>
    /// <b>This is the negative control for a "last reading" implementation.</b> The megabyte is
    /// deleted before the final sample, so a watch reporting what it saw last would report roughly
    /// nothing and pass every other test in this file. Under sharding it is exactly the shape that
    /// matters: the shard databases are merged and deleted, so the run's true disk high-water mark
    /// is gone by the time the bundle is sealed.
    /// </remarks>
    [Fact]
    public void PeakDiskKeepsTheLargestSizeSeenRatherThanTheLast()
    {
        var file = Path.Combine(_directory, "shard.db");

        using var watch = RunResourceWatch.Start(_directory, TimeProvider.System);

        File.WriteAllBytes(file, new byte[OneMegabyte]);
        watch.Sample();

        File.Delete(file);

        var reading = watch.Stop();

        Assert.True(
            reading.PeakBundleBytes >= OneMegabyte,
            $"Peak disk was {reading.PeakBundleBytes} bytes, but a megabyte was on disk when a "
            + "sample was taken. The watch is reporting its last reading rather than its largest.");
    }

    /// <summary>
    /// A run shorter than one sampling interval still leaves figures behind.
    /// </summary>
    /// <remarks>
    /// A watch that only sampled on its timer would report zero here, and a zero peak reads as
    /// "this run cost nothing" rather than as "nobody looked" - the same confusion between an empty
    /// answer and an unasked question that this product refuses everywhere else.
    /// </remarks>
    [Fact]
    public void ARunShorterThanTheSamplingIntervalStillReportsFigures()
    {
        using var watch = RunResourceWatch.Start(_directory, TimeProvider.System);

        var reading = watch.Stop();

        Assert.True(reading.Samples > 0, "No reading was taken at all.");
        Assert.True(reading.PeakWorkingSetBytes > 0, "The process working set reported as zero.");
        Assert.True(reading.PeakManagedHeapBytes > 0, "The managed heap reported as zero.");
    }

    /// <summary>
    /// A watch that ran to the end reports complete.
    /// </summary>
    [Fact]
    public void AWatchThatRanThroughoutIsComplete()
    {
        using var watch = RunResourceWatch.Start(_directory, TimeProvider.System);

        var reading = watch.Stop();

        Assert.True(reading.IsComplete);
        Assert.Null(reading.StoppedBecause);
    }

    /// <summary>
    /// A directory that disappears stops the watching and is named as the reason.
    /// </summary>
    [Fact]
    public void SamplingStopsAndSaysWhyWhenTheDirectoryGoesAway()
    {
        using var watch = RunResourceWatch.Start(_directory, TimeProvider.System);

        Directory.Delete(_directory, recursive: true);
        watch.Sample();

        var reading = watch.Stop();

        Assert.False(reading.IsComplete);
        Assert.False(string.IsNullOrWhiteSpace(reading.StoppedBecause));
    }

    /// <summary>
    /// Sampling a directory that is gone does not throw into the run that was being watched.
    /// </summary>
    /// <remarks>
    /// Losing the account of what a capture cost is not a reason to lose the capture, which is hours
    /// against a directory that has moved on since. The same judgement <c>RunLogFile</c> makes about
    /// a log that will not open.
    /// </remarks>
    [Fact]
    public void SamplingNeverThrowsIntoTheRun()
    {
        using var watch = RunResourceWatch.Start(_directory, TimeProvider.System);

        Directory.Delete(_directory, recursive: true);

        watch.Sample();
        var reading = watch.Stop();

        Assert.False(reading.IsComplete);
    }

    /// <summary>
    /// What was seen before the watching stopped is kept, and still marked as incomplete.
    /// </summary>
    /// <remarks>
    /// The figures remain useful - a floor is worth more than nothing when a run has just cost
    /// somebody a night - but they must not be offered as peaks.
    /// </remarks>
    [Fact]
    public void PeaksSeenBeforeSamplingStoppedAreKeptAndStillMarkedIncomplete()
    {
        File.WriteAllBytes(Path.Combine(_directory, "shard.db"), new byte[OneMegabyte]);

        using var watch = RunResourceWatch.Start(_directory, TimeProvider.System);

        Directory.Delete(_directory, recursive: true);

        var reading = watch.Stop();

        Assert.True(reading.PeakBundleBytes >= OneMegabyte);
        Assert.False(reading.IsComplete);
    }

    /// <summary>
    /// Once the watching has stopped, no later reading revives it.
    /// </summary>
    /// <remarks>
    /// <b>This is the guard against a floor turning back into a peak.</b> If a directory came back -
    /// a share that reconnected, a transient permission failure - sampling from that point on would
    /// produce a figure covering two stretches of a run with an unmeasured gap between them, and
    /// nothing on the line would say so.
    /// </remarks>
    [Fact]
    public void AStoppedWatchTakesNoFurtherReadings()
    {
        using var watch = RunResourceWatch.Start(_directory, TimeProvider.System);

        Directory.Delete(_directory, recursive: true);
        watch.Sample();

        var afterStopping = watch.Stop();

        Directory.CreateDirectory(_directory);
        File.WriteAllBytes(Path.Combine(_directory, "late.db"), new byte[OneMegabyte]);

        watch.Sample();
        var later = watch.Stop();

        Assert.Equal(afterStopping.Samples, later.Samples);
        Assert.False(later.IsComplete);
        Assert.True(
            later.PeakBundleBytes < OneMegabyte,
            "A reading taken after the watching stopped was counted, so an unmeasured gap in the "
            + "run is hidden inside a figure presented as a peak.");
    }

    /// <summary>
    /// The log line says the figures are floors when the watching stopped.
    /// </summary>
    /// <remarks>
    /// The incompleteness has to survive the journey onto the line an operator actually reads.
    /// A property on a record nobody prints protects nobody.
    /// </remarks>
    [Fact]
    public void TheLogDetailSaysTheFiguresAreFloorsWhenSamplingStopped()
    {
        using var watch = RunResourceWatch.Start(_directory, TimeProvider.System);

        Directory.Delete(_directory, recursive: true);
        watch.Sample();

        var detail = watch.Stop().Details();

        Assert.Contains(detail, d => d.Name == "sampling" && d.Value == "stopped");
        Assert.Contains(detail, d => d.Name == "figuresAre" && d.Value == "floors, not peaks");
        Assert.Contains(detail, d => d.Name == "samplingStoppedBecause");
    }

    /// <summary>
    /// The log line says so when the figures are genuine peaks.
    /// </summary>
    /// <remarks>
    /// Stated on the good case as well as the bad one, so a reader never has to know that the
    /// absence of a word means anything.
    /// </remarks>
    [Fact]
    public void TheLogDetailSaysSamplingWasCompleteWhenItWas()
    {
        using var watch = RunResourceWatch.Start(_directory, TimeProvider.System);

        var detail = watch.Stop().Details();

        Assert.Contains(detail, d => d.Name == "sampling" && d.Value == "complete");
        Assert.DoesNotContain(detail, d => d.Name == "figuresAre");
        Assert.DoesNotContain(detail, d => d.Name == "samplingStoppedBecause");
    }

    /// <summary>
    /// Every figure reaches the line, named.
    /// </summary>
    [Theory]
    [InlineData("peakWorkingSetMb")]
    [InlineData("workingSetAtStartMb")]
    [InlineData("peakManagedHeapMb")]
    [InlineData("peakBundleMb")]
    [InlineData("samples")]
    public void EveryFigureIsNamedOnTheLine(string name)
    {
        using var watch = RunResourceWatch.Start(_directory, TimeProvider.System);

        Assert.Contains(watch.Stop().Details(), d => d.Name == name);
    }

    /// <summary>
    /// A watch needs a directory to watch.
    /// </summary>
    [Fact]
    public void AWatchWithoutADirectoryIsRefused() =>
        Assert.Throws<ArgumentException>(() =>
            RunResourceWatch.Start("  ", TimeProvider.System));

    /// <summary>
    /// A watch needs a clock to sample on.
    /// </summary>
    [Fact]
    public void AWatchWithoutAClockIsRefused() =>
        Assert.Throws<ArgumentNullException>(() =>
            RunResourceWatch.Start(_directory, null!));

    /// <summary>
    /// The figures survive the journey onto a real log line, legibly.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Written through the real log rather than asserted on the record.</b>
    /// <c>docs/decisions/0088-a-run-writes-a-log.md</c> chose text over JSON on the grounds that the
    /// reader is a person, so a figure that is correct in a record and mangled on the line has
    /// failed the only test that matters. The quoting rule in particular is applied by the log and
    /// not by the reading, so nothing but this would notice it turning a number into
    /// <c>"1.5"</c>.
    /// </para>
    /// <para>
    /// <b>What this does not cover.</b> That <c>CaptureSession</c> actually puts these onto its
    /// endings. It is the composition root, it reaches a live forest, and it has no test harness -
    /// so the wiring is unverified and is recorded as such rather than covered by a source scan
    /// that would pass whatever the code did.
    /// </para>
    /// </remarks>
    [Fact]
    public void TheFiguresAreLegibleOnARealLogLine()
    {
        using var watch = RunResourceWatch.Start(_directory, TimeProvider.System);
        var spent = watch.Stop();

        var opened = RunLogFile.Open(_directory, "capture", new FixedTime(Noon));
        Assert.True(opened.IsSuccess);

        using (var log = opened.Value!)
            log.Note("Capture", "finished", spent.Details());

        var line = File.ReadAllLines(BundleLayout.RunLogPath(_directory))
            .Single(l => l.Contains("finished", StringComparison.Ordinal));

        Assert.Contains("sampling=complete", line, StringComparison.Ordinal);
        Assert.Contains("samples=", line, StringComparison.Ordinal);

        // A megabyte figure is a bare number, never quoted. Quoting would mean the formatter had
        // put a space or an equals sign into it, which for a number means it is not a number.
        Assert.Matches(@"peakWorkingSetMb=\d", line);
        Assert.Matches(@"peakBundleMb=\d", line);
    }

    private static readonly DateTimeOffset Noon =
        new(2026, 9, 13, 11, 6, 2, TimeSpan.Zero);

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
