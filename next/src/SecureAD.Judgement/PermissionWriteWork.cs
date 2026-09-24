using System.Globalization;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

/// <summary>
/// Where storing the saved permission classifications spends its time.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the largest single cost in judging, and until 2026-09-22 nothing measured it.</b> The
/// first object-pass breakdown put 15,544 ms of a 21,341 ms pass in this one call, against 297 ms to
/// reach the verdicts being stored - storing cost about fifty times more than deciding. Two storage
/// redesigns had already been built and rejected without anyone knowing which part of the write was
/// expensive.
/// </para>
/// <para>
/// <b>Flat, never nested, and the remainder is printed</b>, for the same reasons as the object pass
/// itself: buckets that can contain one another cannot be added up, and a breakdown that hides what
/// it failed to account for invites the reader to assume it accounted for everything.
/// </para>
/// </remarks>
internal sealed class PermissionWriteWork
{
    /// <summary>The whole write, against which every other bucket is accounted.</summary>
    public System.Diagnostics.Stopwatch Total { get; } = new();

    /// <summary>Checking the classification before any of it is stored.</summary>
    public System.Diagnostics.Stopwatch Validate { get; } = new();

    /// <summary>Writing the object's own row, including serialising its descriptor.</summary>
    public System.Diagnostics.Stopwatch ObjectRow { get; } = new();

    /// <summary>Storing each access control entry in the shared table.</summary>
    public System.Diagnostics.Stopwatch SharedEntry { get; } = new();

    /// <summary>Storing and verifying the schema support each entry refers to.</summary>
    public System.Diagnostics.Stopwatch SchemaSupport { get; } = new();

    /// <summary>Writing each classified entry row, including serialising its reading.</summary>
    public System.Diagnostics.Stopwatch EntryRow { get; } = new();

    /// <summary>How many entries were stored, so a bucket can be read per entry.</summary>
    public long Entries { get; set; }

    /// <summary>How many objects were stored.</summary>
    public long Objects { get; set; }

    /// <summary>Writes one line per bucket, slowest first, then the accounting line.</summary>
    /// <param name="log">The run log this judging is writing to.</param>
    /// <param name="phase">The phase name the judging coordinator logs under.</param>
    public void Note(IRunLog log, string phase)
    {
        (string Part, TimeSpan Elapsed)[] buckets =
        [
            ("validate", Validate.Elapsed),
            ("object-row", ObjectRow.Elapsed),
            ("shared-entry", SharedEntry.Elapsed),
            ("schema-support", SchemaSupport.Elapsed),
            ("entry-row", EntryRow.Elapsed),
        ];

        foreach (var bucket in buckets.OrderByDescending(b => b.Elapsed))
        {
            log.Note(
                phase,
                "permission write",
                [
                    new RunLogDetail("part", bucket.Part),
                    new RunLogDetail("ms", Milliseconds(bucket.Elapsed)),
                ]);
        }

        var measured = buckets.Aggregate(TimeSpan.Zero, (total, bucket) => total + bucket.Elapsed);
        log.Note(
            phase,
            "permission write accounted",
            [
                new RunLogDetail("totalMs", Milliseconds(Total.Elapsed)),
                new RunLogDetail("measuredMs", Milliseconds(measured)),
                new RunLogDetail("unaccountedMs", Milliseconds(Total.Elapsed - measured)),
                new RunLogDetail("objects", Objects.ToString(CultureInfo.InvariantCulture)),
                new RunLogDetail("entries", Entries.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static string Milliseconds(TimeSpan value) =>
        ((long)value.TotalMilliseconds).ToString(CultureInfo.InvariantCulture);
}
