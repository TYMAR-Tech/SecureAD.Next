using SecureAD.Audit.Connect;
using SecureAD.Evidence;
using SecureAD.Kernel;
using Xunit;

namespace SecureAD.Next.Tests.Connect;

/// <summary>
/// The connection security log under the fan-out that shares it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is worth testing at all.</b> <c>CaptureSession</c> builds one
/// <see cref="ConnectionSecurityLog"/> per run and hands it to one channel factory, and since
/// <c>docs/decisions/0041-capture-reads-domains-in-parallel.md</c> landed, nine domains connect to
/// nine controllers through it at once. What it holds is the record of how the forest was reached -
/// which rung each controller answered on - so an entry lost here is a run that reports connecting
/// to eight controllers when it connected to nine, with nothing saying one went missing.
/// </para>
/// <para>
/// <b>These are volume tests, and that is deliberate.</b> A concurrency test written with two
/// threads and one value passes whether or not the code is correct, which is the failure
/// <c>P-194</c> recorded twice in one session: assertions that counted overlapping reads in a
/// fixture too fast to ever overlap. Each test here drives thousands of writes from every core the
/// machine has, and each was proven to fail against the unsynchronised version before being
/// believed.
/// </para>
/// </remarks>
public sealed class ConnectionSecurityLogConcurrencyTests
{
    /// <summary>How many threads write at once. At least eight, so it is not a two-thread test.</summary>
    private static int Writers => Math.Max(8, Environment.ProcessorCount);

    /// <summary>How many entries each writer contributes.</summary>
    private const int Each = 500;

    /// <summary>
    /// Every controller connected to at once is in the record.
    /// </summary>
    /// <remarks>
    /// <b>The count is the whole assertion, and it is a fact about a customer's forest.</b> A
    /// concurrent <see cref="List{T}.Add"/> loses entries silently - two threads compute the same
    /// slot and one write lands on top of the other - so this is the test that fails when the log
    /// is unguarded, and it fails by reporting fewer controllers than were actually reached.
    /// </remarks>
    [Fact]
    public void EveryControllerReachedAtOnceIsKept()
    {
        var log = new ConnectionSecurityLog();

        WriteFromEveryThread(writer =>
        {
            for (var i = 0; i < Each; i++)
                log.Record($"dc{writer}-{i}.contoso.com", ConnectionSecurityLevel.SignedAndSealed, 0);
        });

        Assert.Equal(Writers * Each, log.Controllers.Count);
    }

    /// <summary>
    /// The record holds no duplicates, however many threads reach the same controller, and the
    /// level it kept is the one every view of it reports.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A different defect from the one above, and it survives a lock on each collection
    /// separately.</b> <c>Record</c> tested a key and then wrote it; split those two steps and two
    /// threads reaching one controller both pass the test and both append. The run then reports one
    /// domain controller twice, which reads as two machines with the same name.
    /// </para>
    /// <para>
    /// <b>The writers offer different levels on purpose.</b> The append-only rule of this class is
    /// that the first answer stands and nothing overwrites it with a better one, because the
    /// question it answers is what the run actually used. Under the fan-out "first" has to mean the
    /// first to take the lock rather than the first to test the key - otherwise a controller read
    /// over an unprotected connection could end up recorded as signed and sealed, and the report
    /// would understate what a customer was exposed to. The final assertion reads the kept level
    /// through two members that consult different fields, so a half-written record shows up as the
    /// two disagreeing.
    /// </para>
    /// <para>
    /// <b>This absorbed a separate test on 2026-09-13 that passed against the unsynchronised
    /// version.</b> That one asserted the same single entry with the same mixed levels and did not
    /// fail when the locks were removed, so it was measuring nothing this does not - the failure
    /// class <c>P-194</c> recorded twice in one session. Its one distinct assertion is the last line
    /// here.
    /// </para>
    /// </remarks>
    [Fact]
    public void AControllerReachedFromManyThreadsAtOnceIsRecordedOnce()
    {
        var log = new ConnectionSecurityLog();

        WriteFromEveryThread(writer =>
        {
            var level = writer % 2 == 0
                ? ConnectionSecurityLevel.Unprotected
                : ConnectionSecurityLevel.SignedAndSealed;

            for (var i = 0; i < Each; i++)
                log.Record("dc01.contoso.com", level, 0);
        });

        var only = Assert.Single(log.Controllers);
        Assert.Equal("dc01.contoso.com", only.DomainController);

        Assert.Equal(
            only.Level == ConnectionSecurityLevel.Unprotected,
            log.AnyUnprotected);
    }

    /// <summary>
    /// Every controller that refused every connection is in the record.
    /// </summary>
    /// <remarks>
    /// These are what let the rest of the log be believed: without them, a run in which every
    /// connection failed and a run in which every connection was protected look identical. Losing
    /// one is losing the evidence that the product could not look, which
    /// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> forbids collapsing into "nothing
    /// was wrong".
    /// </remarks>
    [Fact]
    public void EveryFailureRecordedAtOnceIsKept()
    {
        var log = new ConnectionSecurityLog();

        WriteFromEveryThread(writer =>
        {
            for (var i = 0; i < Each; i++)
                log.RecordFailure(Refusal($"dc{writer}-{i}.contoso.com"));
        });

        Assert.Equal(Writers * Each, log.Errors.Count);
    }

    /// <summary>
    /// Reading the record while domains are still connecting does not throw.
    /// </summary>
    /// <remarks>
    /// <b>Handing back the live collections would move this race rather than remove it.</b> A caller
    /// enumerating while another domain connects gets <see cref="InvalidOperationException"/>, which
    /// is the same defect one layer out and would end a capture that had already read most of a
    /// forest. The reading members return copies taken under the lock, so this is safe by
    /// construction rather than by timing.
    /// </remarks>
    [Fact]
    public void TheRecordCanBeReadWhileDomainsAreStillConnecting()
    {
        var log = new ConnectionSecurityLog();
        using var writing = new CancellationTokenSource();

        var writer = Task.Run(() =>
        {
            for (var i = 0; i < Writers * Each; i++)
            {
                log.Record($"dc{i}.contoso.com", ConnectionSecurityLevel.Unprotected, 1);
                log.RecordFailure(Refusal($"bad{i}.contoso.com"));
            }

            writing.Cancel();
        });

        var reads = 0;
        while (!writing.IsCancellationRequested)
        {
            // Enumerated rather than counted, because counting a snapshot would not touch the
            // elements and this is the operation that throws against a live list.
            foreach (var controller in log.Controllers)
                _ = controller.DomainController;

            foreach (var error in log.Errors)
                _ = error.Description;

            _ = log.AnyUnprotected;
            _ = log.RefusedIntegrity;

            reads++;
        }

        writer.GetAwaiter().GetResult();

        Assert.True(reads > 0, "The reader never ran, so this measured nothing.");
        Assert.Equal(Writers * Each, log.Controllers.Count);
    }

    /// <summary>
    /// Runs <paramref name="write"/> on every writer at once, and surfaces whatever it threw.
    /// </summary>
    /// <remarks>
    /// <b>A barrier rather than a plain loop</b>, so every thread is released at the same instant.
    /// Started one after another, the first would often finish before the last began and the test
    /// would pass against unsynchronised code - which is the shape of concurrency test that measures
    /// nothing.
    /// </remarks>
    /// <param name="write">What one writer does, given its index.</param>
    private static void WriteFromEveryThread(Action<int> write)
    {
        using var ready = new Barrier(Writers);

        var work = Enumerable.Range(0, Writers).Select(writer => Task.Factory.StartNew(
            () =>
            {
                ready.SignalAndWait();
                write(writer);
            },
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default));

        // Waited on together so that a failure on one thread is reported rather than swallowed, and
        // so the assertions below run only once every writer has finished.
        Task.WaitAll([.. work]);
    }

    private static AuditError Refusal(string host) => AuditError.Create(
        ErrorCategory.Capture,
        "ControllerRefusedEveryRung",
        ErrorSeverity.Failed,
        $"{host} accepted no connection this run was permitted to offer.",
        host);
}
