using SecureAD.Next.Tests.Architecture;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

/// <summary>
/// The program file is hashed once, in the background, so no click pays for it, and a click that arrives
/// early waits for that one calculation instead of starting a second read.
/// </summary>
/// <remarks>
/// The first lab run of the fixed build took 2.7 s for its first click, nearly all of it this hash, taken on
/// the screen's own thread. The calculation here is a stand-in that tests can hold open and count, so the
/// behaviour is proved without depending on how fast a disk reads the real program file; the real
/// calculation is checked by <see cref="NavigationDiagnosticsTests"/>, which compares the logged hash with
/// the process's actual one.
/// </remarks>
public sealed class ProgramFingerprintTests
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(10);

    // Far beyond any wait above, so a held calculation is only ever freed by the test.
    private static readonly TimeSpan HoldLimit = TimeSpan.FromSeconds(60);

    [Fact]
    public void BeginningWorksTheFingerprintOutOnAnotherThreadBeforeAnyoneAsksForIt()
    {
        using var work = new Work(held: false, "HASH");
        var fingerprint = new ProgramFingerprint(work.Calculate);

        fingerprint.Begin();

        Assert.True(work.Finished.Wait(Patience), "The calculation never ran in the background.");
        Assert.NotEqual(Environment.CurrentManagedThreadId, work.ThreadId);
        Assert.Equal("HASH", fingerprint.Value());
        Assert.Equal(1, work.Runs);
    }

    [Fact]
    public async Task BeginningNeverWaitsForTheCalculation()
    {
        using var work = new Work(held: true, "HASH");
        var fingerprint = new ProgramFingerprint(work.Calculate);

        var beginning = Task.Run(fingerprint.Begin);

        Assert.True(await Task.WhenAny(beginning, Task.Delay(Patience)) == beginning, "Begin waited for the calculation.");
        work.Release();
        Assert.Equal("HASH", fingerprint.Value());
    }

    [Fact]
    public async Task ARequestWhileTheCalculationIsUnderWayWaitsForItAndStartsNoSecondRead()
    {
        using var work = new Work(held: true, "HASH");
        var fingerprint = new ProgramFingerprint(work.Calculate);
        fingerprint.Begin();
        Assert.True(work.Entered.Wait(Patience), "The calculation never started.");

        var asking = Task.Run(fingerprint.Value);
        await Task.Delay(300);
        Assert.False(asking.IsCompleted, "The request did not wait for the calculation under way.");

        work.Release();
        Assert.Equal("HASH", await asking.WaitAsync(Patience));
        Assert.Equal(1, work.Runs);
    }

    [Fact]
    public void AskingBeforeAnythingHasBegunWorksItOutOnceForEveryAsker()
    {
        using var work = new Work(held: false, "HASH");
        var fingerprint = new ProgramFingerprint(work.Calculate);

        Assert.Equal("HASH", fingerprint.Value());
        Assert.Equal("HASH", fingerprint.Value());
        fingerprint.Begin();

        Assert.Equal(1, work.Runs);
    }

    [Fact]
    public void AFingerprintThatCannotBeWorkedOutIsUnavailableNowAndTriedAgainNextTime()
    {
        using var work = new Work(held: false, null, "LATER");
        var fingerprint = new ProgramFingerprint(work.Calculate);

        Assert.Equal("unavailable", fingerprint.Value());
        Assert.Equal("LATER", fingerprint.Value());
        Assert.Equal("LATER", fingerprint.Value());

        Assert.Equal(2, work.Runs);
    }

    [Fact]
    public void AReadFailureInTheBackgroundIsUnavailableAndDoesNotPoisonLaterRequests()
    {
        using var work = new Work(held: false, new IOException("The program file is locked."), "LATER");
        var fingerprint = new ProgramFingerprint(work.Calculate);

        fingerprint.Begin();
        Assert.True(work.Finished.Wait(Patience), "The calculation never ran in the background.");

        Assert.Equal("unavailable", fingerprint.Value());
        Assert.Equal("LATER", fingerprint.Value());
        Assert.Equal(2, work.Runs);
    }

    [Fact]
    public void TheApplicationStartsTheHashOnceTheLibraryHasBeenListed()
    {
        var source = File.ReadAllText(Path.Combine(RebuildTree.Root(), "src", "SecureAD.Shell", "App.xaml.cs"));

        Assert.True(StartsAfterTheLibraryIsListed(source),
            "App.OnStartup must call NavigationDiagnostics.BeginProgramFingerprint() after the library refresh completes: "
            + "before it, the hash competes with the start-up reads; never, the first click pays for it.");
    }

    [Theory]
    [InlineData("_startup(AppStartupPoint.LibraryRefreshCompleted); NavigationDiagnostics.BeginProgramFingerprint();", true)]
    [InlineData("NavigationDiagnostics.BeginProgramFingerprint(); _startup(AppStartupPoint.LibraryRefreshCompleted);", false)]
    [InlineData("_startup(AppStartupPoint.LibraryRefreshCompleted);", false)]
    [InlineData("NavigationDiagnostics.BeginProgramFingerprint();", false)]
    public void TheStartOrderCheckCanFail(string source, bool expected) =>
        Assert.Equal(expected, StartsAfterTheLibraryIsListed(source));

    private static bool StartsAfterTheLibraryIsListed(string source)
    {
        var listed = source.IndexOf("_startup(AppStartupPoint.LibraryRefreshCompleted);", StringComparison.Ordinal);
        var started = source.IndexOf("NavigationDiagnostics.BeginProgramFingerprint();", StringComparison.Ordinal);
        return listed >= 0 && started > listed;
    }

    /// <summary>
    /// A stand-in for the hash: counts its runs, notes the thread, and can be held open until the test releases it.
    /// </summary>
    /// <remarks>
    /// Each run takes the next outcome, a value, null or an exception to throw; the last outcome repeats.
    /// </remarks>
    private sealed class Work : IDisposable
    {
        private readonly object?[] _outcomes;
        private readonly ManualResetEventSlim _release;
        private int _runs;
        private int _threadId;

        internal Work(bool held, params object?[] outcomes)
        {
            _outcomes = outcomes;
            _release = new ManualResetEventSlim(!held);
        }

        internal ManualResetEventSlim Entered { get; } = new(false);
        internal ManualResetEventSlim Finished { get; } = new(false);
        internal int Runs => Volatile.Read(ref _runs);
        internal int ThreadId => Volatile.Read(ref _threadId);

        internal string? Calculate()
        {
            var run = Interlocked.Increment(ref _runs);
            if (run == 1) Volatile.Write(ref _threadId, Environment.CurrentManagedThreadId);
            Entered.Set();
            try
            {
                _release.Wait(HoldLimit);
                var outcome = _outcomes[Math.Min(run, _outcomes.Length) - 1];
                if (outcome is Exception error) throw error;
                return (string?)outcome;
            }
            finally
            {
                Finished.Set();
            }
        }

        internal void Release() => _release.Set();

        public void Dispose() => _release.Set();
    }
}
