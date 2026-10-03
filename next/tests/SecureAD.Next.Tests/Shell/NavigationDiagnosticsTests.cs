using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using SecureAD.Evidence;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class NavigationDiagnosticsTests
{
    [Fact]
    public void SubsequentNavigationDoesNotReadTheExecutableAgain()
    {
        var directory = TempDirectories.Create("navigation-fingerprint");
        using var reads = new ExecutableReads();
        using (var warmup = NavigationDiagnostics.Begin(directory, "first navigation"))
            warmup.Complete("success", null);
        var before = reads.Count;

        for (var index = 0; index < 3; index++)
        {
            using var navigation = NavigationDiagnostics.Begin(directory, "subsequent navigation");
            navigation.Complete("success", null);
        }

        var log = File.ReadAllText(BundleLayout.RunLogPath(directory));
        Assert.True(reads.InstrumentObserved);
        Assert.Equal(before, reads.Count);
        Assert.Equal(4, Regex.Matches(log, "processSha256=" + ActualFingerprint()).Count);
    }

    [Fact]
    public async Task SharedExecutableIdentityDoesNotShareRunGenerationOrOutcome()
    {
        var first = TempDirectories.Create("navigation-first-run");
        var second = TempDirectories.Create("navigation-second-run");
        var firstGeneration = Guid.NewGuid().ToString("D");
        var secondGeneration = Guid.NewGuid().ToString("D");
        await Task.WhenAll(
            Task.Run(() => Record(first, firstGeneration, "success")),
            Task.Run(() => Record(second, secondGeneration, "refused")));

        var fingerprint = ActualFingerprint();
        AssertBound(first, firstGeneration, secondGeneration, "success", fingerprint);
        AssertBound(second, secondGeneration, firstGeneration, "refused", fingerprint);
    }

    private static void Record(string directory, string generation, string outcome)
    {
        using var navigation = NavigationDiagnostics.Begin(directory, "read selected result");
        NavigationDiagnostics.Identity("judgementGeneration", generation);
        navigation.Complete(outcome, null);
    }

    private static void AssertBound(string directory, string generation, string otherGeneration,
        string outcome, string fingerprint)
    {
        var log = File.ReadAllText(BundleLayout.RunLogPath(directory));
        Assert.Contains(directory, log, StringComparison.Ordinal);
        Assert.Contains("processSha256=" + fingerprint, log, StringComparison.Ordinal);
        Assert.Contains("judgementGeneration=" + generation, log, StringComparison.Ordinal);
        Assert.DoesNotContain(otherGeneration, log, StringComparison.Ordinal);
        Assert.Contains("outcome=" + outcome, log, StringComparison.Ordinal);
    }

    private static string ActualFingerprint()
    {
        var path = Environment.ProcessPath ?? throw new InvalidOperationException("The test process has no executable path.");
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private sealed class ExecutableReads : IDisposable
    {
        private readonly MeterListener _listener = new();
        private long _count;
        private int _instrumentObserved;

        internal ExecutableReads()
        {
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name != "SecureAD.Shell.Navigation"
                    || instrument.Name != "navigation.executable_hash_reads") return;
                Interlocked.Exchange(ref _instrumentObserved, 1);
                listener.EnableMeasurementEvents(instrument);
            };
            _listener.SetMeasurementEventCallback<long>((_, value, _, _) => Interlocked.Add(ref _count, value));
            _listener.Start();
        }

        internal long Count => Interlocked.Read(ref _count);
        internal bool InstrumentObserved => Volatile.Read(ref _instrumentObserved) != 0;
        public void Dispose() => _listener.Dispose();
    }

    [Fact]
    public void NavigationLogCarriesActionBuildWorkIdentityAndAppliedOutcome()
    {
        var directory = Path.Combine(Path.GetTempPath(), "securead-navigation-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            using (var navigation = NavigationDiagnostics.Begin(directory, "read selected object"))
            {
                NavigationDiagnostics.Identity("judgementGeneration", Guid.Empty.ToString("D"));
                NavigationDiagnostics.Mark("query", TimeSpan.FromMilliseconds(12));
                navigation.Complete("success", null);
            }

            var log = File.ReadAllText(BundleLayout.RunLogPath(directory));
            Assert.Contains("action=\"read selected object\"", log, StringComparison.Ordinal);
            Assert.Contains("processSha256=", log, StringComparison.Ordinal);
            Assert.Contains("shellMvid=", log, StringComparison.Ordinal);
            Assert.Contains("work=query", log, StringComparison.Ordinal);
            Assert.Contains("judgementGeneration=00000000-0000-0000-0000-000000000000", log, StringComparison.Ordinal);
            Assert.Contains("outcome=success", log, StringComparison.Ordinal);
            Assert.Contains("appliedMs=", log, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
