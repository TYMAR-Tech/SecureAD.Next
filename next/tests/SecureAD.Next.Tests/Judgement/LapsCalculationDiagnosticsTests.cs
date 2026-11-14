using System.Diagnostics.Metrics;
using System.Text.Json;
using SecureAD.Derivation;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Measure;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

[Collection("GPO preparation diagnostics")]
public sealed class LapsCalculationDiagnosticsTests
{
    [Fact]
    public void RealCalculationsMeasureAllFiveCostsAndOriginalWorkWithoutChangingAnswers()
    {
        var directory = TempDirectories.Create("laps-calculation-work");
        ConfiguredLapsWorkload.Write(directory, new(9, 12, 3, 0)
        {
            Profile = ConfiguredLapsWorkloadProfile.MixedLegacyWindows,
        }, CancellationToken.None);
        Assert.True(Stage2aRun.Derive(directory, ExpansionBudget.Bulk, ConfiguredLapsWorkload.When,
            Stage2aRun.Unwatched, RunLog.Discarded, CancellationToken.None).IsSuccess);
        using var reader = LapsConfiguredPolicyReader.Open(directory, CancellationToken.None).Value;
        var computers = reader.Bundle.StreamComputerIdentities(CancellationToken.None).ToArray();
        Assert.Equal(9, computers.Length);
        var expected = computers.Select(computer => JsonSerializer.Serialize(
            reader.Read(computer, CancellationToken.None).Value)).ToArray();
        using var stopping = new CancellationTokenSource();
        using var observer = new EnterpriseBaselineObservation(TempDirectories.Create("laps-work-observation"),
            8L * 1024 * 1024 * 1024, stopping, directory);
        var actual = observer.Measure("Judgement", () => computers.Select(computer =>
            JsonSerializer.Serialize(reader.Read(computer, CancellationToken.None).Value)).ToArray());
        observer.Dispose();
        Assert.Equal(expected, actual);
        Assert.Equal(9, observer.CalculationTimings["calculation"].Samples);
        Assert.Equal(9, observer.CalculationTimings["hierarchy"].Samples);
        Assert.Equal(63, observer.CalculationTimings["permission"].Samples);
        Assert.Equal(63, observer.CalculationTimings["captured-os"].Samples);
        Assert.Equal(9, observer.CalculationTimings["membership-preparation"].Samples);
        Assert.Equal(9, observer.CalculationTimings["membership-graph"].Samples);
        Assert.Equal(36, observer.CalculationTimings["membership-identity"].Samples);
        Assert.Equal(27, observer.CalculationTimings["membership-witness"].Samples);
        Assert.Equal(9, observer.CalculationTimings["settings-calculation"].Samples);
        var work = observer.CalculationWork;
        Assert.Equal(9, work["computers-calculated"]);
        Assert.Equal(18, work["hierarchy-containers"]);
        Assert.Equal(63, work["hierarchy-link-occurrences"]);
        Assert.Equal(126, work["permission-entries-read"]);
        Assert.Equal(189, work["permission-right-evaluations"]);
        Assert.Equal(45, work["membership-graph-nodes"]);
        Assert.Equal(36, work["membership-graph-links"]);
        Assert.Equal(36, work["membership-identity-resolutions"]);
        Assert.Equal(27, work["membership-witness-reads"]);
        Assert.Equal(63, work["os-queries-assessed"]);
        Assert.Equal(99, work["registry-instructions-copied"]);
        Assert.Equal(63, work["ordered-links-visited"]);
        Assert.Equal(36, work["registry-setting-instructions-applied"]);
        Assert.Equal(36, work["conditional-branches-created"]);
        var selections = observer.CalculationTimings.Where(pair =>
            pair.Key.StartsWith("current-selection/", StringComparison.Ordinal)).ToArray();
        Assert.Empty(selections);
        Assert.False(observer.CalculationTimings.ContainsKey("capture-selection"));
        Assert.False(observer.CalculationTimings.ContainsKey("derivation-selection"));
        Assert.Empty(observer.SelectionManifestReads);
        var breakdown = ConfiguredLapsMeasurement.BreakDownCalculation(observer.CalculationTimings);
        Assert.Equal("Observed", breakdown.State);
        Assert.Empty(breakdown.MissingOperations);
        Assert.Equal(breakdown.CalculationMilliseconds!.Value, breakdown.ExclusiveMilliseconds!.Values.Sum(), 6);
        Assert.All(breakdown.ExclusiveMilliseconds.Values, value => Assert.True(value >= 0));
        Assert.True(observer.CalculationCollectorMilliseconds > 0);
        Assert.True(observer.CalculationCollectorEvents > observer.CalculationTimings.Values.Sum(value => value.Samples));
    }

    [Fact]
    public void CurrentSelectionAttributionRestoresEnclosingAreaAndIgnoresWorkOutsideCalculation()
    {
        var directory = TempDirectories.Create("laps-selection-area");
        using var stopping = new CancellationTokenSource();
        using var observer = new EnterpriseBaselineObservation(TempDirectories.Create("laps-selection-observation"),
            8L * 1024 * 1024 * 1024, stopping, directory);
        LapsCalculationDiagnostics.RecordCurrentSelection(1000);
        using (LapsCalculationDiagnostics.Begin(directory))
        {
            using (LapsCalculationDiagnostics.Measure("permission"))
            {
                LapsCalculationDiagnostics.RecordCurrentSelection(2);
                void Interrupt()
                {
                    using var membership = LapsCalculationDiagnostics.Measure("membership");
                    LapsCalculationDiagnostics.RecordCurrentSelection(4);
                    throw new InvalidOperationException("Deliberately interrupted diagnostic area.");
                }
                Assert.Throws<InvalidOperationException>(Interrupt);
                LapsCalculationDiagnostics.RecordCurrentSelection(3);
            }
            LapsCalculationDiagnostics.RecordCurrentSelection(7);
        }
        LapsCalculationDiagnostics.RecordCurrentSelection(1000);
        observer.Dispose();
        var timings = observer.CalculationTimings;
        Assert.True(timings.ContainsKey("current-selection/permission"));
        Assert.True(timings.ContainsKey("current-selection/membership"));
        Assert.True(timings.ContainsKey("current-selection/calculation"));
        Assert.Equal(new EnterpriseWorkTiming(2, 5), timings["current-selection/permission"]);
        Assert.Equal(new EnterpriseWorkTiming(1, 4), timings["current-selection/membership"]);
        Assert.Equal(new EnterpriseWorkTiming(1, 7), timings["current-selection/calculation"]);
    }

    [Fact]
    public void CollectorKeepsExactSourceAndRestoresContextAfterNestedFailure()
    {
        var selected = TempDirectories.Create("laps-selected-source");
        var other = TempDirectories.Create("laps-other-source");
        using var stopping = new CancellationTokenSource();
        using var observer = new EnterpriseBaselineObservation(TempDirectories.Create("laps-context-observation"),
            8L * 1024 * 1024 * 1024, stopping, selected);
        using (LapsCalculationDiagnostics.Begin(selected))
        {
            LapsCalculationDiagnostics.Count("witness", 2);
            void Interrupt()
            {
                using var foreign = LapsCalculationDiagnostics.Begin(other);
                using var work = LapsCalculationDiagnostics.Measure("foreign-work");
                LapsCalculationDiagnostics.Count("witness", 100);
                throw new InvalidOperationException("Deliberately interrupted diagnostic scope.");
            }
            Assert.Throws<InvalidOperationException>(Interrupt);
            using var restored = LapsCalculationDiagnostics.Measure("restored-work");
            LapsCalculationDiagnostics.Count("witness", 3);
        }
        LapsCalculationDiagnostics.Count("witness", 1000);
        using (LapsCalculationDiagnostics.Measure("outside-work")) { }
        observer.Dispose();
        Assert.Equal(5, observer.CalculationWork["witness"]);
        Assert.Equal(1, observer.CalculationTimings["calculation"].Samples);
        Assert.True(observer.CalculationTimings.ContainsKey("restored-work"));
        Assert.False(observer.CalculationTimings.ContainsKey("foreign-work"));
        Assert.False(observer.CalculationTimings.ContainsKey("outside-work"));
    }

    [Fact]
    public void TimingOnlyObserverDoesNotEnableCalculationInstrumentation()
    {
        var directory = TempDirectories.Create("laps-timing-only");
        var instruments = new List<Instrument>();
        using var published = new MeterListener();
        published.InstrumentPublished = (instrument, _) =>
        {
            if (instrument.Meter.Name == "SecureAD.Judgement.LapsCalculation") instruments.Add(instrument);
        };
        published.Start();
        using var stopping = new CancellationTokenSource();
        using var observer = new EnterpriseBaselineObservation(TempDirectories.Create("laps-timing-observation"),
            8L * 1024 * 1024 * 1024, stopping);
        using (LapsCalculationDiagnostics.Begin(directory))
        {
            using var work = LapsCalculationDiagnostics.Measure("permission");
            LapsCalculationDiagnostics.Count("permission-entries-read", 2);
        }
        Assert.Equal(new[] { "laps.work", "laps.work_ms" }, instruments.Select(instrument => instrument.Name).Order());
        Assert.All(instruments, instrument => Assert.False(instrument.Enabled));
        observer.Dispose();
        Assert.Empty(observer.CalculationTimings);
        Assert.Empty(observer.CalculationWork);
        Assert.Equal(0, observer.CalculationCollectorEvents);
        Assert.Equal(0, observer.CalculationCollectorMilliseconds);
    }

    [Fact]
    public void ExclusiveBreakdownSubtractsMembershipOnceAndPreservesUnattributedWork()
    {
        var times = Timings();
        times.Add("membership-preparation", new(1, 26));
        times.Add("membership-graph", new(1, 10));
        times.Add("membership-identity", new(1, 12));
        times.Add("membership-witness", new(1, 3));
        var breakdown = ConfiguredLapsMeasurement.BreakDownCalculation(times);
        Assert.Equal("Observed", breakdown.State);
        Assert.Equal(100, breakdown.CalculationMilliseconds);
        var exclusive = breakdown.ExclusiveMilliseconds!;
        Assert.Equal(8, exclusive.Count);
        Assert.Equal(15, exclusive["permission-excluding-membership"]);
        Assert.Equal(30, exclusive["membership"]);
        Assert.Equal(21, exclusive["other-calculation"]);
        Assert.Equal(100, exclusive.Values.Sum());
        Assert.DoesNotContain("membership-preparation", exclusive.Keys);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MissingTimingsAreExplicitlyUnobservedNotZero(bool partial)
    {
        var timings = new Dictionary<string, EnterpriseWorkTiming>();
        if (partial) timings.Add("calculation", new(1, 100));
        var result = ConfiguredLapsMeasurement.BreakDownCalculation(timings);
        Assert.Equal(partial ? "IncompleteTimingCoverage" : "Unobserved", result.State);
        Assert.Contains("membership", result.MissingOperations);
        Assert.Null(result.ExclusiveMilliseconds);
        Assert.Equal(partial ? 100d : (double?)null, result.CalculationMilliseconds);
    }

    [Theory]
    [InlineData("calculation", 90)]
    [InlineData("applicability", 70)]
    [InlineData("policy-assessment", 40)]
    [InlineData("permission", 20)]
    public void ImpossibleNestedTimingCannotBecomeASuccessfulBreakdown(string parent, double milliseconds)
    {
        var timings = Timings();
        timings[parent] = new(1, milliseconds);
        Assert.Throws<InvalidDataException>(() => ConfiguredLapsMeasurement.BreakDownCalculation(timings));
    }

    private static Dictionary<string, EnterpriseWorkTiming> Timings() => new(StringComparer.Ordinal)
    {
        ["calculation"] = new(1, 100),
        ["applicability"] = new(1, 80),
        ["hierarchy"] = new(1, 15),
        ["policy-assessment"] = new(1, 60),
        ["permission"] = new(1, 45),
        ["membership"] = new(1, 30),
        ["captured-os"] = new(1, 5),
        ["registry-preparation"] = new(1, 5),
        ["settings-calculation"] = new(1, 7),
        ["final-input-check"] = new(1, 2),
    };
}
