using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Engines;
using BenchmarkDotNet.Jobs;
using Microsoft.VSDiagnostics;
using SecureAD.Next.Tests.Measurements;

namespace SecureAD.Measurements;
public sealed class SavedPathOpeningConfiguration : ManualConfig
{
    public SavedPathOpeningConfiguration()
    {
        const string temporary = @"C:\Users\jistrand\source\repos\SecureAD.Next\next\artifacts\p246-ddb2a0ff3ba0473892ce08b417939184\isolated-temp";
        System.IO.Directory.CreateDirectory(temporary);
        AddJob(Job.Default.WithStrategy(RunStrategy.Monitoring).WithLaunchCount(1).WithWarmupCount(0)
            .WithIterationCount(1).WithInvocationCount(1).WithUnrollFactor(1)
            .WithEnvironmentVariable("TEMP", temporary).WithEnvironmentVariable("TMP", temporary)
            .WithId("IsolatedSavedOpening"));
    }
}

[Config(typeof(SavedPathOpeningConfiguration))]
[CPUUsageDiagnoser]
public class SavedPathOpeningBenchmarks
{
    private SavedPathOpeningMeasurement adapter = null!;
    [IterationSetup]
    public void Prepare()
    {
        adapter = new SavedPathOpeningMeasurement();
        adapter.Prepare();
    }

    [Benchmark]
    public double OpenSavedPath() => adapter.OpenSavedSection(navigateAway: false);
    [Benchmark]
    public double NavigateAwayDuringOpening() => adapter.OpenSavedSection(navigateAway: true);
    [IterationCleanup]
    public void RetainAndVerify() => adapter.Dispose();
}
