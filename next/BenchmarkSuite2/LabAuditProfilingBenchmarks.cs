using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using Microsoft.Data.Sqlite;
using Microsoft.VSDiagnostics;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Measurements;
/// <summary>Offline, retained-output profiling of one explicitly identified lab capture; never contacts a directory.</summary>
[SimpleJob(RunStrategy.Monitoring, launchCount: 1, warmupCount: 0, iterationCount: 1, invocationCount: 1)]
[CPUUsageDiagnoser]
public class LabAuditProfilingBenchmarks
{
    private const string ArtifactRoot = @"C:\Users\jistrand\source\repos\razamus\SecureAD.Next\.vs\AuditLab-53015de18a534638b9bf9ea22504410c";
    private const string EvidenceHash = "1abe920124537ab380ba5a62a2a1d1c742c553fd7deffd6628f473f1fb53cccf";
    private const string DerivationHash = "69a29fd1b6e4b54dbf2ae791a6eb55e7e1c794ba4557168e8dbf92e63396f109";
    private const string DerivationFile = "derivation.c5079293b41047299b1736b45cbbc2f8.db";
    private static readonly Guid DerivationGeneration = Guid.Parse("c5079293-b410-4729-9b17-36b45cbbc2f8");
    private static readonly DateTimeOffset EvaluationTime = DateTimeOffset.Parse("2026-09-08T15:00:08.7355059+00:00", CultureInfo.InvariantCulture);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };
    private readonly Stopwatch clock = new();
    private readonly List<Boundary> boundaries = [];
    private string sessionDirectory = null!;
    private string bundleDirectory = null!;
    private StoredJudgement? stored;
    private string? previousPhase;
    private long objectsRead;
    private bool invoked;
    private bool succeeded;
    private sealed record Boundary(string Phase, double ElapsedMs, double ProcessCpuMs, long AllocatedBytes, int Gen0, int Gen1, int Gen2, long WorkingSetBytes, long PrivateBytes, long ProcessLifetimePeakWorkingSetBytes, long JudgementFileBytes, long WalBytes);
    [GlobalSetup]
    public void Setup()
    {
        Require(RuleCatalogue.All.Count == 17, "This fixture requires the recorded 17-rule catalogue.");
        sessionDirectory = Path.Combine(ArtifactRoot, "profiles", DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(sessionDirectory);
        Console.WriteLine("Offline lab profile; all outputs retained in " + sessionDirectory);
    }

    [IterationSetup]
    public void PrepareFreshCopy()
    {
        bundleDirectory = Path.Combine(sessionDirectory, "run-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(bundleDirectory);
        var source = Path.Combine(ArtifactRoot, "original-copy");
        foreach (var name in new[]
        {
            "evidence.db",
            "evidence.db.seal",
            DerivationFile,
            DerivationFile + ".seal",
            "derivation.current.json"
        }

        )
            File.Copy(Path.Combine(source, name), Path.Combine(bundleDirectory, name), overwrite: false);
        Require(!File.Exists(Path.Combine(source, DerivationFile + "-wal")) || new FileInfo(Path.Combine(source, DerivationFile + "-wal")).Length == 0, "Refusing an input with uncheckpointed derivation data.");
        VerifyInput();
        using (var evidence = OpenDatabase(Path.Combine(bundleDirectory, "evidence.db")))
        {
            Require(Scalar(evidence, "SELECT COUNT(*) FROM captured_object") == 8407, "Wrong captured-object count.");
            Require(Scalar(evidence, "SELECT COUNT(DISTINCT domain_fqdn) FROM captured_object") == 3, "Wrong domain count.");
        }

        invoked = succeeded = false;
        stored = null;
        objectsRead = 0;
        previousPhase = null;
        boundaries.Clear();
        clock.Reset();
    }

    [Benchmark]
    public JudgementRunState JudgeLabAndReadBack()
    {
        Require(!invoked, "Every invocation must receive a fresh output directory.");
        invoked = true;
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMinutes(15));
        var openedLog = RunLogFile.Open(bundleDirectory, "lab-offline-profile", TimeProvider.System);
        Require(openedLog.IsSuccess, "Could not open the measurement run log: " + openedLog.Error);
        using var log = openedLog.Value;
        clock.Start();
        try
        {
            Observe("Started");
            var result = JudgingRun.Judge(bundleDirectory, RuleCatalogue.All, (SelfMembershipDiscoveryBudget? )null, DateTimeOffset.UtcNow, EvaluationTime, new Watching(progress =>
            {
                objectsRead = Math.Max(objectsRead, progress.ObjectsRead);
                Observe(progress.Phase.ToString());
            }), log, cancellation.Token);
            Require(result.IsSuccess, "Judging failed: " + result.Error);
            Observe("ReadingResults");
            var opened = JudgementReader.Open(bundleDirectory);
            Require(opened.IsSuccess, "Published judgement could not be opened: " + opened.Error);
            using (var reader = opened.Value)
            {
                stored = reader.Read();
                var requesters = reader.ReadSelfMembershipSummary();
                Require(requesters is not null && requesters.AssessmentsStored == 0 && requesters.Discovery.PairsDiscovered == 0, "Requester work was unexpectedly activated.");
            }

            succeeded = true;
            return result.Value;
        }
        finally
        {
            Observe(succeeded ? "Finished" : "FailedOrCancelled");
            clock.Stop();
        }
    }

    [IterationCleanup]
    public void ValidateAndRetain()
    {
        WriteJson("phase-boundaries.json", boundaries);
        WriteJson("provenance.json", new { EvidenceHash, DerivationHash, EvaluationTime, ObjectsRead = objectsRead, Succeeded = succeeded, MemberAttributionBudget = (string? )null, RequesterDiscoveryBudget = (string? )null, DiagnosticCancellationMinutes = 15, Machine = Environment.MachineName, Runtime = RuntimeInformation.FrameworkDescription, OS = RuntimeInformation.OSDescription, Architecture = RuntimeInformation.ProcessArchitecture.ToString(), ProcessId = Environment.ProcessId, Environment.ProcessorCount, RuntimeEnvironment = Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>().Where(e => e.Key.ToString()!.StartsWith("DOTNET_", StringComparison.OrdinalIgnoreCase) || e.Key.ToString()!.StartsWith("COMPlus_", StringComparison.OrdinalIgnoreCase)).ToDictionary(e => e.Key.ToString()!, e => e.Value?.ToString()), Assemblies = AppDomain.CurrentDomain.GetAssemblies().Where(a => !a.IsDynamic && !string.IsNullOrEmpty(a.Location)).Where(a => a.GetName().Name!.StartsWith("SecureAD", StringComparison.Ordinal) || a.GetName().Name!.Contains("Sqlite", StringComparison.OrdinalIgnoreCase) || a.GetName().Name!.StartsWith("SQLitePCL", StringComparison.Ordinal) || a == typeof(LabAuditProfilingBenchmarks).Assembly).Select(a => new { Path = a.Location, SHA256 = Hash(a.Location), Version = a.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion, Configuration = a.GetCustomAttribute<AssemblyConfigurationAttribute>()?.Configuration }).ToArray(), NativeSqlite = Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(m => m.ModuleName.Contains("sqlite", StringComparison.OrdinalIgnoreCase)).Select(m => new { Path = m.FileName, SHA256 = Hash(m.FileName) }).ToArray(), BoundaryCaveat = "Cumulative allocation and CPU counters; memory and file sizes sampled only at phase boundaries. Process peak includes setup. Not peak WAL/temp measurements. Copy, hashing and validation are outside the benchmark; observer overhead is included." });
        Require(succeeded && stored is not null, "The invocation did not finish; diagnostic artifacts were retained.");
        VerifyInput();
        var judgement = stored!;
        Require(objectsRead == 8407 && judgement.RulesRun.Count == 17 && judgement.Findings.Count == 27, "Object, rule or finding count changed from the lab fixture.");
        Require(judgement.Description.State == JudgementRunState.CompletedDegraded && judgement.Description.EvaluationAsOf == EvaluationTime && judgement.Description.DerivationGenerationId == DerivationGeneration && string.Equals(judgement.Description.EvidenceSeal, EvidenceHash, StringComparison.OrdinalIgnoreCase), "Outcome, evaluation time or input generation differs.");
        var database = Directory.GetFiles(bundleDirectory, "judgement.*.db").Single();
        using var connection = OpenDatabase(database);
        var expected = new Dictionary<string, long>
        {
            ["control_object"] = 8407,
            ["control_edge"] = 144732,
            ["control_ace"] = 1327169,
            ["control_precondition"] = 558406,
            ["full_control_assessment"] = 23751,
            ["full_control_support"] = 72422,
            ["membership_route_step"] = 227382,
            ["member_attribution_root"] = 0,
            ["member_attribution_member"] = 0,
            ["member_attribution_permission"] = 0,
            ["self_membership_assessment"] = 0
        };
        foreach (var pair in expected)
            Require(Scalar(connection, "SELECT COUNT(*) FROM " + pair.Key) == pair.Value, "Stored count differs: " + pair.Key);
        Require(Scalar(connection, "SELECT COUNT(*) FROM member_attribution_product WHERE configuration IS NULL AND configuration_hash IS NULL AND root_count=0 AND permission_count=0") == 1, "Member attribution was unexpectedly configured.");
        Require(Scalar(connection, "SELECT COUNT(*) FROM self_membership_discovery WHERE json_type(coverage_json,'$.Budget')='null' AND json_extract(coverage_json,'$.Verdict')='NotStarted' AND json_extract(coverage_json,'$.ObjectsVisited')=0") == 1, "Requester discovery was unexpectedly configured.");
        Require(Scalar(connection, "SELECT COUNT(*) FROM pragma_foreign_key_check") == 0, "Dangling proof references.");
        Require(Scalar(connection, "SELECT COUNT(*) FROM control_edge e CROSS JOIN judgement j WHERE e.generation<>j.judgement_generation_id OR e.derivation_generation IS NOT j.derivation_generation_id") == 0, "Control proof generation binding differs.");
        Require(Scalar(connection, "SELECT COUNT(*) FROM rule_execution WHERE rule_id IN ('SEC-031','SEC-032') AND outcome='Indeterminate' AND objects_not_judged=4") == 2, "The recorded rule uncertainty was not retained.");
        WriteJson("validation.json", new { Passed = true, Scope = "Counts, configured activation, outcome, temporal/input binding, foreign keys and recorded rule uncertainty; not a full proof-equivalence comparison.", Judgement = judgement.Description, Counts = expected, Rules = judgement.RulesRun, JudgementSHA256 = Hash(database), JudgementBytes = new FileInfo(database).Length });
        Console.WriteLine("Verified offline lab invocation; retained output: " + bundleDirectory);
    }

    private void Observe(string phase)
    {
        if (previousPhase == phase)
            return;
        previousPhase = phase;
        using var process = Process.GetCurrentProcess();
        process.Refresh();
        var files = Directory.GetFiles(bundleDirectory, "judgement*").Select(p => new FileInfo(p)).ToArray();
        boundaries.Add(new(phase, clock.Elapsed.TotalMilliseconds, process.TotalProcessorTime.TotalMilliseconds, GC.GetTotalAllocatedBytes(precise: true), GC.CollectionCount(0), GC.CollectionCount(1), GC.CollectionCount(2), process.WorkingSet64, process.PrivateMemorySize64, process.PeakWorkingSet64, files.Sum(f => f.Length), files.Where(f => f.Name.EndsWith("-wal", StringComparison.Ordinal)).Sum(f => f.Length)));
    }

    private void VerifyInput()
    {
        Require(Hash(Path.Combine(bundleDirectory, "evidence.db")) == EvidenceHash, "Evidence fingerprint changed.");
        Require(Hash(Path.Combine(bundleDirectory, DerivationFile)) == DerivationHash, "Derivation fingerprint changed.");
    }

    private void WriteJson(string name, object value) => File.WriteAllText(Path.Combine(bundleDirectory, name), JsonSerializer.Serialize(value, JsonOptions));
    private static string Hash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static SqliteConnection OpenDatabase(string path)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        connection.Open();
        return connection;
    }

    private static long Scalar(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }

    private sealed class Watching(Action<JudgingRun.JudgingProgress> action) : IProgress<JudgingRun.JudgingProgress>
    {
        public void Report(JudgingRun.JudgingProgress value) => action(value);
    }
}