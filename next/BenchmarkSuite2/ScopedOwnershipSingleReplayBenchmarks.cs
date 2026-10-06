using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using Microsoft.Data.Sqlite;
using Microsoft.VSDiagnostics;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Measurements;
[SimpleJob(RunStrategy.Monitoring, launchCount: 1, warmupCount: 0, iterationCount: 1, invocationCount: 1)]
[CPUUsageDiagnoser]
public class ScopedOwnershipSingleReplayBenchmarks
{
    private const string Root = @"C:\Users\jistrand\source\repos\SecureAD.Next\next\artifacts\measurement-inputs\ScopedOwnershipSingleReplay-6f33d43a38f54f07aa6f86a3b9e84dcc";
    private const string Input = @"C:\Users\jistrand\source\repos\SecureAD.Next\next\artifacts\measurement-inputs\ScopedOwnershipAssessment-138558efc4054a9bb16d4bc1ef36c400\input-copy";
    private const string EvidenceHash = "A6F1F001F53ADD970B42D55A710F3FC3B083AC62C8E54AB1B140955E46EBB16C";
    private const string DerivationHash = "0C2FE5FE6BA7655EC2FFEDF059353524BC1271B22B13AF47BBF817C3CC15F31E";
    private const string DerivationFile = "derivation.c2d92b832e234a1ab6112cca9344cf9f.db";
    private static readonly Guid DerivationGeneration = Guid.Parse("c2d92b83-2e23-4a1a-b611-2cca9344cf9f");
    private static readonly DateTimeOffset EvaluationTime = DateTimeOffset.Parse("2026-09-09T05:08:22.3459193+00:00", CultureInfo.InvariantCulture);
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true
    };
    private readonly Stopwatch clock = new();
    private readonly object gate = new();
    private readonly List<Boundary> boundaries = [];
    private readonly List<DiskSample> disk = [];
    private string directory = null!;
    private string? phase;
    private long objects;
    private bool succeeded;
    private StoredJudgement? stored;
    private sealed record Boundary(string Phase, double ElapsedMs, double CpuMs, long AllocatedBytes, int Gen0, int Gen1, int Gen2, long WorkingSetBytes, long PrivateBytes);
    private sealed record DiskSample(double ElapsedMs, string? Phase, long DatabaseBytes, long WalBytes, long OtherJudgementBytes);
    [GlobalSetup]
    public void Prepare()
    {
        Require(Hash(Path.Combine(Input, "evidence.db")) == EvidenceHash, "Wrong Evidence input.");
        Require(Hash(Path.Combine(Input, DerivationFile)) == DerivationHash, "Wrong Derivation input.");
        Require(!File.Exists(Path.Combine(Input, DerivationFile + "-wal")) || new FileInfo(Path.Combine(Input, DerivationFile + "-wal")).Length == 0, "Input WAL is not empty.");
        Require(RuleCatalogue.All.Count == 17, "Rule catalogue differs.");
        directory = Path.Combine(Root, "run-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        foreach (var name in new[]
        {
            "evidence.db",
            "evidence.db.seal",
            DerivationFile,
            DerivationFile + ".seal",
            "derivation.current.json"
        }

        )
            File.Copy(Path.Combine(Input, name), Path.Combine(directory, name), false);
        using var evidence = Open(Path.Combine(directory, "evidence.db"));
        Require(Scalar(evidence, "SELECT COUNT(*) FROM captured_object") == 8407, "Wrong object count.");
        Require(Scalar(evidence, "SELECT COUNT(DISTINCT domain_fqdn) FROM captured_object") == 3, "Wrong domain count.");
        Save("setup.json", new { Input, EvidenceHash, DerivationHash, EvaluationTime, directory, Runtime = RuntimeInformation.FrameworkDescription, Machine = Environment.MachineName, OS = RuntimeInformation.OSDescription, Architecture = RuntimeInformation.ProcessArchitecture.ToString(), ProcessId = Environment.ProcessId, Environment.ProcessorCount, SourceManifest = Path.Combine(Root, "production-source-before.csv"), LabExecutableMatchesLocalBuild = (bool? )null });
        Console.WriteLine("Single offline execution; retained output: " + directory);
    }

    [Benchmark]
    public JudgementRunState JudgeSeptember9Once()
    {
        // A durable claim prevents a diagnoser or later invocation from silently repeating judging.
        using (var claim = new FileStream(Path.Combine(Root, "judging-execution.claim"), FileMode.CreateNew, FileAccess.Write, FileShare.Read))
        using (var text = new StreamWriter(claim))
            text.WriteLine(directory);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMinutes(15));
        var openedLog = RunLogFile.Open(directory, "single-scoped-ownership-profile", TimeProvider.System);
        Require(openedLog.IsSuccess, "Cannot open run log.");
        using var log = openedLog.Value;
        clock.Start();
        using var sampler = new Timer(_ => SampleDisk(), null, TimeSpan.Zero, TimeSpan.FromMilliseconds(100));
        try
        {
            Observe("Started");
            var result = JudgingRun.Judge(directory, RuleCatalogue.All, (SelfMembershipDiscoveryBudget? )null, DateTimeOffset.UtcNow, EvaluationTime, new Watching(value =>
            {
                objects = Math.Max(objects, value.ObjectsRead);
                Observe(value.Phase.ToString());
            }), log, cancellation.Token);
            Require(result.IsSuccess, "Judging failed: " + result.Error);
            Observe("ReadingResults");
            var opened = JudgementReader.Open(directory);
            Require(opened.IsSuccess, "Published result could not be opened: " + opened.Error);
            using (var reader = opened.Value)
            {
                stored = reader.Read();
                var requesters = reader.ReadSelfMembershipSummary();
                Require(requesters is not null && requesters.AssessmentsStored == 0 && requesters.Discovery.PairsDiscovered == 0, "Requester activation changed.");
            }

            succeeded = true;
            return result.Value;
        }
        finally
        {
            using var stopped = new ManualResetEvent(false);
            sampler.Dispose(stopped);
            stopped.WaitOne();
            Observe(succeeded ? "Finished" : "FailedOrCancelled");
            clock.Stop();
            Save("phase-boundaries.json", boundaries);
            Save("disk-samples.json", disk);
            Save("execution.json", new { Succeeded = succeeded, ObjectsRead = objects, ElapsedMs = clock.Elapsed.TotalMilliseconds, MaximumObservedDatabaseBytes = disk.Max(s => s.DatabaseBytes), MaximumObservedWalBytes = disk.Max(s => s.WalBytes), MaximumObservedCombinedBytes = disk.Max(s => s.DatabaseBytes + s.WalBytes + s.OtherJudgementBytes), Caveat = "One profiled execution, no warmups or averaging. Observer/profiler overhead included. Disk samples every 100ms and at phase boundaries are observed lower bounds, not guaranteed peaks; external temp files and filesystem compression/allocation are not measured. No claim of matching the lab executable or of production acceptance." });
        }
    }

    [GlobalCleanup]
    public void ValidateAndRetain()
    {
        if (directory is null)
            return;
        Save("assemblies.json", AppDomain.CurrentDomain.GetAssemblies().Where(a => !a.IsDynamic && !string.IsNullOrEmpty(a.Location)).Where(a => a.GetName().Name!.StartsWith("SecureAD", StringComparison.Ordinal) || a.GetName().Name!.Contains("Sqlite", StringComparison.OrdinalIgnoreCase) || a.GetName().Name!.StartsWith("SQLitePCL", StringComparison.Ordinal) || a == GetType().Assembly).Select(a => new { Path = a.Location, SHA256 = Hash(a.Location), Version = a.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion, Configuration = a.GetCustomAttribute<AssemblyConfigurationAttribute>()?.Configuration }).ToArray());
        Require(succeeded && stored is not null, "No successful judging invocation; outputs retained, do not retry automatically.");
        Require(Hash(Path.Combine(directory, "evidence.db")) == EvidenceHash && Hash(Path.Combine(directory, DerivationFile)) == DerivationHash, "Input changed.");
        Require(objects == 8407 && stored!.RulesRun.Count == 17 && stored.Findings.Count == 27, "Object/rule/finding count differs.");
        Require(stored.Description.EvaluationAsOf == EvaluationTime && stored.Description.DerivationGenerationId == DerivationGeneration && stored.Description.State == JudgementRunState.CompletedDegraded && string.Equals(stored.Description.EvidenceSeal, EvidenceHash, StringComparison.OrdinalIgnoreCase), "Input/time/outcome binding differs.");
        var database = Directory.GetFiles(directory, "judgement.*.db").Single();
        using var connection = Open(database);
        var expected = new Dictionary<string, long>
        {
            ["control_object"] = 8407,
            ["control_edge"] = 112303,
            ["control_ace"] = 342812,
            ["control_precondition"] = 71971,
            ["permission_entry"] = 208960,
            ["full_control_assessment"] = 23751,
            ["full_control_support"] = 72422,
            ["full_control_source_entry"] = 208900,
            ["membership_route_step"] = 174764,
            ["ownership_target"] = 8407,
            ["ownership_seed"] = 50,
            ["ownership_relation"] = 840,
            ["member_attribution_root"] = 0,
            ["member_attribution_member"] = 0,
            ["member_attribution_permission"] = 0,
            ["self_membership_assessment"] = 0
        };
        foreach (var pair in expected)
            Require(Scalar(connection, "SELECT COUNT(*) FROM " + pair.Key) == pair.Value, "Stored count differs: " + pair.Key);
        Require(Scalar(connection, "SELECT schema_version FROM judgement") == 26 && Scalar(connection, "SELECT engine_version FROM control_product") == 9, "Schema/engine differs.");
        Require(Scalar(connection, "SELECT COUNT(*) FROM ownership_target WHERE selection='Included' AND execution='CompletedWithLimitations'") == 51, "Selected assessment count differs.");
        Require(Scalar(connection, "SELECT COUNT(*) FROM control_edge WHERE capability='CanBecomeOwnerAndRewriteDacl' AND evaluation='Unknown' AND counted=0") == 210, "Owner transition limitation differs.");
        Require(Scalar(connection, "SELECT COUNT(*) FROM ownership_audit WHERE completed=1 AND json_extract(header,'$.Coverage.ProcessingComplete')=1 AND json_extract(header,'$.Coverage.IsComplete')=0") == 1, "Incomplete scope disclosure differs.");
        Require(Scalar(connection, "SELECT COUNT(*) FROM member_attribution_product WHERE configuration IS NULL AND configuration_hash IS NULL AND root_count=0 AND permission_count=0") == 1, "Member attribution activated.");
        Require(Scalar(connection, "SELECT COUNT(*) FROM self_membership_discovery WHERE json_type(coverage_json,'$.Budget')='null' AND json_extract(coverage_json,'$.Verdict')='NotStarted' AND json_extract(coverage_json,'$.ObjectsVisited')=0") == 1, "Requester discovery activated.");
        Require(Scalar(connection, "SELECT COUNT(*) FROM pragma_foreign_key_check") == 0, "Dangling proof reference.");
        Require(Scalar(connection, "SELECT COUNT(*) FROM control_edge e CROSS JOIN judgement j WHERE e.generation<>j.judgement_generation_id OR e.derivation_generation IS NOT j.derivation_generation_id") == 0, "Generation mismatch.");
        Require(Scalar(connection, "SELECT COUNT(*) FROM rule_execution WHERE rule_id IN ('SEC-031','SEC-032') AND outcome='Indeterminate' AND objects_not_judged=4") == 2, "Rule uncertainty differs.");
        Save("validation.json", new { Passed = true, expected, stored.Description, DatabaseBytes = new FileInfo(database).Length, DatabaseSHA256 = Hash(database), Scope = "Counts, bindings, activation and limitations; not exhaustive permission equivalence." });
    }

    private void Observe(string next)
    {
        lock (gate)
        {
            if (phase == next)
                return;
            phase = next;
            using var process = Process.GetCurrentProcess();
            boundaries.Add(new(next, clock.Elapsed.TotalMilliseconds, process.TotalProcessorTime.TotalMilliseconds, GC.GetTotalAllocatedBytes(false), GC.CollectionCount(0), GC.CollectionCount(1), GC.CollectionCount(2), process.WorkingSet64, process.PrivateMemorySize64));
            SampleDisk();
        }
    }

    private void SampleDisk()
    {
        lock (gate)
        {
            long db = 0, wal = 0, other = 0;
            foreach (var path in Directory.EnumerateFiles(directory, "judgement*"))
            {
                try
                {
                    var length = new FileInfo(path).Length;
                    if (path.EndsWith("-wal", StringComparison.Ordinal))
                        wal += length;
                    else if (path.EndsWith(".db", StringComparison.Ordinal))
                        db += length;
                    else
                        other += length;
                }
                catch (FileNotFoundException)
                {
                }
            }

            disk.Add(new(clock.Elapsed.TotalMilliseconds, phase, db, wal, other));
        }
    }

    private void Save(string name, object value) => File.WriteAllText(Path.Combine(directory, name), JsonSerializer.Serialize(value, Json));
    private static SqliteConnection Open(string path)
    {
        var connection = new SqliteConnection("Data Source=" + path + ";Mode=ReadOnly;Pooling=False");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA query_only=ON";
        command.ExecuteNonQuery();
        return connection;
    }

    private static long Scalar(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private static string Hash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }

    private sealed class Watching(Action<JudgingRun.JudgingProgress> observe) : IProgress<JudgingRun.JudgingProgress>
    {
        public void Report(JudgingRun.JudgingProgress value) => observe(value);
    }
}
