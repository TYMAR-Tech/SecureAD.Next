using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Engines;
using Microsoft.Data.Sqlite;
using Microsoft.VSDiagnostics;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;

namespace SecureAD.Measurements;
internal static class DescriptorBaselineIsolation
{
    internal const string Root = @"C:\Users\jistrand\source\repos\SecureAD.Next\next\artifacts\descriptor-first-baseline-20261001-54ee5c13";
    internal static readonly string Temporary = Path.Combine(Root, "temporary", Environment.ProcessId + "-" + Guid.NewGuid().ToString("N"));
    // Isolation must precede benchmark discovery or any assembly initialization, not just GlobalSetup.
    [ModuleInitializer]
    internal static void Initialize()
    {
        Directory.CreateDirectory(Temporary);
        Environment.SetEnvironmentVariable("TEMP", Temporary);
        Environment.SetEnvironmentVariable("TMP", Temporary);
    }
}

public sealed class DescriptorBaselineConfig : ManualConfig
{
    public DescriptorBaselineConfig()
    {
        this.WithArtifactsPath(Path.Combine(DescriptorBaselineIsolation.Root, "benchmarkdotnet", DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N")));
        this.WithOptions(ConfigOptions.KeepBenchmarkFiles);
    }
}

[Config(typeof(DescriptorBaselineConfig))]
[SimpleJob(RunStrategy.Monitoring, launchCount: 1, warmupCount: 0, iterationCount: 1, invocationCount: 1)]
[CPUUsageDiagnoser]
public class DescriptorPreparationBenchmarks
{
    private const string LabSource = @"C:\Users\jistrand\source\repos\SecureAD.Next\next\artifacts\q290-f68804df\after";
    private const string LabEvidenceHash = "7E859ACADD5A709FF898A699D9790D2BDCA3BAC631298C97879F726467F53E08";
    private const string LabDerivationHash = "FD1BFAD3802D91A87F56BE34C34F9EF2DBDDAEC4C298F6EDA268CD1B4C806C5D";
    private const string LabDerivationFile = "derivation.342f3ae8c58e48e28d24d09ab906f3ac.db";
    private const int Domains = 9;
    private const int UsersPerDomain = 64;
    private const int EntriesPerDescriptor = 512;
    private const int MaximumInvocations = 4;
    private static readonly DateTimeOffset When = new(2026, 9, 28, 0, 0, 0, TimeSpan.Zero);
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true
    };
    private readonly Queue<string> copies = new();
    private readonly List<Invocation> invocations = [];
    private Input input = null!;
    private string session = null!;
    private string phase = null!;
    private int invocationCount;
    [Params("Shared", "Distinct", "Lab")]
    public string Workload { get; set; } = null!;

    private sealed record Shape(long Objects, long Domains, long DescriptorLinks, long Descriptors, long CanonicalDescriptorEntries);
    private sealed record Input(string Directory, string EvidenceHash, string DerivationFile, string DerivationHash, Guid DerivationGeneration, Shape Shape);
    private sealed record Sample(double ElapsedMs, string Phase, double ProcessCpuMs, long AllocatedBytes, int Gen0, int Gen1, int Gen2, long WorkingSetBytes, long PrivateBytes, long ProcessLifetimePeakBytes, long JudgementBytes, long WalBytes, long? TemporaryBytes);
    private sealed class Invocation
    {
        internal readonly object Gate = new();
        public required string Directory { get; init; }
        public bool Succeeded { get; set; }
        public string? Error { get; set; }
        public double JudgingMs { get; set; }
        public double ReopeningMs { get; set; }
        public long ObjectsReported { get; set; }
        public string Phase { get; set; } = "Started";
        public Guid? Generation { get; set; }
        public string? State { get; set; }
        public List<Sample> Samples { get; } = [];
    }

    [GlobalSetup]
    public void Prepare()
    {
        Require(Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar).Equals(DescriptorBaselineIsolation.Temporary, StringComparison.OrdinalIgnoreCase), "TEMP was not isolated before benchmark setup.");
        Require(!AppDomain.CurrentDomain.GetAssemblies().Any(a => a.GetName().Name == "SecureAD.Next.Tests"), "The isolated runner must not load the test assembly.");
        Require(RuleCatalogue.All.Count == 17, "The approved rule catalogue changed.");
        Require(Workload is "Shared" or "Distinct" or "Lab", "Unknown workload.");
        phase = File.ReadAllText(Path.Combine(DescriptorBaselineIsolation.Root, "phase.txt")).Trim();
        Require(phase is "before" or "after", "Only the approved before/after phases are supported.");
        session = Path.Combine(DescriptorBaselineIsolation.Root, phase, Workload, Environment.ProcessId + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(session);
        Console.WriteLine("Retained descriptor baseline: " + session);
        var setup = Stopwatch.StartNew();
        input = PrepareInput();
        VerifyInput(input);
        Refuses(() => CheckHash(Path.Combine(input.Directory, "evidence.db"), new string ('0', 64)));
        if (Workload != "Lab")
        {
            var expectedObjects = Domains * (UsersPerDomain + 1);
            var expectedDescriptors = Workload == "Shared" ? 1 : expectedObjects;
            CheckShape(input.Shape, expectedObjects, expectedDescriptors);
            Refuses(() => CheckShape(input.Shape, expectedObjects + 1, expectedDescriptors));
            Refuses(() => CheckShape(input.Shape, expectedObjects, expectedDescriptors + 1));
        }

        // Diagnostic/GC passes may invoke the body again. Each receives its own retained copy, with a hard bound.
        for (var i = 0; i < MaximumInvocations; i++)
        {
            var directory = Path.Combine(session, "invocation-" + (i + 1).ToString(CultureInfo.InvariantCulture));
            CopyInput(input.Directory, directory, input.DerivationFile);
            CheckHash(Path.Combine(directory, "evidence.db"), input.EvidenceHash);
            CheckHash(Path.Combine(directory, input.DerivationFile), input.DerivationHash);
            copies.Enqueue(directory);
        }

        setup.Stop();
        Save(Path.Combine(session, "setup.json"), new { Workload, phase, Input = input, EvaluationTime = When, SetupMs = setup.Elapsed.TotalMilliseconds, PreparedCopies = MaximumInvocations, DiagnosticCancellationMinutes = 5, RequesterPolicy = PathRequesterPolicy.Disabled.ToString(), SelfMembershipDiscoveryBudget = (string? )null, Scope = "Small synthetic sharing extremes and a saved lab capture; not representative production-scale evidence or a production budget.", ShapeCaveat = "CanonicalDescriptorEntries are evidence-side canonical positions, not raw object-weighted permission occurrences.", FixtureNegativeControlsPassed = true });
        SaveProvenance("provenance-before.json");
    }

    [Benchmark]
    public JudgementRunState JudgeAuditAndReopen()
    {
        Require(++invocationCount <= MaximumInvocations && copies.Count > 0, "Diagnostic invocation limit reached; retain this attempt and stop.");
        var run = new Invocation
        {
            Directory = copies.Dequeue()
        };
        invocations.Add(run);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        var openedLog = RunLogFile.Open(run.Directory, "descriptor-baseline", TimeProvider.System);
        Require(openedLog.IsSuccess, "Cannot open retained run log: " + openedLog.Error);
        using var log = openedLog.Value;
        var clock = Stopwatch.StartNew();
        Capture(run, clock);
        using var sampler = new Timer(_ => Capture(run, clock), null, TimeSpan.FromMilliseconds(250), TimeSpan.FromMilliseconds(250));
        var judging = Stopwatch.StartNew();
        try
        {
            var result = JudgingRun.JudgeAudit(run.Directory, RuleCatalogue.All, PathRequesterPolicy.Disabled, When, When, new Watching(value =>
            {
                lock (run.Gate)
                {
                    run.ObjectsReported = Math.Max(run.ObjectsReported, value.ObjectsRead);
                    var next = value.Phase.ToString();
                    if (run.Phase == next)
                        return;
                    run.Phase = next;
                }

                Capture(run, clock);
            }), log, cancellation.Token, null);
            judging.Stop();
            run.JudgingMs = judging.Elapsed.TotalMilliseconds;
            Require(result.IsSuccess, "Judging failed: " + result.Error);
            lock (run.Gate)
                run.Phase = "Reopening";
            Capture(run, clock);
            var reading = Stopwatch.StartNew();
            var opened = JudgementReader.Open(run.Directory);
            Require(opened.IsSuccess, "Published judgement refused: " + opened.Error);
            using (var reader = opened.Value)
            {
                var stored = reader.Read();
                Require(stored.Description.EvidenceSeal.Equals(input.EvidenceHash, StringComparison.OrdinalIgnoreCase) && stored.Description.DerivationGenerationId == input.DerivationGeneration && stored.Description.EvaluationAsOf == When && stored.Description.State == result.Value, "Result input, generation, evaluation-time or outcome binding differs.");
                Require(stored.RulesRun.Count == 17, "The current audit did not record every rule.");
                var requester = reader.ReadSelfMembershipSummary();
                Require(requester is not null && requester.AssessmentsStored == 0 && requester.Discovery.PairsDiscovered == 0, "Requester discovery was activated.");
                run.Generation = stored.Description.GenerationId;
                run.State = stored.Description.State.ToString();
                Save(Path.Combine(run.Directory, "saved-summary.json"), stored);
            }

            reading.Stop();
            run.ReopeningMs = reading.Elapsed.TotalMilliseconds;
            run.Succeeded = true;
            return result.Value;
        }
        catch (Exception error)
        {
            run.Error = error.ToString();
            throw;
        }
        finally
        {
            if (judging.IsRunning)
            {
                judging.Stop();
                run.JudgingMs = judging.Elapsed.TotalMilliseconds;
            }

            using var drained = new ManualResetEvent(false);
            sampler.Dispose(drained);
            drained.WaitOne();
            lock (run.Gate)
                run.Phase = run.Succeeded ? "Finished" : "FailedOrCancelled";
            Capture(run, clock);
            clock.Stop();
            Save(Path.Combine(run.Directory, "measurement.json"), run);
        }
    }

    [GlobalCleanup]
    public void ValidateAndRetain()
    {
        if (session is null)
            return;
        SaveProvenance("provenance-after.json");
        var failures = new List<string>();
        foreach (var run in invocations)
        {
            try
            {
                CheckHash(Path.Combine(run.Directory, "evidence.db"), input.EvidenceHash);
                CheckHash(Path.Combine(run.Directory, input.DerivationFile), input.DerivationHash);
                Require(run.Succeeded && run.Generation.HasValue, "The invocation did not publish and reopen a result.");
                var database = Path.Combine(run.Directory, "judgement." + run.Generation!.Value.ToString("N") + ".db");
                using var connection = Open(database);
                Require(Scalar(connection, "SELECT COUNT(*) FROM pragma_foreign_key_check") == 0, "Dangling saved references.");
                var counts = new[]
                {
                    "control_object",
                    "control_edge",
                    "control_ace",
                    "ownership_target",
                    "ownership_relation",
                    "tier0_path_node",
                    "finding",
                    "permission_entry",
                    "permission_classification_object",
                    "permission_classification_descriptor",
                    "permission_classification_entry",
                    "permission_classification_reading"
                }.ToDictionary(name => name, name => Scalar(connection, "SELECT COUNT(*) FROM " + name), StringComparer.Ordinal);
                Require(counts["permission_classification_object"] == input.Shape.Objects, "Saved classification links did not cover the captured objects.");
                var occurrences = Scalar(connection, "SELECT COALESCE(SUM(d.entry_count),0) FROM permission_classification_object o JOIN permission_classification_descriptor d ON d.descriptor_id=o.descriptor_id");
                if (Workload != "Lab")
                    Require(occurrences == input.Shape.Objects * EntriesPerDescriptor, "Raw duplicate/SELF/generic-mask occurrences were lost.");
                Save(Path.Combine(run.Directory, "validation.json"), new { Passed = true, Counts = counts, ObjectWeightedPermissionOccurrences = occurrences, JudgementSha256 = Hash(database), JudgementBytes = new FileInfo(database).Length, Scope = "Input hashes, reopen/binding, rule coverage, disabled requester discovery, foreign keys and occurrence/count smoke checks; not complete security-answer or permission-proof equivalence. The full sealed results are retained for that separate comparison." });
            }
            catch (Exception error)
            {
                failures.Add(run.Directory + ": " + error);
                Save(Path.Combine(run.Directory, "validation-failed.json"), new { Error = error.ToString() });
            }
        }

        if (input is not null)
            VerifyInput(input);
        Save(Path.Combine(session, "completion.json"), new { Workload, phase, Invocations = invocations.Count, UnusedPreparedCopies = copies.Count, Passed = invocations.Count > 0 && failures.Count == 0, Failures = failures, TimingCaveat = "Benchmark time includes the observer, sampled telemetry, reopening and per-invocation output. Input construction/copying, binary archival and final validation are outside the measured body. JudgingMs and ReopeningMs are recorded separately.", MemoryCaveat = "Allocation and CPU counters are process-wide cumulative values. Timer samples are approximate, not exact memory/WAL/temp peaks. ProcessLifetimePeakBytes also includes setup and any earlier diagnostic invocation." });
        Require(invocations.Count > 0 && failures.Count == 0, "No complete validated measurement; all attempts were retained.");
    }

    private Input PrepareInput()
    {
        var directory = Path.Combine(DescriptorBaselineIsolation.Root, "inputs", Workload);
        var manifest = Path.Combine(directory, "input.json");
        if (File.Exists(manifest))
        {
            var existing = JsonSerializer.Deserialize<Input>(File.ReadAllText(manifest), Json)!;
            Require(existing.Directory == directory, "Frozen input directory differs.");
            return existing;
        }

        Require(!Directory.Exists(directory), "Partial input preparation already exists; retain it and stop instead of overwriting it.");
        if (Workload == "Lab")
        {
            CheckHash(Path.Combine(LabSource, "evidence.db"), LabEvidenceHash);
            CheckHash(Path.Combine(LabSource, LabDerivationFile), LabDerivationHash);
            CopyInput(LabSource, directory, LabDerivationFile);
        }
        else
        {
            BuildSynthetic(directory, Workload == "Shared");
            var opened = RunLogFile.Open(directory, "descriptor-input-derivation", TimeProvider.System);
            Require(opened.IsSuccess, "Cannot open fixture derivation log.");
            using var log = opened.Value;
            using var cancellation = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            var derived = Stage2aRun.Derive(directory, ExpansionBudget.Bulk, When.AddSeconds(-30), Stage2aRun.Unwatched, log, cancellation.Token);
            Require(derived.IsSuccess, "Synthetic derivation failed: " + derived.Error);
        }

        var file = Path.GetFileName(Directory.GetFiles(directory, "derivation.*.db").Single());
        var generation = Guid.ParseExact(Path.GetFileNameWithoutExtension(file)["derivation.".Length..], "N");
        var created = new Input(directory, Hash(Path.Combine(directory, "evidence.db")), file, Hash(Path.Combine(directory, file)), generation, ReadShape(directory));
        if (Workload == "Lab")
            Require(created.EvidenceHash == LabEvidenceHash && created.DerivationHash == LabDerivationHash, "The isolated lab copy differs.");
        VerifyInput(created);
        Save(manifest, created);
        return created;
    }

    private static void BuildSynthetic(string directory, bool shared)
    {
        var domains = Enumerable.Range(0, Domains).Select(i => i == 0 ? "measure.invalid" : "d" + i + ".measure.invalid").ToArray();
        var aces = "(A;;GR;;;WD)(A;;RP;;;PS)(A;;RP;;;WD)(A;;RP;;;WD)" + string.Concat(Enumerable.Range(0, EntriesPerDescriptor - 5).Select(i => "(A;;RP;;;S-1-5-21-600-700-800-" + (2000 + i).ToString(CultureInfo.InvariantCulture) + ")"));
        using var writer = BundleWriter.Create(directory, When.AddMinutes(-2));
        var index = 0;
        for (var domain = 0; domain < Domains; domain++)
        {
            var namingContext = domain == 0 ? "DC=measure,DC=invalid" : "DC=d" + domain + ",DC=measure,DC=invalid";
            var sid = "S-1-5-21-600-700-" + (800 + domain).ToString(CultureInfo.InvariantCulture);
            var coverage = new PartitionCoverage(namingContext, NamingContextKind.Domain, "dc1." + domains[domain], ConnectionSecurityLevel.SignedAndSealed, 3, UsersPerDomain + 1, 1, [], false);
            writer.WriteCoverage(coverage);
            for (var member = 0; member <= UsersPerDomain; member++)
            {
                var name = member == 0 ? namingContext : "CN=User" + member.ToString("D4", CultureInfo.InvariantCulture) + ",OU=Accounts,OU=Directory," + namingContext;
                var objectSid = member == 0 ? sid : sid + "-" + (1000 + member).ToString(CultureInfo.InvariantCulture);
                var identity = new Guid(SHA256.HashData(Encoding.UTF8.GetBytes(name)).AsSpan(0, 16));
                var subject = new EvidenceObject(coverage, name, identity, [Text("objectClass", "top", member == 0 ? "domainDNS" : "user"), new EvidenceAttribute("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(objectSid)!)]), Text("userAccountControl", "512")], When.AddMinutes(-2));
                var objectId = writer.WriteObject(subject);
                var last = shared ? 900000 : 900000 + index;
                var descriptor = new RawSecurityDescriptor("O:SYG:SYD:" + aces + "(A;;RP;;;S-1-5-21-600-700-800-" + last.ToString(CultureInfo.InvariantCulture) + ")");
                Require(descriptor.DiscretionaryAcl!.Count == EntriesPerDescriptor, "Synthetic raw DACL has the wrong entry count.");
                var bytes = new byte[descriptor.BinaryLength];
                descriptor.GetBinaryForm(bytes, 0);
                writer.WriteSecurityDescriptor(objectId, bytes, AceNormalizer.Normalize(identity, SecurityDescriptorParser.Parse(bytes)));
                index++;
            }
        }

        writer.Complete(RunCoverage.Of(CoverageId.ForDomains("measure.invalid", domains), domains.Select(DomainCoverage.Read).ToArray(), [ForestPartitionCoverage.Read("CN=Configuration,DC=measure,DC=invalid", NamingContextKind.Configuration), ForestPartitionCoverage.Read("CN=Schema,CN=Configuration,DC=measure,DC=invalid", NamingContextKind.Schema)], SysvolCoverage.Of([])), When.AddMinutes(-1));
    }

    private static EvidenceAttribute Text(string name, params string[] values) => new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
    private static void CopyInput(string source, string destination, string derivationFile)
    {
        Require(!Directory.Exists(destination), "Refusing to overwrite a retained workload.");
        foreach (var database in new[]
        {
            "evidence.db",
            derivationFile
        }

        )
            Require(!File.Exists(Path.Combine(source, database + "-wal")) || new FileInfo(Path.Combine(source, database + "-wal")).Length == 0, "Input has uncheckpointed changes: " + database);
        Directory.CreateDirectory(destination);
        foreach (var file in new[]
        {
            "evidence.db",
            "evidence.db.seal",
            derivationFile,
            derivationFile + ".seal",
            "derivation.current.json"
        }

        )
            File.Copy(Path.Combine(source, file), Path.Combine(destination, file), false);
        if (File.Exists(Path.Combine(source, "preflight.json")))
            File.Copy(Path.Combine(source, "preflight.json"), Path.Combine(destination, "preflight.json"), false);
    }

    private static Shape ReadShape(string directory)
    {
        using var connection = Open(Path.Combine(directory, "evidence.db"));
        return new(Scalar(connection, "SELECT COUNT(*) FROM captured_object"), Scalar(connection, "SELECT COUNT(DISTINCT domain_fqdn) FROM captured_object"), Scalar(connection, "SELECT COUNT(*) FROM object_security_descriptor"), Scalar(connection, "SELECT COUNT(DISTINCT descriptor_id) FROM object_security_descriptor"), Scalar(connection, "SELECT COUNT(*) FROM descriptor_entry"));
    }

    private static void CheckShape(Shape shape, long objects, long descriptors) => Require(shape.Objects == objects && shape.Domains == Domains && shape.DescriptorLinks == objects && shape.Descriptors == descriptors, "Synthetic descriptor sharing does not match the workload.");
    private static void VerifyInput(Input value)
    {
        CheckHash(Path.Combine(value.Directory, "evidence.db"), value.EvidenceHash);
        CheckHash(Path.Combine(value.Directory, value.DerivationFile), value.DerivationHash);
        Require(ReadShape(value.Directory) == value.Shape, "Frozen input shape changed.");
    }

    private static void Capture(Invocation run, Stopwatch clock)
    {
        lock (run.Gate)
        {
            using var process = Process.GetCurrentProcess();
            process.Refresh();
            var files = Directory.EnumerateFiles(run.Directory, "judgement*", SearchOption.TopDirectoryOnly).ToArray();
            run.Samples.Add(new(clock.Elapsed.TotalMilliseconds, run.Phase, process.TotalProcessorTime.TotalMilliseconds, GC.GetTotalAllocatedBytes(precise: true), GC.CollectionCount(0), GC.CollectionCount(1), GC.CollectionCount(2), process.WorkingSet64, process.PrivateMemorySize64, process.PeakWorkingSet64, files.Sum(Size), files.Where(path => path.EndsWith("-wal", StringComparison.Ordinal)).Sum(Size), TemporarySize()));
        }
    }

    private void SaveProvenance(string file)
    {
        var binaries = Path.Combine(session, "binaries");
        Directory.CreateDirectory(binaries);
        var assemblies = AppDomain.CurrentDomain.GetAssemblies().Where(a => !a.IsDynamic && !string.IsNullOrEmpty(a.Location) && (a.GetName().Name!.StartsWith("SecureAD", StringComparison.Ordinal) || a == GetType().Assembly || a == Assembly.GetEntryAssembly() || a.GetName().Name!.Contains("Sqlite", StringComparison.OrdinalIgnoreCase) || a.GetName().Name!.StartsWith("SQLitePCL", StringComparison.Ordinal))).Select(a => new { a.Location, SHA256 = Hash(a.Location), Mvid = a.ManifestModule.ModuleVersionId, Version = a.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion, Configuration = a.GetCustomAttribute<AssemblyConfigurationAttribute>()?.Configuration }).ToArray();
        foreach (var assembly in assemblies)
        {
            var target = Path.Combine(binaries, assembly.Mvid.ToString("N"));
            Directory.CreateDirectory(target);
            var destination = Path.Combine(target, Path.GetFileName(assembly.Location));
            if (!File.Exists(destination))
                File.Copy(assembly.Location, destination, false);
            CheckHash(destination, assembly.SHA256);
        }

        using var process = Process.GetCurrentProcess();
        var native = process.Modules.Cast<ProcessModule>().Where(module => module.ModuleName.Contains("sqlite", StringComparison.OrdinalIgnoreCase)).Select(module => new { Path = module.FileName, SHA256 = Hash(module.FileName) }).ToArray();
        foreach (var module in native)
        {
            var destination = Path.Combine(binaries, module.SHA256 + "-" + Path.GetFileName(module.Path));
            if (!File.Exists(destination))
                File.Copy(module.Path, destination, false);
            CheckHash(destination, module.SHA256);
        }

        var executable = Environment.ProcessPath!;
        var executableHash = Hash(executable);
        var executableCopy = Path.Combine(binaries, executableHash + "-" + Path.GetFileName(executable));
        if (!File.Exists(executableCopy))
            File.Copy(executable, executableCopy, false);
        CheckHash(executableCopy, executableHash);
        var source = SourcePath();
        Save(Path.Combine(session, file), new { Workload, phase, Input = input, EvaluationTime = When, Executable = executable, ExecutableSHA256 = executableHash, Assemblies = assemblies, NativeSqlite = native, BenchmarkSource = source, BenchmarkSourceSHA256 = Hash(source), Runtime = RuntimeInformation.FrameworkDescription, OS = RuntimeInformation.OSDescription, Architecture = RuntimeInformation.ProcessArchitecture.ToString(), Environment.MachineName, Environment.ProcessorCount, Environment.ProcessId, Temporary = Path.GetTempPath(), FrameworkInvocationLimit = MaximumInvocations, RuntimeEnvironment = Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>().Where(item => item.Key.ToString()!.StartsWith("DOTNET_", StringComparison.OrdinalIgnoreCase) || item.Key.ToString()!.StartsWith("COMPlus_", StringComparison.OrdinalIgnoreCase)).ToDictionary(item => item.Key.ToString()!, item => item.Value?.ToString()), SourcesBefore = Path.Combine(DescriptorBaselineIsolation.Root, "source-before.json") });
    }

    private static string SourcePath([CallerFilePath] string path = "") => path;
    private static long? TemporarySize()
    {
        try
        {
            return Directory.EnumerateFiles(DescriptorBaselineIsolation.Temporary, "*", SearchOption.AllDirectories).Sum(Size);
        }
        catch (DirectoryNotFoundException)
        {
            // A reader may dispose a temporary subtree during sampling; that sample is unknown, not zero.
            return null;
        }
    }

    private static long Size(string path)
    {
        try
        {
            return new FileInfo(path).Length;
        }
        catch (FileNotFoundException)
        {
            return 0;
        }
        catch (DirectoryNotFoundException)
        {
            return 0;
        }
    }

    private static SqliteConnection Open(string path)
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

    private static string Hash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void CheckHash(string path, string expected) => Require(Hash(path).Equals(expected, StringComparison.OrdinalIgnoreCase), "Fingerprint differs: " + path);
    private static void Save(string path, object value) => File.WriteAllText(path, JsonSerializer.Serialize(value, Json));
    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }

    private static void Refuses(Action action)
    {
        var refused = false;
        try
        {
            action();
        }
        catch (InvalidOperationException)
        {
            refused = true;
        }

        Require(refused, "A deliberately wrong fixture expectation was accepted.");
    }

    private sealed class Watching(Action<JudgingRun.JudgingProgress> report) : IProgress<JudgingRun.JudgingProgress>
    {
        public void Report(JudgingRun.JudgingProgress value) => report(value);
    }
}
