using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using BenchmarkDotNet.Attributes;
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
internal static class PostPassLookupIsolation
{
    internal const string Root = @"C:\Users\jistrand\source\repos\SecureAD.Next\next\artifacts\lookup-correction-20260929-a1";
    // Runs before benchmark-host discovery can load the historical test assembly's cleanup initializer.
    [ModuleInitializer]
    internal static void Initialize()
    {
        var temporary = Path.Combine(Root, "temporary", Environment.ProcessId + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temporary);
        Environment.SetEnvironmentVariable("TEMP", temporary);
        Environment.SetEnvironmentVariable("TMP", temporary);
    }
}

[SimpleJob(RunStrategy.Monitoring, launchCount: 1, warmupCount: 0, iterationCount: 1, invocationCount: 1)]
[CPUUsageDiagnoser]
public class PostPassLookupBenchmarks
{
    private const int ForestObjects = 940067;
    private const int Domains = 9;
    private const int FocusedObjects = Domains * 3;
    private const string Repo = @"C:\Users\jistrand\source\repos\SecureAD.Next";
    private const string LabSource = Repo + @"\next\artifacts\q290-f68804df\after";
    private const string DerivedFile = "derivation.342f3ae8c58e48e28d24d09ab906f3ac.db";
    private const string LabEvidenceHash = "7E859ACADD5A709FF898A699D9790D2BDCA3BAC631298C97879F726467F53E08";
    private const string LabDerivationHash = "FD1BFAD3802D91A87F56BE34C34F9EF2DBDDAEC4C298F6EDA268CD1B4C806C5D";
    private static readonly DateTimeOffset When = new(2026, 9, 28, 0, 0, 0, TimeSpan.Zero);
    private static readonly Guid Derived = Guid.Parse("11223344-5566-7788-9900-112233445566");
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true
    };
    private readonly List<object> measurements = [];
    private string slot = null!;
    private string output = null!;
    private string synthetic = null!;
    private string lab = null!;
    private BundleReader bundle = null!;
    private JudgementWriter writer = null!;
    private SqliteConnection connection = null!;
    private CapturedMembershipInput input = null!;
    private Tier0InputBinding binding = null!;
    private Tier0DiscoveryScheduler discovery = null!;
    private JudgingContext context = null!;
    private JudgementDescription description = null!;
    private ObjectAttributes[] subjects = null!;
    private bool succeeded;
    private static string Domain(int d) => $"measure{d}.invalid";
    private static string Dn(int d) => $"DC=measure{d},DC=invalid";
    private static string SidFor(int d) => $"S-1-5-21-11-22-{1000 + d}";
    private static string[] Names(int d) => [Dn(d), "CN=Domain Admins," + Dn(d), "CN=Controller," + Dn(d)];
    private static string? DomainSid(string domain) => Enumerable.Range(0, Domains).Where(d => Domain(d) == domain).Select(SidFor).SingleOrDefault();
    [GlobalSetup]
    public void Prepare()
    {
        var slotFile = Path.Combine(PostPassLookupIsolation.Root, "active-slot.txt");
        slot = File.Exists(slotFile) ? File.ReadAllText(slotFile).Trim() : "before";
        Require(slot is "before" or "after", "Only the approved before/after slots exist.");
        Require(!File.Exists(Path.Combine(PostPassLookupIsolation.Root, slot + ".claim")), "Slot already executed; retain it and stop.");
        output = Path.Combine(PostPassLookupIsolation.Root, slot + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(output);
        Console.WriteLine("Retained lookup validation: " + output);
        synthetic = Path.Combine(PostPassLookupIsolation.Root, "synthetic-input-v2");
        if (!Directory.Exists(synthetic))
            BuildSynthetic();
        var seal = JsonSerializer.Deserialize<BundleSealContents>(File.ReadAllText(BundleLayout.SealPath(synthetic)))!;
        Require(Hash(BundleLayout.EvidencePath(synthetic)).Equals(seal.Hash, StringComparison.OrdinalIgnoreCase), "Synthetic evidence seal mismatch.");
        var opened = BundleReader.Open(synthetic);
        Require(opened.IsSuccess, "Cannot open sealed synthetic evidence: " + opened.Error);
        bundle = opened.Value;
        subjects = Enumerable.Range(0, Domains).SelectMany(Names).Select(name => bundle.ReadObjectAttributes(name) ?? throw new InvalidOperationException("Missing fixture object.")).ToArray();
        input = new(Derived, false, subjects);
        binding = new(seal.Hash, Derived, new string ('B', 64), PrincipalClassificationRegistry.Version, PolicyVersion: 2, ContractVersion: 2, ForestRootNamingContext: Dn(0), ConfigurationNamingContext: null);
        var contexts = Enumerable.Range(0, Domains).ToDictionary(Dn, _ => NamingContextKind.Domain, StringComparer.OrdinalIgnoreCase);
        var byName = subjects.ToDictionary(subject => subject.DistinguishedName, StringComparer.OrdinalIgnoreCase);
        context = JudgingContext.At(When)with
        {
            ForestFqdn = Domain(0),
            NamingContexts = contexts,
            SchemaGuids = bundle.ReadSchemaGuids(),
            ControlPrincipals = name => byName.GetValueOrDefault(name)
        };
        var store = Path.Combine(output, "focused-store");
        Directory.CreateDirectory(store);
        File.Copy(BundleLayout.SealPath(synthetic), BundleLayout.SealPath(store));
        writer = JudgementWriter.Create(store, seal.Hash, Derived, When, When);
        description = new(seal.Hash, writer.GenerationId, Derived, JudgementRunState.Running, When, When, default);
        writer.StartControlEdges(false, true);
        writer.StartAutomaticOwnership(description, OwnershipAuditRun.OwnerRightsHash(context.OwnerImplicitRights));
        writer.StartPathInputs(description, true);
        discovery = new(binding, false, name => byName.GetValueOrDefault(name), subject => OwnershipAuditRun.Target(subject, contexts), CancellationToken.None);
        foreach (var subject in subjects)
        {
            writer.WriteControlEdges(ControlEdgeDeriver.Derive(subject, null, context, writer.GenerationId, Derived, DomainSid), OwnershipAuditRun.Target(subject, contexts));
            discovery.Observe(subject, bundle.ReadPermissions(subject.DistinguishedName));
        }

        writer.FlushObjects();
        connection = Open(BundleLayout.JudgementPartialPath(store), false);
        Require(Count(connection, "control_object") == FocusedObjects, "Focused fixture count mismatch.");
        using (var evidence = Open(BundleLayout.EvidencePath(synthetic), true))
        {
            Require(Count(evidence, "captured_object") == ForestObjects, "Wrong forest-sized lookup population.");
            Save("name-plans.json", new { NameLookup = Plan(evidence, "SELECT object_id, distinguished_name FROM captured_object WHERE distinguished_name=$dn COLLATE NOCASE LIMIT 1", "$dn", Names(8)[1]), RowLookup = Plan(evidence, "SELECT object_id, distinguished_name FROM captured_object WHERE object_id=$id LIMIT 1", "$id", ForestObjects) });
        }

        Require(Hash(Path.Combine(LabSource, "evidence.db")) == LabEvidenceHash && Hash(Path.Combine(LabSource, DerivedFile)) == LabDerivationHash, "Retained lab input changed.");
        Require(!File.Exists(Path.Combine(LabSource, DerivedFile + "-wal")) || new FileInfo(Path.Combine(LabSource, DerivedFile + "-wal")).Length == 0, "Refusing nonempty input WAL.");
        lab = Path.Combine(output, "lab-copy");
        Directory.CreateDirectory(lab);
        foreach (var name in new[]
        {
            "evidence.db",
            "evidence.db.seal",
            DerivedFile,
            DerivedFile + ".seal",
            "derivation.current.json",
            "preflight.json"
        }

        )
            File.Copy(Path.Combine(LabSource, name), Path.Combine(lab, name), false);
        Save("provenance.json", new { slot, ForestObjects, Domains, FocusedObjects, SyntheticEvidenceHash = seal.Hash, LabEvidenceHash, LabDerivationHash, Runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription, Temporary = Path.GetTempPath(), Assemblies = AppDomain.CurrentDomain.GetAssemblies().Where(a => !a.IsDynamic && !string.IsNullOrEmpty(a.Location) && (a.GetName().Name!.StartsWith("SecureAD", StringComparison.Ordinal) || a == GetType().Assembly)).Select(a => new { a.Location, SHA256 = Hash(a.Location) }).ToArray(), Sources = new[] { "Tier0AdmissionRun.cs", "ControlEdgeStorage.cs" }.Select(name => new { Name = name, SHA256 = Hash(Path.Combine(Repo, "next", "src", "SecureAD.Judgement", name)) }).ToArray() });
    }

    [Benchmark]
    public int MeasureBothLookupsAndJudgeLab()
    {
        using (var claim = new FileStream(Path.Combine(PostPassLookupIsolation.Root, slot + ".claim"), FileMode.CreateNew, FileAccess.Write, FileShare.Read))
        using (var text = new StreamWriter(claim))
            text.WriteLine(output);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        var token = cancellation.Token;
        var admitted = Measure("AdmissionIncludingIdentityPreparation", () => writer.AdmitDiscoveredScope(bundle, description, input, binding, discovery, context, DomainSid, Derived, token, status: null));
        Require(admitted == FocusedObjects, "Admission did not exercise all 27 expected targets.");
        var openedLog = RunLogFile.Open(output, "lookup-validation", TimeProvider.System);
        Require(openedLog.IsSuccess, "Cannot open retained log.");
        using var log = openedLog.Value;
        Measure("OwnershipReusingReader", () =>
        {
            writer.AssessAutomaticOwnership(bundle, description, input, binding, context, DomainSid, FocusedObjects, JudgingRun.NobodyIsWatching, log, token, scopeAlreadyPlanned: true);
            return 0;
        });
        writer.CompleteControlEdges();
        Require(Scalar(connection, "SELECT COUNT(*) FROM control_edge WHERE capability='CanSetOwner'") == 18, "Candidate fixture is not the expected 18 edges.");
        Require(Scalar(connection, "SELECT COUNT(*) FROM control_edge WHERE capability='CanBecomeOwnerAndRewriteDacl'") == 18, "Ownership did not assess all 18 candidates.");
        Save("ownership.json", OwnershipAuditStorage.Targets(connection));
        // Only this disposable query fixture is extended; no sealed file or published judgement is edited.
        Execute(connection, $"WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<{ForestObjects - FocusedObjects}) INSERT INTO control_object SELECT 'CN=Filler'||printf('%07d',x)||',DC=measure'||(x%9)||',DC=invalid',NULL,NULL,'DescriptorNotRead',0,0 FROM n");
        Require(Count(connection, "control_object") == ForestObjects, "Wrong parent lookup population.");
        var sqlSource = File.ReadAllText(Path.Combine(Repo, "next", "src", "SecureAD.Judgement", "ControlEdgeStorage.cs"));
        var match = Regex.Match(sqlSource, "query.CommandText = \"(SELECT control_edge\\.\\*[^\"\\r\\n]+)\";");
        Require(match.Success, "Cannot identify the exact production stored-edge statement; refusing a guessed query plan.");
        var id = Scalar(connection, "SELECT MIN(id) FROM control_edge WHERE capability='CanSetOwner'");
        Save("edge-plan.json", new { Sql = match.Groups[1].Value, Plan = Plan(connection, match.Groups[1].Value, "$id", id) });
        var edges = Measure("OwnerCandidateReadsAtForestSize", () =>
        {
            var results = new List<ControlEdge>();
            for (var repeat = 0; repeat < 6; repeat++)
                foreach (var d in Enumerable.Range(0, Domains))
                    foreach (var name in Names(d).Take(2))
                    {
                        token.ThrowIfCancellationRequested();
                        var found = ControlEdgeStorage.ReadOwnerCandidates(connection, description, name);
                        Require(found.Count == 1 && found[0].GenerationId == description.GenerationId && found[0].DerivationGenerationId == Derived, "Wrong candidate or generation.");
                        results.Add(found[0]);
                    }

            return results;
        });
        Require(edges.Count == 108, "Candidate read check measured no work.");
        Save("candidate-answers.json", edges.Select(edge => edge with { GenerationId = Guid.Empty }).ToArray());
        var labLog = RunLogFile.Open(lab, "lookup-lab", TimeProvider.System);
        Require(labLog.IsSuccess, "Cannot open lab log.");
        using var retainedLabLog = labLog.Value;
        var result = Measure("CompleteLabJudging", () => JudgingRun.JudgeAudit(lab, RuleCatalogue.All, PathRequesterPolicy.Disabled, When, When, JudgingRun.NobodyIsWatching, retainedLabLog, token, null));
        Require(result.IsSuccess, "Lab judging failed: " + result.Error);
        var opened = JudgementReader.Open(lab);
        Require(opened.IsSuccess, "Lab result cannot be opened.");
        using var reader = opened.Value;
        var stored = reader.Read();
        Require(stored.Description.EvidenceSeal.Equals(LabEvidenceHash, StringComparison.OrdinalIgnoreCase) && stored.Description.DerivationGenerationId == Guid.Parse("342f3ae8-c58e-48e2-8d24-d09ab906f3ac"), "Lab binding mismatch.");
        var requester = reader.ReadSelfMembershipSummary();
        Require(requester is not null && requester.AssessmentsStored == 0 && requester.Discovery.PairsDiscovered == 0, "Requester discovery activated.");
        Save("lab-rules.json", stored.RulesRun);
        using var labStore = Open(Directory.GetFiles(lab, "judgement.*.db").Single(), true);
        var tables = new[]
        {
            "control_object",
            "control_edge",
            "control_ace",
            "ownership_target",
            "ownership_seed",
            "ownership_relation",
            "full_control_assessment",
            "tier0_path_node",
            "finding",
            "permission_classification_entry"
        };
        Save("lab-counts.json", tables.ToDictionary(table => table, table => Count(labStore, table)));
        Require(Scalar(labStore, "SELECT COUNT(*) FROM pragma_foreign_key_check") == 0, "Dangling lab proof references.");
        Require(Hash(Path.Combine(lab, "evidence.db")) == LabEvidenceHash && Hash(Path.Combine(lab, DerivedFile)) == LabDerivationHash, "Lab input copy changed.");
        succeeded = true;
        return edges.Count + admitted;
    }

    private T Measure<T>(string name, Func<T> action)
    {
        using var process = Process.GetCurrentProcess();
        var cpu = process.TotalProcessorTime;
        var bytes = GC.GetTotalAllocatedBytes(true);
        var collections = new[]
        {
            GC.CollectionCount(0),
            GC.CollectionCount(1),
            GC.CollectionCount(2)
        };
        var watch = Stopwatch.StartNew();
        var value = action();
        watch.Stop();
        process.Refresh();
        measurements.Add(new { Name = name, ElapsedMs = watch.Elapsed.TotalMilliseconds, CpuMs = (process.TotalProcessorTime - cpu).TotalMilliseconds, AllocatedBytes = GC.GetTotalAllocatedBytes(true) - bytes, Gen0 = GC.CollectionCount(0) - collections[0], Gen1 = GC.CollectionCount(1) - collections[1], Gen2 = GC.CollectionCount(2) - collections[2], WorkingSetBytes = process.WorkingSet64, PrivateBytes = process.PrivateMemorySize64 });
        Save("measurements.json", measurements);
        Console.WriteLine(name + ": " + watch.Elapsed.TotalMilliseconds.ToString("F1", CultureInfo.InvariantCulture) + " ms");
        return value;
    }

    private void BuildSynthetic()
    {
        Directory.CreateDirectory(synthetic);
        var coverages = Enumerable.Range(0, Domains).Select(d => new PartitionCoverage(Dn(d), NamingContextKind.Domain, "dc." + Domain(d), ConnectionSecurityLevel.SignedAndSealed, 1, 1, 1, [], false)).ToArray();
        using var capture = BundleWriter.Create(synthetic, When);
        foreach (var coverage in coverages)
            capture.WriteCoverage(coverage);
        for (var i = 0; i < ForestObjects - FocusedObjects - 2; i++)
        {
            var d = i % Domains;
            capture.WriteObject(new EvidenceObject(coverages[d], $"CN=Filler{i:D7},OU=Directory,OU=LookupFixture,{Dn(d)}", Guid.NewGuid(), [], When));
        }

        foreach (var d in Enumerable.Range(0, Domains))
        {
            var names = Names(d);
            for (var i = 0; i < 3; i++)
            {
                var sid = SidFor(d) + (i == 0 ? "" : i == 1 ? "-512" : "-1100");
                var attributes = new List<EvidenceAttribute>
                {
                    Text("objectClass", "top", i == 0 ? "domainDNS" : i == 1 ? "group" : "user"),
                    new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(sid)!)])
                };
                if (i == 1)
                    attributes.Add(Text("groupType", "-2147483646"));
                var subject = new EvidenceObject(coverages[d], names[i], Guid.NewGuid(), attributes, When);
                var objectId = capture.WriteObject(subject);
                var raw = new RawSecurityDescriptor(i == 2 ? "O:SYG:SYD:" : $"O:SYG:SYD:(A;;WO;;;{SidFor(d)}-1100)");
                var bytes = new byte[raw.BinaryLength];
                raw.GetBinaryForm(bytes, 0);
                capture.WriteSecurityDescriptor(objectId, bytes, AceNormalizer.Normalize(subject.ObjectGuid!.Value, SecurityDescriptorParser.Parse(bytes)));
            }
        }

        var partitions = new[]
        {
            (Name: "CN=Configuration," + Dn(0), Kind: NamingContextKind.Configuration, Class: "configuration"),
            (Name: "CN=Schema,CN=Configuration," + Dn(0), Kind: NamingContextKind.Schema, Class: "dMD"),
        };
        foreach (var partition in partitions)
        {
            var coverage = new PartitionCoverage(partition.Name, partition.Kind, "dc." + Domain(0), ConnectionSecurityLevel.SignedAndSealed, 1, 1, 1, [], false);
            capture.WriteCoverage(coverage);
            capture.WriteObject(new EvidenceObject(coverage, partition.Name, Guid.NewGuid(), [Text("objectClass", "top", partition.Class)], When));
        }
        var domains = Enumerable.Range(0, Domains).Select(Domain).ToArray();
        capture.Complete(RunCoverage.Of(CoverageId.ForDomains(Domain(0), domains), domains.Select(DomainCoverage.Read).ToArray(),
            partitions.Select(partition => ForestPartitionCoverage.Read(partition.Name, partition.Kind)).ToArray(), SysvolCoverage.Of([])), When.AddMinutes(1));
    }

    [GlobalCleanup]
    public void Retain()
    {
        connection?.Dispose();
        writer?.Dispose();
        bundle?.Dispose();
        if (output is not null)
            Save("completion.json", new { Succeeded = succeeded, Caveat = "Focused 27-target admission and 108 candidate reads over a 940067-row lookup population; not a full production graph or permission-volume forecast. Memory is sampled at phase boundaries, not peak retention." });
    }

    private static EvidenceAttribute Text(string name, params string[] values) => new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
    private void Save(string name, object value) => File.WriteAllText(Path.Combine(output, name), JsonSerializer.Serialize(value, Json));
    private static string Hash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static SqliteConnection Open(string path, bool readOnly)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Mode = readOnly ? SqliteOpenMode.ReadOnly : SqliteOpenMode.ReadWrite, Pooling = false }.ToString());
        connection.Open();
        Execute(connection, readOnly ? "PRAGMA query_only=ON" : "PRAGMA foreign_keys=ON");
        return connection;
    }

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static long Count(SqliteConnection connection, string table) => Scalar(connection, "SELECT COUNT(*) FROM " + table);
    private static long Scalar(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private static string[] Plan(SqliteConnection connection, string sql, string parameter, object value)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "EXPLAIN QUERY PLAN " + sql;
        command.Parameters.AddWithValue(parameter, value);
        using var read = command.ExecuteReader();
        var rows = new List<string>();
        while (read.Read())
            rows.Add(read.GetString(3));
        return rows.ToArray();
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }
}
