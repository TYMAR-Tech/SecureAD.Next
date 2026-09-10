using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using Microsoft.Data.Sqlite;
using Microsoft.VSDiagnostics;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;

namespace SecureAD.Measurements;
[SimpleJob(RunStrategy.Monitoring, launchCount: 1, warmupCount: 0, iterationCount: 1, invocationCount: 1)]
[CPUUsageDiagnoser]
public class S1ProofStorageBenchmarks
{
    private const string Root = @"C:\Users\jistrand\source\repos\razamus\SecureAD.Next\.vs\S1ProofStorage-cb5272c3ac7c49c5b2a9e80bb847e290";
    private const string Input = @"C:\Users\jistrand\source\repos\razamus\SecureAD.Next\.vs\ScopedOwnershipAssessment-138558efc4054a9bb16d4bc1ef36c400\input-copy";
    private const string EvidenceHash = "A6F1F001F53ADD970B42D55A710F3FC3B083AC62C8E54AB1B140955E46EBB16C";
    private const string DerivationHash = "0C2FE5FE6BA7655EC2FFEDF059353524BC1271B22B13AF47BBF817C3CC15F31E";
    private const string DerivationFile = "derivation.c2d92b832e234a1ab6112cca9344cf9f.db";
    private const string OldJudgement = "judgement.fc3c03a0b5414514ab47ff5ebede3675.db";
    private const string Selected = "CN=Account Operators,CN=Builtin,DC=ad,DC=lab";
    private const string Unselected = "CN=00232167-f3a4-43c6-b503-9acb7a81b01c,CN=Operations,CN=ForestUpdates,CN=Configuration,DC=ad,DC=lab";
    private static readonly Guid DerivationGeneration = Guid.Parse("c2d92b83-2e23-4a1a-b611-2cca9344cf9f");
    private static readonly DateTimeOffset Evaluation = DateTimeOffset.Parse("2026-09-09T05:08:22.3459193+00:00", CultureInfo.InvariantCulture);
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true
    };
    private readonly Stopwatch clock = new();
    private readonly object gate = new();
    private readonly List<object> boundaries = [];
    private readonly List<DiskSample> samples = [];
    private string slot = null!;
    private string directory = null!;
    private string? phase;
    private long objects;
    private bool succeeded;
    private JudgementDescription description = null!;
    private readonly SortedDictionary<string, Digest> digests = new(StringComparer.Ordinal);
    private sealed record DiskSample(double ElapsedMs, string? Phase, long DbBytes, long WalBytes, long SidecarBytes);
    private sealed record Digest(long Rows, string SHA256);
    private sealed record EntryProof(string Target, int Ordinal, byte[] Hash);
    [GlobalSetup]
    public void Prepare()
    {
        slot = File.ReadAllText(Path.Combine(Root, "active-slot.txt")).Trim();
        Require(slot is "before" or "after", "Unapproved measurement slot.");
        Require(!File.Exists(Path.Combine(Root, slot + ".claim")), "This slot has already executed; do not retry.");
        Require(RuntimeInformation.FrameworkDescription == ".NET 10.0.12", "Runtime differs from the approved paired measurement.");
        Require(HashFile(Path.Combine(Input, "evidence.db")) == EvidenceHash && HashFile(Path.Combine(Input, DerivationFile)) == DerivationHash, "Input fingerprint differs.");
        Require(HashFile(Path.Combine(Input, OldJudgement)) == "BA84E9B4C3D5532AA3F8A47CF78EB798CB871EBBE364DD8FB92D87F405915370", "Retained prior generation differs.");
        Require(RuleCatalogue.All.Count == 17, "Rule catalogue differs.");
        directory = Path.Combine(Root, slot + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        foreach (var file in new[]
        {
            "evidence.db",
            "evidence.db.seal",
            DerivationFile,
            DerivationFile + ".seal",
            "derivation.current.json",
            OldJudgement,
            OldJudgement + ".seal",
            "judgement.current.json"
        }

        )
            File.Copy(Path.Combine(Input, file), Path.Combine(directory, file), false);
        using var evidence = Open(Path.Combine(directory, "evidence.db"));
        Require(Scalar(evidence, "SELECT COUNT(*) FROM captured_object") == 8407, "Object count differs.");
        description = new(EvidenceHash, Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), DerivationGeneration, JudgementRunState.CompletedDegraded, Evaluation, Evaluation, Evaluation.AddSeconds(1));
        var normal = Canonical(JsonNode.Parse("{\"GenerationId\":\"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\",\"Name\":\"Case\"}")!).ToJsonString();
        Require(normal != Canonical(JsonNode.Parse("{\"GenerationId\":\"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\",\"Name\":\"case\"}")!).ToJsonString(), "Case-only mutation was hidden.");
        Require(normal != Canonical(JsonNode.Parse("{\"GenerationId\":\"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb\",\"Name\":\"Case\"}")!).ToJsonString(), "Wrong generation was hidden.");
        var rejected = false;
        try
        {
            Canonical(JsonNode.Parse("{\"StartedUtc\":\"2000-01-01T00:00:00Z\"}")!);
        }
        catch (InvalidOperationException)
        {
            rejected = true;
        }

        Require(rejected, "Unexpected timestamp normalization was accepted.");
        Save("setup.json", new { slot, directory, Input, EvidenceHash, DerivationHash, DerivationGeneration, Evaluation, Selected, Unselected, Holder = "S-1-1-0", HolderScope = (string? )null, Runtime = RuntimeInformation.FrameworkDescription, Machine = Environment.MachineName, OS = RuntimeInformation.OSDescription, Architecture = RuntimeInformation.ProcessArchitecture.ToString(), Environment.ProcessorCount, NormalizerNegativeControlsPassed = true, BeforeSourceManifest = Path.Combine(Root, "before-source-manifest.csv") });
        var binaryDirectory = Path.Combine(directory, "binaries");
        Directory.CreateDirectory(binaryDirectory);
        var assemblies = AppDomain.CurrentDomain.GetAssemblies().Where(a => !a.IsDynamic && !string.IsNullOrEmpty(a.Location)).Where(a => a.GetName().Name!.StartsWith("SecureAD", StringComparison.Ordinal) || a == GetType().Assembly || a.GetName().Name!.Contains("Sqlite", StringComparison.OrdinalIgnoreCase) || a.GetName().Name!.StartsWith("SQLitePCL", StringComparison.Ordinal)).ToArray();
        foreach (var assembly in assemblies)
            File.Copy(assembly.Location, Path.Combine(binaryDirectory, Path.GetFileName(assembly.Location)), false);
        Save("assemblies.json", assemblies.Select(a => new { Path = a.Location, SHA256 = HashFile(a.Location), Configuration = a.GetCustomAttribute<AssemblyConfigurationAttribute>()?.Configuration, Version = a.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion }).ToArray());
        Console.WriteLine("Approved S1 " + slot + " execution; retained artifacts: " + directory);
    }

    [Benchmark]
    public JudgementRunState JudgeAndReadPinnedPages()
    {
        using (var claim = new StreamWriter(new FileStream(Path.Combine(Root, slot + ".claim"), FileMode.CreateNew, FileAccess.Write, FileShare.Read)))
            claim.Write(directory);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMinutes(15));
        var openedLog = RunLogFile.Open(directory, "s1-" + slot, TimeProvider.System);
        Require(openedLog.IsSuccess, "Cannot open run log.");
        using var log = openedLog.Value;
        clock.Start();
        using var sampler = new Timer(_ => Sample(), null, TimeSpan.Zero, TimeSpan.FromMilliseconds(100));
        try
        {
            Observe("Started");
            var result = JudgingRun.Judge(directory, RuleCatalogue.All, (SelfMembershipDiscoveryBudget? )null, DateTimeOffset.UtcNow, Evaluation, new Watching(value =>
            {
                objects = Math.Max(objects, value.ObjectsRead);
                Observe(value.Phase.ToString());
            }), log, cancellation.Token);
            Require(result.IsSuccess, "Judging failed: " + result.Error);
            Observe("CompletionReadback");
            var opened = JudgementReader.Open(directory);
            Require(opened.IsSuccess, "Cannot open completed judgement: " + opened.Error);
            using (var reader = opened.Value)
            {
                description = reader.Description;
                Require(description.EvidenceSeal.Equals(EvidenceHash, StringComparison.OrdinalIgnoreCase) && description.DerivationGenerationId == DerivationGeneration && description.EvaluationAsOf == Evaluation && description.State == JudgementRunState.CompletedDegraded, "Input/time/outcome binding differs.");
                var stored = reader.Read();
                Require(stored.Findings.Count == 27 && stored.RulesRun.Count == 17 && objects == 8407, "Basic output counts differ.");
                Snapshot("completion", stored);
                Snapshot("requesters", reader.ReadSelfMembershipSummary()!);
            }

            foreach (var repeat in new[]
            {
                "first",
                "repeat"
            }

            )
            {
                Page("selected-" + repeat, Selected, null);
                Page("unselected-" + repeat, Unselected, null);
                Page("holder-" + repeat, null, "S-1-1-0");
            }

            succeeded = true;
            return result.Value;
        }
        finally
        {
            using var done = new ManualResetEvent(false);
            sampler.Dispose(done);
            done.WaitOne();
            Observe(succeeded ? "Finished" : "FailedOrCancelled");
            clock.Stop();
            Save("phase-boundaries.json", boundaries);
            Save("disk-samples.json", samples);
            Save("execution.json", new { Succeeded = succeeded, ObjectsRead = objects, ElapsedMs = clock.Elapsed.TotalMilliseconds, MaximumObservedDbBytes = samples.Max(s => s.DbBytes), MaximumObservedWalBytes = samples.Max(s => s.WalBytes), MaximumObservedCombinedBytes = samples.Max(s => s.DbBytes + s.WalBytes + s.SidecarBytes), RetainedPriorJudgementBytes = new FileInfo(Path.Combine(directory, OldJudgement)).Length, Caveat = "One judging execution per slot; no warmups or averages. Includes profiler/observer and bounded snapshot overhead. Disk includes the retained prior judgement and is sampled, not a guaranteed peak; external temp and filesystem allocation are unmeasured." });
        }
    }

    private void Page(string name, string? target, string? holder)
    {
        Observe(name);
        var opened = JudgementReader.Open(directory);
        Require(opened.IsSuccess, "Page open failed: " + opened.Error);
        using var reader = opened.Value;
        var page = reader.ReadControlEdges(target, holder, null, true, 0);
        Require(page.Edges.Count + page.FullControlAssessments.Count > 0, "A pinned page is empty.");
        Snapshot(name, page);
    }

    [GlobalCleanup]
    public void Validate()
    {
        Require(succeeded, "No successful execution; slot stays consumed and artifacts remain retained.");
        var path = BundleLayout.AnalysisGenerationDataPath(directory, AnalysisStoreKind.Judgement, description.GenerationId);
        using var connection = Open(path);
        var schema = Scalar(connection, "SELECT schema_version FROM judgement");
        Require(schema == (slot == "before" ? 26 : 27), "Unexpected schema for this slot.");
        var expected = new Dictionary<string, long>
        {
            ["control_object"] = 8407,
            ["control_edge"] = 112303,
            ["control_ace"] = 342812,
            ["permission_entry"] = 208960,
            ["control_precondition"] = 71971,
            ["full_control_assessment"] = 23751,
            ["full_control_support"] = 72422,
            ["full_control_source_entry"] = 208900,
            ["ownership_target"] = 8407,
            ["ownership_seed"] = 50,
            ["ownership_relation"] = 840,
            ["member_attribution_root"] = 0,
            ["member_attribution_member"] = 0,
            ["member_attribution_permission"] = 0,
            ["self_membership_assessment"] = 0
        };
        foreach (var pair in expected)
            Require(Scalar(connection, "SELECT COUNT(*) FROM " + pair.Key) == pair.Value, "Count differs: " + pair.Key);
        Require(Scalar(connection, "SELECT COUNT(*) FROM pragma_foreign_key_check") == 0, "Foreign-key damage.");
        Require(Scalar(connection, "SELECT COUNT(*) FROM ownership_target WHERE selection='Included' AND execution='CompletedWithLimitations'") == 51, "Selected targets differ.");
        Require(Scalar(connection, "SELECT COUNT(*) FROM control_edge WHERE capability='CanBecomeOwnerAndRewriteDacl' AND evaluation='Unknown' AND counted=0") == 210, "Owner transition limitations differ.");
        Require(Scalar(connection, "SELECT COUNT(*) FROM member_attribution_product WHERE configuration IS NULL AND configuration_hash IS NULL AND root_count=0 AND permission_count=0") == 1, "Member activation changed.");
        Require(Scalar(connection, "SELECT COUNT(*) FROM self_membership_discovery WHERE json_type(coverage_json,'$.Budget')='null' AND json_extract(coverage_json,'$.Verdict')='NotStarted' AND json_extract(coverage_json,'$.ObjectsVisited')=0") == 1, "Requester activation changed.");
        CaptureLogical(connection, schema);
        Save("logical-digests.json", digests);
        if (slot == "after")
        {
            var before = File.ReadAllText(Path.Combine(Root, "before-output.txt")).Trim();
            var original = JsonSerializer.Deserialize<SortedDictionary<string, Digest>>(File.ReadAllText(Path.Combine(before, "logical-digests.json")))!;
            Require(original.Count == digests.Count && original.All(pair => digests.TryGetValue(pair.Key, out var value) && value == pair.Value), "Independent logical parity failed; do not weaken the comparer.");
        }

        Require(HashFile(Path.Combine(directory, "evidence.db")) == EvidenceHash && HashFile(Path.Combine(directory, DerivationFile)) == DerivationHash, "Inputs changed.");
        Save("validation.json", new { Passed = true, schema, expected, description, DatabaseBytes = new FileInfo(path).Length, DatabaseSHA256 = HashFile(path), Scope = "Complete logical permission values, control routes, full-control stored proof, unchanged products and their bindings; bounded public reads; not an exhaustive public export." });
        File.WriteAllText(Path.Combine(Root, slot + "-output.txt"), directory);
    }

    private void CaptureLogical(SqliteConnection c, long schema)
    {
        var projection = schema == 26 ? "p.*" : "p.id,p.target,p.generation,p.ordinal,p.ace_type,p.sid,p.name,p.dn,p.domain,p.unresolved_reason,p.role,v.payload AS meaning,p.mask,p.object_type,p.inherited_object_type,p.inherited,p.inheritance_flags,p.propagation_flags,p.has_object_type,p.has_inherited_object_type,p.application_data";
        var permissionSql = "SELECT " + projection + " FROM permission_entry p" + (schema == 26 ? "" : " LEFT JOIN shared_proof_value v ON v.id=p.meaning") + " ORDER BY p.id";
        digests["permission_entry"] = HashQuery(c, permissionSql);
        var entries = new Dictionary<long, EntryProof>();
        using (var command = c.CreateCommand())
        {
            command.CommandText = permissionSql;
            using var r = command.ExecuteReader();
            while (r.Read())
            {
                Require(r.GetString(2) == description.GenerationId.ToString("D"), "Permission generation differs.");
                var value = new PermissionEntry(r.GetInt32(3), r.GetString(4), new PermissionTrustee(r.GetString(5), Text(r, 6), Text(r, 7), Text(r, 8), Text(r, 9)is { } reason ? Enum.Parse<UnresolvedReferenceReason>(reason) : null, Text(r, 10)is { } role ? Enum.Parse<WellKnownSidRole>(role) : null, Text(r, 11)), r.GetInt32(12), Text(r, 13), Text(r, 14), r.GetBoolean(15), checked((byte)r.GetInt32(16)), checked((byte)r.GetInt32(17)), r.GetBoolean(18), r.GetBoolean(19), (byte[])r.GetValue(20));
                var json = JsonSerializer.Serialize(new { Target = r.GetString(1), Generation = description.GenerationId, Entry = value });
                entries.Add(r.GetInt64(0), new(r.GetString(1), r.GetInt32(3), SHA256.HashData(Encoding.UTF8.GetBytes(json))));
            }
        }

        foreach (var sql in new[]
        {
            "SELECT e.target,e.generation,a.entry_id,a.ordinal,a.fingerprint FROM control_ace a JOIN control_edge e ON e.id=a.edge_id",
            "SELECT s.target,j.judgement_generation_id,s.entry_id,s.ordinal,s.fingerprint FROM full_control_source_entry s CROSS JOIN judgement j"
        }

        )
        {
            using var command = c.CreateCommand();
            command.CommandText = sql;
            using var r = command.ExecuteReader();
            while (r.Read())
                Require(entries.TryGetValue(r.GetInt64(2), out var entry) && entry.Target == r.GetString(0) && entry.Ordinal == r.GetInt32(3) && r.GetString(1) == description.GenerationId.ToString("D") && entry.Hash.AsSpan().SequenceEqual((byte[])r.GetValue(4)), "Complete ACE fingerprint/binding failed.");
        }

        digests["control_ace"] = HashQuery(c, "SELECT edge_id,ordinal,entry_id FROM control_ace ORDER BY edge_id,ordinal");
        digests["full_control_source_entry"] = HashQuery(c, "SELECT target,position,ordinal,entry_id FROM full_control_source_entry ORDER BY target,position");
        using (var command = c.CreateCommand())
        {
            command.CommandText = "SELECT header,fingerprint FROM ownership_audit";
            using var r = command.ExecuteReader();
            while (r.Read())
                Require(SHA256.HashData(Encoding.UTF8.GetBytes(r.GetString(0))).AsSpan().SequenceEqual((byte[])r.GetValue(1)), "Ownership header fingerprint differs.");
        }

        digests["ownership_audit"] = HashQuery(c, "SELECT id,header,completed FROM ownership_audit ORDER BY id");
        var tables = new List<string>();
        using (var command = c.CreateCommand())
        {
            command.CommandText = "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT IN ('judgement','permission_entry','control_ace','full_control_source_entry','full_control_assessment','ownership_audit','membership_route_summary','membership_route','membership_route_step','shared_proof_value','control_membership_route') ORDER BY name";
            using var r = command.ExecuteReader();
            while (r.Read())
                tables.Add(r.GetString(0));
        }

        foreach (var table in tables)
            digests[table] = HashQuery(c, "SELECT * FROM \"" + table + "\" ORDER BY rowid");
        foreach (var table in new[]
        {
            "membership_route_summary",
            "membership_route",
            "membership_route_step"
        }

        )
            digests["finding-" + table] = HashQuery(c, "SELECT * FROM " + table + " WHERE subject_id NOT LIKE 'control:%' AND subject_id NOT LIKE 'proof-route:%' ORDER BY rowid");
        using var headers = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var routes = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var steps = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long nh = 0, nr = 0, ns = 0;
        if (schema == 26)
        {
            digests["control-route-headers"] = HashQuery(c, "SELECT e.id,s.incomplete_reasons FROM control_edge e JOIN membership_route_summary s ON s.subject_id='control:'||e.id ORDER BY e.id");
            digests["control-route-values"] = HashQuery(c, "SELECT e.id,r.membership_ordinal,r.route_ordinal,r.catalogue_entry_id,r.root_name,r.authorization,r.establishes_protection FROM control_edge e JOIN membership_route r ON r.subject_id='control:'||e.id ORDER BY e.id,r.membership_ordinal,r.route_ordinal");
            digests["control-route-steps"] = HashQuery(c, "SELECT e.id,s.membership_ordinal,s.route_ordinal,s.step_ordinal,s.sid,s.scope,s.distinguished_name,s.is_primary_group FROM control_edge e JOIN membership_route_step s ON s.subject_id='control:'||e.id ORDER BY e.id,s.membership_ordinal,s.route_ordinal,s.step_ordinal");
        }
        else
        {
            using var command = c.CreateCommand();
            command.CommandText = "SELECT r.edge_id,v.id,v.payload FROM control_membership_route r JOIN shared_proof_value v ON v.id=r.value_id ORDER BY r.edge_id";
            using var r = command.ExecuteReader();
            var cached = new Dictionary<long, MembershipRouteSummary>();
            while (r.Read())
            {
                var id = r.GetInt64(0);
                var valueId = r.GetInt64(1);
                if (!cached.TryGetValue(valueId, out var summary))
                    cached[valueId] = summary = JsonSerializer.Deserialize<MembershipRouteSummary>(r.GetString(2))!;
                Add(headers, new object? [] { id, (int)summary.IncompleteReasons });
                nh++;
                for (var m = 0; m < summary.Memberships.Count; m++)
                    for (var p = 0; p < summary.Memberships[m].Routes.Count; p++)
                    {
                        var route = summary.Memberships[m].Routes[p];
                        Add(routes, new object? [] { id, m, p, route.CatalogueEntryId, route.RootName, route.Authorization.ToString(), route.EstablishesProtection ? 1 : 0 });
                        nr++;
                        for (var s = 0; s < route.Steps.Count; s++)
                        {
                            var step = route.Steps[s];
                            Add(steps, new object? [] { id, m, p, s, step.Principal.Sid, step.Principal.Scope, step.Principal.DistinguishedName, step.IsPrimaryGroup ? 1 : 0 });
                            ns++;
                        }
                    }
            }

            digests["control-route-headers"] = new(nh, Convert.ToHexString(headers.GetHashAndReset()));
            digests["control-route-values"] = new(nr, Convert.ToHexString(routes.GetHashAndReset()));
            digests["control-route-steps"] = new(ns, Convert.ToHexString(steps.GetHashAndReset()));
        }

        Require(digests["control-route-headers"].Rows == 112303 && digests["control-route-values"].Rows == 87340 && digests["control-route-steps"].Rows == 174764, "Logical route counts differ.");
        using var proofHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long proofs = 0;
        using (var command = c.CreateCommand())
        {
            command.CommandText = schema == 26 ? "SELECT id,proof FROM full_control_assessment ORDER BY id" : "SELECT a.id,a.proof,v.payload FROM full_control_assessment a LEFT JOIN shared_proof_value v ON v.id=a.route_value_id ORDER BY a.id";
            using var r = command.ExecuteReader();
            while (r.Read())
            {
                var node = JsonNode.Parse(r.GetString(1))!;
                if (schema == 27)
                {
                    Require(node["Source"] is JsonObject source && !source.ContainsKey("MembershipRoutes") && !r.IsDBNull(2), "Invalid stored route reference.");
                    node["Source"]!["MembershipRoutes"] = JsonNode.Parse(r.GetString(2));
                }

                Add(proofHash, new JsonArray(JsonValue.Create(r.GetInt64(0)), Canonical(node)));
                proofs++;
            }
        }

        digests["full_control_assessment-proof"] = new(proofs, Convert.ToHexString(proofHash.GetHashAndReset()));
        digests["full_control_assessment-bindings"] = HashQuery(c, "SELECT id,target,holder_sid,holder_scope,evaluation,expectedness,generation,derivation_generation,support_count FROM full_control_assessment ORDER BY id");
    }

    private Digest HashQuery(SqliteConnection c, string sql)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long count = 0;
        using var command = c.CreateCommand();
        command.CommandText = sql;
        using var r = command.ExecuteReader();
        while (r.Read())
        {
            var values = new JsonArray();
            for (var i = 0; i < r.FieldCount; i++)
                values.Add(r.IsDBNull(i) ? null : Canonical(JsonSerializer.SerializeToNode(r.GetValue(i))!, r.GetName(i)));
            Add(hash, values);
            count++;
        }

        return new(count, Convert.ToHexString(hash.GetHashAndReset()));
    }

    private JsonNode Canonical(JsonNode node, string name = "")
    {
        if (node is JsonObject obj)
        {
            var result = new JsonObject();
            foreach (var pair in obj.OrderBy(p => p.Key, StringComparer.Ordinal))
                result[pair.Key] = pair.Value is null ? null : Canonical(pair.Value, pair.Key);
            return result;
        }

        if (node is JsonArray array)
        {
            var result = new JsonArray();
            foreach (var item in array)
                result.Add(item is null ? null : Canonical(item));
            return result;
        }

        if (node is JsonValue value && value.TryGetValue<string>(out var text))
        {
            if (text == description.GenerationId.ToString("D"))
            {
                Require(name is "GenerationId" or "Generation" or "JudgementGenerationId" or "generation", "Unexpected generation normalization site.");
                return JsonValue.Create("<judgement-generation>")!;
            }

            if (name is "StartedUtc" or "CompletedUtc")
            {
                Require(DateTimeOffset.Parse(text, CultureInfo.InvariantCulture) == (name == "StartedUtc" ? description.StartedUtc : description.CompletedUtc), "Unexpected timestamp normalization.");
                return JsonValue.Create("<" + name + ">")!;
            }

            if (text.Contains(description.GenerationId.ToString("D"), StringComparison.Ordinal) && (text.StartsWith('{') || text.StartsWith('[')))
                return JsonValue.Create(Canonical(JsonNode.Parse(text)!).ToJsonString())!;
        }

        return node.DeepClone();
    }

    private void Snapshot(string name, object value)
    {
        var canonical = Canonical(JsonSerializer.SerializeToNode(value)!);
        File.WriteAllText(Path.Combine(directory, name + ".json"), canonical.ToJsonString(Json));
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Add(hash, canonical);
        digests["public-" + name] = new(1, Convert.ToHexString(hash.GetHashAndReset()));
    }

    private static void Add(IncrementalHash hash, object value)
    {
        hash.AppendData(JsonSerializer.SerializeToUtf8Bytes(value));
        hash.AppendData(new byte[] { 10 });
    }

    private void Observe(string next)
    {
        lock (gate)
        {
            if (phase == next)
                return;
            phase = next;
            using var p = Process.GetCurrentProcess();
            boundaries.Add(new { Phase = next, ElapsedMs = clock.Elapsed.TotalMilliseconds, CpuMs = p.TotalProcessorTime.TotalMilliseconds, AllocatedBytes = GC.GetTotalAllocatedBytes(false), Gen0 = GC.CollectionCount(0), Gen1 = GC.CollectionCount(1), Gen2 = GC.CollectionCount(2), WorkingSetBytes = p.WorkingSet64, PrivateBytes = p.PrivateMemorySize64 });
            Sample();
        }
    }

    private void Sample()
    {
        lock (gate)
        {
            long db = 0, wal = 0, sidecar = 0;
            foreach (var file in Directory.EnumerateFiles(directory, "judgement*"))
                try
                {
                    var length = new FileInfo(file).Length;
                    if (file.EndsWith("-wal", StringComparison.Ordinal))
                        wal += length;
                    else if (file.EndsWith(".db", StringComparison.Ordinal))
                        db += length;
                    else
                        sidecar += length;
                }
                catch (FileNotFoundException)
                {
                }

            samples.Add(new(clock.Elapsed.TotalMilliseconds, phase, db, wal, sidecar));
        }
    }

    private void Save(string name, object value) => File.WriteAllText(Path.Combine(directory, name), JsonSerializer.Serialize(value, Json));
    private static SqliteConnection Open(string path)
    {
        var c = new SqliteConnection("Data Source=" + path + ";Mode=ReadOnly;Pooling=False");
        c.Open();
        using var command = c.CreateCommand();
        command.CommandText = "PRAGMA query_only=ON";
        command.ExecuteNonQuery();
        return c;
    }

    private static long Scalar(SqliteConnection c, string sql)
    {
        using var command = c.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private static string? Text(SqliteDataReader r, int index) => r.IsDBNull(index) ? null : r.GetString(index);
    private static string HashFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
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