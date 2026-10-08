using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Measure;

internal static class RequesterMeasurement
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
    private static readonly DateTimeOffset AsOf = new(2026, 9, 17, 0, 0, 0, TimeSpan.Zero);

    internal static int Run(string[] args)
    {
        if (args.Length < 3 || args[0] is not ("inspect" or "measure" or "cancel"))
            throw new ArgumentException("--requester inspect|measure|cancel SOURCE NEW_OUTPUT [CANCEL_PHASE DELAY_MS]");
        var output = Path.GetFullPath(args[2]);
        Require(!Directory.Exists(output) && !File.Exists(output), "Output already exists; retained runs must not be overwritten.");
        Directory.CreateDirectory(output);
        try
        {
            var build = Path.Combine(AppContext.BaseDirectory, "measurement-build.json");
            Require(File.Exists(build), "An archived build/source manifest is required beside this executable.");
            Save(output, "provenance.json", new
            {
                Arguments = args, StartedUtc = DateTimeOffset.UtcNow, Build = JsonDocument.Parse(File.ReadAllText(build)).RootElement,
                Runtime = RuntimeInformation.FrameworkDescription, OS = RuntimeInformation.OSDescription,
                Architecture = RuntimeInformation.ProcessArchitecture, Environment.ProcessorCount,
                ProcessorOverride = Environment.GetEnvironmentVariable("DOTNET_PROCESSOR_COUNT"),
                Process = Environment.ProcessPath, ProcessHash = Hash(Environment.ProcessPath!),
                Binaries = Directory.GetFiles(AppContext.BaseDirectory, "*", SearchOption.AllDirectories)
                    .Where(p => p.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                        || p.EndsWith(".json", StringComparison.OrdinalIgnoreCase)).Order(StringComparer.Ordinal)
                    .Select(p => new { Path = p, Sha256 = Hash(p) }).ToArray(),
                Rules = "None: isolates the shared JudgeAudit path, not total normal-host rule cost",
                RequesterPolicy = "SupportedCapturedQuestions, offline only", LegacyDiscoveryBudget = "null",
                Optimization = false, CustomerScaleAcceptance = false,
                MemoryMethod = "20ms process working-set/private-byte sampling; cumulative managed allocations include runner/logging overhead; process peak is lifetime, not per phase",
            });
            var bundle = CopyEvidence(Path.GetFullPath(args[1]), output);
            Inspect(bundle, output);
            if (args[0] == "inspect") return 0;
            PathRequesterWorkPhase? cancel = args[0] == "cancel" ? Enum.Parse<PathRequesterWorkPhase>(args[3]) : null;
            var delay = cancel.HasValue ? int.Parse(args[4], CultureInfo.InvariantCulture) : 0;
            Require(!cancel.HasValue || delay > 0, "Cancellation must be delayed into work, not requested on phase entry.");
            using var stopping = new CancellationTokenSource();
            using var observer = new Observer(output, stopping, cancel, delay);
            using var log = new Log(output);
            observer.Enter("Derivation");
            var derived = Stage2aRun.Derive(bundle, ExpansionBudget.Bulk, AsOf, Stage2aRun.Unwatched, log, CancellationToken.None);
            Require(derived.IsSuccess, derived.Error?.Description ?? "Derivation failed.");
            Save(output, "derivation.json", new { Outcome = derived.Value, Budget = ExpansionBudget.Bulk });
            observer.Enter("PreviousValidJudgement");
            var previousRun = JudgingRun.JudgeAudit(bundle, [], PathRequesterPolicy.Disabled, AsOf, AsOf,
                JudgingRun.NobodyIsWatching, log, CancellationToken.None, null);
            Require(previousRun.IsSuccess, previousRun.Error?.Description ?? "Previous generation was not published.");
            var previous = AnalysisStoreLifecycle.Resolve(bundle, AnalysisStoreKind.Judgement).Value.GenerationId;
            var previousPath = BundleLayout.AnalysisGenerationDataPath(bundle, AnalysisStoreKind.Judgement, previous);
            var previousHash = Hash(previousPath);
            var evidenceHash = Hash(BundleLayout.EvidencePath(bundle));
            observer.Enter("SelectedJudgingBeforePaths");
            var watch = Stopwatch.StartNew();
            var allocated = GC.GetTotalAllocatedBytes(true);
            var cancelled = false;
            try
            {
                var judged = JudgingRun.JudgeAudit(bundle, [], PathRequesterPolicy.SupportedCapturedQuestions,
                    AsOf, AsOf, observer, log, stopping.Token, null);
                Require(judged.IsSuccess, judged.Error?.Description ?? "Selected judging failed.");
            }
            catch (OperationCanceledException) when (stopping.IsCancellationRequested)
            {
                cancelled = true;
            }
            watch.Stop();
            var judging = new { Ms = watch.Elapsed.TotalMilliseconds, AllocatedBytes = GC.GetTotalAllocatedBytes(true) - allocated };
            observer.EndCancellation();
            var current = AnalysisStoreLifecycle.Resolve(bundle, AnalysisStoreKind.Judgement).Value.GenerationId;
            Save(output, "judging.json", new { judging, Cancelled = cancelled, PreviousGeneration = previous, CurrentGeneration = current, Cancellation = observer.Cancellation });
            Require(!cancel.HasValue || cancelled, "The requested phase finished before cancellation; this is a retained missed attempt, not a cancellation measurement.");
            if (cancelled)
            {
                Require(current == previous && Hash(previousPath) == previousHash, "Cancellation replaced or changed the previous valid generation.");
                Require(observer.MidWorkCancellation, "Cancellation was not observed within the requested phase after work had begun.");
            }
            observer.Enter("ReopeningAndSavedProofValidation");
            watch.Restart();
            allocated = GC.GetTotalAllocatedBytes(true);
            var analysisPath = BundleLayout.AnalysisGenerationDataPath(bundle, AnalysisStoreKind.Judgement, current);
            var beforeRead = Hash(analysisPath);
            var opened = JudgementReader.Open(bundle);
            Require(opened.IsSuccess, opened.Error?.Description ?? "Reopening failed.");
            PathRequesterSummary coverage;
            using (var reader = opened.Value) coverage = reader.ReadPathRequesterSummary();
            watch.Stop();
            Save(output, "reopening.json", new { Ms = watch.Elapsed.TotalMilliseconds, AllocatedBytes = GC.GetTotalAllocatedBytes(true) - allocated, Coverage = coverage });
            observer.Enter("IndependentStoredProofInspection");
            var proof = ProofCounts(analysisPath, output);
            Require(Hash(analysisPath) == beforeRead && Hash(BundleLayout.EvidencePath(bundle)) == evidenceHash,
                "Passive reading or judging modified immutable input bytes.");
            Save(output, "result.json", new
            {
                State = cancelled ? "CancelledMidWorkPreviousGenerationPreserved" : "MeasuredSupportedQuestions",
                PreviousGeneration = previous, Generation = current, coverage.Verdict, proof,
                StoredJudgementBytes = new FileInfo(analysisPath).Length, EvidenceUnchanged = true, PassiveReadback = true,
                ThreeFamiliesExercised = !cancelled && proof.AllFamiliesExercised,
                Stage7Complete = false, CustomerScaleAcceptance = false,
            });
            Console.WriteLine($"Retained result: {output}; three-family work: {!cancelled && proof.AllFamiliesExercised}");
            return 0;
        }
        catch (Exception error)
        {
            File.WriteAllText(Path.Combine(output, "failure.txt"), error.ToString());
            Console.Error.WriteLine(error);
            return 1;
        }
    }

    internal static string CopyEvidence(string source, string output)
    {
        var destination = Path.Combine(output, "bundle");
        Directory.CreateDirectory(destination);
        var evidence = BundleLayout.EvidencePath(source);
        Require(!File.Exists(evidence + "-wal") || new FileInfo(evidence + "-wal").Length == 0,
            "A nonempty source WAL requires separate review; do not checkpoint or rewrite the original.");
        var originals = new[] { evidence, BundleLayout.SealPath(source) };
        var records = originals.Select(path => new { Path = path, Sha256 = Hash(path), new FileInfo(path).Length, new FileInfo(path).LastWriteTimeUtc }).ToArray();
        Save(output, "originals-before.json", records);
        foreach (var record in records)
        {
            var target = Path.Combine(destination, Path.GetFileName(record.Path));
            File.Copy(record.Path, target, overwrite: false);
            Require(Hash(target) == record.Sha256 && Hash(record.Path) == record.Sha256
                && new FileInfo(record.Path).LastWriteTimeUtc == record.LastWriteTimeUtc, "Evidence changed while copying.");
        }
        var seal = BundleSealing.ReadSeal(BundleLayout.SealPath(destination));
        Require(seal?.Algorithm == BundleSealing.Algorithm && seal.Hash == Hash(BundleLayout.EvidencePath(destination)), "The copied evidence seal does not match.");
        Save(output, "copy-verification.json", new { Originals = records, CopiesMatch = true, SealMatches = true });
        return destination;
    }

    private static void Inspect(string bundle, string output)
    {
        using var connection = ReadOnly(BundleLayout.EvidencePath(bundle));
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name";
        var tables = new List<(string Name, string Sql)>();
        using (var rows = command.ExecuteReader()) while (rows.Read()) tables.Add((rows.GetString(0), rows.GetString(1)));
        Save(output, "schema.json", tables.Select(t => new { t.Name, t.Sql }));
        command.CommandText = "SELECT COUNT(*),COUNT(DISTINCT domain_fqdn),AVG(LENGTH(distinguished_name)),COALESCE(SUM(ace_count),0),(SELECT COUNT(*) FROM descriptor_entry) FROM captured_object";
        using (var rows = command.ExecuteReader())
        {
            Require(rows.Read(), "Missing stored counts.");
            Save(output, "stored-shape.json", new { Objects = rows.GetInt64(0), DomainFqdns = rows.GetInt64(1), MeanDnLength = rows.GetDouble(2), LogicalAces = rows.GetInt64(3), PhysicalAces = rows.GetInt64(4) });
        }
        var counts = new Dictionary<string, long>();
        foreach (var table in tables.Where(t => t.Name.Contains("member", StringComparison.OrdinalIgnoreCase) || t.Name.Contains("objectclass", StringComparison.OrdinalIgnoreCase)))
        {
            command.CommandText = "SELECT COUNT(*) FROM \"" + table.Name.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
            counts.Add(table.Name, Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture));
        }
        command.CommandText = "SELECT COUNT(*) FROM descriptor_entry JOIN access_entry USING (entry_id) WHERE (access_mask & 262144) != 0";
        counts.Add("PhysicalWriteDacAces", Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture));
        command.CommandText = "SELECT COUNT(*) FROM descriptor_entry JOIN access_entry USING (entry_id) WHERE (access_mask & 40) != 0 AND lower(object_type_guid)='bf9679c0-0de6-11d0-a285-00aa003049e2'";
        counts.Add("PhysicalMemberWriteOrSelfMembershipAces", Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture));
        Save(output, "stored-input-indicators.json", counts);
        Console.WriteLine($"Inspected isolated evidence: {bundle}");
    }

    internal sealed record WorkCounts(int RequesterDacl, int OwnAccountMembership, int MembershipDacl, int PostMembershipDacl,
        int EstablishedPostMembershipDacl, bool QuestionsMatch)
    {
        public bool AllFamiliesExercised => RequesterDacl > 0 && OwnAccountMembership > 0 && MembershipDacl > 0 && PostMembershipDacl > 0 && QuestionsMatch;
    }

    internal static WorkCounts ProofCounts(string path, string output)
    {
        using var connection = ReadOnly(path);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT proof FROM tier0_path_calculation WHERE id=1";
        var text = (string?)command.ExecuteScalar() ?? throw new InvalidDataException("No saved proof header.");
        // Retain the actual questions and proofs, not merely the counters projected by coverage.
        File.WriteAllText(Path.Combine(output, "saved-proof-header.json"), text);
        using var document = JsonDocument.Parse(text);
        var header = document.RootElement;
        var families = new[] { "Requesters", "OwnAccounts", "MembershipDacls" };
        var selected = header.GetProperty("Selection");
        var expected = new HashSet<string>(StringComparer.Ordinal);
        if (selected.ValueKind != JsonValueKind.Null)
            foreach (var candidate in selected.GetProperty("Candidates").EnumerateArray())
                Require(expected.Add(Key(candidate.GetProperty("Family").GetString()!, candidate)), "Duplicate selected question.");
        var actual = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < families.Length; index++)
            foreach (var item in header.GetProperty(families[index]).EnumerateArray())
            {
                var assessment = item.GetProperty("Assessment");
                Require(assessment.GetProperty("GenerationId").GetGuid() == header.GetProperty("Generation").GetGuid(), "Proof belongs to another generation.");
                Require(actual.Add(Key(((PathRequesterFamily)index).ToString(), assessment.GetProperty("Request"))), "Duplicate saved assessment.");
            }
        var match = expected.SetEquals(actual);
        Require(match, "Saved question identities differ from saved proof identities.");
        var combined = header.GetProperty("MembershipDacls").EnumerateArray().Select(p => p.GetProperty("Assessment")).ToArray();
        var afterMembership = combined.Where(p => p.GetProperty("Dacl").ValueKind != JsonValueKind.Null).ToArray();
        var result = new WorkCounts(header.GetProperty("Requesters").GetArrayLength(), header.GetProperty("OwnAccounts").GetArrayLength(), combined.Length,
            afterMembership.Length, afterMembership.Count(p => p.GetProperty("Dacl").GetProperty("Authorization").GetString() == "Established"), match);
        Save(output, "proof-work.json", result);
        return result;
    }

    private static string Key(string family, JsonElement item)
    {
        var group = family == "MembershipDacl" ? item.GetProperty("GroupDn").GetString() : null;
        var permission = family != "RequesterDacl" ? item.GetProperty("PermissionKind").GetString() : null;
        return string.Join('\0', family, item.GetProperty("RequesterDn").GetString()?.ToUpperInvariant(),
            item.GetProperty("TargetDn").GetString()?.ToUpperInvariant(), group?.ToUpperInvariant(), permission);
    }

    private static SqliteConnection ReadOnly(string path)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        connection.Open();
        return connection;
    }

    private static string Hash(string path) => BundleSealing.HashFile(path);
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidDataException(message); }
    private static void Save(string output, string name, object value) => File.WriteAllText(Path.Combine(output, name), JsonSerializer.Serialize(value, Json));

    private sealed class Log(string output) : IRunLog, IDisposable
    {
        private readonly StreamWriter _writer = new(Path.Combine(output, "run-log.jsonl")) { AutoFlush = true };
        public void Note(string phase, string message, IReadOnlyList<RunLogDetail> detail) => Write(phase, message, detail);
        public void Record(string phase, AuditError error, IReadOnlyList<RunLogDetail> detail) => Write(phase, error.Description, detail);
        private void Write(string phase, string message, IReadOnlyList<RunLogDetail> detail)
        {
            _writer.WriteLine(JsonSerializer.Serialize(new { Utc = DateTimeOffset.UtcNow, Phase = phase, Message = message, Detail = detail }));
            if (message == "path-requester-phase") Console.WriteLine(string.Join(" ", detail.Select(d => d.Name + "=" + d.Value)));
        }
        public void Dispose() => _writer.Dispose();
    }

    private sealed class Observer : IProgress<JudgingRun.JudgingProgress>, IDisposable
    {
        private readonly object _gate = new();
        private readonly StreamWriter _writer;
        private readonly CancellationTokenSource _stopping;
        private readonly PathRequesterWorkPhase? _cancel;
        private readonly int _delay;
        private readonly Timer _sampler;
        private Timer? _canceller;
        private readonly Process _process = Process.GetCurrentProcess();
        private string? _phase;
        private long _started, _allocated, _peakWorking, _peakPrivate;
        private bool _armed;
        private long? _cancelledAt;
        private string? _phaseAtCancellation;
        private double? _elapsedAtCancellation;
        private long? _allocationsBeforeCancellation;
        private double? _responseMs;
        internal object Cancellation => new { RequestedPhase = _cancel, DelayMs = _delay, ActualPhase = _phaseAtCancellation,
            ElapsedInPhaseMs = _elapsedAtCancellation, ManagedBytesBeforeRequest = _allocationsBeforeCancellation, ResponseMs = _responseMs };
        internal bool MidWorkCancellation => _phaseAtCancellation == _cancel?.ToString() && _elapsedAtCancellation > 0 && _allocationsBeforeCancellation > 0;

        internal Observer(string output, CancellationTokenSource stopping, PathRequesterWorkPhase? cancel, int delay)
        {
            _writer = new StreamWriter(Path.Combine(output, "phase-memory.jsonl")) { AutoFlush = true };
            _stopping = stopping; _cancel = cancel; _delay = delay;
            _sampler = new Timer(_ => { lock (_gate) Sample(); }, null, 20, 20);
        }
        public void Report(JudgingRun.JudgingProgress value)
        {
            if (value.RequesterPhase is { } phase)
            {
                Enter(phase.ToString());
                if (phase == _cancel && !_armed)
                {
                    _armed = true;
                    _canceller = new Timer(_ =>
                    {
                        lock (_gate)
                        {
                            _cancelledAt = Stopwatch.GetTimestamp(); _phaseAtCancellation = _phase;
                            _elapsedAtCancellation = Stopwatch.GetElapsedTime(_started).TotalMilliseconds;
                            _allocationsBeforeCancellation = GC.GetTotalAllocatedBytes(true) - _allocated;
                            _stopping.Cancel();
                        }
                    }, null, _delay, Timeout.Infinite);
                }
            }
            else if (value.Phase == JudgingPhase.PublishingJudgement) Enter("PublishingJudgement");
        }
        internal void Enter(string phase)
        {
            lock (_gate)
            {
                Flush(); _phase = phase; _started = Stopwatch.GetTimestamp(); _allocated = GC.GetTotalAllocatedBytes(true);
                _peakWorking = 0; _peakPrivate = 0; Sample();
            }
        }
        internal void EndCancellation()
        {
            if (_canceller is not null) _canceller.DisposeAsync().AsTask().GetAwaiter().GetResult();
            lock (_gate) if (_cancelledAt.HasValue) _responseMs = Stopwatch.GetElapsedTime(_cancelledAt.Value).TotalMilliseconds;
        }
        private void Sample()
        {
            _process.Refresh();
            _peakWorking = Math.Max(_peakWorking, _process.WorkingSet64);
            _peakPrivate = Math.Max(_peakPrivate, _process.PrivateMemorySize64);
        }
        private void Flush()
        {
            if (_phase is null) return;
            Sample();
            _writer.WriteLine(JsonSerializer.Serialize(new { Phase = _phase, Ms = Stopwatch.GetElapsedTime(_started).TotalMilliseconds,
                AllocatedBytes = GC.GetTotalAllocatedBytes(true) - _allocated, SampledPeakWorkingSetBytes = _peakWorking,
                SampledPeakPrivateBytes = _peakPrivate, ProcessLifetimePeakWorkingSetBytes = _process.PeakWorkingSet64 }));
        }
        public void Dispose()
        {
            _sampler.DisposeAsync().AsTask().GetAwaiter().GetResult();
            if (_canceller is not null) _canceller.DisposeAsync().AsTask().GetAwaiter().GetResult();
            lock (_gate) { Flush(); _phase = null; _writer.Dispose(); _process.Dispose(); }
        }
    }
}
