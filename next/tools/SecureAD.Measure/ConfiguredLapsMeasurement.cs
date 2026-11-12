using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Measure;

internal sealed record ConfiguredLapsScenario(ConfiguredLapsShape Shape, Guid CaptureGeneration,
    string EvidenceSeal, IReadOnlyList<EnterpriseProductFingerprint> Inputs);
internal sealed record ConfiguredLapsScope(string Policy, string State, long Observed, long Considered,
    long Calculated, long Unassessed, Guid Generation, Guid CaptureGeneration, string EvidenceSeal);
internal sealed record ConfiguredLapsCapturedCounts(long Objects, long Computers, long Policies, long Filters, long Partitions);
internal sealed record ConfiguredLapsMixedCounts(long WindowsPolicies, long LegacyPolicies, long UnrelatedPolicies,
    long LinkedPolicies, long UnlinkedPolicies);

internal static class ConfiguredLapsMeasurement
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    internal static int Run(string[] args)
    {
        if (args.Length == 7 && args[0] is "generate" or "generate-mixed")
            return Generate(args[1], args[2], new(Parse(args[3]), Parse(args[4]), Parse(args[5]), Parse(args[6]))
            {
                Profile = args[0] == "generate-mixed" ? ConfiguredLapsWorkloadProfile.MixedLegacyWindows : ConfiguredLapsWorkloadProfile.AllWindowsLaps,
            });
        if (args.Length is 5 or 6 && args[0] is "judge" or "judge-timing"
            && Enum.TryParse<ConfiguredLapsPolicy>(args[4], out var policy) && Enum.IsDefined(policy)
            && policy.ToString() == args[4])
            return Judge(args[1], args[2], args[3], policy, args.Length == 6 ? Parse(args[5]) : null, WorkCountersEnabled(args[0]));
        throw new ArgumentException("--configured-laps generate|generate-mixed NEW_OUTPUT BUILD_RECORD COMPUTERS POLICIES GROUP_DEPTH FILLER | judge|judge-timing SCENARIO NEW_OUTPUT BUILD_RECORD Disabled|AllCapturedComputers [CANCEL_AFTER_QUESTIONS]");
    }

    internal static bool WorkCountersEnabled(string operation) => operation switch
    {
        "judge" => true,
        "judge-timing" => false,
        _ => throw new ArgumentException("Unknown judging observation mode.", nameof(operation)),
    };

    private static int Generate(string path, string buildPath, ConfiguredLapsShape shape)
    {
        shape.Validate();
        var build = Read<EnterpriseBuildRecord>(buildPath);
        EnterpriseBaseline.VerifyBuild(build);
        var output = EnterpriseBaseline.CreateOutput(path);
        try
        {
            var bundle = Path.Combine(output, "bundle");
            Directory.CreateDirectory(bundle);
            ConfiguredLapsWorkload.Write(bundle, shape, CancellationToken.None);
            var counts = InspectCaptured(bundle);
            if (counts.Objects != shape.Objects || counts.Computers != shape.Computers
                || counts.Policies != 9L * shape.PoliciesPerDomain || counts.Filters != 18 || counts.Partitions != 11)
                throw new InvalidDataException("Generated source counts do not match the independent workload recipe.");
            var derived = Stage2aRun.Derive(bundle, ExpansionBudget.Bulk, ConfiguredLapsWorkload.When,
                Stage2aRun.Unwatched, RunLog.Discarded, CancellationToken.None);
            Require(derived.IsSuccess, derived.Error?.Description ?? "Derivation failed.");
            using var reader = BundleReader.Open(bundle).Value;
            var scenario = new ConfiguredLapsScenario(shape, reader.Description.CaptureGenerationId,
                AnalysisStoreLifecycle.ResolveRoot(bundle, AnalysisStoreKind.Derivation).Value.EvidenceSeal,
                EnterpriseBaseline.FingerprintProducts(bundle));
            Save(output, "scenario.json", scenario);
            Save(output, "source-counts.json", counts);
            if (shape.Profile == ConfiguredLapsWorkloadProfile.MixedLegacyWindows)
            {
                var mixed = InspectMixedCaptured(bundle);
                var expectedLinked = 9L * shape.LinkedPoliciesPerDomain;
                Require(mixed == new ConfiguredLapsMixedCounts(9, 9, 9L * (shape.PoliciesPerDomain - 2),
                    expectedLinked, 9L * shape.PoliciesPerDomain - expectedLinked), "Mixed-policy populations differ from the independent recipe.");
                Save(output, "mixed-source-counts.json", mixed);
            }
            EnterpriseBaseline.VerifyBuild(build);
            Console.WriteLine("Generated and derived synthetic scenario: " + output);
            return 0;
        }
        catch (Exception error) when (error is IOException or InvalidOperationException or SqliteException or UnauthorizedAccessException)
        {
            Save(output, "failure.json", new { State = "FailedSyntheticGeneration", Error = error.ToString() });
            Console.Error.WriteLine(error);
            return 1;
        }
    }

    private static int Judge(string scenarioPath, string path, string buildPath, ConfiguredLapsPolicy policy, int? cancelAfter, bool workCounters)
    {
        var scenarioRoot = Path.GetFullPath(scenarioPath);
        var scenario = Read<ConfiguredLapsScenario>(Path.Combine(scenarioRoot, "scenario.json"));
        scenario.Shape.Validate();
        if (cancelAfter is { } after && (policy != ConfiguredLapsPolicy.AllCapturedComputers
            || after < 1000 || after % 1000 != 0 || after >= scenario.Shape.Computers))
            throw new ArgumentException("Mid-calculation cancellation requires an enabled scenario larger than its positive 1,000-question progress boundary.");
        var build = Read<EnterpriseBuildRecord>(buildPath);
        EnterpriseBaseline.VerifyBuild(build);
        var output = EnterpriseBaseline.CreateOutput(path);
        var bundle = Path.Combine(scenarioRoot, "bundle");
        try
        {
            Save(output, "provenance.json", new
            {
                Build = build, Scenario = scenario, Policy = policy.ToString(), CancelAfterQuestions = cancelAfter,
                Rules = RuleCatalogue.All.Count, RequesterPolicy = JudgingRun.ProductionPathRequesterPolicy.ToString(),
                ProductionConfiguredLapsPolicy = JudgingRun.ProductionConfiguredLapsPolicy.ToString(),
                FreshProcess = true, FilesystemCacheControlled = false, ProductionAcceptance = false,
                MemoryMethod = "100-ms sampled process private/working bytes; OS peak working set is process-lifetime, not additional LAPS memory",
                TimingMethod = "Whole JudgeAudit including source verification, ordinary rules, other enabled host work and publication; generator, derivation and independent readback excluded",
                ObserverOverheadCalibrated = false,
                WorkCountersEnabled = workCounters,
                CounterInterpretation = "Empty counter dictionaries mean not observed, never zero work; an older product may not publish later diagnostics",
                NameLookupCounterScope = "Timed JudgeAudit only, summed across its reader-local caches and listed SQLite sources; requests and cache hits are logical operations, *-sql counts are statement attempts, exact-hit counts successful exact-name attempts; misses are requests minus cache hits",
                NameLookupCounterOverhead = workCounters ? "Enabled for every lookup; aggregate counters only, no per-lookup SQL trace; uncalibrated"
                    : "Per-operation measurement listeners disabled for primary timings; phase logs and process sampling retained",
                GpoPreparationCounterScope = "Timed JudgeAudit only; GpoPreparations counts source-scoped preparation/read operations, not individual SQL statements; NativePreparations counts actual COM WQL Parse attempts and registry ReadInstructions executions across the whole single-audit process, including ordinary rules",
                SourceGuardCounterScope = "Timed JudgeAudit, selected bundle only; logical owned-scope requests retained by RequireCurrent/RequireCurrentWith, fresh capture/derivation resolution attempts and aggregated validation milliseconds; samples count invocations, not logical scopes; no verdict is cached across calls; initial cancelled/disposed lifetime refusal is excluded",
                SelectionManifestReadScope = "Independent counter at actual selected-root stream opening/deserialization; all capture/derivation/judgement root readers in the timed selected-bundle audit, not just JudgingInputs guards",
            });
            var previous = AnalysisStoreLifecycle.ResolveRoot(bundle, AnalysisStoreKind.Judgement);
            if (cancelAfter.HasValue && !previous.IsSuccess)
                throw new InvalidDataException("Cancellation needs a previous completed generation.");
            var previousInputs = cancelAfter.HasValue ? EnterpriseBaseline.FingerprintProducts(bundle) : [];
            using var stopping = new CancellationTokenSource();
            using var observer = new EnterpriseBaselineObservation(output, build.PhysicalMemoryBytes, stopping, workCounters ? bundle : null);
            var progress = new CancellationProgress(stopping, cancelAfter);
            var allocated = GC.GetTotalAllocatedBytes(true);
            var watch = Stopwatch.StartNew();
            var cancelled = false;
            try
            {
                var result = observer.Measure("Judgement", () =>
                {
                    using var files = new ProtectedRunFiles(bundle);
                    return JudgingRun.JudgeAudit(bundle, RuleCatalogue.All, JudgingRun.ProductionPathRequesterPolicy,
                        ConfiguredLapsWorkload.When, ConfiguredLapsWorkload.When, progress, observer, stopping.Token,
                        null, files, policy);
                });
                Require(result.IsSuccess, result.Error?.Description ?? "Judgement failed.");
            }
            catch (OperationCanceledException) when (stopping.IsCancellationRequested)
            {
                cancelled = true;
            }
            watch.Stop();
            var cancellationToReturnMs = progress.RequestedAt is { } requested
                ? Stopwatch.GetElapsedTime(requested).TotalMilliseconds : (double?)null;
            var allocatedBytes = GC.GetTotalAllocatedBytes(true) - allocated;
            observer.Dispose();
            var selected = AnalysisStoreLifecycle.ResolveRoot(bundle, AnalysisStoreKind.Judgement).Value;
            if (cancelAfter.HasValue)
            {
                Require(cancelled && progress.RequestedAt is not null && progress.CompletedQuestions < scenario.Shape.Computers,
                    "The intended mid-calculation cancellation did not occur; this is a missed attempt, not a successful measurement.");
                Require(selected.GenerationId == previous.Value.GenerationId, "Cancellation replaced the previous completed generation.");
                VerifyInputs(bundle, previousInputs.Where(input => input.Path != "judgement.current.json"));
            }
            else Require(!cancelled, "A safety cancellation is not a completed judging measurement.");
            VerifyInputs(bundle, scenario.Inputs);
            ConfiguredLapsScope? scope = null;
            if (!cancelled)
            {
                using var reader = JudgementReader.Open(bundle).Value;
                scope = ReadScope(bundle);
                ValidateScope(scope, policy, scenario, reader.Description.GenerationId);
                if (policy == ConfiguredLapsPolicy.AllCapturedComputers)
                    InspectSavedQuestions(bundle, scenario, selected);
            }
            EnterpriseBaseline.VerifyBuild(build);
            using var process = Process.GetCurrentProcess();
            process.Refresh();
            Save(output, "result.json", new
            {
                State = cancelled ? "CancelledMidCalculationPreviousGenerationPreserved" : "MeasuredCompletedJudgement",
                Policy = policy.ToString(), JudgementMs = watch.Elapsed.TotalMilliseconds, ManagedAllocatedBytes = allocatedBytes,
                ProcessLifetimePeakWorkingSetBytes = process.PeakWorkingSet64,
                ResourceSamples = observer.ResourceSamples, Stages = observer.Stages, Scope = scope,
                SelectedGeneration = selected.GenerationId, PreviousGeneration = previous.IsSuccess ? previous.Value.GenerationId : (Guid?)null,
                CancelAfterQuestions = cancelAfter, progress.CompletedQuestions,
                CancellationToReturnMs = cancellationToReturnMs,
                JudgementBytes = new[] { StoreSegmentRole.Judgement, StoreSegmentRole.JudgementFacts,
                    StoreSegmentRole.PermissionProof, StoreSegmentRole.PathProof }
                    .Sum(role => new FileInfo(Path.Combine(bundle, selected.Segment(role).FileName)).Length),
                SourceInputsUnchanged = true, WorkCountersEnabled = workCounters, ProductionAcceptance = false,
                NameLookups = observer.NameLookups,
                NameLookupSources = observer.NameLookupSources,
                GpoPreparations = observer.GpoPreparations, NativePreparations = observer.NativePreparations,
                SourceGuards = observer.SourceGuards, SourceGuardMilliseconds = observer.SourceGuardMilliseconds,
                SourceGuardSamples = observer.SourceGuardSamples,
                SelectionManifestReads = observer.SelectionManifestReads,
            });
            Console.WriteLine("Measured synthetic judgement: " + output);
            return 0;
        }
        catch (Exception error) when (error is IOException or InvalidOperationException or SqliteException or UnauthorizedAccessException)
        {
            Save(output, "failure.json", new { State = "FailedMeasurementAttempt", Error = error.ToString(), ProductionAcceptance = false });
            Console.Error.WriteLine(error);
            return 1;
        }
    }

    internal static ConfiguredLapsScope ReadScope(string bundle)
    {
        var root = AnalysisStoreLifecycle.ResolveRoot(bundle, AnalysisStoreKind.Judgement).Value;
        using var connection = Open(Path.Combine(bundle, root.Segment(StoreSegmentRole.Judgement).FileName));
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT policy,state,observed,considered,calculated,unassessed,generation,capture_generation,evidence_seal FROM laps_configured_scope";
        using var row = command.ExecuteReader();
        if (!row.Read()) throw new InvalidDataException("The selected generation has no automatic LAPS scope.");
        var value = new ConfiguredLapsScope(row.GetString(0), row.GetString(1), row.GetInt64(2), row.GetInt64(3),
            row.GetInt64(4), row.GetInt64(5), Guid.Parse(row.GetString(6)), Guid.Parse(row.GetString(7)), row.GetString(8));
        if (row.Read()) throw new InvalidDataException("Automatic LAPS scope is not a singleton.");
        return value;
    }

    internal static void ValidateScope(ConfiguredLapsScope scope, ConfiguredLapsPolicy policy,
        ConfiguredLapsScenario scenario, Guid generation)
    {
        Require(scope.Generation == generation && scope.CaptureGeneration == scenario.CaptureGeneration
            && scope.EvidenceSeal == scenario.EvidenceSeal && scope.Policy == policy.ToString()
            && scope.Observed == scenario.Shape.Computers, "Measured scope is bound to another source or question population.");
        var enabled = policy == ConfiguredLapsPolicy.AllCapturedComputers;
        Require(scope.State == (enabled ? "Complete" : "Disabled")
            && scope.Considered == (enabled ? scope.Observed : 0)
            && scope.Calculated == (enabled ? scope.Observed : 0)
            && scope.Unassessed == (enabled ? 0 : scope.Observed),
            "The measurement did not calculate every required question or mislabeled disabled scope.");
    }

    internal static ConfiguredLapsCapturedCounts InspectCaptured(string bundle)
    {
        using var connection = Open(BundleLayout.EvidencePath(bundle));
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT (SELECT COUNT(*) FROM captured_object),
                (SELECT COUNT(*) FROM captured_object o WHERE
                    (SELECT value FROM objectclass_value WHERE object_id=o.object_id ORDER BY ordinal DESC LIMIT 1)='computer'),
                (SELECT COUNT(*) FROM objectclass_value WHERE value='groupPolicyContainer'),
                (SELECT COUNT(*) FROM objectclass_value WHERE value='msWMI-Som'),
                (SELECT COUNT(*) FROM partition_coverage)
            """;
        using var row = command.ExecuteReader();
        if (!row.Read()) throw new InvalidDataException("Generated source counters are unavailable.");
        return new(row.GetInt64(0), row.GetInt64(1), row.GetInt64(2), row.GetInt64(3), row.GetInt64(4));
    }

    internal static ConfiguredLapsMixedCounts InspectMixedCaptured(string bundle)
    {
        using var connection = Open(BundleLayout.EvidencePath(bundle));
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT COUNT(DISTINCT CASE WHEN key_path=$windows COLLATE NOCASE THEN gpo_guid END),
                COUNT(DISTINCT CASE WHEN key_path=$legacy COLLATE NOCASE THEN gpo_guid END),
                COUNT(DISTINCT CASE WHEN key_path=$other COLLATE NOCASE THEN gpo_guid END)
            FROM gpo_registry_setting WHERE scope='Machine'
            """;
        command.Parameters.AddWithValue("$windows", ConfiguredLapsWorkload.RegistryKey);
        command.Parameters.AddWithValue("$legacy", ConfiguredLapsWorkload.LegacyRegistryKey);
        command.Parameters.AddWithValue("$other", ConfiguredLapsWorkload.UnrelatedRegistryKey);
        long windows, legacy, other;
        using (var row = command.ExecuteReader())
        {
            if (!row.Read()) throw new InvalidDataException("Mixed-policy counts are unavailable.");
            windows = row.GetInt64(0); legacy = row.GetInt64(1); other = row.GetInt64(2);
        }
        using var reader = BundleReader.Open(bundle).Value;
        var linked = Enumerable.Range(0, 9).Sum(domain =>
            SecureAD.Kernel.GroupPolicy.PolicyLinkList.Of(reader.ReadObjectAttributes(ConfiguredLapsWorkload.Domain(domain), ["gPLink"])!
                .Find("gPLink")!.OnlyValue!.Text).Links.Count);
        return new(windows, legacy, other, linked, windows + legacy + other - linked);
    }

    private static void InspectSavedQuestions(string bundle, ConfiguredLapsScenario scenario, StoreRootManifest root)
    {
        using var connection = Open(Path.Combine(bundle, root.Segment(StoreSegmentRole.JudgementFacts).FileName));
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM laps_configured_calculation";
        Require((long)command.ExecuteScalar()! == scenario.Shape.Computers, "Saved calculation row count differs from the measured population.");
        command.CommandText = """
            SELECT payload FROM laps_configured_calculation WHERE computer_id IN
                ((SELECT MIN(computer_id) FROM laps_configured_calculation),(SELECT MAX(computer_id) FROM laps_configured_calculation))
            """;
        using var rows = command.ExecuteReader();
        var inspected = 0;
        while (rows.Read())
        {
            using var payload = JsonDocument.Parse(rows.GetString(0));
            var value = payload.RootElement;
            Require(value.GetProperty("CaptureGenerationId").GetGuid() == scenario.CaptureGeneration
                && value.GetProperty("JudgementGenerationId").GetGuid() == root.GenerationId
                && value.GetProperty("Settings").GetArrayLength() == 4
                && value.GetProperty("Policies").GetArrayLength() == scenario.Shape.LinkedPoliciesPerDomain
                && !value.GetProperty("IsObservedWmiResult").GetBoolean()
                && value.GetProperty("HasOpenPolicyScope").GetBoolean()
                && !string.IsNullOrWhiteSpace(value.GetProperty("DirectoryAssumption").GetString()),
                "The saved sample does not retain real configured questions and qualified assumptions.");
            inspected++;
        }
        Require(inspected == 2, "Both boundary questions were not inspected.");
    }

    private static void VerifyInputs(string root, IEnumerable<EnterpriseProductFingerprint> inputs)
    {
        foreach (var input in inputs)
            EnterpriseBaseline.VerifyFingerprint(root, new(input.Path, input.Sha256));
    }
    private static SqliteConnection Open(string path)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = path, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        connection.Open();
        return connection;
    }
    private static T Read<T>(string path) => JsonSerializer.Deserialize<T>(File.ReadAllText(path))
        ?? throw new InvalidDataException("Measurement input is empty.");
    private static void Save(string output, string name, object value)
    {
        using var file = new FileStream(Path.Combine(output, name), FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        JsonSerializer.Serialize(file, value, Json);
    }
    private static int Parse(string value) => int.Parse(value, NumberStyles.Integer, CultureInfo.InvariantCulture);
    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidDataException(message);
    }
    private sealed class CancellationProgress(CancellationTokenSource stopping, int? after) : IProgress<JudgingRun.JudgingProgress>
    {
        internal long? RequestedAt { get; private set; }
        internal long CompletedQuestions { get; private set; }
        public void Report(JudgingRun.JudgingProgress value)
        {
            if (value.Phase != JudgingPhase.EvaluatingObjects || value.WorkUnit != JudgingWorkUnit.Resources
                || value.WorkCompleted is not { } completed) return;
            CompletedQuestions = completed;
            if (after is { } boundary && completed >= boundary && RequestedAt is null)
            {
                RequestedAt = Stopwatch.GetTimestamp();
                stopping.Cancel();
            }
        }
    }
}
