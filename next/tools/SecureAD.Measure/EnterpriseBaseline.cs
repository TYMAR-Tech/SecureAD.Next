using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Measure;

internal static class EnterpriseBaseline
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
    private static readonly string[] UnavailableEndpoints =
    [
        "process-entry/first-paint", "complete UI rendering and interaction",
        "per-SQL command/row timing", "content-assembly timing", "verification duration/bytes",
        "process I/O and GC pause events", "observer off/on overhead calibration",
        "enterprise input eligibility", "full fixed campaign matrix",
    ];

    internal static int Run(string[] args)
    {
        if (args.Length != 3 || args[0] != "control")
            throw new ArgumentException("--enterprise-baseline control NEW_OUTPUT BUILD_RECORD is required; no enterprise campaign is started implicitly.");
        var build = JsonSerializer.Deserialize<EnterpriseBuildRecord>(File.ReadAllText(args[2]))
            ?? throw new InvalidDataException("The measurement build record is empty.");
        VerifyBuild(build);
        var output = CreateOutput(args[1]);
        Save(output, "provenance.json", new
        {
            Build = build, Runtime = RuntimeInformation.FrameworkDescription, OS = RuntimeInformation.OSDescription,
            Architecture = RuntimeInformation.ProcessArchitecture, ProcessorCount = Environment.ProcessorCount,
            RequesterPolicy = JudgingRun.ProductionPathRequesterPolicy.ToString(), LegacyDiscoveryBudget = "null",
            Rules = RuleCatalogue.All.Count, Synthetic = true, Workload = "CTRL75 producer/readback foundation",
            EnterpriseBaseline = false, UiMeasured = false, SampleIntervalMs = 100,
            TimingScope = "Synthetic writer and offline stages, not GUI coordination, live acquisition or a complete operator journey",
            VerificationScope = "Control-owned opens including independent inspection; not a measurement of real UI handoff lifetimes",
            AllocationMethod = "Process-wide deltas include observer/logging overhead; off/on calibration outstanding",
            MemoryMethod = "Sampled private/working bytes and process-lifetime peak working set, not per-stage private-memory peaks",
            Limits = new { Hours = 24, ScratchGiB = 192, FreeReserveGiB = 32,
                PrivateBytes = Math.Min(48L * 1024 * 1024 * 1024, build.PhysicalMemoryBytes / 4 * 3) },
        });
        using var stopping = new CancellationTokenSource();
        ConsoleCancelEventHandler cancel = (_, eventArgs) => { eventArgs.Cancel = true; stopping.Cancel(); };
        Console.CancelKeyPress += cancel;
        try
        {
            using var observation = new EnterpriseBaselineObservation(output, build.PhysicalMemoryBytes, stopping);
            var run = Path.Combine(output, "run");
            Directory.CreateDirectory(run);
            var seal = observation.Measure("SyntheticCaptureWriteAndSeal",
                () => EnterpriseControlWorkload.Write(run, observation.Token));
            var captured = observation.Measure("IndependentCapturedCounts", () => InspectCaptured(run));
            RequireControlCounts(captured);
            var derived = observation.Measure("Derivation", () => Stage2aRun.Derive(run, ExpansionBudget.Bulk,
                EnterpriseControlWorkload.When, Stage2aRun.Unwatched, observation, observation.Token));
            Require(derived.IsSuccess, derived.Error?.Description ?? "Derivation did not complete.");
            var judged = observation.Measure("Judgement", () => JudgingRun.JudgeAudit(run, RuleCatalogue.All,
                JudgingRun.ProductionPathRequesterPolicy, EnterpriseControlWorkload.When,
                EnterpriseControlWorkload.When, JudgingRun.NobodyIsWatching, observation, observation.Token, null));
            Require(judged.IsSuccess, judged.Error?.Description ?? "Judgement did not complete.");
            var saved = observation.Measure("SavedControlReadback", () => InspectSaved(run, observation.Token));
            Require(saved.RuleExecutions == RuleCatalogue.All.Count && saved.Findings > 0
                && saved.Groups == EnterpriseControlWorkload.Domains * EnterpriseControlWorkload.GroupsPerDomain
                && saved.LapsComputers == EnterpriseControlWorkload.Domains * EnterpriseControlWorkload.ComputersPerDomain
                && saved.ClassifiedTier0Objects > 0 && saved.DirectPermissionRowsFirstPage > 0,
                "The control did not exercise its nonempty saved answers.");
            VerifyBuild(build);
            observation.Dispose();
            Require(observation.ResourceSamples > 0 && observation.Verifications.Values.Sum() > 0,
                "The control did not observe resource samples and actual verification attempts.");
            var files = FingerprintProducts(run);
            Save(output, "control-result.json", new
            {
                State = "ControlProducedAndReadBack", EnterpriseBaselineComplete = false,
                ResponseBudgetsEstablished = false, UiMeasured = false, Captured = captured, Saved = saved,
                Seal = seal, Stages = observation.Stages, VerificationAttempts = observation.Verifications,
                ResourceSamples = observation.ResourceSamples, OutputFingerprints = files, Unavailable = UnavailableEndpoints,
                FingerprintScope = "Completed sealed data/seals and publication manifests; excludes mutable annotations and SQLite sidecars; does not confer reusable verification",
            });
            Console.WriteLine("Control produced and read back. This is not the whole-journey or enterprise baseline.");
            Console.WriteLine("Retained outputs: " + output);
            return 0;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException
            or OperationCanceledException or SqliteException)
        {
            Save(output, "failure.json", new { State = "FailedControlAttempt", Error = error.ToString(),
                EnterpriseBaselineComplete = false });
            Console.Error.WriteLine(error);
            return 1;
        }
        finally { Console.CancelKeyPress -= cancel; }
    }

    internal static string CreateOutput(string path)
    {
        var full = Path.GetFullPath(path);
        if (Directory.Exists(full) || File.Exists(full))
            throw new IOException("Measurement output already exists; retained attempts must not be overwritten.");
        Directory.CreateDirectory(full);
        return full;
    }

    internal static void VerifyBuild(EnterpriseBuildRecord build)
    {
        Require(build.PhysicalMemoryBytes > 0, "Physical-memory provenance is required.");
        Require(Path.GetFullPath(build.BinaryRoot).TrimEnd(Path.DirectorySeparatorChar)
            .Equals(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase),
            "The build record belongs to another binary output.");
        var expected = Path.GetFullPath(Path.Combine(build.SourceRoot, "next", "tools", "SecureAD.Measure", "EnterpriseBaseline.cs"));
        Require(expected.Equals(CompiledSource(), StringComparison.OrdinalIgnoreCase),
            "The measured executable was compiled from another source tree.");
        Require(build.Sources.Count > 0 && build.Binaries.Count > 0, "Source and binary fingerprints are required.");
        foreach (var input in build.Sources) VerifyFingerprint(build.SourceRoot, input);
        foreach (var binary in build.Binaries) VerifyFingerprint(build.BinaryRoot, binary);
    }

    internal static void VerifyFingerprint(string root, EnterpriseFingerprint fingerprint)
    {
        var prefix = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var path = Path.GetFullPath(Path.Combine(prefix, fingerprint.Path));
        Require(path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase), "A build fingerprint escapes its declared root.");
        Require(File.Exists(path), "A fingerprinted build input is missing: " + path);
        Require(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))
            .Equals(fingerprint.Sha256, StringComparison.OrdinalIgnoreCase), "A build fingerprint changed: " + path);
    }

    internal static EnterpriseCapturedCounts InspectCaptured(string run)
    {
        using var reader = RequireValue(BundleReader.Open(run));
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = BundleLayout.EvidencePath(run), Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        connection.Open();
        using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT (SELECT COUNT(*) FROM captured_object),
                   (SELECT COUNT(*) FROM member_value),
                   (SELECT COUNT(*) FROM descriptor_entry),
                   (SELECT COUNT(*) FROM object_security_descriptor),
                   (SELECT COUNT(*) FROM partition_coverage)
            """;
        using var row = query.ExecuteReader();
        Require(row.Read(), "The captured counters were not read.");
        return new(reader.Description.SchemaVersion, row.GetInt64(0), row.GetInt64(1), row.GetInt64(2),
            row.GetInt64(3), row.GetInt64(4));
    }

    internal static void RequireControlCounts(EnterpriseCapturedCounts counts) =>
        Require(counts.EvidenceVersion == 17 && counts.Objects == EnterpriseControlWorkload.Objects
            && counts.MemberOccurrences == EnterpriseControlWorkload.MemberOccurrences
            && counts.DescriptorPositions == 7 && counts.DescriptorLinks == EnterpriseControlWorkload.Objects
            && counts.CapturedPartitions == 5, "Independent captured counts do not match the CTRL75 recipe.");

    internal static IReadOnlyList<EnterpriseProductFingerprint> FingerprintProducts(string run) =>
        Directory.EnumerateFiles(run, "*", SearchOption.AllDirectories)
            .Where(path => path.EndsWith(".seal", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".current.json", StringComparison.OrdinalIgnoreCase)
                || File.Exists(path + ".seal"))
            .Order(StringComparer.Ordinal)
            .Select(path =>
            {
                using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                return new EnterpriseProductFingerprint(Path.GetRelativePath(run, path), input.Length,
                    Convert.ToHexString(SHA256.HashData(input)));
            }).ToArray();

    private static EnterpriseSavedControl InspectSaved(string run, CancellationToken token)
    {
        using var evidence = RequireValue(BundleReader.Open(run));
        using var derivation = RequireValue(DerivationReader.Open(run));
        using var judgement = RequireValue(JudgementReader.Open(run, token));
        var root = RequireValue(AnalysisStoreLifecycle.ResolveRoot(run, AnalysisStoreKind.Judgement));
        var executions = judgement.ReadRuleExecutions();
        var groups = judgement.ReadGroupInventory(new(null, ListingScope.Subtree, "", GroupInventoryScope.All,
            GroupInventoryKind.All, false, GroupInventorySort.Name), null, token);
        var tier0 = judgement.ReadTier0Overview(Tier0OverviewScope.All, null, token)
            ?? throw new InvalidDataException("The control has no saved Tier 0 overview.");
        var laps = 0;
        for (var domain = 0; domain < EnterpriseControlWorkload.Domains; domain++)
        {
            var query = new LapsQuery(EnterpriseControlWorkload.Accounts(domain), ListingScope.OneLevel, "", null);
            laps += judgement.ListLapsComputers(query, null,
                evidence.ReadListingCoverage(query.Container, query.Scope), token).Total;
        }
        var direct = evidence.ReadDelegations(new(new(null, "S-1-5-11", "Authenticated Users", null, null),
            DelegationPermission.All, true), null, token);
        return new(derivation.Description.SchemaVersion, root.Segment(StoreSegmentRole.Judgement).SchemaVersion,
            judgement.Description.EvidenceSeal, evidence.Description.CaptureGenerationId,
            derivation.Description.GenerationId, judgement.Description.GenerationId,
            executions.Executions.Count, executions.Executions.Sum(rule => rule.FindingsProduced), groups.Total,
            laps, tier0.Summary.ClassifiedTier0Objects, direct.Entries.Count, direct.Next is not null);
    }

    private static T RequireValue<T>(Result<T> result) =>
        result.IsSuccess ? result.Value : throw new InvalidDataException(result.Error.Description);

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidDataException(message);
    }

    private static string CompiledSource([CallerFilePath] string path = "") => Path.GetFullPath(path);

    private static void Save(string directory, string name, object value) =>
        File.WriteAllText(Path.Combine(directory, name), JsonSerializer.Serialize(value, Json));
}

internal sealed record EnterpriseFingerprint(string Path, string Sha256);
internal sealed record EnterpriseProductFingerprint(string Path, long Bytes, string Sha256);
internal sealed record EnterpriseBuildRecord(string SourceRoot, string BinaryRoot, long PhysicalMemoryBytes,
    IReadOnlyList<EnterpriseFingerprint> Sources, IReadOnlyList<EnterpriseFingerprint> Binaries);
internal sealed record EnterpriseCapturedCounts(int EvidenceVersion, long Objects, long MemberOccurrences,
    long DescriptorPositions, long DescriptorLinks, long CapturedPartitions);
internal sealed record EnterpriseSavedControl(int DerivationVersion, int JudgementVersion, string EvidenceSeal, Guid CaptureGeneration,
    Guid DerivationGeneration, Guid JudgementGeneration, int RuleExecutions, int Findings, int Groups,
    int LapsComputers, int ClassifiedTier0Objects, int DirectPermissionRowsFirstPage, bool DirectPermissionsHaveMore);
