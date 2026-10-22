using System.Security.Cryptography;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using Xunit;
using static SecureAD.Next.Tests.Judgement.JudgingStatusTests;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class PostPassDiagnosticsTests
{
    private static readonly Guid Generation = Guid.Parse("75a675e2-cade-4f49-a599-f1c8c0aec624");
    private static PostPassMemory Memory() => new(11, 22, 33, 44, 5, 6, 7, "available");

    [Fact]
    public void HeartbeatShowsActiveWorkWithoutInventingTargetOrScreenProgress()
    {
        var log = new StatusLog();
        var clock = new TimerClock();
        var screen = new Screen();
        using var status = new JudgingStatus(log, screen, clock, Memory);
        status.CompleteObject(7);
        using var diagnostic = status.BeginPostPass("ownership-assessment", Generation);
        diagnostic.Targets(2);
        diagnostic.Part("read-evidence");
        var beforeTimer = screen.Calls;
        Assert.Equal(1, beforeTimer);
        clock.Advance(TimeSpan.FromMinutes(1));
        var line = Assert.Single(log.Lines.Where(item => item.Message == "post-pass status" && item.Value("outcome") == "running"));
        Assert.Equal(("read-evidence", "60000", "0", "2", Generation.ToString("D")),
            (line.Value("activePart"), line.Value("elapsedMs"), line.Value("targetsProcessed"), line.Value("targetsTotal"), line.Value("generation")));
        var part = Assert.Single(log.Lines.Where(item => item.Message == "post-pass part"));
        Assert.Equal(("0", "60000"), (part.Value("completedMs"), part.Value("activeMs")));
        Assert.Equal("7", Assert.Single(log.Lines.Where(item => item.Message == "judging status")).Value("objects"));
        Assert.Equal(beforeTimer, screen.Calls);
    }

    [Fact]
    public void CompletedPartsAccountForTimeOnce()
    {
        var log = new StatusLog();
        var clock = new TimerClock();
        using var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching, clock, Memory);
        using (var diagnostic = status.BeginPostPass("admitted-control", Generation))
        {
            diagnostic.Part("read-evidence");
            clock.Advance(TimeSpan.FromSeconds(30));
            diagnostic.Part("store-control");
            clock.Advance(TimeSpan.FromSeconds(60));
            diagnostic.Complete();
        }
        var line = Completed(log, "admitted-control");
        Assert.Equal(("90000", "90000", "0", "none"),
            (line.Value("elapsedMs"), line.Value("accountedMs"), line.Value("unaccountedMs"), line.Value("activePart")));
        var parts = log.Lines.Where(item => item.Message == "post-pass part" && item.Value("outcome") == "completed").ToArray();
        Assert.Equal(new[] { "30000", "60000" }, parts.Select(item => item.Value("completedMs")));
        Assert.All(parts, item => Assert.Equal("0", item.Value("activeMs")));
    }

    [Fact]
    public void TargetAndTraversalCountsRetainTheirDifferentMeanings()
    {
        var log = new StatusLog();
        using var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching, new TimerClock(), Memory);
        using (var diagnostic = status.BeginPostPass("admitted-control", Generation))
        {
            diagnostic.Targets(2);
            diagnostic.TargetFinished();
            diagnostic.TargetFinished(available: false);
            diagnostic.ScopeProgress.Report(new(3, 17, 4));
            diagnostic.Complete();
        }
        var line = Completed(log, "admitted-control");
        Assert.Equal(("2", "2", "1", "1", "3", "17", "4", "execution-only"),
            (line.Value("targetsTotal"), line.Value("targetsProcessed"), line.Value("targetsCompleted"), line.Value("targetsUnavailable"),
             line.Value("scopeTargetsVisited"), line.Value("scopeRelationsExamined"), line.Value("scopeTargetsIncluded"), line.Value("kind")));
    }

    [Fact]
    public void CancellationCannotLabelUnfinishedWorkCompleted()
    {
        var log = new StatusLog();
        var clock = new TimerClock();
        using var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching, clock, Memory);
        Assert.Throws<OperationCanceledException>((Action)(() =>
        {
            using var diagnostic = status.BeginPostPass("scope-selection", Generation);
            diagnostic.Part("select-scope");
            clock.Advance(TimeSpan.FromSeconds(10));
            throw new OperationCanceledException();
        }));
        var line = log.Lines.Last(item => item.Message == "post-pass status");
        Assert.Equal(("interrupted", "select-scope"), (line.Value("outcome"), line.Value("activePart")));
        var part = log.Lines.Last(item => item.Message == "post-pass part");
        Assert.Equal(("0", "10000"), (part.Value("completedMs"), part.Value("activeMs")));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void MemoryIsSampledAtBoundariesAndUnknownIsNotZero(bool available)
    {
        var log = new StatusLog();
        var clock = new TimerClock();
        var samples = 0;
        PostPassMemory Sample()
        {
            samples++;
            return new(available ? samples * 11 : null, available ? samples * 22 : null, 33, 44, 5, 6, 7,
                available ? "available" : "unavailable:Test");
        }
        using var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching, clock, Sample);
        using (var diagnostic = status.BeginPostPass("scope-selection", Generation))
        {
            diagnostic.Part("select-scope");
            clock.Advance(TimeSpan.FromMinutes(1));
            diagnostic.Complete();
        }
        Assert.Equal(3, samples);
        var lines = log.Lines.Where(item => item.Message == "post-pass status").ToArray();
        Assert.Equal(new[] { "started", "running", "completed" }, lines.Select(item => item.Value("outcome")));
        Assert.Equal(available ? new[] { "11", "22", "33" } : new[] { "unavailable", "unavailable", "unavailable" }, lines.Select(item => item.Value("workingSetBytes")));
        Assert.Equal(available ? "66" : "unavailable", lines[^1].Value("privateBytes"));
        Assert.Equal(("33", "44", "5", "6", "7", "process-snapshot-not-peak"),
            (lines[^1].Value("managedEstimatedBytes"), lines[^1].Value("processAllocatedBytes"), lines[^1].Value("processGen0"),
             lines[^1].Value("processGen1"), lines[^1].Value("processGen2"), lines[^1].Value("memoryKind")));
    }

    [Fact]
    public void DisposedReporterCannotEmitLatePostPassMessages()
    {
        var log = new StatusLog();
        var clock = new TimerClock();
        var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching, clock, Memory);
        var diagnostic = status.BeginPostPass("scope-selection", Generation);
        diagnostic.Part("select-scope");
        var count = log.Lines.Count;
        status.Dispose();
        clock.FireQueuedCallback();
        diagnostic.Dispose();
        Assert.Equal(count, log.Lines.Count);
    }

    [Fact]
    public void DiagnosticLogFailureDoesNotAbortWorkerOrRetry()
    {
        var log = new StatusLog(_ => throw new IOException("Unavailable diagnostic log"));
        var clock = new TimerClock();
        using var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching, clock, Memory);
        using (var diagnostic = status.BeginPostPass("admitted-control", Generation))
        {
            diagnostic.Targets(1);
            diagnostic.Part("store-control");
            diagnostic.TargetFinished();
            clock.Advance(TimeSpan.FromMinutes(2));
            diagnostic.Complete();
        }
        Assert.Single(log.Lines);
    }

    [Fact]
    public void PostPassLogFailureStopsTheSameHeartbeatsRemainingDetails()
    {
        var fail = false;
        var log = new StatusLog(line =>
        {
            if (fail && line.Message == "post-pass status") throw new IOException("Unavailable log");
        });
        var clock = new TimerClock();
        using var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching, clock, Memory);
        status.BeginRule("TEST");
        status.EndRule("TEST", TimeSpan.FromSeconds(5), 1, 0);
        using var diagnostic = status.BeginPostPass("scope-selection", Generation);
        clock.Advance(TimeSpan.FromMinutes(4));
        var before = log.Lines.Count;
        fail = true;
        clock.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(new[] { "judging status", "post-pass status" }, log.Lines.Skip(before).Select(item => item.Message));
        var after = log.Lines.Count;
        clock.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(after, log.Lines.Count);
    }

    [Fact]
    public void BuildIdentityNamesActualExecutingEngineAndFiles()
    {
        var log = new StatusLog();
        using var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching, new TimerClock(), Memory);
        status.RecordBuildIdentity();
        status.RecordGeneration(Generation, new string('A', 64), null);
        var line = Assert.Single(log.Lines.Where(item => item.Message == "judging build"));
        var bound = Assert.Single(log.Lines.Where(item => item.Message == "judging generation"));
        var engine = typeof(JudgingRun).Assembly;
        Assert.Equal("judging build", line.Message);
        Assert.Equal(status.AttemptId.ToString("D"), line.Value("attempt"));
        Assert.Equal(line.Value("attempt"), bound.Value("attempt"));
        Assert.Equal((Generation.ToString("D"), new string('A', 64), "none"),
            (bound.Value("generation"), bound.Value("evidenceSeal"), bound.Value("derivationGeneration")));
        Assert.Equal(engine.ManifestModule.ModuleVersionId.ToString("D"), line.Value("engineMvid"));
        Assert.Equal(engine.Location, line.Value("enginePath"));
        Assert.Equal(Hash(engine.Location), line.Value("engineFileSha256"));
        Assert.Equal(Environment.ProcessPath, line.Value("processPath"));
        Assert.Equal(Hash(Environment.ProcessPath!), line.Value("processFileSha256"));
    }

    [Fact]
    public void RealGatedJudgingReportsAllPostPassBoundariesAndActualCounts()
    {
        var directory = Bundle(rootDescriptor: $"O:SYG:SYD:(A;;WO;;;{UserSid})");
        Derive(directory);
        var log = new StatusLog();
        var result = JudgingRun.JudgeWithTier0Discovery(directory, [], Started, Started,
            JudgingRun.NobodyIsWatching, log, CancellationToken.None, selfMembershipDiscoveryBudget: null);
        Assert.True(result.IsSuccess, result.Error?.Description);
        var opened = JudgementReader.Open(directory);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        using var reader = opened.Value;
        var generation = reader.Read().Description.GenerationId.ToString("D");
        var completed = log.Lines.Where(item => item.Message == "post-pass status" && item.Value("outcome") == "completed").ToArray();
        Assert.Equal(new[] { "scope-selection", "admitted-control", "ownership-assessment", "Preparing requester work",
            "Preparing membership prerequisites", "Evaluating requester resource batches", "Matching saved answers",
            "Publishing judgement" }, completed.Select(item => item.Value("stage")));
        Assert.All(completed, item => Assert.Equal(generation, item.Value("generation")));
        var scope = Completed(log, "scope-selection");
        Assert.True(long.Parse(scope.Value("candidateFactsTotal")!, System.Globalization.CultureInfo.InvariantCulture) > 0);
        Assert.Equal(scope.Value("candidateFactsTotal"), scope.Value("candidateFactsCheckpoint"));
        Assert.Equal("4096", scope.Value("candidateCheckpointInterval"));
        Assert.Equal(("2", "2", "0"), (completed[1].Value("targetsTotal"), completed[1].Value("targetsCompleted"), completed[1].Value("targetsUnavailable")));
        Assert.Equal(("2", "2", "1", "1"), (completed[2].Value("targetsTotal"), completed[2].Value("targetsCompleted"),
            completed[2].Value("ownerCandidatesRead"), completed[2].Value("ownerCandidateEvaluations")));
        var binding = Assert.Single(log.Lines.Where(item => item.Message == "judging generation" && item.Value("generation") == generation));
        Assert.Equal(reader.Read().Description.EvidenceSeal, binding.Value("evidenceSeal"));
        Assert.Single(log.Lines.Where(item => item.Message == "judging build" && item.Value("attempt") == binding.Value("attempt")));
        Assert.Equal("judging build", log.Lines.First().Message);
        var parts = log.Lines.Where(item => item.Message == "post-pass part" && item.Value("outcome") == "completed").Select(item => item.Value("part")).ToArray();
        foreach (var part in new[] { "resolve-candidates", "order-candidates", "classify-targets", "select-scope", "save-scope", "save-path-uncertainty",
                     "prepare-identities", "read-evidence", "evaluate-control", "store-control", "recount-owner-candidates",
                     "read-candidates", "evaluate-ownership", "store-ownership", "complete-check" }) Assert.Contains(part, parts);
    }

    private static Line Completed(StatusLog log, string stage) => Assert.Single(log.Lines.Where(item =>
        item.Message == "post-pass status" && item.Value("stage") == stage && item.Value("outcome") == "completed"));

    private static string Hash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private sealed class Screen : IProgress<JudgingRun.JudgingProgress>
    {
        internal int Calls { get; private set; }
        public void Report(JudgingRun.JudgingProgress value) => Calls++;
    }
}
