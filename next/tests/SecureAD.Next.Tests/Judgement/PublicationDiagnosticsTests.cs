using System.Globalization;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using Xunit;
using static SecureAD.Next.Tests.Judgement.JudgingStatusTests;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class PublicationDiagnosticsTests
{
    [Fact]
    public void DerivationAndJudgementRecordTheirOwnSealingGenerationAndByteCounts()
    {
        var directory = Bundle(rootDescriptor: $"O:SYG:SYD:(A;;WD;;;{UserSid})");
        var log = new StatusLog();
        var derived = Stage2aRun.Derive(directory, ExpansionBudget.Bulk, Started, Stage2aRun.Unwatched, log, CancellationToken.None);
        Assert.True(derived.IsSuccess, derived.Error?.Description);
        Assert.True(Judge(directory, log).IsSuccess);
        var reports = log.Lines.Where(line => line.Message == "file sealing").ToArray();

        Assert.Equal(6, reports.Length);
        foreach (var kind in new[] { AnalysisStoreKind.Derivation, AnalysisStoreKind.Judgement })
        {
            var root = AnalysisStoreLifecycle.ResolveRoot(directory, kind).Value;
            var roles = kind == AnalysisStoreKind.Derivation
                ? new[] { StoreSegmentRole.Derivation, StoreSegmentRole.Membership }
                : new[] { StoreSegmentRole.Judgement, StoreSegmentRole.PermissionProof,
                    StoreSegmentRole.PathProof, StoreSegmentRole.JudgementFacts };
            Assert.Equal(roles, root.Segments.Select(segment => segment.Role));
            var selected = reports.Where(line => line.Value("artifact") == kind.ToString()).ToArray();
            Assert.Equal(root.Segments.Count, selected.Length);
            foreach (var (segment, report) in root.Segments.Zip(selected))
            {
                var length = new FileInfo(Path.Combine(directory, segment.FileName)).Length;
                Assert.Equal(root.GenerationId.ToString("D"), report.Value("generation"));
                Assert.Equal("Completed", report.Value("outcome"));
                Assert.Equal(length.ToString(CultureInfo.InvariantCulture), report.Value("bytesRead"));
                Assert.Equal(report.Value("bytesRead"), report.Value("bytesHashed"));
            }
        }
    }

    private static readonly string[] Parts =
    [
        "protect-input-generation", "validate-laps", "validate-permission-classifications",
        "validate-path-fragments", "validate-path-questions", "validate-tier0-findings", "record-completion",
        "build-indexes", "checkpoint-database", "close-database", "write-pending-manifest",
        "move-generation-file", "seal-generation", "select-generation", "release-write-lock",
    ];

    [Fact]
    public void CompletedJudgingNamesEveryPublicationPartAndThePublishedGeneration()
    {
        var directory = Ready();
        var log = new StatusLog();

        var result = Judge(directory, log);

        Assert.True(result.IsSuccess, result.Error?.Description);
        var generation = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId;
        var summary = Assert.Single(log.Lines.Where(line => IsPublication(line) && line.Message == "post-pass status"
            && line.Value("outcome") == "completed"));
        Assert.Equal(generation.ToString("D"), summary.Value("generation"));
        Assert.Equal("execution-only", summary.Value("kind"));
        Assert.Equal("none", summary.Value("activePart"));
        Assert.Equal("0", summary.Value("generationFileMoves"));
        var parts = log.Lines.Where(line => IsPublication(line) && line.Message == "post-pass part" && line.Value("outcome") == "completed").ToArray();
        Assert.Equal(Parts, parts.Select(line => line.Value("part")));
        Assert.All(parts, line =>
        {
            Assert.Equal(generation.ToString("D"), line.Value("generation"));
            Assert.True(double.Parse(line.Value("completedMs")!, CultureInfo.InvariantCulture) >= 0);
            Assert.Equal("0", line.Value("activeMs"));
        });
        Assert.False(AnalysisStoreLifecycle.HasUnpublishedChanges(directory, AnalysisStoreKind.Judgement));
    }

    [Fact]
    public void PublicationDiagnosticsContainStagesAndTimingNotDirectoryObjects()
    {
        var directory = Ready();
        var log = new StatusLog();
        Assert.True(Judge(directory, log).IsSuccess);
        var lines = log.Lines.Where(IsPublication).ToArray();

        Assert.Equal(17, lines.Count(line => line.Value("outcome") is "started" or "completed"));
        foreach (var value in lines.SelectMany(line => line.Detail).Select(detail => detail.Value))
        {
            Assert.DoesNotContain(directory, value, StringComparison.Ordinal);
            Assert.DoesNotContain("CN=", value, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("DC=", value, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("S-1-", value, StringComparison.Ordinal);
            Assert.DoesNotContain("contoso.com", value, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("dc01", value, StringComparison.OrdinalIgnoreCase);
        }
        Assert.All(lines.Where(line => line.Message == "post-pass part"),
            line => Assert.Contains(line.Value("part"), Parts));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InterruptedPublicationReportsItsPartWithoutReplacingThePreviousResult(bool cancel)
    {
        var directory = Ready();
        Assert.True(Judge(directory, RunLog.Discarded).IsSuccess);
        var previous = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId;
        using var stopping = new CancellationTokenSource();
        var log = new StatusLog();
        var interrupt = new InterruptPublication(directory, stopping, cancel);

        var error = Record.Exception(() => Judge(directory, log, interrupt, stopping.Token));

        Assert.True(interrupt.Reached);
        if (cancel) Assert.IsType<OperationCanceledException>(error);
        else Assert.IsType<SqliteException>(error);
        var summary = Assert.Single(log.Lines.Where(line => IsPublication(line) && line.Message == "post-pass status"
            && line.Value("outcome") != "started"));
        Assert.Equal(cancel ? "cancelled" : "failed", summary.Value("outcome"));
        Assert.Equal(cancel ? "protect-input-generation" : "record-completion", summary.Value("activePart"));
        Assert.DoesNotContain(log.Lines, line => IsPublication(line) && line.Value("outcome") == "completed");
        Assert.Equal(previous, AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId);
    }

    [Fact]
    public void PublicationDiagnosticLogFailureDoesNotAbortOrRetryPublication()
    {
        var directory = Ready();
        var attempts = 0;
        var log = new StatusLog(line =>
        {
            if (!IsPublication(line)) return;
            attempts++;
            throw new IOException("Synthetic unavailable diagnostic log");
        });

        var result = Judge(directory, log);

        Assert.True(result.IsSuccess, result.Error?.Description);
        Assert.Equal(1, attempts);
        Assert.DoesNotContain(log.Lines, line => line.Message == "file sealing");
        Assert.True(AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).IsSuccess);
        Assert.False(AnalysisStoreLifecycle.HasUnpublishedChanges(directory, AnalysisStoreKind.Judgement));
    }

    private static bool IsPublication(Line line) => line.Value("stage") == "Publishing judgement";

    private static string Ready()
    {
        var directory = Bundle(rootDescriptor: $"O:SYG:SYD:(A;;WD;;;{UserSid})");
        Derive(directory);
        return directory;
    }

    private static Result<JudgementRunState> Judge(string directory, IRunLog log,
        IProgress<JudgingRun.JudgingProgress>? progress = null, CancellationToken token = default) =>
        JudgingRun.JudgeWithTier0Discovery(directory, [], Started, Started,
            progress ?? JudgingRun.NobodyIsWatching, log, token, selfMembershipDiscoveryBudget: null);

    private sealed class InterruptPublication(string directory, CancellationTokenSource stopping, bool cancel)
        : IProgress<JudgingRun.JudgingProgress>
    {
        internal bool Reached { get; private set; }
        public void Report(JudgingRun.JudgingProgress value)
        {
            if (value.Phase != JudgingPhase.PublishingJudgement || Reached) return;
            Reached = true;
            if (cancel) { stopping.Cancel(); return; }
            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = TestSealing.PendingJudgementPath(directory),
                Mode = SqliteOpenMode.ReadWrite, Pooling = false,
            }.ToString());
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = """
                CREATE TRIGGER fail_completion BEFORE UPDATE OF state ON judgement
                WHEN NEW.state IN ('Completed','CompletedDegraded')
                BEGIN SELECT RAISE(ABORT,'synthetic completion failure'); END
                """;
            command.ExecuteNonQuery();
        }
    }
}
