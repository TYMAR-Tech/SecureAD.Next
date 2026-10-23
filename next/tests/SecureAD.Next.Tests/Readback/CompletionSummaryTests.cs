using System.Reflection;
using Microsoft.Data.Sqlite;
using SecureAD.Cli;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Next.Tests.Architecture;
using SecureAD.Shell.Services;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Readback;

public sealed class CompletionSummaryTests
{
    [Fact]
    public void JudgementSummaryCountsSavedFindingsAndExecutionsWithoutOpeningHeavyProducts()
    {
        var directory = Judged();
        using var locks = new ProductLocks(directory, pathProof: true);
        using var reader = JudgementReader.Open(directory).Value;
        var read = reader.ReadSummary();
        Assert.True(read.IsSuccess, read.Error?.Description);
        var summary = read.Value;
        Assert.Equal(3, summary.ObjectsJudged);
        Assert.Equal(3, summary.Findings);
        Assert.Equal(new[] { (Severity.Low, 1), (Severity.High, 2) },
            summary.FindingsBySeverity.OrderBy(pair => pair.Key).Select(pair => (pair.Key, pair.Value)));
        Assert.Equal(new[] { ("TEST-A", 2), ("TEST-B", 1) },
            summary.RulesRun.Select(rule => (rule.RuleId, rule.FindingsProduced)));
        Assert.Equal(new MissingInput("member", 2), Assert.Single(summary.RulesRun[1].MissingInputs));
        Assert.Equal(JudgementRunState.CompletedDegraded, summary.Description.State);
        Assert.Equal(AnalysisStoreLifecycle.ResolveCapture(directory).Value.EvidenceSeal, summary.Description.EvidenceSeal);
        Assert.Equal(AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Derivation).Value.GenerationId,
            summary.Description.DerivationGenerationId);
        Assert.Null(summary.Requesters);
        Assert.Null(summary.PathRequesters);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void NoRulesAndSuccessfulEmptyFindingsRemainDifferent(bool scheduled)
    {
        var directory = Bundle();
        WriteJudgement(directory, writer =>
        {
            if (scheduled) writer.Write(RuleExecution.Judged(Definition("TEST-A"), 3, 0, []));
        });
        using var reader = JudgementReader.Open(directory).Value;
        var read = reader.ReadSummary();
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.Equal(!scheduled, read.Value.DidNotRun);
        Assert.Equal(0, read.Value.Findings);
        Assert.Equal(JudgementRunState.Completed, read.Value.Description.State);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void NoDerivationPhasesAndASuccessfulEmptyDerivationRemainDifferent(bool scheduled)
    {
        var directory = Bundle();
        using (var writer = DerivationWriter.Create(directory,
            AnalysisStoreLifecycle.ResolveCapture(directory).Value.EvidenceSeal, Started))
        {
            writer.WriteSids([], []);
            if (scheduled) writer.RecordPhase("Worked", DerivationPhaseOutcome.Succeeded, null);
            writer.RecordCompleteness(new(true, [], [], [], writer.GenerationId, ExpansionLimit.None));
            writer.Complete(Started.AddMinutes(1));
        }
        var read = DerivationReader.ReadSummary(directory);
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.Equal(!scheduled, read.Value.DidNotRun);
        Assert.Equal(new DerivationSize(0, 0, 0), read.Value.Size);
        Assert.Equal(DerivationRunState.Completed, read.Value.Description.State);
    }

    [Fact]
    public async Task GuiCompletionUsesSavedCountsAndCoverageWithoutReconstructingOriginalResults()
    {
        var directory = Bundle(writeAdditional: (writer, domain) => writer.WriteObject(new(domain,
            "CN=Delegated,DC=contoso,DC=com", Guid.NewGuid(),
            [
                new("objectClass", StoredAttributeCompleteness.Complete,
                    [EvidenceValue.OfText("top"), EvidenceValue.OfText("person"), EvidenceValue.OfText("user")]),
                new("objectSid", StoredAttributeCompleteness.Complete,
                    [EvidenceValue.OfBytes(Sid.ToBytes("S-1-5-21-1-2-3-1300")!)]),
                new("userAccountControl", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("524288")]),
                new("primaryGroupID", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("513")]),
                new("sAMAccountName", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("Delegated")]),
            ], Started)));
        Derive(directory);
        var completionObserved = false;
        var result = await new JudgingLauncher(null).RunAsync(directory,
            new Watched<JudgingRun.JudgingProgress>(value =>
            {
                if (value.Phase == JudgingPhase.ReadingResults) completionObserved = true;
            }), CancellationToken.None);
        Assert.True(completionObserved);
        Assert.True(result.IsSuccess, result.Error?.Description);
        RequireSummaryCompletion(typeof(JudgingLauncher), typeof(JudgingRun), nameof(JudgingRun.JudgeAudit),
            typeof(JudgementReader));
        using var reader = JudgementReader.Open(directory).Value;
        var original = reader.Read();
        Assert.Equal(4, result.Value.ObjectsJudged);
        Assert.NotEqual(4, original.RulesRun.Sum(rule => rule.ObjectsJudged));
        Assert.Contains(original.Findings, finding => finding.RuleId == "SEC-010");
        Assert.NotEmpty(original.RulesRun.SelectMany(rule => rule.MissingInputs));
        Assert.Equal(original.Findings.GroupBy(finding => finding.Severity).OrderBy(group => group.Key)
                .Select(group => (group.Key, group.Count())),
            result.Value.Findings.OrderBy(pair => pair.Key).Select(pair => (pair.Key, pair.Value)));
        Assert.Equal(original.Description.State, result.Value.State);
        var requesters = reader.ReadSelfMembershipSummary()!;
        Assert.Equal((requesters.GenerationId, requesters.EvidenceSeal, requesters.AssessmentsStored,
                requesters.AuthorizationUnknown, requesters.ReadinessUnknown, requesters.Verdict),
            (result.Value.Requesters!.GenerationId, result.Value.Requesters.EvidenceSeal, result.Value.Requesters.AssessmentsStored,
                result.Value.Requesters.AuthorizationUnknown, result.Value.Requesters.ReadinessUnknown, result.Value.Requesters.Verdict));
        var paths = reader.ReadPathRequesterSummary();
        Assert.Equal((paths.JudgementGenerationId, paths.EvidenceSeal, paths.DerivationGenerationId, paths.Verdict),
            (result.Value.PathRequesters!.JudgementGenerationId, result.Value.PathRequesters.EvidenceSeal,
                result.Value.PathRequesters.DerivationGenerationId, result.Value.PathRequesters.Verdict));
        Assert.Equal(paths.Families, result.Value.PathRequesters.Families);
        Assert.Equal(original.RulesRun.SelectMany(rule => rule.MissingInputs)
                .GroupBy(input => input.Attribute, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.Sum(input => input.ObjectsAffected)).Order(),
            result.Value.CouldNotDecide.Select(value => value.ObjectsAffected).Order());
    }

    [Fact]
    public void CliCompletionUsesAggregatesAndPreservesFailedRuleAndZeroObjectWarnings()
    {
        var directory = Judged();
        WriteJudgement(directory, writer =>
        {
            writer.Write(RuleExecution.Judged(Definition("TEST-A"), 1, 2, Findings("TEST-A", Severity.High, 2)));
            writer.Write(RuleExecution.Threw(Definition("TEST-B"), "Operator-only error"));
        });
        using var locks = new ProductLocks(directory, pathProof: false);
        var summary = Program.Summarise(directory, GenerationId(directory, AnalysisStoreKind.Judgement),
            PathRequesterPolicy.Disabled, CancellationToken.None);
        Assert.True(summary.IsSuccess, summary.Error?.Description);
        Assert.Equal("Judged: 2 rules ran, 1 did not complete, 2 findings."
            + Environment.NewLine
            + "  WARNING: TEST-B examined no objects at all. A rule offered the whole forest that finds nothing it is even about is usually "
            + "broken rather than satisfied - check its subject classes before trusting a zero.", summary.Value);
    }

    [Fact]
    public void CliUnreadableCompletionIsARefusalRatherThanAnEmptySuccessLine()
    {
        var directory = Judged();
        File.AppendAllText(AnalysisPath(directory, AnalysisStoreKind.Judgement), "corrupt");
        var summary = Program.Summarise(directory, GenerationId(directory, AnalysisStoreKind.Judgement),
            PathRequesterPolicy.Disabled, CancellationToken.None);
        Assert.False(summary.IsSuccess);
        Assert.NotNull(summary.Error);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DerivationSummaryReadsOnlySavedSizeAndPhaseOutcomes(bool degraded)
    {
        var directory = Derived(degraded);
        Change(directory, AnalysisStoreKind.Derivation, StoreSegmentRole.Derivation,
            "DROP TABLE completeness_unresolved_trustee");
        using var lockedCapture = new ProductLocks(directory, pathProof: true, derivation: false);
        var read = DerivationReader.ReadSummary(directory);
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.Equal(new DerivationSize(2, 2, 1), read.Value.Size);
        Assert.Equal(degraded ? DerivationRunState.CompletedDegraded : DerivationRunState.Completed, read.Value.Description.State);
        Assert.Equal(!degraded, read.Value.EveryPhaseThatRanSucceeded);
        Assert.Equal(new[] { degraded ? DerivationPhaseOutcome.DidNotRun : DerivationPhaseOutcome.Succeeded,
                degraded ? DerivationPhaseOutcome.Failed : DerivationPhaseOutcome.Succeeded },
            read.Value.Phases.Select(phase => phase.Outcome));
        Assert.Equal(AnalysisStoreLifecycle.ResolveCapture(directory).Value.EvidenceSeal, read.Value.Description.EvidenceSeal);
    }

    [Theory]
    [InlineData("shell")]
    [InlineData("portable")]
    public async Task DerivationCompletionDoesNotReconstructWholeDerivation(string host)
    {
        var directory = Bundle();
        if (host == "shell")
        {
            var completionObserved = false;
            var result = await new DerivationLauncher().RunAsync(directory, new Watched<DerivationProgress>(value =>
            {
                if (value.Phase == "ReadingDerivedResults") completionObserved = true;
            }), CancellationToken.None);
            Assert.True(completionObserved);
            Assert.True(result.IsSuccess, result.Error?.Description);
            RequireSummaryCompletion(typeof(DerivationLauncher), typeof(Stage2aRun), nameof(Stage2aRun.Derive),
                typeof(DerivationReader));
            Assert.Equal(DerivationReader.ReadSummary(directory).Value.Size.Principals, result.Value.Principals);
            Assert.Equal(DerivationReader.ReadSummary(directory).Value.Size.NestingEdges, result.Value.NestingEdges);
        }
        else
        {
            directory = Derived(degraded: true);
            Change(directory, AnalysisStoreKind.Derivation, StoreSegmentRole.Derivation,
                "DROP TABLE completeness_unresolved_trustee");
            Stage2aRun.AppendPortableSummary(directory, GenerationId(directory, AnalysisStoreKind.Derivation), TimeSpan.FromMilliseconds(123),
                [new("Measured", 17)], RunLog.Discarded, CancellationToken.None);
            var summaryPath = BundleLayout.PortableSummaryPath(directory);
            Assert.True(File.Exists(summaryPath), "Portable completion did not write its saved summary.");
            var written = File.ReadAllText(summaryPath);
            Assert.Contains("CompletedDegraded", written, StringComparison.Ordinal);
            Assert.Contains("2", Field(written, "Principals"), StringComparison.Ordinal);
            Assert.Equal("1 relationships", Field(written, "Nesting"));
            Assert.Contains("DerivationPhaseFailed", written, StringComparison.Ordinal);
            Assert.Contains("Measured", written, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void PortableJudgingTakesAnswersFromSavedExecutionsAndOnlyDurationsFromTimings()
    {
        var directory = Judged();
        using var locks = new ProductLocks(directory, pathProof: true);
        JudgingRun.AppendPortableSummary(directory, GenerationId(directory, AnalysisStoreKind.Judgement), TimeSpan.FromMilliseconds(123), [new("Measured", 17)],
            [new("TEST-B", "WrongInFlightOutcome", 9876, 9877, 19), new("TEST-A", "WrongInFlightOutcome", 9878, 9879, 23)],
            RunLog.Discarded, CancellationToken.None);
        var written = File.ReadAllText(BundleLayout.PortableSummaryPath(directory));
        Assert.Equal("3 judged", Field(written, "Objects"));
        Assert.Contains("CompletedDegraded", written, StringComparison.Ordinal);
        Assert.DoesNotContain("WrongInFlightOutcome", written, StringComparison.Ordinal);
        Assert.DoesNotContain("987", written, StringComparison.Ordinal);
        var a = RuleFields(written, "TEST-A");
        var b = RuleFields(written, "TEST-B");
        Assert.Equal(new[] { "TEST-A", "Succeeded", "3", "0", "23" }, a);
        Assert.Equal(new[] { "TEST-B", "Indeterminate", "1", "0", "19" }, b);
        Assert.Contains("RuleIndeterminate", written, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingRuleTimingsCannotSilentlyRemoveSavedExecutionsFromPortableSummary()
    {
        var directory = Judged();
        File.WriteAllText(BundleLayout.PortableSummaryPath(directory), "Original summary");
        var log = new Errors();
        JudgingRun.AppendPortableSummary(directory, GenerationId(directory, AnalysisStoreKind.Judgement), TimeSpan.Zero, [],
            [new("TEST-A", "Succeeded", 0, 0, 1)], log, CancellationToken.None);
        Assert.Equal("Evidence.JudgementSummaryTimingsMismatch", Assert.Single(log.Values).Code);
        Assert.Equal("Original summary", File.ReadAllText(BundleLayout.PortableSummaryPath(directory)));
    }

    [Fact]
    public void UnsupportedSavedSeverityCannotDisappearFromCompletionCounts()
    {
        var directory = Judged();
        Change(directory, AnalysisStoreKind.Judgement, StoreSegmentRole.Judgement,
            "UPDATE finding SET severity='Unsupported'");
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Equal("Evidence.JudgementSummaryUnreadable", reader.ReadSummary().Error?.Code);
    }

    [Theory]
    [InlineData(AnalysisStoreKind.Derivation)]
    [InlineData(AnalysisStoreKind.Judgement)]
    public void PortableSummaryReadFailuresAreLoggedWithoutInventingASection(AnalysisStoreKind kind)
    {
        var directory = kind == AnalysisStoreKind.Judgement ? Judged() : Derived(degraded: false);
        var summaryPath = BundleLayout.PortableSummaryPath(directory);
        File.WriteAllText(summaryPath, "Original summary");
        File.AppendAllText(AnalysisPath(directory, kind), "corrupt");
        var log = new Errors();
        if (kind == AnalysisStoreKind.Judgement)
            JudgingRun.AppendPortableSummary(directory, GenerationId(directory, kind), TimeSpan.Zero, [], [], log, CancellationToken.None);
        else
            Stage2aRun.AppendPortableSummary(directory, GenerationId(directory, kind), TimeSpan.Zero, [], log, CancellationToken.None);
        Assert.Single(log.Values);
        Assert.Equal("Original summary", File.ReadAllText(summaryPath));
    }

    [Theory]
    [InlineData(AnalysisStoreKind.Derivation)]
    [InlineData(AnalysisStoreKind.Judgement)]
    public void CompletionReadsRemainCancellable(AnalysisStoreKind kind)
    {
        var directory = kind == AnalysisStoreKind.Judgement ? Judged() : Derived(degraded: false);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() =>
        {
            if (kind == AnalysisStoreKind.Derivation)
                _ = DerivationReader.ReadSummary(directory, cancellation.Token);
            else
                using (var reader = JudgementReader.Open(directory, cancellation.Token).Value)
                    _ = reader.ReadSummary();
        });
    }

    [Theory]
    [InlineData(AnalysisStoreKind.Derivation)]
    [InlineData(AnalysisStoreKind.Judgement)]
    public void UnfinishedSavedHeadersCannotProduceCompletedSummaries(AnalysisStoreKind kind)
    {
        var directory = kind == AnalysisStoreKind.Judgement ? Judged() : Derived(degraded: false);
        Change(directory, kind, kind == AnalysisStoreKind.Judgement ? StoreSegmentRole.Judgement : StoreSegmentRole.Derivation,
            $"UPDATE {(kind == AnalysisStoreKind.Judgement ? "judgement" : "derivation")} SET state='Running'");
        if (kind == AnalysisStoreKind.Derivation)
            Assert.Equal("Evidence.DerivationUnfinished", DerivationReader.ReadSummary(directory).Error?.Code);
        else
        {
            using var reader = JudgementReader.Open(directory).Value;
            Assert.Equal("Evidence.JudgementUnfinished", reader.ReadSummary().Error?.Code);
        }
    }

    [Fact]
    public void AReaderCannotReturnCompletionCountsAfterItsSelectedGenerationChanged()
    {
        var directory = Judged();
        using var old = JudgementReader.Open(directory).Value;
        Assert.True(old.ReadSummary().IsSuccess);
        WriteJudgement(directory, writer => writer.Write(RuleExecution.Judged(Definition("OTHER"), 3, 0, [])));
        Assert.Equal("Evidence.JudgementGenerationChanged", old.ReadSummary().Error?.Code);
    }

    [Fact]
    public void RequestedCoverageIsProtectedAndInvalidCoverageIsNeverAnEmptyScan()
    {
        var directory = Judged();
        var generation = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value;
        File.AppendAllText(BundleLayout.AnalysisSegmentDataPath(directory, generation, StoreSegmentRole.PathProof), "corrupt");
        using var reader = JudgementReader.Open(directory).Value;
        Assert.True(reader.ReadSummary().IsSuccess);
        var refused = reader.ReadSummary(includeRequesters: true, includePathRequesters: true);
        Assert.False(refused.IsSuccess);
        Assert.Equal("Evidence.JudgementSummaryUnreadable", refused.Error?.Code);
    }

    [Theory]
    [InlineData(AnalysisStoreKind.Derivation)]
    [InlineData(AnalysisStoreKind.Judgement)]
    public async Task GuiCompletionRejectsASupersedingPublishedGeneration(AnalysisStoreKind kind)
    {
        var directory = Bundle();
        var replaced = false;
        if (kind == AnalysisStoreKind.Judgement)
        {
            Derive(directory);
            var result = await new JudgingLauncher(null, PathRequesterPolicy.Disabled).RunAsync(directory,
                new Watched<JudgingRun.JudgingProgress>(value =>
                {
                    if (value.Phase != JudgingPhase.ReadingResults) return;
                    ReplaceGeneration(directory, kind);
                    replaced = true;
                }), CancellationToken.None);
            Assert.False(result.IsSuccess);
            Assert.Equal("Evidence.JudgementGenerationChanged", result.Error?.Code);
            using var reader = JudgementReader.Open(directory).Value;
            Assert.True(reader.ReadSummary().IsSuccess);
        }
        else
        {
            var result = await new DerivationLauncher().RunAsync(directory, new Watched<DerivationProgress>(value =>
            {
                if (value.Phase != "ReadingDerivedResults") return;
                ReplaceGeneration(directory, kind);
                replaced = true;
            }), CancellationToken.None);
            Assert.False(result.IsSuccess);
            Assert.Equal("Evidence.DerivationGenerationChanged", result.Error?.Code);
            Assert.True(DerivationReader.ReadSummary(directory).IsSuccess);
        }
        Assert.True(replaced);
    }

    [Fact]
    public void CliCompletionRejectsADifferentPublishedAttempt()
    {
        var directory = Judged();
        var original = GenerationId(directory, AnalysisStoreKind.Judgement);
        ReplaceGeneration(directory, AnalysisStoreKind.Judgement);
        var summary = Program.Summarise(directory, original, PathRequesterPolicy.Disabled, CancellationToken.None);
        Assert.Equal("Evidence.JudgementGenerationChanged", summary.Error?.Code);
        using var reader = JudgementReader.Open(directory).Value;
        Assert.True(reader.ReadSummary().IsSuccess);
    }

    [Theory]
    [InlineData(AnalysisStoreKind.Derivation)]
    [InlineData(AnalysisStoreKind.Judgement)]
    public void PortableSummaryCannotMixAnotherGenerationWithThisAttemptsDurations(AnalysisStoreKind kind)
    {
        var directory = kind == AnalysisStoreKind.Judgement ? Judged() : Derived(degraded: false);
        var original = GenerationId(directory, kind);
        ReplaceGeneration(directory, kind);
        File.WriteAllText(BundleLayout.PortableSummaryPath(directory), "Original summary");
        var log = new Errors();
        if (kind == AnalysisStoreKind.Judgement)
            JudgingRun.AppendPortableSummary(directory, original, TimeSpan.Zero, [],
                [new("TEST-A", "Succeeded", 3, 0, 1), new("TEST-B", "Succeeded", 3, 0, 1)], log, CancellationToken.None);
        else
            Stage2aRun.AppendPortableSummary(directory, original, TimeSpan.Zero, [], log, CancellationToken.None);
        Assert.Equal("Evidence." + kind + "GenerationChanged", Assert.Single(log.Values).Code);
        Assert.Equal("Original summary", File.ReadAllText(BundleLayout.PortableSummaryPath(directory)));
    }

    private static string Judged()
    {
        var directory = Bundle();
        Derive(directory);
        WriteJudgement(directory, writer =>
        {
            writer.Write(RuleExecution.Judged(Definition("TEST-A"), 3, 0, Findings("TEST-A", Severity.High, 2)));
            writer.Write(RuleExecution.Indeterminate(Definition("TEST-B"), 1, 0, 2,
                [new("member", 2)], Findings("TEST-B", Severity.Low, 1)));
        });
        return directory;
    }

    private static RuleDefinition Definition(string id) => new(id, "Synthetic saved summary", Severity.High, 1,
        ["user"], ["member"], []);

    private static Finding[] Findings(string rule, Severity severity, int count) =>
        Enumerable.Range(0, count).Select(index => new Finding(rule, 1, severity,
            new(FindingSubjectKind.Account, rule + index), Guid.NewGuid(),
            $"CN={rule}{index},DC=contoso,DC=com", "contoso.com", "user", "Recorded recommendation",
            EvidenceCompleteness.Complete, new UnconstrainedDelegationEvidence(0x80000, false, new(false, false, false)))).ToArray();

    private static void WriteJudgement(string directory, Action<JudgementWriter> write)
    {
        var capture = AnalysisStoreLifecycle.ResolveCapture(directory).Value;
        var derived = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Derivation);
        using var writer = JudgementWriter.Create(directory, capture.EvidenceSeal,
            derived.IsSuccess ? derived.Value.GenerationId : null, Started, Started);
        write(writer);
        writer.Complete(Started.AddMinutes(1));
    }

    private static string Derived(bool degraded)
    {
        var directory = Bundle();
        using var writer = DerivationWriter.Create(directory, AnalysisStoreLifecycle.ResolveCapture(directory).Value.EvidenceSeal, Started);
        writer.WriteSids([UserSid, TargetSid, "S-1-5-21-1-2-3-9999"], [null, null, null]);
        writer.WriteSidIdentities([new(0, 0, SidIdentityKind.Current), new(1, 1, SidIdentityKind.Current)]);
        writer.WritePrincipals([new(0, Guid.NewGuid(), false, null, null), new(1, Guid.NewGuid(), true, -2147483646, null)]);
        writer.WriteNestingEdges([new(0, 1)]);
        writer.RecordPhase("NoInput", degraded ? DerivationPhaseOutcome.DidNotRun : DerivationPhaseOutcome.Succeeded, null);
        writer.RecordPhase("Worked", degraded ? DerivationPhaseOutcome.Failed : DerivationPhaseOutcome.Succeeded,
            degraded ? "Operator-only details" : null);
        writer.RecordCompleteness(new(!degraded, [], [], [], writer.GenerationId, ExpansionLimit.None));
        writer.Complete(Started.AddMinutes(1));
        return directory;
    }

    private static string AnalysisPath(string directory, AnalysisStoreKind kind) =>
        BundleLayout.AnalysisGenerationDataPath(directory, kind, AnalysisStoreLifecycle.Resolve(directory, kind).Value.GenerationId);

    private static Guid GenerationId(string directory, AnalysisStoreKind kind) =>
        AnalysisStoreLifecycle.Resolve(directory, kind).Value.GenerationId;

    private static void ReplaceGeneration(string directory, AnalysisStoreKind kind)
    {
        if (kind == AnalysisStoreKind.Judgement)
        {
            WriteJudgement(directory, writer =>
            {
                writer.Write(RuleExecution.Judged(Definition("TEST-A"), 3, 0, []));
                writer.Write(RuleExecution.Judged(Definition("TEST-B"), 3, 0, []));
            });
        }
        else
        {
            using var writer = DerivationWriter.Create(directory, AnalysisStoreLifecycle.ResolveCapture(directory).Value.EvidenceSeal, Started);
            writer.WriteSids([], []);
            writer.RecordPhase("Worked", DerivationPhaseOutcome.Succeeded, null);
            writer.RecordCompleteness(new(true, [], [], [], writer.GenerationId, ExpansionLimit.None));
            writer.Complete(Started.AddMinutes(1));
        }
    }

    private static void Change(string directory, AnalysisStoreKind kind, StoreSegmentRole role, string sql)
    {
        var generation = AnalysisStoreLifecycle.Resolve(directory, kind).Value;
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = BundleLayout.AnalysisSegmentDataPath(directory, generation, role),
            Mode = SqliteOpenMode.ReadWrite, Pooling = false,
        }.ToString()))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = sql;
            command.ExecuteNonQuery();
            command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)";
            command.ExecuteNonQuery();
        }
        TestSealing.ResealAnalysis(directory, generation);
    }

    private static string Field(string text, string name) =>
        text.Split(Environment.NewLine).Single(line => line.StartsWith(name.PadRight(14), StringComparison.Ordinal))[14..].Trim();

    private static void RequireSummaryCompletion(Type launcher, Type producer, string operation, Type reader)
    {
        var entry = Assert.Single(launcher.GetMethods(BindingFlags.Public | BindingFlags.Instance),
            method => method.Name == "RunAsync");
        var boundaries = producer.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)
            .Where(method => method.Name == operation).Cast<MethodBase>().ToHashSet();
        Assert.NotEmpty(boundaries);
        var calls = ReachabilityTrace.CalledMethods(entry, boundaries);
        Assert.Contains(calls, method => boundaries.Contains(method));
        Assert.Contains(calls, method => method.DeclaringType == reader && method.Name == "ReadSummary");
        Assert.Empty(calls.Where(method =>
            method.DeclaringType == typeof(DerivationReader) && method.Name == nameof(DerivationReader.Read)
            || method.DeclaringType == typeof(JudgementReader) && method.Name is
                nameof(JudgementReader.Read) or nameof(JudgementReader.ReadPage)
                or nameof(JudgementReader.ReadPathInputs) or nameof(JudgementReader.ReadControlEdges)
                or nameof(JudgementReader.ReadControlEdge) or nameof(JudgementReader.ReadMemberAttribution)
                or nameof(JudgementReader.ReadSelfMembershipAssessments)
                or nameof(JudgementReader.ReadPermissionsThroughMembership)
            || method.DeclaringType == typeof(BundleReader)
                && method.Name is "StreamObjects" or "ReadPermissions" or "ReadObjectAttributes"));
    }

    private static string[] RuleFields(string text, string rule) =>
        text.Split(Environment.NewLine).Single(line => line.TrimStart().StartsWith(rule + " ", StringComparison.Ordinal))
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);

    private sealed class Watched<T>(Action<T> report) : IProgress<T>
    {
        public void Report(T value) => report(value);
    }

    private sealed class Errors : IRunLog
    {
        internal List<AuditError> Values { get; } = [];
        public void Note(string phase, string message, IReadOnlyList<RunLogDetail> detail) { }
        public void Record(string phase, AuditError error, IReadOnlyList<RunLogDetail> detail) => Values.Add(error);
    }

    private sealed class ProductLocks : IDisposable
    {
        private readonly List<FileStream> _files = [];
        internal ProductLocks(string directory, bool pathProof, bool derivation = true)
        {
            var paths = new List<string> { BundleLayout.EvidencePath(directory) };
            var capture = AnalysisStoreLifecycle.ResolveCapture(directory).Value;
            paths.AddRange(capture.Segments.Where(segment => segment.Role != StoreSegmentRole.Evidence)
                .Select(segment => Path.Combine(directory, segment.FileName)));
            var judgement = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement);
            if (judgement.IsSuccess)
                paths.AddRange(judgement.Value.Segments.Where(segment => segment.Role != StoreSegmentRole.Judgement
                        && (pathProof || segment.Role != StoreSegmentRole.PathProof))
                    .Select(segment => Path.Combine(directory, segment.FileName)));
            var derived = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Derivation);
            if (derivation && derived.IsSuccess) paths.Add(AnalysisPath(directory, AnalysisStoreKind.Derivation));
            try
            {
                foreach (var path in paths) _files.Add(new(path, FileMode.Open, FileAccess.Read, FileShare.None));
            }
            catch
            {
                Dispose();
                throw;
            }
        }
        public void Dispose()
        {
            foreach (var file in _files) file.Dispose();
        }
    }
}
