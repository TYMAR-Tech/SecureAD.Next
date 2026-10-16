using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    private const string FirstDn = "CN=A,DC=ad,DC=lab";
    private const string SecondDn = "CN=B,DC=ad,DC=lab";

    [Fact]
    public void StoredFindingsAreReadFromTheBoundGeneration()
    {
        var directory = CreateRun();
        using var session = new OpenedRunResults(directory);

        var read = session.ReadJudgement(reader => reader.ReadPage(FindingsQuery.Everything()));

        Assert.Equal(new[] { FirstDn, SecondDn }, read.Value.Value.Findings.Select(value => value.DistinguishedName));
    }

    [Fact]
    public void FindingsFiltersAndRuleExecutionsVerifyEachFileOnce()
    {
        var directory = CreateRun();
        using var counts = new ReadbackCounts(directory);
        using var source = new BundleAssetSource();

        source.ReadTree(directory);
        source.ReadFindings(directory, FindingsQuery.Everything());
        source.ReadFindingsFilterValues(directory);
        source.ReadRuleExecutions(directory);
        source.ReadFindings(directory, FindingsQuery.About(FirstDn));

        Assert.Equal((0L, 1L, 1L, 1L),
            (counts.EvidenceVerifications, counts.JudgementVerifications, counts.EvidenceFormatChecks, counts.NavigationVerifications));
    }

    [Fact]
    public void FindingsDoNotEnterAnalyticalReaders()
    {
        var directory = CreateRun();
        using var counts = new ReadbackCounts(directory);
        using var source = new BundleAssetSource();
        source.ReadFindings(directory, FindingsQuery.Everything());
        source.ReadFindingsFilterValues(directory);
        source.ReadRuleExecutions(directory);
        var browsing = counts.AnalyticalReads;

        using var verifier = JudgementReader.Open(directory).Value;
        PathProofVerification.ReadInputs(verifier);

        Assert.Equal((0L, 1L), (browsing, counts.AnalyticalReads));
    }

    [Fact]
    public void ClosingAndReopeningTheRunVerifiesAgain()
    {
        var directory = CreateRun();
        using var counts = new ReadbackCounts(directory);
        using var source = new BundleAssetSource();
        source.ReadFindings(directory, FindingsQuery.Everything());

        source.CloseRun();
        source.SelectRun(directory);
        source.ReadFindings(directory, FindingsQuery.Everything());

        Assert.Equal((0L, 2L), (counts.EvidenceVerifications, counts.JudgementVerifications));
    }

    [Fact]
    public void FindingsPagesRetainTheStoredOrdering()
    {
        var directory = CreateRun();
        using var source = new BundleAssetSource();
        var first = source.ReadFindings(directory, FindingsQuery.Everything() with { PageSize = 1 }).Value;

        var second = source.ReadFindings(directory, FindingsQuery.Everything() with { PageSize = 1, After = first.Next });

        Assert.Equal(new[] { FirstDn, SecondDn }, first.Findings.Concat(second.Value.Findings).Select(value => value.DistinguishedName));
    }

    [Fact]
    public void ObjectFilteringStillReturnsOnlyTheRequestedObject()
    {
        var directory = CreateRun();
        using var source = new BundleAssetSource();

        var read = source.ReadFindings(directory, FindingsQuery.About(FirstDn));

        Assert.Equal(FirstDn, Assert.Single(read.Value.Findings).DistinguishedName);
    }

    [Fact]
    public void FilterAndRuleMetadataMatchTheStoredAnswers()
    {
        var directory = CreateRun();
        using var reader = JudgementReader.Open(directory).Value;
        var expected = JsonSerializer.Serialize(new { Rules = reader.ReadRuleExecutions(), Filters = reader.ReadFilterValues() });
        using var source = new BundleAssetSource();

        var actual = JsonSerializer.Serialize(new
            { Rules = source.ReadRuleExecutions(directory).Value, Filters = source.ReadFindingsFilterValues(directory).Value });

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void AContinuationCannotCrossJudgementGenerations()
    {
        var directory = CreateRun();
        using var source = new BundleAssetSource();
        var first = source.ReadFindings(directory, FindingsQuery.Everything() with { PageSize = 1 }).Value;
        WriteJudgement(directory);
        source.SelectRun(directory);

        var read = source.ReadFindings(directory, FindingsQuery.Everything() with { After = first.Next });

        Assert.Equal("Shell.SavedResultsGenerationChanged", read.Error?.Code);
    }

    [Fact]
    public void ReplacementFindingsRequireExplicitReselection()
    {
        var directory = CreateRun();
        using var source = new BundleAssetSource();
        source.ReadFindingsFilterValues(directory);
        WriteJudgement(directory);

        var read = source.ReadFindings(directory, FindingsQuery.Everything());

        Assert.Equal("Shell.SavedResultsGenerationChanged", read.Error?.Code);
    }

    [Fact]
    public void ReselectionReadsTheNewCompletedGeneration()
    {
        var directory = CreateRun();
        using var source = new BundleAssetSource();
        source.ReadFindings(directory, FindingsQuery.Everything());
        WriteJudgement(directory);
        var expected = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId;

        source.SelectRun(directory);
        var read = source.ReadFindings(directory, FindingsQuery.Everything() with { PageSize = 1 });

        Assert.Equal(expected, read.Value?.Next?.GenerationId);
    }

    [Fact]
    public void LateRequestsCannotReopenAClosedRun()
    {
        var directory = CreateRun();
        using var source = new BundleAssetSource();
        source.ReadFindings(directory, FindingsQuery.Everything());
        source.CloseRun();

        var read = source.ReadFindings(directory, FindingsQuery.Everything());

        Assert.Equal("Shell.SavedResultsGenerationChanged", read.Error?.Code);
    }

    [Fact]
    public void AnUnboundContinuationIsNotAccepted()
    {
        var directory = CreateRun();
        using var source = new BundleAssetSource();
        var mark = new FindingsPageMark((int)Severity.High, "SEC-022", FirstDn, 1);

        var read = source.ReadFindings(directory, FindingsQuery.Everything() with { After = mark });

        Assert.Equal("Shell.SavedResultsGenerationChanged", read.Error?.Code);
    }

    [Fact]
    public void PendingAnalysisCannotReturnThePreviousFindings()
    {
        var directory = CreateRun();
        using var source = new BundleAssetSource();
        source.ReadFindings(directory, FindingsQuery.Everything());
        AnalysisStoreLifecycle.BeginAttempt(directory, AnalysisStoreKind.Judgement);

        var read = source.ReadFindings(directory, FindingsQuery.Everything());

        Assert.Equal("Shell.SavedResultsUnfinished", read.Error?.Code);
    }

    [Fact]
    public void PublicationDuringAReadRejectsItsLateResult()
    {
        var directory = CreateRun();
        using var session = new OpenedRunResults(directory);

        var read = session.ReadJudgement(reader =>
        {
            var result = reader.ReadPage(FindingsQuery.Everything());
            WriteJudgement(directory);
            return result;
        });

        Assert.Equal("Shell.SavedResultsGenerationChanged", read.Error?.Code);
    }

    [Fact]
    public void AttemptBeginningDuringAReadRejectsItsLateResult()
    {
        var directory = CreateRun();
        using var session = new OpenedRunResults(directory);

        var read = session.ReadJudgement(reader =>
        {
            var result = reader.ReadPage(FindingsQuery.Everything());
            AnalysisStoreLifecycle.BeginAttempt(directory, AnalysisStoreKind.Derivation);
            return result;
        });

        Assert.Equal("Shell.SavedResultsUnfinished", read.Error?.Code);
    }

    [Fact]
    public void SessionClosureRejectsAnAlreadyReadResult()
    {
        var directory = CreateRun();
        using var session = new OpenedRunResults(directory);

        var read = session.ReadJudgement(reader =>
        {
            var result = reader.ReadPage(FindingsQuery.Everything());
            session.Dispose();
            return result;
        });

        Assert.Equal("Shell.SavedResultsGenerationChanged", read.Error?.Code);
    }

    [Fact]
    public void CancellationDoesNotReturnAnAlreadyReadResult()
    {
        var directory = CreateRun();
        using var session = new OpenedRunResults(directory);
        using var stopping = new CancellationTokenSource();

        Assert.Throws<OperationCanceledException>(() => session.ReadJudgement(reader =>
        {
            var result = reader.ReadPage(FindingsQuery.Everything());
            stopping.Cancel();
            return result;
        }, stopping.Token));
    }

    [Fact]
    public async Task AsyncSessionClosureDrainsAQueryBeforeJudgementDeletion()
    {
        var directory = CreateRun();
        var generation = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value;
        using var session = new OpenedRunResults(directory);
        using var release = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var reading = Task.Run(() => session.ReadJudgement(reader =>
        {
            entered.SetResult();
            if (!release.Wait(TimeSpan.FromSeconds(15))) throw new TimeoutException("The test query was not released.");
            return reader.Description.GenerationId;
        }));
        Task closing;
        bool waited;
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            closing = session.DisposeAsync().AsTask();
            waited = !closing.IsCompleted;
        }
        finally { release.Set(); }
        var late = await reading.WaitAsync(TimeSpan.FromSeconds(10));
        await closing.WaitAsync(TimeSpan.FromSeconds(10));
        var data = BundleLayout.AnalysisGenerationDataPath(directory, generation.Kind, generation.GenerationId);
        File.Delete(data);

        Assert.True(waited);
        Assert.False(late.IsSuccess);
        Assert.False(File.Exists(data));
    }

    [Fact]
    public async Task SourceAsyncClosureInvalidatesOldRequestsAndReleasesJudgementFiles()
    {
        var directory = CreateRun();
        var generation = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value;
        using var source = new BundleAssetSource();
        Assert.True(source.ReadFindings(directory, FindingsQuery.Everything()).IsSuccess);
        var current = source.CaptureReadValidity();

        await source.CloseRunAsync();

        Assert.False(current());
        Assert.False(source.ReadFindings(directory, FindingsQuery.Everything()).IsSuccess);
        var data = BundleLayout.AnalysisGenerationDataPath(directory, generation.Kind, generation.GenerationId);
        File.Delete(data);
        Assert.False(File.Exists(data));
    }

    [Fact]
    public async Task ConcurrentReadsDoNotShareAConnection()
    {
        var directory = CreateRun();
        using var session = new OpenedRunResults(directory);
        using var ready = new CountdownEvent(2);
        using var release = new ManualResetEventSlim();
        using var stopping = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var pending = Enumerable.Range(0, 2).Select(_ => Task.Factory.StartNew(() => session.ReadJudgement(reader =>
        {
            ready.Signal();
            release.Wait(stopping.Token);
            return reader.ReadPage(FindingsQuery.Everything()).Value.Findings.Select(value => value.DistinguishedName).ToArray();
        }, stopping.Token), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default)).ToArray();
        bool overlapped;
        try { overlapped = ready.Wait(TimeSpan.FromSeconds(15)); }
        finally { release.Set(); }
        // Join both workers before asserting so a deliberate serialization defect leaves no work behind.
        var reads = await Task.WhenAll(pending);

        Assert.True(overlapped, "Both independently owned readers must be usable at the same time.");
        Assert.All(reads, read => Assert.Equal(new[] { FirstDn, SecondDn }, read.Value));
    }

    [Fact]
    public void AnOldRunRequestCannotReplaceTheSelectedRun()
    {
        var oldRun = CreateRun();
        var newRun = CreateRun();
        using var source = new BundleAssetSource();
        source.SelectRun(oldRun);
        source.ReadFindings(oldRun, FindingsQuery.Everything());
        source.SelectRun(newRun);

        var read = source.ReadFindings(oldRun, FindingsQuery.Everything());

        Assert.Equal("Shell.SavedResultsGenerationChanged", read.Error?.Code);
    }

    [Fact]
    public void ADeletedManifestDoesNotReturnHeldFindings()
    {
        var directory = CreateRun();
        using var source = new BundleAssetSource();
        source.ReadFindings(directory, FindingsQuery.Everything());
        File.Delete(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement));

        var read = source.ReadFindings(directory, FindingsQuery.Everything());

        Assert.Equal("Evidence.judgementManifestAbsent", read.Error?.Code);
    }

    [Theory]
    [InlineData("Running")]
    [InlineData("Failed")]
    public void AnUnfinishedPublishedJudgementIsNotShown(string state)
    {
        var directory = CreateRun();
        RewriteJudgement(directory, "UPDATE judgement SET state=$value", state);
        using var source = new BundleAssetSource();

        var read = source.ReadFindings(directory, FindingsQuery.Everything());

        Assert.Equal("Shell.SavedResultsUnfinished", read.Error?.Code);
    }

    [Fact]
    public void MatchingManifestIdentifiersDoNotReplaceEvidenceIntegrityChecking()
    {
        var directory = CreateRun();
        File.AppendAllText(BundleLayout.EvidencePath(directory), "corruption");
        using var source = new BundleAssetSource();

        var read = source.ReadControlEdges(directory, FirstDn, null, null, true, 0);

        Assert.Equal("Evidence.ProtectedStoreMismatch", read.Error?.Code);
    }

    [Fact]
    public void AJudgementForDifferentEvidenceIsRefused()
    {
        var directory = CreateRun();
        RewriteJudgement(directory, "UPDATE judgement SET evidence_seal=$value", "different evidence");
        using var source = new BundleAssetSource();

        var read = source.ReadFindings(directory, FindingsQuery.Everything());

        Assert.Equal("Evidence.JudgementIsNotForThisEvidence", read.Error?.Code);
    }

    [Fact]
    public void AManifestCannotSubstituteForTheDatabaseGeneration()
    {
        var directory = CreateRun();
        RewriteJudgement(directory, "UPDATE judgement SET judgement_generation_id=$value", Guid.NewGuid().ToString("D"));
        using var source = new BundleAssetSource();

        var read = source.ReadFindings(directory, FindingsQuery.Everything());

        Assert.Equal("Evidence.JudgementGenerationMismatch", read.Error?.Code);
    }

    [Fact]
    public void AnUnsupportedJudgementFormatIsRefused()
    {
        var directory = CreateRun();
        RewriteJudgement(directory, "UPDATE judgement SET schema_version=$value", "-1");
        using var source = new BundleAssetSource();

        var read = source.ReadFindings(directory, FindingsQuery.Everything());

        Assert.Contains("schema version -1", read.Error?.Description ?? "", StringComparison.Ordinal);
    }

    [Fact]
    public void RequiredDerivationIsVerifiedOnceAlongsideItsJudgement()
    {
        var directory = CreateRun();
        var generation = WriteDerivation(directory);
        WriteJudgement(directory, generation);
        using var counts = new ReadbackCounts(directory);
        using var source = new BundleAssetSource();

        source.ReadFindings(directory, FindingsQuery.Everything());
        source.ReadRuleExecutions(directory);

        Assert.Equal((0L, 0L, 1L), (counts.EvidenceVerifications, counts.DerivationVerifications, counts.JudgementVerifications));
    }

    [Fact]
    public void AChangedDerivationInvalidatesItsJudgement()
    {
        var directory = CreateRun();
        WriteJudgement(directory, WriteDerivation(directory));
        WriteDerivation(directory);
        using var source = new BundleAssetSource();

        var read = source.ReadFindings(directory, FindingsQuery.Everything());

        Assert.Equal("Evidence.JudgementIsNotForThisDerivation", read.Error?.Code);
    }

    [Fact]
    public void ACorruptRequiredDerivationCannotBeAcceptedByItsIdentifier()
    {
        var directory = CreateRun();
        var generation = WriteDerivation(directory);
        WriteJudgement(directory, generation);
        File.AppendAllText(BundleLayout.AnalysisGenerationDataPath(directory, AnalysisStoreKind.Derivation, generation), "corruption");
        using var source = new BundleAssetSource();

        var read = source.ReadControlEdges(directory, FirstDn, null, null, true, 0);

        Assert.Equal("Evidence.ProtectedStoreMismatch", read.Error?.Code);
    }

    private static Guid WriteDerivation(string directory)
    {
        using var writer = DerivationWriter.Create(directory, BundleSealing.ReadSeal(BundleLayout.SealPath(directory))!.Hash,
            DateTimeOffset.UnixEpoch);
        writer.Complete(DateTimeOffset.UnixEpoch.AddMinutes(1));
        return writer.GenerationId;
    }

    private static void RewriteJudgement(string directory, string sql, string value)
    {
        var generation = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value;
        var path = BundleLayout.AnalysisGenerationDataPath(directory, generation.Kind, generation.GenerationId);
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = path, Pooling = false }.ToString()))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = sql;
            command.Parameters.AddWithValue("$value", value);
            command.ExecuteNonQuery();
            command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)";
            command.ExecuteNonQuery();
        }
        TestSealing.ResealAnalysis(directory, generation);
    }

    internal sealed class ReadbackCounts : IDisposable
    {
        private readonly MeterListener _listener = new();
        private readonly ConcurrentDictionary<string, long> _counts = new();

        internal ReadbackCounts(string directory)
        {
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Name is "store.verifications" or "judgement.analytical_reads" or "evidence.format_checks")
                    listener.EnableMeasurementEvents(instrument);
            };
            _listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
            {
                foreach (var tag in tags)
                {
                    if (tag.Value is not string path || !path.StartsWith(directory, StringComparison.OrdinalIgnoreCase)) continue;
                    var key = instrument.Name == "judgement.analytical_reads" ? "analysis"
                        : instrument.Name == "evidence.format_checks" ? "format"
                        : Path.GetFileName(path).StartsWith("evidence.", StringComparison.Ordinal) ? "evidence"
                        : Path.GetFileName(path).StartsWith("navigation.", StringComparison.Ordinal) ? "navigation"
                        : Path.GetFileName(path).Contains(".permission-proof.", StringComparison.Ordinal) ? "permission-proof"
                        : Path.GetFileName(path).Contains(".path-proof.", StringComparison.Ordinal) ? "path-proof"
                        : Path.GetFileName(path).Contains(".facts.", StringComparison.Ordinal) ? "facts"
                        : Path.GetFileName(path).Contains(".membership.", StringComparison.Ordinal) ? "membership"
                        : Path.GetFileName(path).StartsWith("delegations.", StringComparison.Ordinal) ? "delegations"
                        : Path.GetFileName(path).StartsWith("overview.", StringComparison.Ordinal) ? "overview"
                        : Path.GetFileName(path).StartsWith("derivation.", StringComparison.Ordinal) ? "derivation"
                        : Path.GetFileName(path).StartsWith("judgement.", StringComparison.Ordinal) ? "judgement"
                        : throw new InvalidOperationException("An observed verified product has no counter: " + path);
                    _counts.AddOrUpdate(key, value, (_, count) => count + value);
                }
            });
            _listener.Start();
        }

        internal long EvidenceVerifications => _counts.GetValueOrDefault("evidence");
        internal long NavigationVerifications => _counts.GetValueOrDefault("navigation");
        internal long OverviewVerifications => _counts.GetValueOrDefault("overview");
        internal long EvidenceFormatChecks => _counts.GetValueOrDefault("format");
        internal long DerivationVerifications => _counts.GetValueOrDefault("derivation");
        internal long JudgementVerifications => _counts.GetValueOrDefault("judgement");
        internal long PermissionProofVerifications => _counts.GetValueOrDefault("permission-proof");
        internal long PathProofVerifications => _counts.GetValueOrDefault("path-proof");
        internal long FactsVerifications => _counts.GetValueOrDefault("facts");
        internal long MembershipVerifications => _counts.GetValueOrDefault("membership");
        internal long DelegationVerifications => _counts.GetValueOrDefault("delegations");
        internal long AnalyticalReads => _counts.GetValueOrDefault("analysis");
        public void Dispose() => _listener.Dispose();
    }

    private static string CreateRun()
    {
        var directory = LapsBundle.BuildMany(
            [(FirstDn, null, null, null, null, 0x400202), (SecondDn, null, null, null, null, 0x400202)],
            DateTimeOffset.UnixEpoch);
        WriteJudgement(directory);
        return directory;
    }

    private static void WriteJudgement(string directory, Guid? derivation = null)
    {
        var seal = BundleSealing.ReadSeal(BundleLayout.SealPath(directory))!;
        using var writer = JudgementWriter.Create(directory, seal.Hash, derivation, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);
        var definition = new RuleDefinition("SEC-022", "Kerberos pre-authentication not required", Severity.High, 1,
            ["computer"], ["userAccountControl", "objectClass"], []);
        var findings = new[] { FirstDn, SecondDn }.Select(dn => new Finding("SEC-022", 1, Severity.High,
            new(FindingSubjectKind.Account, dn), Guid.NewGuid(), dn, "ad.lab", "computer", "Recorded finding",
            EvidenceCompleteness.Complete, new UserAccountControlEvidence(0x400202))).ToArray();
        writer.Write(RuleExecution.Judged(definition, 2, 0, findings));
        writer.Complete(DateTimeOffset.UnixEpoch.AddMinutes(1));
    }
}
