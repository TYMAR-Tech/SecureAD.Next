using System.Collections.Immutable;
using System.Data;
using Microsoft.Data.Sqlite;
using SecureAD.Audit.Capture;
using SecureAD.Audit.Connect;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Capture;
using SecureAD.Next.Tests.Connect;
using SecureAD.Next.Tests.Sysvol;
using Xunit;

namespace SecureAD.Next.Tests.EndToEnd;

/// <summary>
/// A run, end to end: discover the forest, read every partition, write a bundle, seal it, and read
/// it back.
///
/// <para>
/// <b>These are the first tests in this repository that join two subsystems.</b> Everything before
/// them proved one component against fixtures. Connect, capture, the schema and run identity were
/// each finished and none of them called another, so a defect in the seam between any two of them
/// could not have been detected by anything.
/// </para>
/// <para>
/// <b>What they do not prove.</b> The controller is <see cref="ControllerModel"/>, whose behaviour
/// is taken from Microsoft's documentation rather than from a domain controller - F-S7-37. Nothing
/// here has bound, completed a TLS handshake, or seen a real paging cookie. These tests prove that
/// the pieces fit each other, not that they fit Active Directory.
/// </para>
/// <para>
/// <b>They are written against the two sides' own rules rather than against the seam.</b> What a
/// table means came from docs/layers/evidence/what-a-bundle-holds.md; which files a finished
/// bundle holds came from docs/layers/evidence/the-bundle-on-disk.md, both deleted 2026-09-12 and
/// in git history; what a run that ended badly must leave behind comes from
/// <c>docs/decisions/0029-a-run-that-ends-badly-says-so.md</c>. A test written against the seam's
/// own behaviour would agree with it by construction.
/// </para>
/// </summary>
public sealed class CaptureRunEndToEndTests : IDisposable
{
    private static readonly DateTimeOffset RunStarted =
        new(2026, 8, 29, 3, 0, 0, TimeSpan.Zero);

    private readonly string _root =
        Path.Combine(Path.GetTempPath(), $"secad-e2e-{Guid.NewGuid():N}");

    public void Dispose()
    {
        // Left on disk deliberately where a test failed: the bundle is the evidence of what went
        // wrong, and deleting it is how a failure becomes hard to investigate.
        SqliteConnection.ClearAllPools();
    }

    [Fact]
    public async Task AForestIsReadIntoASealedBundle()
    {
        var controller = ForestOfThreeObjects();
        var run = await RunAsync(controller);

        Assert.Equal(RunCompletion.Sealed, run.Outcome);
        Assert.True(run.ProducedABundle);

        // the-bundle-on-disk.md: a finished bundle holds the evidence, its seal and the
        // annotations. A reader opens evidence.db, and the partial file is gone because the rename
        // is the last act.
        Assert.True(File.Exists(BundleLayout.EvidencePath(run.BundleDirectory)));
        Assert.True(File.Exists(BundleLayout.SealPath(run.BundleDirectory)));
        Assert.False(File.Exists(BundleLayout.PartialPath(run.BundleDirectory)));

        // 0029: only a bad ending writes one, and a finished bundle's evidence and intact seal
        // already say it succeeded.
        Assert.False(File.Exists(BundleLayout.OutcomePath(run.BundleDirectory)));
    }

    [Fact]
    public async Task ACompleteReconciliationThatFindsUnplannedScopeFailsBeforeSealing()
    {
        var controller = ForestOfThreeObjects();
        controller.SupportedControls.Remove("1.2.840.113556.1.4.1339");
        controller.References.Add("ldap://dc02.example.com/DC=child,DC=example,DC=com");

        var run = await RunAsync(controller);

        Assert.Equal(RunCompletion.Ended, run.Outcome);
        Assert.False(File.Exists(BundleLayout.EvidencePath(run.BundleDirectory)));
        Assert.True(File.Exists(BundleLayout.OutcomePath(run.BundleDirectory)));
    }

    [Fact]
    public async Task AnIncompleteReconciliationIsPersistedWithoutClaimingNoUnplannedScope()
    {
        var run = await RunAsync(ForestOfThreeObjects());

        var opening = BundleReader.Open(run.BundleDirectory);
        using var reader = opening.Value!;

        Assert.Equal(
            ContinuationReconciliationOutcome.Incomplete,
            reader.ContinuationReconciliation.Outcome);
    }

    /// <summary>
    /// Every partition the run reads is announced before it starts and accounted for when it
    /// finishes.
    ///
    /// <para>
    /// <b>This is the whole of what a failed production capture will have to be diagnosed from.</b>
    /// Before this, a run wrote two lines for the entire stage - <c>started</c> and
    /// <c>finished</c> - so a capture of a nine-domain forest that stopped at hour two left a file
    /// saying it had begun, with no controller named, no domain named and no count. Deriving logs
    /// six phases and judging logs per-rule shortfalls; capture, the only stage that runs for
    /// hours, logged the least.
    /// </para>
    /// <para>
    /// The start line is what matters most and is the one that is easiest to lose: it is the only
    /// line a partition that never finished will have written.
    /// </para>
    /// </summary>
    /// <summary>
    /// The stretch between the last partition and the end of the run accounts for itself.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>It was silent until 2026-09-13, and in the owner's three-domain laboratory it was 47% of
    /// the capture</b> - seven seconds of fifteen, between the last <c>partition read</c> line and
    /// <c>finished</c>. Four separate things happen in there: the policy share is read, eleven
    /// indexes are built, two set-based passes run over every object, and the file is checkpointed
    /// and hashed.
    /// </para>
    /// <para>
    /// <b>Against 347,000 objects and 5.9 million entries this is the part most likely to
    /// dominate</b>, and an operator watching a capture that has read every domain and then sat
    /// still for twenty minutes needs to know which of the four it is doing. A capture that looks
    /// hung and a capture that is hashing are the same screen.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task TheStretchAfterTheLastPartitionAccountsForItself()
    {
        var (run, log) = await RunAndLogAsync(ForestOfThreeObjects());

        Assert.Equal(RunCompletion.Sealed, run.Outcome);

        Assert.Single(log.Saying("reading the policy share"));
        Assert.Single(log.Saying("policy share read"));
        Assert.Single(log.Saying("sealing the bundle"));
        Assert.Single(log.Saying("bundle sealed"));

        // The share was read even though this forest declares no policies, and how long it took is
        // on the line. A run that read nothing and a run that could not reach the share take very
        // different amounts of time, and only one of them is a problem.
        var share = log.Saying("policy share read")[0];
        Assert.NotNull(RecordingRunLog.Value(share, "policies"));
        Assert.NotNull(RecordingRunLog.Value(share, "elapsedSeconds"));
    }

    /// <summary>
    /// Sealing reports its phases separately, because they fail and scale differently.
    /// </summary>
    /// <remarks>
    /// One figure covering all five would say a capture was slow without saying what to look at.
    /// The index build is three sorts of the entries table; the backfill is two set-based passes
    /// over every object; the seal is a hash of the whole file, so it grows with bytes rather than
    /// rows.
    /// </remarks>
    [Theory]
    [InlineData("commitSeconds")]
    [InlineData("indexSeconds")]
    [InlineData("backfillSeconds")]
    [InlineData("checkpointSeconds")]
    [InlineData("sealSeconds")]
    [InlineData("totalSeconds")]
    public async Task EverySealPhaseIsReportedSeparately(string name)
    {
        var (_, log) = await RunAndLogAsync(ForestOfThreeObjects());

        var sealed_ = log.Saying("bundle sealed")[0];

        Assert.NotNull(RecordingRunLog.Value(sealed_, name));
    }

    [Fact]
    public async Task EveryPartitionIsAnnouncedBeforeItIsReadAndAccountedForAfterwards()
    {
        var (run, log) = await RunAndLogAsync(ForestOfThreeObjects());

        Assert.Equal(RunCompletion.Sealed, run.Outcome);

        var started = log.Saying("reading a partition");
        var finished = log.Saying("partition read");

        // Configuration, schema and the one domain.
        Assert.Equal(3, started.Count);
        Assert.Equal(3, finished.Count);

        Assert.Equal(
            ["CN=Configuration,DC=example,DC=com", "CN=Schema,CN=Configuration,DC=example,DC=com",
             "DC=example,DC=com"],
            started.Select(d => RecordingRunLog.Value(d, "namingContext")).Order().ToList());

        foreach (var partition in started)
        {
            Assert.Equal("dc01.example.com", RecordingRunLog.Value(partition, "controller"));
            Assert.NotNull(RecordingRunLog.Value(partition, "kind"));
        }

        var domain = Assert.Single(
            finished,
            d => RecordingRunLog.Value(d, "namingContext") == "DC=example,DC=com");

        Assert.Equal("dc01.example.com", RecordingRunLog.Value(domain, "controller"));
        Assert.Equal("3", RecordingRunLog.Value(domain, "objects"));
        Assert.Equal("1", RecordingRunLog.Value(domain, "pages"));
        Assert.NotNull(RecordingRunLog.Value(domain, "connection"));
        Assert.NotNull(RecordingRunLog.Value(domain, "referralsSuppressed"));
        Assert.NotNull(RecordingRunLog.Value(domain, "elapsedSeconds"));
    }

    /// <summary>
    /// The rung the connection reached and whether referrals were suppressed are written when the
    /// connection is made, not only when the partition completes.
    ///
    /// <para>
    /// A run that dies part way through a partition never reaches the coverage record, and those
    /// two facts are the ones nothing else would leave behind - the first says whether a customer's
    /// evidence could have been altered in transit, the second whether the read could have been
    /// silently truncated.
    /// </para>
    /// </summary>
    [Fact]
    public async Task TheConnectionIsAccountedForBeforeThePartitionIsRead()
    {
        var (_, log) = await RunAndLogAsync(ForestOfThreeObjects());

        var connected = log.Saying("connected to a controller");

        Assert.Equal(3, connected.Count);

        foreach (var connection in connected)
        {
            Assert.Equal("dc01.example.com", RecordingRunLog.Value(connection, "controller"));
            Assert.NotNull(RecordingRunLog.Value(connection, "connection"));
            Assert.NotNull(RecordingRunLog.Value(connection, "referralsSuppressed"));
        }

        // Before the read, not after: the whole point is the line a half-read partition leaves.
        var first = log.Notes.FindIndex(n => n.Message == "connected to a controller");
        var read = log.Notes.FindIndex(n => n.Message == "partition read");
        Assert.True(first < read, "The connection was accounted for after the partition finished.");
    }

    /// <summary>
    /// A partition that could not be read is recorded as a failure naming the controller, with how
    /// long it had been running.
    ///
    /// <para>
    /// A controller that refused at once and one that answered for an hour and then stopped produce
    /// the same error and want different remedies, so the elapsed time is on the failure as well as
    /// on the success.
    /// </para>
    /// </summary>
    [Fact]
    public async Task APartitionThatFailedIsRecordedWithTheControllerAndHowLongItHadRun()
    {
        var controller = ForestOfThreeObjects();
        controller.FailuresBeforeAnswering = 99;

        // AdminLimitExceeded rather than Busy: the policy stops on it immediately, so this test
        // does not spend the retry policy's five and ten seconds proving something about logging.
        // That the exception type reaches the policy at all is PartitionCaptureTests' to show.
        controller.FailWithCode = 11;
        controller.FailsAsServerResult = true;

        var (run, log) = await RunAndLogAsync(controller);

        Assert.Equal(RunCompletion.Ended, run.Outcome);

        var (phase, error, detail) = Assert.Single(log.Errors);

        Assert.Equal("Capture", phase);
        Assert.Contains("DirectoryRequestFailed", error.Code, StringComparison.Ordinal);
        Assert.Equal("dc01.example.com", RecordingRunLog.Value(detail, "controller"));
        Assert.NotNull(RecordingRunLog.Value(detail, "namingContext"));
        Assert.NotNull(RecordingRunLog.Value(detail, "elapsedSeconds"));
    }

    /// <summary>
    /// The objects the controller served are in the bundle, under the names it served them by.
    /// </summary>
    /// <remarks>
    /// This is the assertion that would fail against an empty implementation, which is the property
    /// asked of a test written where there is no oracle.
    /// </remarks>
    [Fact]
    public async Task EveryObjectTheControllerServedIsStored()
    {
        var controller = ForestOfThreeObjects();
        var run = await RunAsync(controller);

        var stored = Query(
            run.BundleDirectory,
            "SELECT distinguished_name FROM captured_object ORDER BY distinguished_name");

        Assert.Equal(
            [
                "CN=alice,DC=example,DC=com",
                "CN=bob,DC=example,DC=com",
                "CN=carol,DC=example,DC=com",
            ],
            stored);
    }

    /// <summary>
    /// Every partition the plan named has a coverage row, and each row was completed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Coverage is what an absence is interpreted against, and this is the first time a row has
    /// been opened before the pass that fills it. A row left at zero objects with no completion
    /// would mean the reservation was never completed, which is the failure the two-step design
    /// could introduce.
    /// </para>
    /// <para>
    /// <b>The domain partition reports its continuation references as incomplete, and that is the
    /// correct answer rather than a regression.</b> It read <c>1</c> until <c>F-S30-3</c>, because
    /// the model advertised paged results and nothing else, so capture never sent the domain-scope
    /// control and never suppressed referrals. Against a real controller it always does, so this
    /// assertion held only against a world the product does not run in - the real 2026-08-10 bundle
    /// has this column false on all three domains and true on Configuration and Schema, which is
    /// exactly the shape below. Suppressing referrals means the reference list is empty because we
    /// asked not to be told, not because there is nothing there, and saying so is what
    /// <c>docs/decisions/0002</c> requires.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task EveryPartitionReadHasACompletedCoverageRow()
    {
        var controller = ForestOfThreeObjects();
        var run = await RunAsync(controller);

        var rows = Query(
            run.BundleDirectory,
            "SELECT naming_context_dn || ' references_complete=' || continuation_references_are_complete || ' objects=' || objects_read "
            + "FROM partition_coverage ORDER BY naming_context_dn");

        // The three objects live under the domain partition, so the two forest-wide partitions are
        // read and hold nothing. A partition read and found empty is a fact; a partition never
        // read is a different one, and both have a row saying which.
        Assert.Equal(
            [
                "CN=Configuration,DC=example,DC=com references_complete=1 objects=0",
                "CN=Schema,CN=Configuration,DC=example,DC=com references_complete=1 objects=0",
                "DC=example,DC=com references_complete=0 objects=3",
            ],
            rows);
    }

    /// <summary>
    /// A run states, in the evidence, the partitions it declined to read.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>F-S31-5</c>. The DNS zone partitions are out of scope under the DNS scope decision of
    /// 2026-08-11, and until this test the fact reached the operator's console and stopped there.
    /// A reader opening the bundle afterwards could not tell a forest whose DNS partitions were
    /// skipped from a forest that has none.
    /// </para>
    /// <para>
    /// <b>Asserted end to end rather than against the writer alone, and that is not belt and
    /// braces.</b> Tests covering only <c>BundleWriter.RecordUnreadPartition</c> pass whether or not
    /// anything ever calls it: emptying the loop in <c>CaptureRun</c> was observed to leave the
    /// whole suite green. A written value nothing writes is the shape of failure this repository
    /// keeps producing.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task ARunStatesThePartitionsItDeclinedToRead()
    {
        var controller = ForestOfThreeObjects();
        var run = await RunAsync(controller);

        Assert.Equal(
            ["DC=DomainDnsZones,DC=example,DC=com"],
            Query(run.BundleDirectory, "SELECT naming_context_dn FROM unread_partition"));
    }

    /// <summary>
    /// A run stopped partway leaves no bundle a reader can open, and says why.
    /// </summary>
    /// <remarks>
    /// This is <c>0029</c> and <c>0003</c> together: an incomplete capture is refused, so what a
    /// failed run must leave is a partial file no reader asks for, an outcome file that names the
    /// ending, and no seal.
    /// </remarks>
    [Fact]
    public async Task ARunThatFailsPartwayLeavesNoReadableBundleAndSaysWhy()
    {
        var controller = ForestOfThreeObjects();

        // A controller that answers without the paging control has not said the search finished -
        // it has said nothing about it - so a partition read on that answer cannot be reported as
        // read whole. Capture refuses rather than settling for what it has.
        //
        // Note what is deliberately *not* used here: ClaimToBeFinishedAfterOnePage. That models a
        // controller reporting success while holding more, which is precisely the failure no
        // response distinguishes and which capture therefore cannot detect - the defence against
        // it is that referral chasing was off, checked before the first request.
        controller.AnswerWithoutThePagingControl = true;

        var run = await RunAsync(controller);

        Assert.Equal(RunCompletion.Ended, run.Outcome);
        Assert.False(run.ProducedABundle);
        Assert.NotNull(run.Error);

        Assert.False(File.Exists(BundleLayout.EvidencePath(run.BundleDirectory)));
        Assert.False(File.Exists(BundleLayout.SealPath(run.BundleDirectory)));
        Assert.True(File.Exists(BundleLayout.PartialPath(run.BundleDirectory)));

        var outcome = RunOutcomeFile.Read(run.BundleDirectory);
        Assert.True(outcome.IsSuccess);
        Assert.Equal(RunOutcome.Failed, outcome.Value!.Outcome);
        Assert.Contains("could not be read", outcome.Value.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AConnectionFailureAfterOnePersistedPageRestartsWithoutDuplicatingTheAttempt()
    {
        var controller = new ControllerModel
        {
            // Configuration and Schema consume requests one and two. The domain's first page is
            // request three and persists 1,000 objects; fail its continuation request.
            FailRequestNumber = 4,
            FailWithCode = 81,
        };
        controller.AnswersTo.Add("example.com");
        controller.AddObjects(1_001, "DC=example,DC=com");

        var run = await RunAsync(controller);

        Assert.Equal(RunCompletion.Sealed, run.Outcome);
        Assert.Equal(
            1_001,
            Query(run.BundleDirectory, "SELECT distinguished_name FROM captured_object").Count);
    }

    /// <summary>
    /// The state reader agrees with what the run left on disk.
    /// </summary>
    /// <remarks>
    /// <c>RunStateReader</c> is how the run library will tell a dead run from a live one, and it
    /// had never been pointed at a directory a run actually produced.
    /// </remarks>
    [Fact]
    public async Task AFailedRunIsObservedAsFailedRatherThanInterrupted()
    {
        var controller = ForestOfThreeObjects();
        controller.AnswerWithoutThePagingControl = true;

        var run = await RunAsync(controller);

        var observed = RunStateReader.Observe(run.BundleDirectory);

        Assert.True(observed.IsSuccess);
        Assert.Equal(RunState.Failed, observed.Value!.State);
    }

    /// <summary>
    /// The seal covers the evidence that is actually there.
    /// </summary>
    /// <remarks>
    /// The checkpoint happens before the hash, because a hash taken while changes are still in the
    /// write-ahead log covers a database that is not all there. Nothing had ever verified a seal
    /// over a bundle a capture produced.
    /// </remarks>
    [Fact]
    public async Task TheSealOverAFinishedBundleVerifies()
    {
        var controller = ForestOfThreeObjects();
        var run = await RunAsync(controller);

        var verdict = BundleSealing.Verify(run.BundleDirectory);

        Assert.Equal(SealState.Intact, verdict.State);
        Assert.True(verdict.MayBeOpened);
    }

    /// <summary>
    /// The scanner self-test: the model really does serve what these tests assume, so a run that
    /// wrote nothing could not pass them by finding nothing wrong with an empty bundle.
    /// </summary>
    [Fact]
    public async Task TheModelServesTheObjectsTheseTestsAssume()
    {
        var controller = ForestOfThreeObjects();
        var run = await RunAsync(controller);

        Assert.Equal(["3"], Query(run.BundleDirectory, "SELECT COUNT(*) FROM captured_object"));
        Assert.NotEqual(0, controller.RequestsReceived);
    }

    /// <summary>
    /// Three objects, each with the identity and the descriptor a real one carries.
    /// </summary>
    private static ControllerModel ForestOfThreeObjects()
    {
        var controller = new ControllerModel();

        // The domain is reached through its own DNS name, which resolves to this controller. A run
        // is given one controller and discovers the rest of the forest from the cross-references,
        // so every domain unit names a DNS root rather than a host.
        controller.AnswersTo.Add("example.com");

        foreach (var name in new[] { "alice", "bob", "carol" })
        {
            controller.AddObject(
                $"CN={name},DC=example,DC=com",
                ("objectClass", ["user"]),
                ("objectGUID", [Guid.NewGuid().ToByteArray()]));
        }

        return controller;
    }

    /// <summary>
    /// Discovers the forest, creates a run inside the library, and reads it.
    /// </summary>
    private async Task<CaptureRunResult> RunAsync(
        ControllerModel controller, AttestedExclusion? excluding = null)
    {
        var (run, _) = await RunAndLogAsync(controller, excluding);
        return run;
    }

    /// <summary>
    /// The same run, with what it said about itself.
    /// </summary>
    private async Task<(CaptureRunResult Run, RecordingRunLog Log)> RunAndLogAsync(
        ControllerModel controller, AttestedExclusion? excluding = null)
    {
        var time = new FakeTimeProvider(RunStarted);
        var connections = controller.Connections();

        var opened = connections.Connect(
            CaptureUnit.Create(
                "DC=example,DC=com",
                NamingContextKind.Domain,
                controller.DomainController).Value!);

        Assert.True(opened.IsSuccess);

        using var channel = opened.Value!;

        // The plan is built directly rather than through ForestDiscovery. Discovery now reads
        // CN=Sites to rank controllers, and seeding this fixture with site and server objects would
        // change the object set these tests assert on - they are about what a run writes, not about
        // how a controller is chosen. ForestDiscoveryTests covers the choosing.
        var plan = CapturePlan.For(
            controller.DomainController,
            "example.com",
            "CN=Configuration,DC=example,DC=com",
            "CN=Schema,CN=Configuration,DC=example,DC=com",
            [("DC=example,DC=com", "example.com", controller.DomainController)],
            controller.NamingContexts,
            ["DC=DomainDnsZones,DC=example,DC=com"]);

        Assert.True(plan.IsSuccess, plan.Error?.Description);

        var library = new RunLibrary(_root, time);
        var directory = library.CreateRun("example.com");
        Assert.True(directory.IsSuccess);

        var log = new RecordingRunLog();

        // An empty share. This forest's fixture declares no Group Policy, so there is nothing to
        // read and nothing missed - which the coverage record reports as such rather than as a
        // failure.
        var run = new CaptureRun(connections, new InMemorySysvolFileReader(), time, log);

        var exclusions = excluding is null
            ? ImmutableDictionary<string, AttestedExclusion>.Empty
            : ImmutableDictionary<string, AttestedExclusion>.Empty
                .Add(excluding.NamingContext, excluding);

        var result = await run.RunAsync(
            plan.Value!.Excluding(exclusions.Keys),
            directory.Value!,
            exclusions,
            CancellationToken.None);

        return (result, log);
    }

    /// <summary>
    /// A run that leaves a declared domain out still seals, and says so in its coverage.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Found in the lab, as a crash.</b> Taking the excluded domain out of the plan left the
    /// domain declared but with no outcome, and <c>RunCoverage.Of</c> refused it at the seal - the
    /// guard doing exactly its job, because a declared domain nobody accounted for must never pass
    /// as one that was read. What was missing was the outcome, not the guard.
    /// </para>
    /// <para>
    /// The row says <i>excluded by choice</i> rather than <i>not read</i>, per
    /// <c>docs/decisions/0063-excluded-never-looks-like-unreachable.md</c>: a reader of coverage
    /// tells a domain the operator left out from one nothing could reach without opening another
    /// table.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task ARunThatExcludedADomainSealsAndSaysWhyItWasNotRead()
    {
        var controller = ForestOfThreeObjects();

        var run = await RunAsync(controller, excluding: new AttestedExclusion(
            "DC=example,DC=com",
            "example.com",
            ExclusionKind.ByChoice,
            "outside-remit",
            null,
            @"EXAMPLE\operator",
            "R. Zamus",
            new DateTimeOffset(2026, 9, 9, 12, 0, 0, TimeSpan.Zero)));

        Assert.True(run.ProducedABundle);

        Assert.Equal(
            [nameof(DomainReadOutcome.ExcludedByChoice)],
            Query(run.BundleDirectory, "SELECT outcome FROM domain_coverage"));

        // And nothing from it was read, which is the whole point of having excluded it.
        Assert.Empty(Query(run.BundleDirectory, "SELECT distinguished_name FROM captured_object"));
    }

    /// <summary>
    /// The bundle does not claim to have covered a forest it deliberately left part of unread.
    /// </summary>
    [Fact]
    public async Task ARunThatExcludedADomainDoesNotClaimFullCoverage()
    {
        var controller = ForestOfThreeObjects();

        var run = await RunAsync(controller, excluding: new AttestedExclusion(
            "DC=example,DC=com",
            "example.com",
            ExclusionKind.ByChoice,
            "outside-remit",
            null,
            @"EXAMPLE\operator",
            "R. Zamus",
            new DateTimeOffset(2026, 9, 9, 12, 0, 0, TimeSpan.Zero)));

        Assert.Equal(
            ["0"],
            Query(
                run.BundleDirectory,
                "SELECT every_declared_unit_recorded_as_read FROM bundle"));
    }

    private static List<string> Query(string bundleDirectory, string sql)
    {
        using var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = BundleLayout.EvidencePath(bundleDirectory),
                Mode = SqliteOpenMode.ReadOnly,
            }.ToString());

        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = sql;

        var results = new List<string>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            results.Add(reader.GetValue(0)?.ToString() ?? string.Empty);
        }

        return results;
    }

    private sealed class FakeTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
