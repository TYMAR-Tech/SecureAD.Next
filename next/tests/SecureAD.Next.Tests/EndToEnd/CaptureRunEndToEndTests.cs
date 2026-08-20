using System.Collections.Immutable;
using System.Data;
using Microsoft.Data.Sqlite;
using SecureAD.Audit.Capture;
using SecureAD.Audit.Connect;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
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
/// table means comes from <c>S-16</c>; what a run that ended badly must leave behind comes from
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

        // S-16: a finished bundle holds the evidence, its seal and the annotations. A reader opens
        // evidence.db, and the partial file is gone because the rename is the last act.
        Assert.True(File.Exists(BundleLayout.EvidencePath(run.BundleDirectory)));
        Assert.True(File.Exists(BundleLayout.SealPath(run.BundleDirectory)));
        Assert.False(File.Exists(BundleLayout.PartialPath(run.BundleDirectory)));

        // 0029: only a bad ending writes one, and a finished bundle's evidence and intact seal
        // already say it succeeded.
        Assert.False(File.Exists(BundleLayout.OutcomePath(run.BundleDirectory)));
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

        // An empty share. This forest's fixture declares no Group Policy, so there is nothing to
        // read and nothing missed - which the coverage record reports as such rather than as a
        // failure.
        var run = new CaptureRun(connections, new InMemorySysvolFileReader(), time);

        var exclusions = excluding is null
            ? ImmutableDictionary<string, AttestedExclusion>.Empty
            : ImmutableDictionary<string, AttestedExclusion>.Empty
                .Add(excluding.NamingContext, excluding);

        return await run.RunAsync(
            plan.Value!.Excluding(exclusions.Keys),
            directory.Value!,
            exclusions,
            CancellationToken.None);
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
