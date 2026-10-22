using Microsoft.Data.Sqlite;
using SecureAD.Audit.Capture;
using SecureAD.Audit.Connect;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Naming;
using SecureAD.Next.Tests.Capture;
using SecureAD.Next.Tests.Sysvol;
using Xunit;

namespace SecureAD.Next.Tests.EndToEnd;

/// <summary>
/// Reading a forest's domains at the same time, each into its own database, and putting them back
/// together.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is <c>docs/decisions/0041-capture-reads-domains-in-parallel.md</c> end to end.</b> A
/// forest of nine domains lives on nine controllers, and reading them one after another spends a
/// customer's night for no reason. What makes that safe is not the fan-out but the turn-taking
/// underneath it: two paged searches at one controller draw on a single budget of intermediate
/// results and can truncate each other silently, so the rule is one request per controller rather
/// than one request per run.
/// </para>
/// <para>
/// <b>The concurrency assertions rendezvous rather than measure elapsed time.</b> A test that
/// timed a run and called it parallel if it was fast enough would pass on a quick machine and fail
/// on a loaded one, which is a test that reports the build agent rather than the code. Here each
/// domain announces itself and waits for the others, so a serial run cannot pass by being quick
/// and a parallel one cannot fail by being slow.
/// </para>
/// </remarks>
public sealed class ParallelDomainCaptureTests : IDisposable
{
    [Fact]
    public async Task LiveReportsReachTheCallerWithExactPartitionCountsAndASeparateSealingPhase()
    {
        var forest = TwoDomainsOnTwoControllers(TimeSpan.Zero);
        var reports = new CaptureProgressTests.Reports();
        var result = await RunAsync(forest, 2, reports);
        Assert.True(result.ProducedABundle, result.Error?.Description);
        var final = Assert.IsType<CaptureProgress>(result.Progress);
        Assert.Equal(4, final.Scopes.Count);
        Assert.All(final.Scopes, scope => Assert.Equal(CaptureReadState.ReadComplete, scope.State));
        Assert.Equal(forest.ObjectsIn(FirstDomain), final.Scopes.Single(scope => scope.NamingContext == FirstDomain).ObjectsRead);
        Assert.Equal(forest.ObjectsIn(SecondDomain), final.Scopes.Single(scope => scope.NamingContext == SecondDomain).ObjectsRead);
        Assert.Equal(Scalar(result.BundleDirectory, "SELECT COUNT(*) FROM captured_object"),
            final.Scopes.Sum(scope => scope.ObjectsRead!.Value));
        Assert.Contains(reports.Values, report => report.Scopes.Any(scope =>
            scope.State == CaptureReadState.Reading && scope.ObjectsRead > 0));
        Assert.Contains(reports.Values, report => report.Phase == CaptureWorkPhase.Merging);
        Assert.Contains(reports.Values, report => report.Phase == CaptureWorkPhase.PolicyFiles);
        Assert.Equal(CaptureWorkPhase.Sealing, reports.Values.Last().Phase);
        Assert.Same(final, reports.Values.Last());
    }

    private const string Forest = "example.com";
    private const string Configuration = "CN=Configuration,DC=example,DC=com";
    private const string Schema = "CN=Schema,CN=Configuration,DC=example,DC=com";
    private const string FirstDomain = "DC=one,DC=example,DC=com";
    private const string SecondDomain = "DC=two,DC=example,DC=com";

    private const string RootHost = "dc0.example.com";
    private const string FirstHost = "dc1.example.com";
    private const string SecondHost = "dc2.example.com";

    private static readonly DateTimeOffset Started =
        new(2026, 9, 13, 2, 0, 0, TimeSpan.Zero);

    private readonly string _root =
        Path.Combine(Path.GetTempPath(), "securead-fanout-" + Guid.NewGuid().ToString("N"));

    // ---------------------------------------------------------------------------------------
    // That they are read together at all
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Two domains on two controllers are in flight at the same moment.
    /// </summary>
    /// <remarks>
    /// The fire test for the whole decision. Before the fan-out landed, the rendezvous below could
    /// never complete: the second domain's read did not begin until the first had finished.
    /// </remarks>
    [Fact]
    public async Task DomainsOnDifferentControllersAreReadAtTheSameTime()
    {
        var forest = TwoDomainsOnTwoControllers(ForestModel.UntilTheOthersArrive);

        var run = await RunAsync(forest, domainsAtOnce: 2);

        Assert.True(run.ProducedABundle, run.Error?.Description);
        Assert.True(
            forest.EveryoneArrived,
            "The domains never overlapped, so they were read one after another.");
    }

    /// <summary>
    /// The ceiling is obeyed: at one domain at a time, nothing overlaps.
    /// </summary>
    /// <remarks>
    /// The negative control for the test above. Without it, a fan-out that ignored
    /// <c>DomainsAtOnce</c> entirely would pass every other assertion here - and the setting would
    /// go on reading as consumed while binding nothing, which is the state
    /// <c>MaxInFlightRequestsPerDc</c> shipped in for years in the predecessor.
    /// </remarks>
    [Fact]
    public async Task TheCeilingKeepsMoreDomainsThanItAllowsFromRunningTogether()
    {
        var forest = TwoDomainsOnTwoControllers(ForestModel.LongEnoughToCatchAnOverlap);

        var run = await RunAsync(forest, domainsAtOnce: 1);

        Assert.True(run.ProducedABundle, run.Error?.Description);
        Assert.Equal(1, forest.MostReadsOpenAtOnce);
    }

    /// <summary>
    /// Two domains that share a controller are never read at the same time.
    /// </summary>
    /// <remarks>
    /// <b>The correctness rule the parallelism is arranged around, not an exception to it.</b> A
    /// writable controller holds one domain, so Active Directory does not usually produce this -
    /// but <c>ControllerSelection</c> has no rule against it, and a concurrency that is safe only
    /// because the directory happens to be shaped a certain way is the defect the dispatcher
    /// exists to remove. The ceiling here is wide open; what holds the line is the per-host turn.
    /// </remarks>
    [Fact]
    public async Task TwoDomainsOnOneControllerAreNeverReadTogether()
    {
        var forest = TwoDomainsOnOneController(ForestModel.LongEnoughToCatchAnOverlap);

        var run = await RunAsync(forest, domainsAtOnce: 9);

        Assert.True(run.ProducedABundle, run.Error?.Description);
        Assert.Equal(1, forest.MostReadsOpenAtOnce);
    }

    // ---------------------------------------------------------------------------------------
    // That the shards are put back together
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Every domain's objects are in the sealed bundle.
    /// </summary>
    /// <remarks>
    /// Each domain was read into a database of its own, so this is the merge working rather than
    /// the capture working. A merge that dropped a shard would leave a bundle reporting a domain
    /// it had read as holding nothing.
    /// </remarks>
    [Fact]
    public async Task EveryDomainsObjectsReachTheBundle()
    {
        var forest = TwoDomainsOnTwoControllers(TimeSpan.Zero);

        var run = await RunAsync(forest, domainsAtOnce: 2);

        Assert.True(run.ProducedABundle, run.Error?.Description);

        Assert.Equal(
            forest.ObjectsIn(FirstDomain),
            ObjectsUnder(run.BundleDirectory, FirstDomain));

        Assert.Equal(
            forest.ObjectsIn(SecondDomain),
            ObjectsUnder(run.BundleDirectory, SecondDomain));
    }

    /// <summary>
    /// Two domains' objects keep their own identifiers through the merge.
    /// </summary>
    /// <remarks>
    /// <b>What the shard ranges exist for.</b> Every keyed table in the schema counts from one, so
    /// two shards each hand identifier 1 to a different object. A merge that let them collide
    /// would attach one domain's permissions to another domain's principal - a permission reported
    /// against the wrong account, in a bundle that looks perfectly healthy.
    /// </remarks>
    [Fact]
    public async Task NoTwoObjectsShareAnIdentifierAcrossDomains()
    {
        var forest = TwoDomainsOnTwoControllers(TimeSpan.Zero);

        var run = await RunAsync(forest, domainsAtOnce: 2);

        Assert.True(run.ProducedABundle, run.Error?.Description);

        Assert.Equal(
            Scalar(run.BundleDirectory, "SELECT COUNT(*) FROM captured_object"),
            Scalar(run.BundleDirectory, "SELECT COUNT(DISTINCT object_id) FROM captured_object"));
    }

    /// <summary>
    /// A shard is deleted once its rows are in the bundle.
    /// </summary>
    /// <remarks>
    /// Scaffolding rather than evidence: never sealed, never given the name a reader asks for.
    /// Nine left behind would roughly double what a capture costs on disk at the moment the bundle
    /// is at its largest, which on the forest this is built for is the binding constraint.
    /// </remarks>
    [Fact]
    public async Task NoShardSurvivesASealedBundle()
    {
        var forest = TwoDomainsOnTwoControllers(TimeSpan.Zero);

        var run = await RunAsync(forest, domainsAtOnce: 2);

        Assert.True(run.ProducedABundle, run.Error?.Description);

        Assert.False(File.Exists(BundleLayout.ShardPath(run.BundleDirectory, BundleShard.Number(1))));
        Assert.False(File.Exists(BundleLayout.ShardPath(run.BundleDirectory, BundleShard.Number(2))));
    }

    // ---------------------------------------------------------------------------------------
    // A domain that failed
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// One domain nothing could reach ends the run, and no bundle is sealed.
    /// </summary>
    /// <remarks>
    /// <c>docs/decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md</c> survives the
    /// fan-out unchanged. A bundle covering part of a forest is evidence a customer would act on.
    /// </remarks>
    [Fact]
    public async Task ADomainThatCouldNotBeReachedSealsNoBundle()
    {
        var forest = TwoDomainsOnTwoControllers(TimeSpan.Zero);
        forest.Refuse(SecondHost);

        var run = await RunAsync(forest, domainsAtOnce: 2);

        Assert.False(run.ProducedABundle);
        Assert.False(File.Exists(BundleLayout.EvidencePath(run.BundleDirectory)));
    }

    /// <summary>
    /// The failed domain's shard is never folded in.
    /// </summary>
    /// <remarks>
    /// <b>This is what "recorded as unread, never as empty" comes to in the code.</b> The writer
    /// for a domain that failed is disposed without being finished, so there is nothing the merge
    /// can open - and the bundle can never contain a domain that reports having been read and
    /// found to hold nothing.
    /// </remarks>
    [Fact]
    public async Task AFailedDomainsShardIsNeverMerged()
    {
        var forest = TwoDomainsOnTwoControllers(TimeSpan.Zero);
        forest.Refuse(SecondHost);

        var run = await RunAsync(forest, domainsAtOnce: 2);

        Assert.False(run.ProducedABundle);

        // Nothing was merged at all, because the run ended before the merge pass - so the domain
        // that did succeed still has its shard on disk. Deleting the record of how far a run got is
        // the run library's decision, not that of the code that has just failed.
        Assert.True(File.Exists(BundleLayout.ShardPath(run.BundleDirectory, BundleShard.Number(1))));
    }

    /// <summary>
    /// The run says which domain failed.
    /// </summary>
    [Fact]
    public async Task AFailedDomainIsNamedInTheOutcome()
    {
        var forest = TwoDomainsOnTwoControllers(TimeSpan.Zero);
        forest.Refuse(SecondHost);

        var run = await RunAsync(forest, domainsAtOnce: 2);

        var outcome = await File.ReadAllTextAsync(
            Path.Combine(run.BundleDirectory, "run-outcome.json"));

        Assert.Contains(SecondDomain, outcome, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------------------------------

    private Task<CaptureRunResult> RunAsync(ForestModel forest, int domainsAtOnce) => RunAsync(forest, domainsAtOnce, null);

    private async Task<CaptureRunResult> RunAsync(ForestModel forest, int domainsAtOnce, IProgress<CaptureProgress>? progress)
    {
        var plan = CapturePlan.For(
            RootHost,
            Forest,
            Configuration,
            Schema,
            [
                (FirstDomain, "one.example.com", forest.HostOf(FirstDomain)),
                (SecondDomain, "two.example.com", forest.HostOf(SecondDomain)),
            ],
            [Configuration, Schema, FirstDomain, SecondDomain],
            [],
            new Dictionary<string, IReadOnlyList<string>>());

        Assert.True(plan.IsSuccess, plan.Error?.Description);

        var library = new RunLibrary(_root, TimeProvider.System);
        var directory = library.CreateRun(Forest);
        Assert.True(directory.IsSuccess, directory.Error?.Description);

        var run = new CaptureRun(
            forest.Connections(),
            new InMemorySysvolFileReader(),
            new FrozenClock(Started),
            RunLog.Discarded,
            domainsAtOnce);

        using var files = new ProtectedRunFiles(directory.Value!);
        return await run.RunAsync(plan.Value!, directory.Value!, new Dictionary<string, AttestedExclusion>(),
            CaptureOptions.Default, CancellationToken.None, files, progress);
    }

    /// <summary>Two domains, each pinned to a controller of its own.</summary>
    private static ForestModel TwoDomainsOnTwoControllers(TimeSpan holding) =>
        new([(FirstDomain, FirstHost), (SecondDomain, SecondHost)], holding);

    /// <summary>
    /// Two domains a forest has put on one machine, which the dispatcher must serialise.
    /// </summary>
    private static ForestModel TwoDomainsOnOneController(TimeSpan holding) =>
        new([(FirstDomain, FirstHost), (SecondDomain, FirstHost)], holding);

    private static long ObjectsUnder(string bundleDirectory, string namingContextDn) =>
        Scalar(
            bundleDirectory,
            "SELECT COUNT(*) FROM captured_object WHERE distinguished_name LIKE '%"
            + namingContextDn + "'");

    private static long Scalar(string bundleDirectory, string sql)
    {
        using var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = BundleLayout.EvidencePath(bundleDirectory),
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false,
            }.ToString());

        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = sql;

        return Convert.ToInt64(command.ExecuteScalar());
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();

        if (Directory.Exists(_root))
            Directory.Delete(_root, recursive: true);
    }

    /// <summary>
    /// A clock that does not move, so two runs of one fixture agree.
    /// </summary>
    private sealed class FrozenClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
