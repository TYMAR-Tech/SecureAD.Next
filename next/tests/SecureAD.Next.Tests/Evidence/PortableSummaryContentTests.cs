using System.Globalization;
using System.Security.AccessControl;
using Microsoft.Data.Sqlite;
using SecureAD.Audit.Capture;
using SecureAD.Audit.Connect;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Next.Tests.Capture;
using SecureAD.Next.Tests.Kernel.Security;
using SecureAD.Next.Tests.Sysvol;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// What the portable run summary actually says, against a real capture of a real bundle.
/// </summary>
/// <remarks>
/// <para>
/// <b><c>PortableSummaryLeakTests</c> holds the promise; this holds the content.</b> That one asks
/// whether a forbidden value can reach the file by any route. These ask whether the figures in it
/// are the ones the stores hold - because a summary that is safe to send and wrong about the run is
/// no better than one that is right and cannot be sent.
/// </para>
/// <para>
/// <b>Anchored to the evidence database, not to arithmetic done here.</b> Every count is checked
/// against a query over the bundle the capture produced, so a test cannot agree with a summary that
/// both got wrong. Where a check could pass without measuring anything - because the fixture
/// happens not to distinguish the two cases - it asserts that the fixture does distinguish them
/// first.
/// </para>
/// </remarks>
public sealed class PortableSummaryContentTests
{
    private const string Domain = "DC=example,DC=com";
    private const string Configuration = "CN=Configuration,DC=example,DC=com";
    private const string Controller = "dc01.example.com";

    private static readonly DateTimeOffset Started = new(2026, 9, 22, 1, 0, 0, TimeSpan.Zero);

    // -----------------------------------------------------------------------------------------
    // The capture section.
    // -----------------------------------------------------------------------------------------

    /// <summary>
    /// The domain row carries the object and entry counts the bundle holds for that domain, and
    /// not every object the run captured.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The configuration and schema partitions must not be billed to a domain.</b> Every
    /// captured object is stamped with the domain of its own distinguished name, and the
    /// configuration partition lives under the forest root's - so counting without restricting to
    /// domain partitions reports the root as several times larger than it is, plausibly, which is
    /// the worst kind of wrong figure.
    /// </para>
    /// <para>
    /// The first assertion is the check on the check: if the fixture captured nothing outside a
    /// domain partition, the second assertion would pass against a count that never filtered
    /// anything.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task TheDomainRowCountsWhatTheBundleHoldsForThatDomainAlone()
    {
        var bundle = await ACapturedForest(withAnObjectOutsideAnyDomain: true);

        var everything = Count(bundle, "SELECT COUNT(*) FROM captured_object");
        var inDomains = Count(bundle, DomainObjectCount);

        Assert.NotEqual(everything, inDomains);

        var row = DomainRow(Summarised(bundle));

        Assert.Equal(Number(inDomains), row.Objects);
        Assert.Equal(Number(Count(bundle, DomainEntryCount)), row.Entries);
    }

    /// <summary>
    /// The domain is named as the coverage names it, and what became of reading it is said beside
    /// the counts.
    /// </summary>
    /// <remarks>
    /// <b>The outcome is what makes the numbers readable</b>: a count with nothing qualifying it
    /// cannot say whether it was reached. Asserted as a whole column rather than as a substring,
    /// because <c>Read</c> is inside <c>NotRead</c> - the two opposite answers a reader most needs
    /// told apart.
    /// </remarks>
    [Fact]
    public async Task TheDomainRowNamesTheDomainAndWhatBecameOfReadingIt()
    {
        var row = DomainRow(Summarised(await ACapturedForest()));

        Assert.Equal("example.com", row.Domain);
        Assert.Equal(nameof(DomainReadOutcome.Read), row.Outcome);
    }

    /// <summary>
    /// How long a domain took reaches the file, because nothing else in the product records it.
    /// </summary>
    [Fact]
    public async Task TheDomainRowCarriesTheElapsedTimeTheRunMeasured()
    {
        var bundle = await ACapturedForest();

        var row = DomainRow(Summarised(bundle, elapsed: 91_412));

        Assert.Equal("91,412", row.Milliseconds);
    }

    /// <summary>
    /// A domain read from a controller beside the capture machine says so.
    /// </summary>
    [Fact]
    public async Task AControllerInTheOperatorsOwnSiteIsReportedAsYes() =>
        Assert.Equal("yes", DomainRow(Summarised(await ACapturedForest(), inSite: true)).Site);

    /// <summary>
    /// A domain read across a link says that instead.
    /// </summary>
    /// <remarks>
    /// Asserted as a whole column, because <c>no</c> is inside <c>not established</c> and a
    /// substring check would pass against the one answer this must never be confused with.
    /// </remarks>
    [Fact]
    public async Task AControllerOutsideTheOperatorsSiteIsReportedAsNo() =>
        Assert.Equal("no", DomainRow(Summarised(await ACapturedForest(), inSite: false)).Site);

    /// <summary>
    /// A capture machine with no site of its own is not reported as having been elsewhere.
    /// </summary>
    /// <remarks>
    /// <b>The case the three-state flag exists for.</b> <i>No</i> and <i>nothing to compare
    /// against</i> are different facts, and rendering the second as the first asserts something
    /// nobody established - about the customer's forest rather than about the machine the audit was
    /// run from. Collapse the flag to a boolean and this fails.
    /// </remarks>
    [Fact]
    public async Task AMachineWithNoSiteOfItsOwnIsNotReportedAsBeingElsewhere() =>
        Assert.Equal(
            "not established",
            DomainRow(Summarised(await ACapturedForest(), inSite: null)).Site);

    /// <summary>
    /// Each domain's elapsed time leaves the capture, which is the only place it is ever known.
    /// </summary>
    /// <remarks>
    /// <b>Checked on the run's own result rather than through the file</b>, because this is the
    /// carrying rather than the writing. Stop measuring and the summary reports every domain as
    /// having taken no time - a figure, and a wrong one.
    /// </remarks>
    [Fact]
    public async Task TheCaptureCarriesEachDomainsElapsedTimeOutOfTheRun()
    {
        // A clock that moves a second at every reading, so a real elapsed time is a multiple of a
        // second and an unmeasured one is nought. The system clock would leave the two
        // indistinguishable on a capture this small, and the test would pass whatever the run did.
        var captured = await Capture(
            TempDirectories.Create("summary-timings"), clock: new SteppingClock());

        var timing = Assert.Single(captured.DomainTimings);

        Assert.Equal(Domain, timing.NamingContext);
        Assert.True(
            timing.ElapsedMilliseconds > 0,
            $"The domain was reported as having taken {timing.ElapsedMilliseconds} ms.");
    }

    // -----------------------------------------------------------------------------------------
    // What a capture-only run says, and what it must not.
    // -----------------------------------------------------------------------------------------

    /// <summary>
    /// A run that was captured and not yet analysed claims nothing about deriving or judging.
    /// </summary>
    /// <remarks>
    /// <b>Absence rather than zeros, which is <c>docs/decisions/0002</c>'s exact case.</b> A
    /// derivation section reading <i>0 principals</i> and a judging section reading <i>None were
    /// recorded</i> would tell an operator his forest is quiet, when what happened is that nobody
    /// has looked yet. The sections are simply not there until those stages run.
    /// </remarks>
    [Fact]
    public async Task ACaptureOnlySummaryClaimsNothingAboutDerivingOrJudging()
    {
        var written = Summarised(await ACapturedForest());

        Assert.DoesNotContain("Derivation", written, StringComparison.Ordinal);
        Assert.DoesNotContain("Judging", written, StringComparison.Ordinal);
        Assert.DoesNotContain("Principals", written, StringComparison.Ordinal);
        Assert.DoesNotContain("judged", written, StringComparison.Ordinal);
        Assert.DoesNotContain("Findings", written, StringComparison.Ordinal);
    }

    // -----------------------------------------------------------------------------------------
    // The two sections that arrive later, possibly days later.
    // -----------------------------------------------------------------------------------------

    /// <summary>
    /// Deriving appends what the derivation store holds, beside where its time went.
    /// </summary>
    [Fact]
    public async Task DerivingAppendsThePrincipalCountTheStoreHolds()
    {
        var bundle = await ACapturedForest();
        Summarised(bundle);

        Derive(bundle);

        var written = File.ReadAllText(BundleLayout.PortableSummaryPath(bundle));

        using var reader = DerivationReader.Open(bundle).Value!;
        var derivation = reader.Read();

        Assert.Contains("Derivation", written, StringComparison.Ordinal);
        Assert.Contains(derivation.Description.State.ToString(), written, StringComparison.Ordinal);
        Assert.Contains(
            Number(derivation.Size.Principals), written, StringComparison.Ordinal);

        // The phase breakdown is the half nothing persists, so its absence would be silent.
        Assert.Contains(MembershipNestingPass.PhaseName, written, StringComparison.Ordinal);
    }

    /// <summary>
    /// Judging appends every scheduled rule and how many findings there were of each severity.
    /// </summary>
    /// <remarks>
    /// <b>Counted by severity and never listed.</b> A finding names the object it is about, so the
    /// findings stay in the bundle; how many there were of each kind is the part that travels.
    /// </remarks>
    [Fact]
    public async Task JudgingAppendsEveryRuleAndTheFindingsBySeverity()
    {
        var bundle = await ACapturedForest();
        Summarised(bundle);
        Derive(bundle);

        Judge(bundle);

        var written = File.ReadAllText(BundleLayout.PortableSummaryPath(bundle));

        using var reader = JudgementReader.Open(bundle).Value!;
        var severities = reader.ReadFindingCountsBySeverity();

        Assert.Contains("Judging", written, StringComparison.Ordinal);

        // Every scheduled rule has a row, whatever it concluded. A rule that is missing from the
        // table and a rule that found nothing must not look alike.
        foreach (var rule in reader.ReadRuleExecutions().Executions)
            Assert.Contains(rule.RuleId, written, StringComparison.Ordinal);

        Assert.NotEmpty(severities);

        foreach (var severity in severities)
            Assert.Contains(severity.Key.ToString(), written, StringComparison.Ordinal);
    }

    /// <summary>
    /// The whole summary of a captured, derived and judged run carries nothing out of the forest
    /// but a domain name.
    /// </summary>
    /// <remarks>
    /// <b>The promise, checked against the run rather than against a hand-built summary.</b>
    /// <c>PortableSummaryLeakTests</c> proves the writer cannot be handed a forbidden value;
    /// this proves that what a real run hands it does not contain one - which is the half a
    /// customer is actually relying on.
    /// </remarks>
    [Fact]
    public async Task ThePortableSummaryOfAJudgedRunHoldsNoNameFromTheForest()
    {
        var bundle = await ACapturedForest();
        Summarised(bundle);
        Derive(bundle);
        Judge(bundle);

        var written = File.ReadAllText(BundleLayout.PortableSummaryPath(bundle));

        Assert.DoesNotContain(Controller, written, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("CN=", written, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("OU=", written, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("DC=", written, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("svc-web", written, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(bundle, written, StringComparison.OrdinalIgnoreCase);

        // The negative control. Every assertion above passes against an empty file.
        Assert.Contains("example.com", written, StringComparison.Ordinal);
    }

    // -----------------------------------------------------------------------------------------
    // Fixtures.
    // -----------------------------------------------------------------------------------------

    /// <summary>Objects captured under a partition the forest calls a domain.</summary>
    private const string DomainObjectCount =
        """
        SELECT COUNT(*) FROM captured_object o
        JOIN partition_coverage p ON p.coverage_id = o.coverage_id
        WHERE p.naming_context_kind = 'Domain'
        """;

    /// <summary>Access control entries on those objects, counting only descriptors that were read.</summary>
    private const string DomainEntryCount =
        """
        SELECT COALESCE(SUM(o.ace_count), 0) FROM captured_object o
        JOIN partition_coverage p ON p.coverage_id = o.coverage_id
        WHERE p.naming_context_kind = 'Domain'
        """;

    /// <summary>
    /// Writes the capture section of a real bundle and hands back what reached the file.
    /// </summary>
    /// <param name="bundleDirectory">A sealed bundle.</param>
    /// <param name="elapsed">How long the domain took, which no store holds.</param>
    /// <param name="inSite">Whether its controller was beside the capture machine.</param>
    /// <returns>The written summary.</returns>
    private static string Summarised(
        string bundleDirectory, long elapsed = 1_204, bool? inSite = true)
    {
        var written = PortableSummaryFile.WriteCapture(
            bundleDirectory,
            PortableSummaryReading.OfCapture(
                bundleDirectory,
                elapsedMilliseconds: 12_000,
                [new StageTiming("preflight", 400), new StageTiming("capture", 11_600)],
                [new DomainRunTiming(Domain, elapsed, inSite)],
                ending: null));

        // A write that failed leaves nothing, and nothing passes every check that looks for an
        // absence.
        Assert.True(written.IsSuccess, written.IsSuccess ? string.Empty : written.Error.Description);

        return File.ReadAllText(BundleLayout.PortableSummaryPath(bundleDirectory));
    }

    /// <summary>
    /// One row of the domain table, split into its columns.
    /// </summary>
    /// <remarks>
    /// <b>Parsed rather than searched, and mutation testing is why.</b> Substring checks over the
    /// whole row passed against the wrong value in three places: <c>2</c> is inside the elapsed
    /// <c>1,204</c>, <c>no</c> is inside <c>not established</c>, and <c>Read</c> is inside
    /// <c>NotRead</c> - the last two being the exact pairs a reader must never have confused.
    /// </remarks>
    /// <param name="Domain">The domain, in DNS form.</param>
    /// <param name="Outcome">What became of reading it.</param>
    /// <param name="Objects">How many objects, as written.</param>
    /// <param name="Entries">How many access control entries, as written.</param>
    /// <param name="Milliseconds">How long it took, as written.</param>
    /// <param name="Site">Whether its controller was in the capture machine's site.</param>
    private readonly record struct DomainColumns(
        string Domain,
        string Outcome,
        string Objects,
        string Entries,
        string Milliseconds,
        string Site);

    /// <summary>The one line of the domain table, which is where every per-domain figure is.</summary>
    /// <param name="written">The written summary.</param>
    /// <returns>The row for the captured domain, in columns.</returns>
    private static DomainColumns DomainRow(string written)
    {
        var row = Assert.Single(written
            .Split(Environment.NewLine)
            .Where(line => line.StartsWith("  example.com", StringComparison.Ordinal)));

        var fields = row.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        // Six columns, the last of which is two words when nothing was established. Fewer means
        // the row is not the shape this reads, and asserting on columns that were never there is
        // how a check comes to measure nothing.
        Assert.True(fields.Length >= 6, row);

        return new DomainColumns(
            fields[0],
            fields[1],
            fields[2],
            fields[3],
            fields[4],
            string.Join(' ', fields[5..]));
    }

    private static void Derive(string bundleDirectory)
    {
        var derived = Stage2aRun.Derive(
            bundleDirectory,
            ExpansionBudget.Bulk,
            Started,
            Stage2aRun.Unwatched,
            RunLog.Discarded,
            CancellationToken.None);

        Assert.True(derived.IsSuccess, derived.Error?.Description);
    }

    private static void Judge(string bundleDirectory)
    {
        var judged = JudgingRun.Judge(
            bundleDirectory,
            RuleCatalogue.All,
            Started,
            Started,
            JudgingRun.NobodyIsWatching,
            RunLog.Discarded,
            CancellationToken.None);

        Assert.True(judged.IsSuccess, judged.Error?.Description);
    }

    /// <summary>A forest captured into a sealed bundle, ready to be summarised.</summary>
    /// <param name="withAnObjectOutsideAnyDomain">
    /// Whether to include an object in the configuration partition.
    /// <para>
    /// <b>Off unless a test needs it, and the reason is the test controller rather than the
    /// product.</b> <c>ControllerModel</c> scopes a search by distinguished-name suffix, and every
    /// configuration object's name ends in the forest root's - so the domain search returns it as
    /// well and it is captured twice. A real controller cannot do that, because naming contexts do
    /// not overlap, but a bundle holding one object twice makes judging refuse a duplicate.
    /// </para>
    /// </param>
    /// <returns>The bundle's directory.</returns>
    private static async Task<string> ACapturedForest(bool withAnObjectOutsideAnyDomain = false)
    {
        var captured = await Capture(
            TempDirectories.Create("summary-content"), withAnObjectOutsideAnyDomain);

        return captured.BundleDirectory;
    }

    private static async Task<CaptureRunResult> Capture(
        string root, bool withAnObjectOutsideAnyDomain = false, TimeProvider? clock = null)
    {
        var controller = AForest(withAnObjectOutsideAnyDomain);
        var plan = CapturePlan.For(
            controller.DomainController,
            "example.com",
            Configuration,
            "CN=Schema," + Configuration,
            [(Domain, "example.com", controller.DomainController)],
            controller.NamingContexts,
            ["DC=DomainDnsZones,DC=example,DC=com"],
            new Dictionary<string, IReadOnlyList<string>>());

        Assert.True(plan.IsSuccess, plan.Error?.Description);

        var directory = new RunLibrary(root, TimeProvider.System).CreateRun("example.com");
        Assert.True(directory.IsSuccess, directory.Error?.Description);

        var captured = await new CaptureRun(
            controller.Connections(),
            new InMemorySysvolFileReader(),
            clock ?? TimeProvider.System,
            RunLog.Discarded,
            DirectoryConnectionSettings.DefaultDomainsAtOnce).RunAsync(
                plan.Value!,
                directory.Value!,
                new Dictionary<string, AttestedExclusion>(),
                CancellationToken.None);

        Assert.True(captured.ProducedABundle, captured.Error?.Description);

        return captured;
    }

    /// <summary>
    /// A forest with an account, and optionally one object outside any domain partition.
    /// </summary>
    /// <remarks>
    /// The configuration object is what makes the per-domain count worth checking: it is captured,
    /// and its own coverage row must not be counted against the domain.
    /// </remarks>
    /// <param name="withAnObjectOutsideAnyDomain">Whether to add the configuration object.</param>
    /// <returns>The forest.</returns>
    private static ControllerModel AForest(bool withAnObjectOutsideAnyDomain)
    {
        var controller = new ControllerModel(Controller);
        controller.AnswersTo.Add("example.com");

        controller.AddObject(
            "CN=svc-web," + Domain,
            ("objectClass", ["top", "person", "organizationalPerson", "user"]),
            ("objectGUID", [Guid.NewGuid().ToByteArray()]),
            ("objectSid", [Sid(1104)]),
            ("sAMAccountName", ["svc-web"]),
            ("userAccountControl", ["524800"]),
            ("primaryGroupID", ["513"]),
            ("nTSecurityDescriptor", [Descriptor()]));

        if (withAnObjectOutsideAnyDomain)
        {
            controller.AddObject(
                "CN=Partitions," + Configuration,
                ("objectClass", ["top", "crossRefContainer"]),
                ("objectGUID", [Guid.NewGuid().ToByteArray()]),
                ("nTSecurityDescriptor", [Descriptor()]));
        }

        return controller;
    }

    private static byte[] Descriptor()
    {
        var descriptor = new RawSecurityDescriptor("O:SYG:SYD:(A;;RP;;;BA)");
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        return bytes;
    }

    private static byte[] Sid(uint relativeIdentifier) =>
        SdBytes.Sid(1, 5, [21, 1111111111, 2222222222, 3333333333, relativeIdentifier]);

    private static string Number(long value) =>
        value.ToString("N0", CultureInfo.InvariantCulture);

    /// <summary>
    /// A clock that moves on a second every time it is read.
    /// </summary>
    /// <remarks>
    /// <b>So that "measured" and "not measured" cannot look alike.</b> A capture of two objects
    /// takes less than a millisecond on the system clock, so a run that measured its domains
    /// honestly and one that reported nought would both write nought - and a test asserting the
    /// elapsed time would pass whatever the run did.
    /// </remarks>
    private sealed class SteppingClock : TimeProvider
    {
        private static readonly DateTimeOffset Origin =
            new(2026, 9, 22, 9, 0, 0, TimeSpan.Zero);

        private long _readings;

        public override DateTimeOffset GetUtcNow() =>
            Origin.AddSeconds(Interlocked.Increment(ref _readings));
    }

    private static long Count(string bundleDirectory, string sql)
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = BundleLayout.EvidencePath(bundleDirectory),
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());

        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = sql;

        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }
}
