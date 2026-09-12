using System.Text.Json;
using SecureAD.Audit.Capture;
using SecureAD.Audit.Connect;
using SecureAD.Evidence;
using SecureAD.Next.Tests.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Connect;

/// <summary>
/// Preflight: asking every question of every domain before a run commits hours to a controller
/// that was never going to work.
///
/// <para>
/// The behaviour under test is
/// <c>docs/decisions/0048-preflight-proves-a-controller-before-a-run-commits.md</c>, and in
/// particular its requirement that <i>every question is answered for every domain before any is
/// allowed to stop the run</i>. The loop this replaced returned on the first bad domain, so a
/// forest with three faults cost four attempts to discover three facts.
/// </para>
/// </summary>
public sealed class PreflightTests
{
    private const string Root = "DC=example,DC=com";
    private const string Reachable = "DC=good,DC=example,DC=com";
    private const string Absent = "DC=gone,DC=example,DC=com";
    private const string Elsewhere = "DC=elsewhere,DC=example,DC=com";
    private const string Denied = "DC=denied,DC=example,DC=com";

    /// <summary>
    /// A forest of four domains, three of which are faulty in a different way. One pass must
    /// produce four answers.
    /// </summary>
    /// <remarks>
    /// This is the failure the session removed, stated as a test: four attempts to learn three
    /// facts, each attempt repeating discovery and reconnecting to every healthy domain.
    /// </remarks>
    [Fact]
    public async Task EveryDomainIsAskedEvenWhenTheFirstOneFails()
    {
        var report = await AskAsync(AForestWithSeveralFaults(), Absent, Root, Elsewhere, Denied);

        Assert.Equal(
            [Absent, Root, Elsewhere, Denied],
            report.Domains.Select(d => d.NamingContext));
    }

    /// <summary>
    /// A controller nothing answered from is given no connection rung.
    ///
    /// <para>
    /// This is finding <c>F-S35-1</c>. A host that does not resolve descends the ladder, is refused
    /// at every rung because there is nothing there, and must not emerge described as a controller
    /// that declines protected connections. That would be a security claim about a customer's
    /// forest that the product never measured, which
    /// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> forbids.
    /// </para>
    /// </summary>
    [Fact]
    public async Task AControllerThatAnsweredNothingIsGivenNoRung()
    {
        var report = await AskAsync(AForestWithSeveralFaults(), Absent);

        var domain = Assert.Single(report.Domains);
        Assert.False(domain.Answered);
        Assert.Null(domain.RungReached);
    }

    /// <summary>
    /// The questions a failed connection never reached are recorded as unasked, not as negative
    /// answers. A boolean would have had to say <c>false</c> to both.
    /// </summary>
    [Fact]
    public async Task TheQuestionsAnUnreachableControllerWasNeverAskedAreRecordedAsUnasked()
    {
        var report = await AskAsync(AForestWithSeveralFaults(), Absent);

        var domain = Assert.Single(report.Domains);
        Assert.Equal(PreflightAnswer.NotAsked, domain.ServesThePartition);
        Assert.Equal(PreflightAnswer.NotAsked, domain.PasswordSettingsContainerReadable);
    }

    /// <summary>
    /// The rung each controller answered on reaches the caller, for a domain that succeeded.
    ///
    /// <para>
    /// It was measured and discarded before this session: <c>ValidateAsync</c> built a
    /// <c>ConnectionSecurityLog</c>, walked the ladder with it and threw it away, so which rung a
    /// controller answered on - the whole point of
    /// <c>docs/decisions/0018-connection-security-is-an-ordered-ladder.md</c> - never left the
    /// method.
    /// </para>
    /// </summary>
    [Fact]
    public async Task TheRungAControllerAnsweredOnReachesTheCaller()
    {
        var forest = AForestWithSeveralFaults();

        var report = await AskAsync(forest, Root);

        Assert.Equal(ConnectionSecurityLevel.Signed, Assert.Single(report.Domains).RungReached);
    }

    /// <summary>
    /// A controller that does not serve the partition it was chosen for is recorded as such, and
    /// the domain cannot be read.
    /// </summary>
    [Fact]
    public async Task AControllerThatDoesNotServeThePartitionIsRecorded()
    {
        var report = await AskAsync(AForestWithSeveralFaults(), Elsewhere);

        var domain = Assert.Single(report.Domains);
        Assert.Equal(PreflightAnswer.No, domain.ServesThePartition);
        Assert.False(domain.CanBeRead);
    }

    /// <summary>
    /// A Password Settings Container that could not be read is recorded and does not stop the run.
    ///
    /// <para>
    /// <c>0048</c> states that Enterprise Admins is not required and that the supported posture is
    /// an ordinary account with read access delegated per domain. A run that refused to start over
    /// one container would refuse that posture. What the answer buys is paid later: a report that
    /// says it could not tell, instead of one reporting that the domain has no fine-grained
    /// password policy when it has several.
    /// </para>
    /// </summary>
    [Fact]
    public async Task AnUnreadablePasswordSettingsContainerDoesNotStopTheRun()
    {
        var report = await AskAsync(AForestWithSeveralFaults(), Denied);

        var domain = Assert.Single(report.Domains);
        Assert.Equal(PreflightAnswer.No, domain.PasswordSettingsContainerReadable);
        Assert.True(domain.CanBeRead);
        Assert.True(report.RunMayProceed);
    }

    /// <summary>
    /// The domain whose container could not be read is named, so a report can later say it could
    /// not tell rather than that there is no fine-grained password policy.
    /// </summary>
    [Fact]
    public async Task TheDomainWhoseContainerCouldNotBeReadIsNamed()
    {
        var report = await AskAsync(AForestWithSeveralFaults(), Root, Denied);

        Assert.Equal(
            [Denied],
            report.CouldNotReadPasswordSettings.Select(d => d.NamingContext));
    }

    /// <summary>
    /// A container that was read is recorded as read, so the answer above is a measurement rather
    /// than a constant.
    /// </summary>
    [Fact]
    public async Task AContainerThatWasReadIsRecordedAsRead()
    {
        var report = await AskAsync(AForestWithSeveralFaults(), Root);

        Assert.Equal(
            PreflightAnswer.Yes,
            Assert.Single(report.Domains).PasswordSettingsContainerReadable);
    }

    /// <summary>
    /// A forest whose domains all answered may proceed.
    /// </summary>
    [Fact]
    public async Task AForestThatAnsweredMayProceed()
    {
        var report = await AskAsync(AForestWithSeveralFaults(), Root, Reachable);

        Assert.True(report.RunMayProceed);
        Assert.Null(report.Refusal([]));
    }

    /// <summary>
    /// The refusal names every domain that failed, rather than the first one met.
    ///
    /// <para>
    /// This is the point at which the collected answers could still have been thrown away. A caller
    /// returning a single error would otherwise have reduced four answers to one, reintroducing
    /// one-fault-per-attempt a layer above the loop that was fixed.
    /// </para>
    /// </summary>
    [Fact]
    public async Task TheRefusalNamesEveryDomainThatFailed()
    {
        var report = await AskAsync(AForestWithSeveralFaults(), Absent, Root, Elsewhere, Denied);

        var refusal = report.Refusal([]);

        Assert.NotNull(refusal);
        Assert.Contains("2 of 4 domains", refusal.Description, StringComparison.Ordinal);
        Assert.Contains(Absent, refusal.Description, StringComparison.Ordinal);
        Assert.Contains(Elsewhere, refusal.Description, StringComparison.Ordinal);
    }

    /// <summary>
    /// A domain the operator has attested his way out of does not stop the run, because nothing is
    /// going to try to read it.
    ///
    /// <para>
    /// A domain with no candidate controllers fails preflight for precisely the reason it was
    /// excluded. Counting it as blocking turned a deliberate exclusion into an unreachable forest,
    /// so a run an operator had already accounted for refused to start.
    /// </para>
    /// </summary>
    [Fact]
    public async Task ADomainTheRunHasAnAttestationForDoesNotBlockIt()
    {
        var report = await AskAsync(AForestWithSeveralFaults(), Absent, Root, Elsewhere, Denied);

        Assert.Null(report.Refusal([Absent, Elsewhere]));
    }

    /// <summary>
    /// An attestation for one blocking domain does not excuse another.
    ///
    /// <para>
    /// The negative control for the test above. Without it, a refusal that simply stopped counting
    /// whenever any exclusion existed would pass, which is the failure - a forest silently read
    /// short - that the whole attestation mechanism exists to prevent.
    /// </para>
    /// </summary>
    [Fact]
    public async Task AnAttestationForOneDomainDoesNotExcuseAnother()
    {
        var report = await AskAsync(AForestWithSeveralFaults(), Absent, Root, Elsewhere, Denied);

        var refusal = report.Refusal([Absent]);

        Assert.NotNull(refusal);
        Assert.Contains("1 of 4 domains", refusal.Description, StringComparison.Ordinal);
        Assert.Contains(Elsewhere, refusal.Description, StringComparison.Ordinal);
        Assert.DoesNotContain(Absent, refusal.Description, StringComparison.Ordinal);
    }

    /// <summary>
    /// An excluded domain is still recorded as one preflight could not read.
    ///
    /// <para>
    /// Only the decision to stop is narrowed. What preflight found is a fact about the customer's
    /// forest and is what <c>preflight.json</c> carries, so an exclusion that quietly erased it
    /// would be trading one silence for another.
    /// </para>
    /// </summary>
    [Fact]
    public async Task AnExcludedDomainIsStillRecordedAsUnreadable()
    {
        var report = await AskAsync(AForestWithSeveralFaults(), Absent, Root, Elsewhere, Denied);

        Assert.Null(report.Refusal([Absent, Elsewhere]));

        Assert.Equal(2, report.Blocking.Count);
        Assert.False(report.RunMayProceed);
    }

    /// <summary>
    /// Every domain is asked exactly once. A pass that reconnected would be paying the cost this
    /// session exists to remove while looking as though it had removed it.
    /// </summary>
    [Fact]
    public async Task EachDomainCostsOneConnection()
    {
        var forest = AForestWithSeveralFaults();

        await Preflight.RunAsync(
            forest, APlanOf(Absent, Root, Elsewhere, Denied), CancellationToken.None);

        Assert.Equal(4, forest.ConnectionsAttempted);
    }

    /// <summary>
    /// Every fact preflight records about a domain is written into <c>preflight.json</c>.
    ///
    /// <para>
    /// The binding the session owed: a question the report names and the file does not carry is a
    /// question answered for nobody, and an unattended run that died leaves the file as the only
    /// account of what preflight proved. It reads the recorded facts - the constructor parameters
    /// - rather than every property, because <c>CanBeRead</c> and <c>Answered</c> are derived from
    /// facts already written and would be a second answer if they were stored.
    /// </para>
    /// </summary>
    [Fact]
    public void EveryFactPreflightRecordsIsWrittenDown()
    {
        var written = typeof(PreflightDomainRecord)
            .GetProperties()
            .Select(p => p.Name)
            .ToHashSet(StringComparer.Ordinal);

        var missing = RecordedFacts()
            .Where(fact => !written.Contains(fact))
            .OrderBy(fact => fact, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "Preflight records these and preflight.json does not carry them: "
            + string.Join(", ", missing)
            + ". A run that dies before sealing leaves that file as the only account of what "
            + "preflight proved, so a fact absent from it was measured for nobody.");
    }

    /// <summary>
    /// The check above can fail.
    ///
    /// <para>
    /// Its shape is a name lookup, and a lookup that matched anything would pass while measuring
    /// nothing - which is how gate 5's original wording came to pass against a tree in which
    /// nothing was used. This asserts that the same lookup rejects a name the file does not carry.
    /// </para>
    /// </summary>
    [Fact]
    public void TheCheckThatEveryFactIsWrittenDownWouldNoticeOneThatIsNot()
    {
        var written = typeof(PreflightDomainRecord)
            .GetProperties()
            .Select(p => p.Name)
            .ToHashSet(StringComparer.Ordinal);

        Assert.DoesNotContain("AFactNobodyWroteDown", written);
        Assert.NotEmpty(RecordedFacts());
    }

    /// <summary>
    /// The file says a controller was never reached, rather than leaving a reader to infer it from
    /// a missing rung they might read as a default.
    /// </summary>
    [Fact]
    public async Task TheFileSaysWhichControllerServedEachDomainAndHowProtectedItWas()
    {
        var report = await AskAsync(AForestWithSeveralFaults(), Root, Absent);

        var directory = TempDirectories.Create("preflight");
        PreflightFile.Write(directory, report, DateTimeOffset.UnixEpoch);

        var written = File.ReadAllText(BundleLayout.PreflightPath(directory));
        var contents = JsonSerializer.Deserialize<JsonElement>(written);

        var domains = contents.GetProperty("Domains").EnumerateArray().ToList();

        Assert.Equal("Signed", domains[0].GetProperty("RungReached").GetString());
        Assert.Equal("example.com", domains[0].GetProperty("DomainController").GetString());
        Assert.Equal(JsonValueKind.Null, domains[1].GetProperty("RungReached").ValueKind);
        Assert.False(domains[1].GetProperty("Answered").GetBoolean());
    }

    /// <summary>
    /// Two domains that share a controller are never asked at the same time.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the rule the parallel pass rests on, and it is not inherited from Active
    /// Directory.</b> A writable controller holds one domain, so two domains sharing a pinned
    /// controller is not a shape a real forest produces - but <c>ControllerSelection</c> has no rule
    /// against it and pins the same host twice when handed a forest that declares one. A
    /// concurrency that is safe only because the directory happens to be well shaped is a defect
    /// waiting for the forest that is not.
    /// </para>
    /// <para>
    /// What two overlapping reads would cost is not an error: the state a controller keeps between
    /// the pages of a paged search comes from one per-controller budget, and when it fills the
    /// controller discards the oldest. The reads truncate each other silently and the run reports
    /// a forest smaller than the one it read.
    /// </para>
    /// <para>
    /// Replace the body of <c>DirectoryWorkDispatch.OneAtATimeAsync</c> with a plain call to the work
    /// and this fails at two connections open on one host. Observed in both directions.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task TwoDomainsOnOneControllerAreNeverAskedAtTheSameTime()
    {
        const string Shared = "shared.example.com";

        var forest = new ForestModel();
        forest.Answering(Shared, AControllerServing(Root, Reachable));

        var watch = new OverlapWatch(forest, waitingFor: 2);

        await Preflight.RunAsync(
            watch, APlanOf(_ => Shared, Root, Reachable), CancellationToken.None);

        Assert.Equal(1, watch.MostAtOnceOn(Shared));
    }

    /// <summary>
    /// Domains on different controllers are asked together.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The other direction, and the reason the check above cannot pass by measuring nothing. A pass
    /// that had quietly gone back to asking one domain at a time would satisfy every same-controller
    /// assertion perfectly while costing an operator the minutes this session exists to give back.
    /// </para>
    /// <para>
    /// It is deterministic rather than timed: each connection waits for the second to arrive, so a
    /// sequential pass reaches the deadline and reports one at a time instead of two.
    /// </para>
    /// <para>
    /// <b>The deadline is thirty seconds, and that costs nothing when the product is right.</b> A
    /// correct run satisfies the rendezvous the moment the second connection opens and never waits.
    /// The deadline is only reached by a build that has gone sequential, which is the failure this
    /// exists to report. It was one second until 2026-09-02, when the test failed in a full-suite
    /// run and passed in isolation twice (`P-115`): under parallel load the second connection had
    /// not arrived within the second, so the harness reported sequential behaviour that had not
    /// happened. A test that cries wolf about a real defect is worse than no test, because the next
    /// person to see it red assumes the machine was busy.
    /// </para>
    /// <para>
    /// The same-controller test above keeps its short deadline deliberately: there the deadline is
    /// always reached, because company never comes, so it is paid on every run.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task DomainsOnDifferentControllersAreAskedAtTheSameTime()
    {
        var watch = new OverlapWatch(
            AForestWithSeveralFaults(), waitingFor: 2, deadlineMilliseconds: 30_000);

        await Preflight.RunAsync(watch, APlanOf(Root, Reachable), CancellationToken.None);

        Assert.Equal(2, watch.MostAtOnceAnywhere);
    }

    /// <summary>A controller holding writable replicas of more than one domain.</summary>
    /// <remarks>
    /// Not a shape Active Directory produces. It exists here because the code under test must be
    /// correct without depending on that.
    /// </remarks>
    private static ControllerModel AControllerServing(params string[] namingContexts)
    {
        var controller = new ControllerModel("shared.example.com");

        controller.NamingContexts.Clear();

        foreach (var namingContext in namingContexts)
        {
            controller.NamingContexts.Add(namingContext);
            controller.AddObject(
                PasswordSettingsContainerOf(namingContext), ("objectClass", ["container"]));
        }

        return controller;
    }

    /// <summary>
    /// The recorded facts: the parameters a <see cref="DomainPreflight"/> is constructed from.
    /// </summary>
    private static IReadOnlyList<string> RecordedFacts() =>
        [.. typeof(DomainPreflight)
            .GetConstructors()
            .OrderByDescending(c => c.GetParameters().Length)
            .First()
            .GetParameters()
            .Select(p => p.Name!)];

    /// <summary>
    /// A forest whose domains each fail in a different way, so one pass can be shown to report all
    /// of them.
    /// </summary>
    /// <remarks>
    /// <c>gone.example.com</c> is deliberately absent from the map, which is how a domain whose
    /// DNS name resolves to nothing behaves: no rung answers.
    /// </remarks>
    private static ForestModel AForestWithSeveralFaults()
    {
        var forest = new ForestModel();

        forest.Answering("example.com", AControllerFor(Root, signedOnly: true));
        forest.Answering("good.example.com", AControllerFor(Reachable, signedOnly: false));
        forest.Answering("denied.example.com", ADeniedContainerControllerFor(Denied));

        // Serves a partition that is not the one it was chosen for.
        forest.Answering("elsewhere.example.com", AControllerFor(Reachable, signedOnly: false));

        return forest;
    }

    /// <summary>A controller serving one domain, holding its Password Settings Container.</summary>
    private static ControllerModel AControllerFor(string namingContext, bool signedOnly)
    {
        var controller = new ControllerModel(HostOf(namingContext));

        controller.NamingContexts.Clear();
        controller.NamingContexts.Add(namingContext);
        controller.AddObject(
            PasswordSettingsContainerOf(namingContext), ("objectClass", ["container"]));

        if (signedOnly)
        {
            controller.SecurityLevel = ConnectionSecurityLevel.Signed;
        }

        return controller;
    }

    /// <summary>A controller that holds the container and will not let this account read it.</summary>
    private static ControllerModel ADeniedContainerControllerFor(string namingContext)
    {
        var controller = AControllerFor(namingContext, signedOnly: false);
        controller.RefusesToRead.Add(PasswordSettingsContainerOf(namingContext));

        return controller;
    }

    private static string PasswordSettingsContainerOf(string namingContext) =>
        "CN=Password Settings Container,CN=System," + namingContext;

    /// <summary>
    /// The DNS name a domain is reached through, which is how a run connects to one it did not
    /// start from.
    /// </summary>
    private static string HostOf(string namingContext) =>
        string.Join(
            '.',
            namingContext.Split(',').Select(part => part["DC=".Length..]));

    private static async Task<PreflightReport> AskAsync(
        ForestModel forest, params string[] domains) =>
        await Preflight.RunAsync(forest, APlanOf(domains), CancellationToken.None);

    /// <summary>
    /// A plan naming the given domains, each read from the controller its own DNS name resolves to.
    /// </summary>
    private static ForestPlan APlanOf(params string[] domains) =>
        APlanOf(HostOf, domains);

    /// <summary>
    /// A plan whose controllers are chosen by <paramref name="controllerFor"/>, with a topology and
    /// roles that match it.
    /// </summary>
    /// <remarks>
    /// The roles name every domain in the plan at
    /// <c>PdcEmulatorKnowledge.NotYetEstablished</c>, which is exactly what discovery produces: the
    /// PDC emulator is preflight's to establish, per <c>0055</c>.
    /// </remarks>
    private static ForestPlan APlanOf(Func<string, string> controllerFor, params string[] domains)
    {
        var capture = new CapturePlan(
            [.. domains.Select(d =>
                CaptureUnit.Create(d, NamingContextKind.Domain, controllerFor(d)).Value!)],
            NotRead: [],
            DeclaredDomains: [.. domains.Select(HostOf)],
            ForestFqdn: "example.com");

        var topology = new ForestTopology(
            [.. domains.Select(d => new ForestController(
                controllerFor(d), "London", [d], $"CN=NTDS Settings,CN={controllerFor(d)}"))],
            [],
            []);

        var roles = new ForestRoles(
            schemaMaster: null,
            domainNamingMaster: null,
            [.. domains.Select(d => new DomainPdcEmulator(
                d, PdcEmulatorKnowledge.NotYetEstablished, Holder: null))]);

        var selection = ControllerSelection.For(
            topology, roles, "London", domains, new Dictionary<string, string>());

        return new ForestPlan(capture, topology, roles, selection.Value!);
    }
}
