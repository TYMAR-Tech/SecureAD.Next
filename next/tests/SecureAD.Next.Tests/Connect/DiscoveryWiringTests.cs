using SecureAD.Audit.Capture;
using SecureAD.Audit.Connect;
using SecureAD.Evidence;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Connect;

/// <summary>
/// The four behaviours `S-40` wired together, each held by a test that fails when the behaviour is
/// removed rather than merely reporting on it.
/// </summary>
/// <remarks>
/// The first of these is the owner's requirement and the reason
/// <c>docs/decisions/0055-the-pdc-emulator-is-established-at-preflight.md</c> exists: an audit is
/// not read from a PDC emulator where it can be avoided. `S-39` left it stated and unenforced, and
/// said so.
/// </remarks>
public sealed class DiscoveryWiringTests
{
    private const string Root = "DC=example,DC=com";
    private const string Configuration = "CN=Configuration,DC=example,DC=com";
    private const string Schema = "CN=Schema,CN=Configuration,DC=example,DC=com";
    private const string Sites = "CN=Sites," + Configuration;
    private const string Site = "London";

    // ---------------------------------------------------------------------------------------
    // The re-pin.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The audit moves off the PDC emulator once preflight establishes which controller that is.
    /// </summary>
    /// <remarks>
    /// Ranking pins <c>dc01</c> because it wins on host name and nothing yet says it is special.
    /// Preflight reads the domain's <c>fSMORoleOwner</c>, learns that it is the PDC emulator, and
    /// selection moves to <c>dc02</c>. Delete the re-pin and this fails: the domain stays on
    /// <c>dc01</c>.
    /// </remarks>
    [Fact]
    public async Task ADomainIsMovedOffItsPdcEmulatorOncePreflightEstablishesIt()
    {
        var plan = await APlanWithPdcEmulator("dc01", "dc01", "dc02");

        Assert.Equal("dc01.example.com", Pinned(plan));

        var report = await Preflight.RunAsync(AForestOf("dc01", "dc02"), plan, default);

        var domain = Assert.Single(report.Domains);

        Assert.Equal("dc02.example.com", domain.DomainController);
        Assert.True(domain.WasRepinnedOffPdcEmulator);
        Assert.False(domain.ReadFromPdcEmulator);
    }

    /// <summary>
    /// The rewritten plan is what capture reads, not just what the report says.
    /// </summary>
    /// <remarks>
    /// A re-pin that changed only the report would leave the run reading the machine the re-pin
    /// exists to avoid, while every screen and file claimed otherwise. That is the failure mode
    /// this repository treats as never deferrable: the product telling a customer something false.
    /// </remarks>
    [Fact]
    public async Task TheRepinnedControllerIsTheOneTheRunWouldRead()
    {
        var plan = await APlanWithPdcEmulator("dc01", "dc01", "dc02");

        var report = await Preflight.RunAsync(AForestOf("dc01", "dc02"), plan, default);

        var unit = Assert.Single(
            report.Plan.Units.Where(u => u.Kind == NamingContextKind.Domain));

        Assert.Equal("dc02.example.com", unit.DomainController);
    }

    /// <summary>
    /// With nowhere else in the site to go, the run proceeds against the PDC emulator and says so.
    /// </summary>
    /// <remarks>
    /// <c>0055</c> permits this and requires the statement. Make <c>ReadFromPdcEmulator</c> always
    /// false and this fails; make the no-alternative case stop the run instead and the assertion on
    /// the controller fails.
    /// </remarks>
    [Fact]
    public async Task ADomainWithNoAlternativeIsReadFromItsPdcEmulatorAndSaysSo()
    {
        var plan = await APlanWithPdcEmulator("dc01", "dc01");

        var report = await Preflight.RunAsync(AForestOf("dc01"), plan, default);

        var domain = Assert.Single(report.Domains);

        Assert.Equal("dc01.example.com", domain.DomainController);
        Assert.True(domain.ReadFromPdcEmulator);
        Assert.False(domain.WasRepinnedOffPdcEmulator);
        Assert.Contains(domain, report.ReadFromPdcEmulator);
    }

    /// <summary>
    /// A domain whose PDC emulator was never established is not reported as informed.
    /// </summary>
    /// <remarks>
    /// This is <c>DomainSelection.IsComplete</c> being acted on. Have
    /// <c>ChosenWithoutFullKnowledge</c> return nothing and this fails - which is the point, because
    /// an unasked question rendered as a clean answer is what puts an audit on a PDC emulator with
    /// nothing recording that it had.
    /// </remarks>
    [Fact]
    public async Task ADomainRankedWithoutItsPdcEmulatorIsReportedAsNotFullyInformed()
    {
        // No fSMORoleOwner on the domain head, so the read fails and knowledge stays incomplete.
        var plan = await APlanWithPdcEmulator(pdcEmulator: null, "dc01", "dc02");

        var report = await Preflight.RunAsync(
            AForestWith(pdcEmulator: null, "dc01", "dc02"), plan, default);

        var domain = Assert.Single(report.Domains);

        Assert.Equal(PdcEmulatorKnowledge.CouldNotBeRead, domain.PdcEmulator);
        Assert.False(domain.SelectionWasInformed);
        Assert.Contains(domain, report.ChosenWithoutFullKnowledge);
    }

    // ---------------------------------------------------------------------------------------
    // The override, refused rather than softened.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A controller that does not serve the domain named stops the plan.
    /// </summary>
    /// <remarks>
    /// Turn the refusal into a warning that falls back to the ranked choice and this fails. The run
    /// would then read from a controller the operator did not ask for while reporting success.
    /// </remarks>
    [Fact]
    public async Task AnOverrideNamingAnIneligibleControllerStopsTheRun()
    {
        var plan = await PlanAsync(
            AModelOf(pdcEmulator: null, "dc01", "dc02"),
            new Dictionary<string, string> { ["example.com"] = "dc99.example.com" });

        Assert.False(plan.IsSuccess);
    }

    /// <summary>
    /// A controller named for a domain this forest does not have stops the plan.
    /// </summary>
    /// <remarks>
    /// Drop the unknown-domain check and this fails: the override is silently ignored, and the run
    /// reads from the ranked choice while the operator believes he redirected it.
    /// </remarks>
    [Fact]
    public async Task AnOverrideNamingADomainThisForestDoesNotHaveStopsTheRun()
    {
        var plan = await PlanAsync(
            AModelOf(pdcEmulator: null, "dc01"),
            new Dictionary<string, string> { ["contoso.com"] = "dc01.example.com" });

        Assert.False(plan.IsSuccess);
        Assert.Contains("contoso.com", plan.Error!.Description, StringComparison.Ordinal);
    }

    /// <summary>
    /// An override an operator did give is obeyed, so the refusals above are not simply a plan that
    /// never accepts one.
    /// </summary>
    [Fact]
    public async Task AnOverrideNamingAnEligibleControllerIsObeyed()
    {
        var plan = await PlanAsync(
            AModelOf(pdcEmulator: null, "dc01", "dc02"),
            new Dictionary<string, string> { ["example.com"] = "dc02.example.com" });

        Assert.True(plan.IsSuccess, plan.Error?.Description);
        Assert.Equal("dc02.example.com", Pinned(plan.Value!));
        Assert.True(Assert.Single(plan.Value!.Selection.Domains).WasOverridden);
    }

    // ---------------------------------------------------------------------------------------
    // Bootstrap as the ordinary entry.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A machine in a forest enters by its own domain, and a typed name is never attempted.
    /// </summary>
    /// <remarks>
    /// Swap the order in <c>ForestBootstrap.Enter</c> and this fails on the source: the run would
    /// have entered by the typed name while the machine knew its own forest all along.
    /// </remarks>
    [Fact]
    public void AMachineInAForestEntersByItsOwnDomainAndNeverTheTypedName()
    {
        var factory = new RecordingFactory("example.com");

        var entry = ForestBootstrap.Enter(
            factory, new StubMachine("example.com", "EXAMPLE"), "typed.example.com");

        Assert.True(entry.IsSuccess);
        Assert.Equal(ForestEntrySource.MachineDnsDomain, entry.Value!.Source);
        Assert.Equal(["example.com"], factory.Attempted);
    }

    /// <summary>
    /// A machine that is in no forest falls back to the typed name.
    /// </summary>
    /// <remarks>
    /// This is the other direction of the same rule. Remove the fallback and this fails, and a
    /// workgroup machine could never audit anything.
    /// </remarks>
    [Fact]
    public void AMachineInNoForestFallsBackToTheTypedName()
    {
        var factory = new RecordingFactory("typed.example.com");

        var entry = ForestBootstrap.Enter(
            factory, new StubMachine(null, null), "typed.example.com");

        Assert.True(entry.IsSuccess);
        Assert.Equal(ForestEntrySource.TypedName, entry.Value!.Source);
        Assert.Equal(["typed.example.com"], factory.Attempted);
    }

    // ---------------------------------------------------------------------------------------
    // The failover list, in ranked order.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The alternatives are carried in the order ranking put them, and shown that way.
    /// </summary>
    /// <remarks>
    /// <b>What this does not prove.</b> Nothing walks the list. <c>0040</c>'s retry is not
    /// implemented, and this asserts only that the order a retry would follow is produced and
    /// displayed. Recorded as a finding at <c>S-40</c> rather than left to look like enforcement.
    /// Sort the failover list differently and this fails in both the selection and the preview.
    /// </remarks>
    [Fact]
    public async Task TheFailoverListIsRankedAndShownInThatOrder()
    {
        var plan = await PlanAsync(AModelOf(pdcEmulator: null, "dc03", "dc01", "dc02"));

        var domain = Assert.Single(plan.Value!.Selection.Domains);

        Assert.Equal("dc01.example.com", domain.PinnedController);
        Assert.Equal(["dc02.example.com", "dc03.example.com"], domain.Failover);

        var preview = PlanPreview.Describe(plan.Value!);

        Assert.Contains(
            "dc02.example.com, dc03.example.com", preview, StringComparison.Ordinal);
    }

    /// <summary>
    /// A domain the forest names no controller for is named in the preview rather than dropped.
    /// </summary>
    [Fact]
    public async Task ADomainWithNoCandidatesIsShownRatherThanOmitted()
    {
        var model = AModelOf(pdcEmulator: null, "dc01");
        model.CrossReferences.Add(
            CrossReference.Domain("DC=orphan,DC=example,DC=com", "orphan.example.com"));

        var plan = await PlanAsync(model);

        Assert.True(plan.IsSuccess, plan.Error?.Description);
        Assert.Contains(
            "DC=orphan,DC=example,DC=com", plan.Value!.Selection.DomainsWithNoCandidates);
        Assert.Contains("orphan", PlanPreview.Describe(plan.Value!), StringComparison.Ordinal);
    }

    /// <summary>
    /// A run with no site of its own does not report where anything is relative to it.
    /// </summary>
    /// <remarks>
    /// <c>DomainSelection.IsInOperatorSite</c> is false both when a controller is genuinely
    /// elsewhere and when the run never established its own site. Rendering the second as "another
    /// site" states where a customer's controllers are relative to a place the product never
    /// located - found on the first live run against a real forest. Restore the two-way rendering
    /// and this fails.
    /// </remarks>
    [Fact]
    public async Task AMachineWithNoSiteIsNotToldWhichControllersAreElsewhere()
    {
        var plan = await PlanAsync(
            AModelOf(pdcEmulator: null, "dc01"), overrides: null, operatorAddress: null);

        var preview = PlanPreview.Describe(plan.Value!);

        Assert.DoesNotContain("(another site)", preview, StringComparison.Ordinal);
        Assert.DoesNotContain("(same site)", preview, StringComparison.Ordinal);
        Assert.Contains("is unknown", preview, StringComparison.Ordinal);

        // The site the forest does state is still reported, because that part was measured.
        Assert.Contains(Site, preview, StringComparison.Ordinal);
    }

    /// <summary>
    /// A forest declaring no subnets is distinguished from one whose subnets did not match.
    /// </summary>
    /// <remarks>
    /// The remedies differ - declare the subnets, or find out why this machine's address is in none
    /// of them. Collapse the two branches and this fails.
    /// </remarks>
    [Fact]
    public async Task AForestWithNoSubnetsIsDistinguishedFromOneWhoseSubnetsDidNotMatch()
    {
        var none = await PlanAsync(
            AModelOf(pdcEmulator: null, "dc01"), overrides: null, operatorAddress: null);

        Assert.Contains(
            "declares no subnets at all", PlanPreview.Describe(none.Value!),
            StringComparison.Ordinal);

        var declared = AModelOf(pdcEmulator: null, "dc01");
        declared.AddObject(
            $"CN=192.168.50.0/24,CN=Subnets,{Sites}",
            ("siteObject", [$"CN={Site},{Sites}"]));

        var unmatched = await PlanAsync(declared, overrides: null, operatorAddress: null);

        Assert.Contains(
            "none of the 1 subnets", PlanPreview.Describe(unmatched.Value!),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A machine that is in a site is told plainly which controllers share it.
    /// </summary>
    /// <remarks>
    /// The other direction of the same rule: the three-way rendering must not swallow the answer
    /// when there is one.
    /// </remarks>
    [Fact]
    public async Task AMachineInASiteIsToldWhichControllersShareIt()
    {
        var model = AModelOf(pdcEmulator: null, "dc01");
        model.AddObject(
            $"CN=10.0.0.0/24,CN=Subnets,{Sites}",
            ("siteObject", [$"CN={Site},{Sites}"]));

        var plan = await PlanAsync(model);

        Assert.Contains("(same site)", PlanPreview.Describe(plan.Value!), StringComparison.Ordinal);
    }

    /// <summary>
    /// A domain the forest names one controller for says so, rather than implying others exist.
    /// </summary>
    /// <remarks>
    /// Found on a live forest of three single-controller domains, where the run reported that no
    /// alternative "was found in this site" - on a machine that had no site, against domains that
    /// had no alternative anywhere. Two different facts under one sentence.
    /// </remarks>
    [Fact]
    public async Task ADomainWithOneControllerReportsThatRatherThanASiteFilter()
    {
        var plan = await APlanWithPdcEmulator("dc01", "dc01");

        var report = await Preflight.RunAsync(AForestOf("dc01"), plan, default);

        var domain = Assert.Single(report.Domains);

        Assert.True(domain.ReadFromPdcEmulator);
        Assert.Equal(0, domain.OtherControllersInTheForest);
    }

    /// <summary>
    /// A domain that did have alternatives carries how many, so the two cases can be told apart.
    /// </summary>
    [Fact]
    public async Task ADomainWithAlternativesCarriesHowMany()
    {
        var plan = await APlanWithPdcEmulator("dc01", "dc01", "dc02", "dc03");

        var report = await Preflight.RunAsync(AForestOf("dc01", "dc02", "dc03"), plan, default);

        var domain = Assert.Single(report.Domains);

        // Moved off the emulator, and the alternatives it was ranked against are stated.
        Assert.True(domain.WasRepinnedOffPdcEmulator);
        Assert.Equal(2, domain.OtherControllersInTheForest);
    }

    /// <summary>
    /// The bundle records that a domain was read from its PDC emulator, not just the console.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A capture that said so only on a terminal has told nobody: the bundle is what an auditor
    /// holds six months later, and the console is gone the moment the window closes. Found on the
    /// first real capture, which printed only "Sealed". Drop the fields from
    /// <c>PreflightDomainRecord</c> and this fails.
    /// </para>
    /// <para>
    /// <b>The domain here has exactly one controller, and that is the point of the case rather
    /// than an accident of the fixture.</b> The New Audit window suppresses the PDC emulator prompt
    /// for precisely this shape, because a warning firing on every domain of a single-controller
    /// forest teaches an operator to click past warnings. <c>0055</c> narrows the prompting and not
    /// the record, so this is the test standing between that narrowing and a fact that is now
    /// recorded nowhere. The assertion on the candidate count is what stops the fixture drifting to
    /// a multi-controller domain and passing while the case that matters goes unwatched.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task ThePreflightFileRecordsThatADomainWasReadFromItsPdcEmulator()
    {
        var plan = await APlanWithPdcEmulator("dc01", "dc01");

        var report = await Preflight.RunAsync(AForestOf("dc01"), plan, default);

        Assert.Equal(0, Assert.Single(report.Domains).OtherControllersInTheForest);

        var directory = Path.Combine(
            Path.GetTempPath(), "securead-tests", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(directory);

        PreflightFile.Write(directory, report, DateTimeOffset.UnixEpoch);

        var written = await File.ReadAllTextAsync(
            Path.Combine(directory, "preflight.json"));

        Assert.Contains("\"ReadFromPdcEmulator\": true", written, StringComparison.Ordinal);
        Assert.Contains("\"PdcEmulator\": \"Established\"", written, StringComparison.Ordinal);
        Assert.Contains("\"SelectionWasInformed\"", written, StringComparison.Ordinal);
        Assert.Contains("\"Alternatives\"", written, StringComparison.Ordinal);
        Assert.Contains("\"ControllerWasNamedByOperator\"", written, StringComparison.Ordinal);
    }

    /// <summary>
    /// The file says what it measured rather than calling it "complete".
    /// </summary>
    /// <remarks>
    /// <c>AllQuestionsWereAsked</c> is routinely true on the same row where
    /// <c>SelectionWasInformed</c> is false - a domain asked everything, whose controller was still
    /// chosen without knowing which machine held the PDC role or where the run was. A field named
    /// <c>IsComplete</c> reading true beside that invites an auditor who was not present to conclude
    /// nothing was missing. Restore the old names and this fails.
    /// </remarks>
    [Fact]
    public async Task ThePreflightFileDoesNotCallAnUninformedChoiceComplete()
    {
        var plan = await APlanWithPdcEmulator("dc01", "dc01");

        var report = await Preflight.RunAsync(AForestOf("dc01"), plan, default);

        var directory = Path.Combine(
            Path.GetTempPath(), "securead-tests", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(directory);

        PreflightFile.Write(directory, report, DateTimeOffset.UnixEpoch);

        var written = await File.ReadAllTextAsync(Path.Combine(directory, "preflight.json"));

        Assert.Contains("\"AllQuestionsWereAsked\": true", written, StringComparison.Ordinal);
        Assert.Contains("\"AllDomainsWereAsked\": true", written, StringComparison.Ordinal);
        Assert.Contains("\"SelectionWasInformed\": false", written, StringComparison.Ordinal);
        Assert.DoesNotContain("\"IsComplete\"", written, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------------------------------
    // Fixtures.
    // ---------------------------------------------------------------------------------------

    private static string Pinned(ForestPlan plan) =>
        plan.Selection.Domains.Single().PinnedController;

    private static string SettingsDn(string host) =>
        $"CN=NTDS Settings,CN={host},CN=Servers,CN={Site},{Sites}";

    /// <summary>
    /// A forest of one domain served by the named controllers, one of which may hold the PDC role.
    /// </summary>
    private static ControllerModel AModelOf(string? pdcEmulator, params string[] hosts)
    {
        var model = new ControllerModel();

        model.AddObject(Schema);
        model.AddObject("CN=Partitions," + Configuration);

        if (pdcEmulator is not null)
        {
            model.AddObject(
                Root, ("fSMORoleOwner", [SettingsDn(pdcEmulator)]));
        }

        foreach (var host in hosts)
        {
            model.AddObject(
                $"CN={host},CN=Servers,CN={Site},{Sites}",
                ("dNSHostName", [host + ".example.com"]));

            model.AddObject(SettingsDn(host), ("msDS-hasMasterNCs", [Root]));
        }

        return model;
    }

    private static async Task<Result<ForestPlan>> PlanAsync(
        ControllerModel model,
        IReadOnlyDictionary<string, string>? overrides = null,
        string? operatorAddress = "10.0.0.5")
    {
        using var channel = model.Connections().Connect(model.DomainController).Value!;

        return await ForestDiscovery.PlanAsync(
            channel,
            operatorAddress is null ? [] : [System.Net.IPAddress.Parse(operatorAddress)],
            overrides ?? new Dictionary<string, string>(),
            CancellationToken.None);
    }

    private static async Task<ForestPlan> APlanWithPdcEmulator(
        string? pdcEmulator, params string[] hosts)
    {
        var plan = await PlanAsync(AModelOf(pdcEmulator, hosts));
        Assert.True(plan.IsSuccess, plan.Error?.Description);
        return plan.Value!;
    }

    /// <summary>
    /// A forest whose controllers each serve the one domain and carry its role owner.
    /// </summary>
    private static ForestModel AForestOf(params string[] hosts) =>
        AForestWith(hosts[0], hosts);

    /// <summary>
    /// A forest whose controllers each serve the one domain, optionally carrying its role owner.
    /// </summary>
    private static ForestModel AForestWith(string? pdcEmulator, params string[] hosts)
    {
        var forest = new ForestModel();

        foreach (var host in hosts)
        {
            var controller = new ControllerModel(host + ".example.com");
            controller.NamingContexts.Clear();
            controller.NamingContexts.Add(Root);

            // Every controller of the domain answers the same fSMORoleOwner, because the attribute
            // is on the domain head and every one of them holds a replica of it. Omitted entirely
            // when the forest names no holder, so that a read which could not be made is not
            // quietly turned into one that succeeded.
            if (pdcEmulator is not null)
            {
                controller.AddObject(Root, ("fSMORoleOwner", [SettingsDn(pdcEmulator)]));
            }

            controller.AddObject(
                "CN=Password Settings Container,CN=System," + Root,
                ("objectClass", ["container"]));

            forest.Answering(host + ".example.com", controller);
        }

        return forest;
    }

    private sealed class StubMachine(string? dns, string? netBios) : IMachineDomain
    {
        public string? DnsDomain { get; } = dns;

        public string? NetBiosDomain { get; } = netBios;
    }

    /// <summary>
    /// A factory that answers for exactly one name and records every name it was asked for.
    /// </summary>
    private sealed class RecordingFactory(string answersFor) : IDirectoryChannelFactory
    {
        private readonly ControllerModel _model = new(answersFor);

        public List<string> Attempted { get; } = [];

        public Result<IDirectoryChannel> Connect(string domainController)
        {
            Attempted.Add(domainController);

            return string.Equals(
                domainController, answersFor, StringComparison.OrdinalIgnoreCase)
                ? _model.Connections().Connect(domainController)
                : Result<IDirectoryChannel>.Failure(AuditError.Create(
                    ErrorCategory.Capture,
                    "NothingAnswered",
                    ErrorSeverity.Failed,
                    $"{domainController} did not answer.",
                    domainController));
        }

        public Result<IDirectoryChannel> Connect(CaptureUnit unit) =>
            Connect(unit.DomainController);
    }
}
