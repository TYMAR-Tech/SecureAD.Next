using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class AuditReadinessTests
{
    [Theory]
    [InlineData("ready")]
    [InlineData("unasked")]
    [InlineData("warning")]
    [InlineData("unknown")]
    [InlineData("refused")]
    [InlineData("blocked")]
    [InlineData("edited")]
    public void ReadinessSummaryNeverTurnsMissingOrProblemEvidenceGreen(string scenario)
    {
        var plan = GoodPlan(Forests.Root, Forests.Controller, "ad.lab");
        if (scenario == "unasked") plan = plan with { WasPreflighted = false };
        if (scenario == "warning") plan = plan with { Alternatives = [] };
        if (scenario == "unknown") plan = plan with { ServesThePartition = Established.NotEstablished };
        var row = new DomainRowViewModel(plan, _ => Task.CompletedTask, (_, _) => { });
        if (scenario == "refused") row.Problem = "Recorded controller refusal";
        if (scenario == "blocked") row.RefreshReadiness(true);
        if (scenario == "edited") row.NamedController = "new-controller.ad.lab";
        var expected = scenario switch
        {
            "ready" => AuditReadinessStatus.Ready,
            "unasked" or "edited" => AuditReadinessStatus.NotChecked,
            "refused" or "blocked" => AuditReadinessStatus.Blocked,
            _ => AuditReadinessStatus.Review,
        };
        Assert.Equal(expected, row.ReadinessStatus);
        if (scenario == "ready") Assert.All(row.FactStates, state => Assert.Equal(FactState.EstablishedGood, state));
        else Assert.NotEqual(AuditReadinessStatus.Ready, row.ReadinessStatus);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ExclusionAuthorizationNeverBecomesAReadyDomain(bool attested)
    {
        var row = new ExcludedDomainViewModel("DC=orphan,DC=ad,DC=lab", "orphan.ad.lab");
        if (attested)
            row.AttestUnder(new(row.NamingContext, row.Domain, row.Inclusion, ExclusionReason.OutsideThisAuditsRemit,
                null, "auditor", "owner", DateTimeOffset.UnixEpoch));
        Assert.Equal(attested ? AuditReadinessStatus.Excluded : AuditReadinessStatus.ExclusionNeedsAuthorization, row.ReadinessStatus);
        Assert.False(row.IsIncluded);
        Assert.False(row.MayChangeInclusion);
    }

    [Fact]
    public void AChangedControllerAndUpdatedAnswersAnnounceTheNewReadiness()
    {
        var row = new DomainRowViewModel(GoodPlan(Forests.Root, Forests.Controller, "ad.lab"),
            _ => Task.CompletedTask, (_, _) => { });
        var changed = new List<string?>();
        row.PropertyChanged += (_, args) => changed.Add(args.PropertyName);
        row.Update(row.Plan with { Alternatives = [] });
        Assert.Equal(AuditReadinessStatus.Review, row.ReadinessStatus);
        Assert.Contains(nameof(AuditRowViewModel.ReadinessStatus), changed);
        changed.Clear();
        row.NamedController = "new-controller.ad.lab";
        Assert.Equal(AuditReadinessStatus.NotChecked, row.ReadinessStatus);
        Assert.Contains(nameof(AuditRowViewModel.ReadinessStatus), changed);
    }

    [Fact]
    public async Task RowDetailsUseOnlyThatDomainsRecordedAnswersWithoutNewChecks()
    {
        var (model, capture) = await Example();
        var checks = capture.TimesChecked;
        var plans = capture.TimesPlanned;
        foreach (var row in model.Rows)
        {
            model.ShowRowDetailsCommand.Execute(row);
            var details = Assert.IsType<DomainDetailsViewModel>(model.Details);
            Assert.Equal(row.Domain, details.Heading);
            if (row is DomainRowViewModel domain)
                Assert.Same(domain, Assert.Single(details.Domains));
            else
            {
                Assert.Empty(details.Domains);
                var exclusion = Assert.Single(details.Exclusions);
                Assert.Equal(row.Domain, exclusion.Domain);
                Assert.Same(row.Attestation, exclusion.Attestation);
                Assert.Equal(row.IsExcludedWithoutAttestation, exclusion.IsUnattested);
            }
            details.CloseCommand.Execute(null);
            Assert.False(model.HasDetails);
        }
        Assert.Equal(checks, capture.TimesChecked);
        Assert.Equal(plans, capture.TimesPlanned);
        Assert.Equal(0, capture.NamedControllersChecked);
        Assert.False(capture.WasRun);
        model.ShowDetailsCommand.Execute(null);
        Assert.Equal(model.Domains, model.Details!.Domains);
        Assert.Equal(model.Exclusions, model.Details.Exclusions);
    }

    [Fact]
    public async Task ARowFromAnotherAuditCannotOpenDetails()
    {
        var (model, _) = await Example();
        var foreign = new DomainRowViewModel(GoodPlan(Forests.Root, Forests.Controller, "ad.lab"),
            _ => Task.CompletedTask, (_, _) => { });
        Assert.Throws<ArgumentException>(() => model.ShowRowDetails(foreign));
        Assert.False(model.HasDetails);
    }

    [Fact]
    public void GeneralDetailsDoNotAttributeAnExcludedDomainToTheOnlyReadableDomain()
    {
        var row = new DomainRowViewModel(GoodPlan(Forests.Root, Forests.Controller, "ad.lab"),
            _ => Task.CompletedTask, (_, _) => { });
        var model = new DomainDetailsViewModel([row],
            [new("orphan.ad.lab", DomainInclusion.ExcludedForWantOfCandidates, null)], () => { });
        Assert.Equal("Domain details", model.Heading);
        Assert.Equal("orphan.ad.lab", Assert.Single(model.Exclusions).Domain);
    }

    [Fact]
    public async Task BackendBlockersRemainVisibleUntilTheExistingNextRecheckClearsThem()
    {
        var capture = new FakeCaptureLauncher
        {
            Plan = Forests.OneDomain(Forests.Other),
            Check = Forests.Answered() with { RunMayProceed = false, BlockingDomains = [Forests.Root] },
        };
        var model = AuditProgressTests.Model(new FakeDerivationLauncher(), new FakeJudgingLauncher(), capture);
        model.Screen = AuditScreen.Domains;
        await model.OpenAsync();
        Assert.Equal(AuditReadinessStatus.Blocked, Assert.Single(model.Domains).ReadinessStatus);
        Assert.False(model.CanStart);
        Assert.True(model.ReviewCommand.CanExecute(null));
        capture.Check = Forests.Answered();
        await model.ReviewAsync();
        Assert.NotEqual(AuditReadinessStatus.Blocked, Assert.Single(model.Domains).ReadinessStatus);
        Assert.Equal(AuditScreen.Review, model.Screen);
        Assert.Equal(2, capture.TimesChecked);
        Assert.False(capture.WasRun);
    }

    internal static DomainPlanRow GoodPlan(string namingContext, string controller, string dnsName) =>
        new(namingContext, controller, "Default-First-Site-Name", Established.Yes, ["alternate." + dnsName], true, false)
        {
            DnsName = dnsName, WasPreflighted = true, Answered = Established.Yes, RungReached = "SignAndSeal",
            ServesThePartition = Established.Yes, PasswordSettingsContainerReadable = Established.Yes,
            IsThisDomainsPdcEmulator = Established.No,
        };

    internal static async Task<(NewAuditViewModel Model, FakeCaptureLauncher Capture)> Example()
    {
        var plans = new[]
        {
            GoodPlan(Forests.Root, Forests.Controller, "ad.lab"),
            GoodPlan("DC=ba," + Forests.Root, "badc.ba.ad.lab", "ba.ad.lab") with { Alternatives = [] },
            GoodPlan("DC=ph," + Forests.Root, "phdc.ph.ad.lab", "ph.ad.lab"),
        };
        var capture = new FakeCaptureLauncher
        {
            Plan = Forests.OneDomain() with
            {
                ThisMachinesSite = "Default-First-Site-Name", Domains = plans,
                DomainsWithNoCandidates = ["DC=orphan," + Forests.Root],
            },
            Check = new(true, []),
        };
        var model = AuditProgressTests.Model(new FakeDerivationLauncher(), new FakeJudgingLauncher(), capture);
        model.Screen = AuditScreen.Domains;
        await model.OpenAsync();
        model.Domains[2].Problem = "Recorded controller refusal";
        return (model, capture);
    }
}
