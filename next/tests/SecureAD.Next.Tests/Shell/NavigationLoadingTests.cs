using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Shell.ViewModels;
using SecureAD.Shell.Settings;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class NavigationLoadingTests
{
    private const string Bundle = @"C:\synthetic-runs\navigation";
    private const string Domain = "DC=contoso,DC=com";
    private const string Subject = "CN=Alice," + Domain;

    [Fact]
    public void OpeningObjectsDoesNotReadHiddenListings()
    {
        var source = Source();
        var screen = Show(source);

        Assert.Equal((1, 0, 0, 0, 0), (screen.Objects.Count, source.FindingsReads,
            source.FilterValueReads, source.LapsListings, source.RuleExecutionReads));
    }

    [Theory]
    [InlineData(1, 2, 0, 0)]
    [InlineData(2, 0, 2, 0)]
    [InlineData(3, 0, 0, 0)]
    public void TreeChangesReadOnlyTheVisibleListing(int pane, int findings, int laps, int rules)
    {
        var source = Source();
        var screen = Show(source);
        screen.Pane = (AssetsPane)pane;
        screen.Selected = screen.Roots[0].Children[0];
        Assert.Equal((1, findings, laps, rules),
            (source.ObjectListings, source.FindingsReads, source.LapsListings, source.RuleExecutionReads));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    public void LevelChangesDoNotReadUnaffectedListings(int pane)
    {
        var source = Source();
        var screen = Show(source);
        screen.Pane = (AssetsPane)pane;
        var before = (source.ObjectListings, source.FindingsReads, source.RuleExecutionReads);
        screen.Scope = ListingScope.OneLevel;
        Assert.Equal(before, (source.ObjectListings, source.FindingsReads, source.RuleExecutionReads));
    }

    [Fact]
    public void FindingsChoicesBelongToOneProtectedLifetime()
    {
        var source = Source();
        var screen = Show(source);
        screen.Pane = AssetsPane.Findings;
        screen.Selected = screen.Roots[0].Children[0];
        screen.Pane = AssetsPane.Objects;
        screen.Pane = AssetsPane.Findings;
        Assert.Equal(1, source.FilterValueReads);
    }

    [Fact]
    public void ReopeningDropsThePreviousFilterChoices()
    {
        var source = Source();
        var screen = Show(source);
        screen.Pane = AssetsPane.Findings;
        screen.Show(Bundle, false);
        Assert.Equal(2, source.FilterValueReads);
    }

    [Fact]
    public void LapsDoesNotInheritTheObjectsPage()
    {
        var source = Source();
        var screen = Show(source);
        screen.NextPage();
        screen.NextPage();
        screen.Pane = AssetsPane.Laps;
        Assert.Equal((3, 1), (screen.PageNumber, source.LapsListedPage));
    }

    [Fact]
    public void FindingOpeningPreparesOnlyIdentityAndFindings()
    {
        var source = Source();
        var screen = Show(source);
        screen.OpenFinding(new FindingRowViewModel(Finding()));
        Assert.Equal(("Identity", 1, 0, 0),
            (string.Join(",", source.Reads), source.FindingsReads, source.ControlQueries.Count, source.SchemaReads));
    }

    [Fact]
    public void OverviewDoesNotPreparePermissionClassificationOrOtherSections()
    {
        var source = Source();
        var screen = Show(source);
        screen.OpenObject(screen.Objects[0]);
        Assert.Equal(("Identity,Permissions,Attributes", 0, 0, 0),
            (string.Join(",", source.Reads), source.FindingsReads, source.ControlQueries.Count, source.SchemaReads));
    }

    [Fact]
    public void HiddenSectionsRemainNavigationMetadata()
    {
        var screen = Show(Source());
        screen.OpenObject(screen.Objects[0]);
        Assert.All(screen.Opened!.Sections.Where(section => section.Key != ObjectSectionCatalog.Overview),
            section => Assert.IsType<UnloadedObjectSectionViewModel>(section));
    }

    [Fact]
    public void SelectedPermissionsReadOnlyTheirOwnSavedProduct()
    {
        var source = Source();
        var screen = Show(source);
        screen.OpenObject(screen.Objects[0]);
        source.Reads.Clear();
        screen.Opened!.Show(ObjectSectionCatalog.Permissions);
        Assert.Equal(("Permissions,Classification", 1, 0, 0),
            (string.Join(",", source.Reads), source.SchemaReads, source.FindingsReads, source.ControlQueries.Count));
    }

    [Fact]
    public void CapturedClassSelectsSectionsRatherThanTheListingHint()
    {
        var screen = Show(Source());
        screen.OpenObject(new(new(Subject, "Alice", Guid.NewGuid(), "computer", Domain)));
        Assert.Equal("user", screen.Opened!.ObjectType);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task LoadingWithholdsRowsGuidanceAndCounts(int pane)
    {
        var source = Source();
        var screen = Show(source);
        screen.Pane = AssetsPane.Findings;
        screen.SelectedFinding = screen.Findings[0];
        screen.Pane = (AssetsPane)((pane + 1) % 3);
        var pending = new PendingRead();
        source.CompleteRead = pending.Hold;
        screen.Pane = (AssetsPane)pane;
        var state = (screen.IsLoading, screen.HasListingResult, screen.IsEmpty, screen.NothingWasFound,
            screen.PageDescription, VisibleRows(screen, pane));
        pending.Release();
        await screen.ReadCompletion;
        Assert.Equal((true, false, false, false, "", 0), state);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SupersededListingSuccessAndFailureCannotReplaceTheNewSelection(bool fail)
    {
        var source = Source();
        var screen = Show(source);
        var pending = new PendingRead();
        source.CompleteRead = pending.Hold;
        screen.NextPage();
        var old = screen.ReadCompletion;
        source.CompleteRead = null;
        source.Page = new([new("CN=Replacement," + Domain, "Replacement", null, "user", Domain)], 1, true, null);
        screen.Selected = screen.Roots[0].Children[0];
        pending.Release(fail);
        await old;
        Assert.Equal(("Replacement", false, false), (Assert.Single(screen.Objects).Name, screen.HasViewRefusal, screen.IsLoading));
    }

    [Fact]
    public async Task SelectingAnotherContainerCancelsThePendingQuery()
    {
        var source = Source();
        var screen = Show(source);
        var pending = new PendingRead();
        source.CompleteRead = pending.Hold;
        screen.NextPage();
        var old = screen.ReadCompletion;
        source.CompleteRead = null;
        screen.Selected = screen.Roots[0].Children[0];
        var cancelled = pending.Token.IsCancellationRequested;
        pending.Release();
        await old;
        Assert.True(cancelled);
    }

    [Fact]
    public async Task ChangingTabsDuringTreeOpeningStillLoadsTheDestination()
    {
        var source = Source();
        var pending = new PendingRead();
        source.CompleteRead = pending.Hold;
        var screen = Show(source);
        var old = screen.ReadCompletion;
        source.CompleteRead = null;
        screen.Pane = AssetsPane.Findings;
        pending.Release();
        await old;
        await screen.ReadCompletion;
        Assert.Equal((true, true, 1), (screen.HasTree, screen.ShowsFindingsListing, screen.Findings.Count));
    }

    [Fact]
    public void BackReusesOnlyTheSameProtectedPage()
    {
        var source = Source();
        var screen = Show(source);
        screen.NextPage();
        screen.OpenObject(screen.Objects[0]);
        screen.CloseObject();
        Assert.Equal((2, 2), (screen.PageNumber, source.ObjectListings));
    }

    [Fact]
    public void BackDoesNotReuseAChangedQuery()
    {
        var source = Source();
        var screen = Show(source);
        screen.OpenObject(screen.Objects[0]);
        screen.PageNumber = 3;
        screen.CloseObject();
        // A page label cannot supply a continuation; the changed question must re-read page one.
        Assert.Equal((1, 2), (source.ListedPage, source.ObjectListings));
    }

    [Fact]
    public void BackDoesNotReuseAnInvalidLifetime()
    {
        var source = Source();
        var screen = Show(source);
        screen.OpenObject(screen.Objects[0]);
        source.IsCurrent = false;
        screen.CloseObject();
        Assert.Equal((0, false, true), (screen.Objects.Count, screen.HasListingResult, screen.HasViewRefusal));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void ObjectsBelongToTheirOpeningTab(int pane)
    {
        var source = Source();
        var screen = Show(source);
        screen.Pane = (AssetsPane)pane;
        screen.OpenObject(new(new(Subject, "Alice", null, "user", Domain)));
        var opened = screen.Opened;
        screen.Pane = AssetsPane.Delegations;
        Assert.Equal((true, true, opened), (screen.HasOpenObject, screen.ShowsDelegationsListing, screen.Opened));
    }

    [Fact]
    public void ReturningToAnObjectReloadsOnlyItsSelectedSection()
    {
        var source = Source();
        var screen = Show(source);
        screen.OpenObject(screen.Objects[0]);
        screen.Opened!.Show(ObjectSectionCatalog.Permissions);
        screen.Pane = AssetsPane.Delegations;
        source.Reads.Clear();
        screen.Pane = AssetsPane.Objects;
        Assert.Equal((ObjectSectionCatalog.Permissions, ""), (screen.Opened.Selected!.Key, string.Join(",", source.Reads)));
    }

    [Fact]
    public async Task AChangedGenerationBeforePublicationIsRefused()
    {
        var source = Source();
        var screen = Show(source);
        var pending = new PendingRead();
        source.CompleteRead = pending.Hold;
        screen.NextPage();
        source.IsCurrent = false;
        pending.Release();
        await screen.ReadCompletion;
        Assert.Equal((false, 0, true), (screen.HasListingResult, screen.Objects.Count, screen.HasViewRefusal));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SupersededObjectSectionCannotPublishRowsOrErrors(bool fail)
    {
        var source = Source();
        var screen = Show(source);
        screen.OpenObject(screen.Objects[0]);
        var pending = new PendingRead();
        source.CompleteRead = pending.Hold;
        screen.Opened!.Show(ObjectSectionCatalog.Permissions);
        var old = screen.Opened.ReadCompletion;
        source.CompleteRead = null;
        screen.Opened.Show(ObjectSectionCatalog.Overview);
        pending.Release(fail);
        await old;
        Assert.Equal((ObjectSectionCatalog.Overview, false), (screen.Opened.Content?.Key, screen.Opened.HasRefusal));
    }

    [Fact]
    public async Task LeavingAssetsCancelsWorkAndKeepsHiddenTabsIdle()
    {
        var source = Source();
        var settings = new FakeSettingsStore();
        var location = new RunLibraryLocation(settings);
        var library = new RunLibraryViewModel(location, new FakeRunCatalog(), new FakeConfirmation(), new FakeRunOpener(),
            new FakeDerivationLauncher(), new FakeJudgingLauncher());
        var screen = new AssetsViewModel(source);
        var shell = new ShellViewModel(new HomeViewModel(location, new FakeFolderPicker(), new FakeNewAuditDialog(), library),
            screen, new DashboardViewModel(source), new SettingsViewModel(new DomainConcurrency(settings)), new RulesViewModel(source));
        shell.Show(ShellSection.Assets);
        screen.Show(Bundle, false);
        var pending = new PendingRead();
        source.CompleteRead = pending.Hold;
        screen.NextPage();
        var old = screen.ReadCompletion;
        shell.Show(ShellSection.Settings);
        source.CompleteRead = null;
        screen.Pane = AssetsPane.Laps;
        pending.Release();
        await old;
        Assert.Equal((true, 0, 0), (pending.Token.IsCancellationRequested, screen.Objects.Count, source.LapsListings));
    }

    [Fact]
    public void HiddenControlSectionsCannotRestartReads()
    {
        var source = Source();
        var screen = Show(source);
        screen.OpenObject(screen.Objects[0]);
        screen.Opened!.Show(ObjectSectionCatalog.ControlEdges);
        var controls = Assert.IsType<ControlEdgesSectionViewModel>(screen.Opened.Selected);
        screen.Opened.Show(ObjectSectionCatalog.Overview);
        var reads = source.ControlQueries.Count;
        controls.FirstPageCommand.Execute(null);
        Assert.Equal(reads, source.ControlQueries.Count);
    }

    [Fact]
    public async Task ControlLoadingWithholdsCountsAndRequesterAnswers()
    {
        var controls = Controls();
        var pending = new PendingRead();
        controls.ConfigureAsync(true, false, async (_, _, _, token) =>
            (Result<ControlEdgePage>)await pending.Hold(Result<ControlEdgePage>.Success(ControlPage(1)), token),
            (_, _) => Task.FromResult(Result<SelfMembershipAssessmentSet>.Success(new([], false, null))));
        var state = (controls.Coverage, controls.Counts, controls.Rows.Count, controls.RequesterAssessments.Count);
        pending.Release();
        await controls.ReadCompletion;
        Assert.Equal(("Loading saved results…", "", 0, 0), state);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SupersededControlsCannotPublishCountsOrRefusal(bool fail)
    {
        var controls = Controls();
        var pending = new PendingRead();
        controls.ConfigureAsync(true, false, async (_, _, _, token) =>
            (Result<ControlEdgePage>)await pending.Hold(Result<ControlEdgePage>.Success(ControlPage(1)), token),
            (_, _) => Task.FromResult(Result<SelfMembershipAssessmentSet>.Success(new([], false, null))));
        var old = controls.ReadCompletion;
        controls.Configure(true, false, (_, _, _) => Result<ControlEdgePage>.Success(ControlPage(7)),
            _ => Result<SelfMembershipAssessmentSet>.Success(new([], false, null)));
        var expected = (controls.Coverage, controls.Counts);
        pending.Release(fail);
        await old;
        Assert.Equal(expected, (controls.Coverage, controls.Counts));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SupersededMemberSupportCannotReplaceTheSelection(bool fail)
    {
        var controls = Controls();
        controls.Configure(true, false, (_, _, _) => Result<ControlEdgePage>.Success(ControlPage(1)),
            _ => Result<SelfMembershipAssessmentSet>.Success(new([], false, null)));
        var pending = new PendingRead();
        controls.ConfigureMemberAttributionAsync(async (_, token) =>
            (Result<MemberAttributionDetail>)await pending.Hold(
                Result<MemberAttributionDetail>.Success(new(false, null, []) { GenerationId = Guid.Empty }), token), null, () => true);
        var edge = Assert.Single(Judgement.GroupMembershipControlTests.Membership(
            Judgement.ControlEdgeDeriverTests.Permissions(Judgement.GroupMembershipControlTests.Scoped(0, 0x08))).Edges);
        controls.SelectedEdge = new ControlEdgeRowViewModel(edge);
        var old = controls.MemberReadCompletion;
        controls.SelectedEdge = null;
        var expected = controls.MemberPanel.Status;
        pending.Release(fail);
        await old;
        Assert.Equal((expected, ""), (controls.MemberPanel.Status, controls.MemberPanel.Evidence));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SuspendedReverseMembershipCannotPublishRowsOrRefusal(bool fail)
    {
        var controls = Controls();
        controls.Configure(true, false, (_, _, _) => Result<ControlEdgePage>.Success(ControlPage(1)),
            _ => Result<SelfMembershipAssessmentSet>.Success(new([], false, null)));
        var pending = new PendingRead();
        controls.ConfigureMemberAttributionAsync((_, _) => Task.FromResult(
                Result<MemberAttributionDetail>.Success(new(false, null, []) { GenerationId = Guid.Empty })),
            async (_, _, token) => (Result<MemberPermissionPage>)await pending.Hold(
                Result<MemberPermissionPage>.Success(new(false, false, Guid.Empty, [], false, 0)), token), () => true);
        var old = controls.MembershipReadCompletion;
        controls.Suspend();
        var expected = controls.ThroughMembershipCoverage;
        pending.Release(fail);
        await old;
        Assert.Equal((expected, 0), (controls.ThroughMembershipCoverage, controls.ThroughMembership.Count));
    }

    [Fact]
    public async Task LocalMemberPagingRequiresItsOriginalProtectedLifetime()
    {
        var sid = Judgement.SelfMembershipDiscoveryTests.TargetSid;
        using var reader = Judgement.MemberAttributionTests.Prepare(
            Judgement.SelfMembershipDiscoveryTests.Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{sid})"));
        using var source = new SecureAD.Shell.Services.BundleAssetSource();
        var controls = await MemberAttributionPresentationTests.OpenAsync(source, reader.BundleDirectory,
            Judgement.SelfMembershipDiscoveryTests.UserDn, false);
        Assert.Single(controls.MemberPanel.Rows);
        source.CloseRun();
        controls.MemberPanel.FirstPageCommand.Execute(null);
        Assert.Equal((0, true), (controls.MemberPanel.Rows.Count,
            controls.MemberPanel.Status.Contains("changed", StringComparison.Ordinal)));
    }

    private static ControlEdgesSectionViewModel Controls() => new(new(ObjectSectionCatalog.ControlEdges, "Control edges", []));

    private static ControlEdgePage ControlPage(long unexpected) =>
        new([], 0, unexpected, 0, 0, true, true, false, 0) { GenerationId = Guid.Empty };

    private static int VisibleRows(AssetsViewModel screen, int pane) => pane switch
    {
        0 => screen.Objects.Count, 1 => screen.Findings.Count, 2 => screen.LapsComputers.Count, _ => screen.Delegations.Count,
    };

    private sealed class PendingRead
    {
        private readonly TaskCompletionSource<object> _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private object? _value;
        internal CancellationToken Token { get; private set; }
        internal Task<object> Hold(object value, CancellationToken token)
        {
            _value = value;
            Token = token;
            return _completion.Task;
        }
        internal void Release(bool fail = false)
        {
            if (fail) _completion.SetException(new IOException("obsolete synthetic failure"));
            else _completion.SetResult(_value ?? throw new InvalidOperationException("No pending read."));
        }
    }

    private static Finding Finding() => new("SEC-010", 1, Severity.High,
        new FindingSubject(FindingSubjectKind.Account, "Alice"), Guid.NewGuid(), Subject, "contoso.com", "user", "Synthetic finding",
        EvidenceCompleteness.Complete, new UnconstrainedDelegationEvidence(0x80000, false, new(false, false, false)));

    private static AssetsViewModel Show(FakeAssetSource source)
    {
        var screen = new AssetsViewModel(source);
        screen.Show(Bundle, false);
        return screen;
    }

    private static FakeAssetSource Source() => new()
    {
        Tree = new([new(Domain, "contoso", Guid.NewGuid(), TreeNodeOrigin.Partition,
            [new("OU=People," + Domain, "People", null, TreeNodeOrigin.Captured, [])])], []),
        Page = new([new(Subject, "Alice", Guid.NewGuid(), "user", Domain)], 205, true, null),
        FindingsPage = new([Finding()], null, RulesRan: 1),
        Attributes = FakeAssetSource.CapturedObject(Subject, "user"),
        Permissions = new(Subject, DescriptorAvailability.Read, null, null, DaclState.Empty,
            DaclCompleteness.Complete, true, false, [], []),
    };
}
