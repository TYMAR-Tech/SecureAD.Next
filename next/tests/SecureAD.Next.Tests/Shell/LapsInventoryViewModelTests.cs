using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.ViewModels;
using System.Xml.Linq;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

/// <summary>
/// The LAPS inventory on the assets screen: what it lists, what it counts, and what it says about
/// the machines the rules leave alone.
/// </summary>
/// <remarks>
/// <b>These test the screen, not the classification.</b> Which state a machine is in is
/// <c>LapsInventoryTests</c>'s question, and it is answered against sealed evidence there. What is
/// tested here is that the screen asks, shows what it is told, and does not ask when nobody is
/// looking.
/// </remarks>
public sealed class LapsInventoryViewModelTests
{
    private const string BundlePath = @"C:\runs\contoso-2026-09-03";
    private const string DomainDn = "DC=contoso,DC=com";

    /// <summary>
    /// The inventory is not read while another view is showing.
    /// </summary>
    /// <remarks>
    /// <b>It counts every computer in scope to produce its totals.</b> Reading it beside the object
    /// listing would pay for that scan on every container an operator clicks while looking at
    /// something else entirely.
    /// </remarks>
    [Fact]
    public void TheInventoryIsNotReadWhileTheObjectsAreShowing()
    {
        var assets = SourceOf(APage());
        var screen = Showing(assets);

        Assert.Equal(0, assets.LapsListings);
        Assert.Empty(screen.LapsComputers);
    }

    [Fact]
    public void ChoosingTheInventoryReadsItForTheSelectedContainer()
    {
        var assets = SourceOf(APage());
        var screen = Showing(assets);

        screen.Pane = AssetsPane.Laps;

        Assert.Equal(1, assets.LapsListings);
        Assert.Equal(DomainDn, assets.LapsListedContainer);
        Assert.True(screen.ShowsLaps);
        Assert.True(screen.ShowsLapsListing);
        Assert.False(screen.ShowsObjects);
        Assert.False(screen.ShowsFindings);
    }

    /// <summary>
    /// Every machine is listed, including the ones both rules leave alone, and the row says why.
    /// </summary>
    /// <remarks>
    /// <b>This is the column the first <c>ad.lab</c> run needed and did not have.</b> Two disabled
    /// leftover accounts were reported as findings because there was nowhere else for them to
    /// appear.
    /// </remarks>
    [Fact]
    public void TheExcludedMachinesAreListedAndSayWhyTheRulesIgnoreThem()
    {
        var assets = SourceOf(APage());
        var screen = Showing(assets);

        screen.Pane = AssetsPane.Laps;

        var rows = screen.LapsComputers.ToDictionary(row => row.Name);

        Assert.Equal(string.Empty, rows["FS01"].NotJudgedBecause);
        Assert.True(rows["FS01"].IsJudged);

        Assert.Equal("Disabled", rows["OLD1"].NotJudgedBecause);
        Assert.False(rows["OLD1"].IsJudged);

        Assert.Equal("Domain controller", rows["DC01"].NotJudgedBecause);
        Assert.False(rows["DC01"].IsJudged);
    }

    /// <summary>
    /// Both timestamps are shown, not the one matching the machine's tier.
    /// </summary>
    /// <remarks>
    /// The predecessor showed whichever suited the tier it had assigned, so a migrated machine
    /// looked modern and the legacy value it still carried was invisible.
    /// </remarks>
    [Fact]
    public void AMigratedMachineShowsBothOfItsTimestamps()
    {
        var assets = SourceOf(APage());
        var screen = Showing(assets);

        screen.Pane = AssetsPane.Laps;

        var migrated = screen.LapsComputers.Single(row => row.Name == "WS01");

        Assert.Equal("Migrated", migrated.Management);
        Assert.NotEqual(string.Empty, migrated.WindowsLapsExpiry);
        Assert.NotEqual(string.Empty, migrated.LegacyLapsExpiry);
    }

    /// <summary>
    /// Every state is counted, including the ones nothing is in.
    /// </summary>
    /// <remarks>
    /// A count list that omits what it did not find reads as a shorter question than the one that
    /// was asked: an operator who cannot see <i>Unexpected 0</i> has to work out whether it was
    /// measured at all.
    /// </remarks>
    [Fact]
    public void EveryStateIsCountedIncludingTheOnesAtZero()
    {
        var assets = SourceOf(APage());
        var screen = Showing(assets);

        screen.Pane = AssetsPane.Laps;

        var counts = screen.LapsCounts.ToDictionary(count => count.State, count => count.Count);

        Assert.Equal(Enum.GetValues<LapsManagement>().Length, screen.LapsCounts.Count);
        Assert.Equal(0, counts[LapsManagement.Unexpected]);

        // Two: the unmanaged member server and the domain controller. The counts describe every
        // machine in the container, including the ones no rule is in scope for - which is the
        // difference between this grid and the findings.
        Assert.Equal(2, counts[LapsManagement.NotManaged]);
    }

    /// <summary>
    /// The counts describe the whole listing, not the page.
    /// </summary>
    [Fact]
    public void TheTotalIsOfTheWholeListingRatherThanThePage()
    {
        var assets = SourceOf(APage(total: 4_000));
        var screen = Showing(assets);

        screen.Pane = AssetsPane.Laps;

        Assert.Equal(4_000, screen.LapsTotal);
        Assert.Equal(4, screen.LapsComputers.Count);
    }

    /// <summary>
    /// A listing that could not be read says so rather than showing an empty grid.
    /// </summary>
    /// <remarks>
    /// <c>docs/decisions/0002</c> on this screen: an unavailable answer must not render as
    /// <i>this container holds no computers</i>.
    /// </remarks>
    [Fact]
    public void AListingThatWasRefusedDoesNotLookLikeAContainerWithNoComputers()
    {
        var assets = SourceOf(APage());
        assets.LapsListingFails = AuditError.Create(
            ErrorCategory.Evidence,
            "EvidenceUnreadable",
            ErrorSeverity.Failed,
            "The evidence file could not be opened.",
            context: null);

        var screen = Showing(assets);
        screen.Pane = AssetsPane.Laps;

        Assert.True(screen.HasLapsRefusal);
        Assert.Empty(screen.LapsComputers);
        Assert.Equal(0, screen.LapsTotal);
    }

    /// <summary>
    /// A listing short by an unknown number of machines says so.
    /// </summary>
    [Fact]
    public void AShortListingStatesWhatItCouldNotCover()
    {
        var assets = SourceOf(
            new LapsPage(
                [],
                0,
                new Dictionary<LapsManagement, int>(),
                ComputersAreComplete: false,
                Shortfall: "'ph.ad.lab' was recorded as Excluded."));

        var screen = Showing(assets);
        screen.Pane = AssetsPane.Laps;

        Assert.True(screen.HasLapsShortfall);
        Assert.Contains("ph.ad.lab", screen.LapsShortfall!, StringComparison.Ordinal);
    }

    /// <summary>
    /// Changing the level re-reads the inventory, without leaving the tab.
    /// </summary>
    /// <remarks>
    /// <b>The owner's complaint of 2026-09-03, in a test.</b> The level control lived in the object
    /// listing and only re-listed the objects, so narrowing during a LAPS rollout meant crossing to
    /// the objects tab, choosing a level, and crossing back. The control now sits beside the tree
    /// and governs whichever view is showing.
    /// </remarks>
    [Fact]
    public void ChangingTheLevelRereadsTheInventoryWithoutLeavingTheTab()
    {
        var assets = SourceOf(APage());
        var screen = Showing(assets);

        screen.Pane = AssetsPane.Laps;
        Assert.Equal(1, assets.LapsListings);

        screen.ShowsBase = true;

        Assert.Equal(2, assets.LapsListings);
        Assert.Equal(ListingScope.Base, assets.LapsListedScope);
    }

    /// <summary>
    /// Changing the level while another view is showing does not read the inventory.
    /// </summary>
    /// <remarks>
    /// The counterpart to the test above, and the reason the refresh is guarded: the inventory
    /// counts every computer in scope, so re-reading it for a grid nobody is watching would pay for
    /// that scan on every click.
    /// </remarks>
    [Fact]
    public void ChangingTheLevelWhileTheObjectsAreShowingDoesNotReadTheInventory()
    {
        var assets = SourceOf(APage());
        var screen = Showing(assets);

        screen.ShowsBase = true;

        Assert.Equal(0, assets.LapsListings);
    }

    /// <summary>
    /// Choosing another container re-reads the inventory while it is showing.
    /// </summary>
    [Fact]
    public void ChoosingAnotherContainerRereadsTheInventory()
    {
        var assets = SourceOf(APage());
        var screen = Showing(assets);

        screen.Pane = AssetsPane.Laps;
        Assert.Equal(1, assets.LapsListings);

        screen.Roots[0].Children[0].IsSelected = true;

        Assert.Equal(2, assets.LapsListings);
        Assert.Equal("OU=Servers," + DomainDn, assets.LapsListedContainer);
    }

    [Fact]
    public void LapsScopeTreeStartsCompactAndTogglesWithoutRereadingOrClearingScope()
    {
        var assets = SourceOf(APage());
        var screen = Showing(assets);
        screen.Pane = AssetsPane.Laps;
        var selected = screen.Selected;
        var reads = assets.LapsListings;

        Assert.False(screen.ShowsScopeTree);
        Assert.Equal("Show scope tree", screen.ScopeTreeAction);
        Assert.Equal(DomainDn, screen.LapsLocation);

        screen.ToggleScopeTreeCommand.Execute(null);

        Assert.True(screen.ShowsScopeTree);
        Assert.Equal("Hide scope tree", screen.ScopeTreeAction);
        Assert.Same(selected, screen.Selected);
        Assert.Equal(reads, assets.LapsListings);
    }

    [Fact]
    public void LapsTableShowsTheRecordedDomainForEveryComputerRow()
    {
        var path = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell", "Views", "LapsInventoryView.xaml");
        var view = XDocument.Load(path);
        var domain = Assert.Single(view.Descendants(), element =>
            element.Name.LocalName == "DataGridTextColumn" && (string?)element.Attribute("Header") == "Domain");
        Assert.Equal("{Binding Domain}", (string?)domain.Attribute("Binding"));
    }

    [Fact]
    public void LapsDisplayedPageFiltersDoNotChangeWholeScopeCounts()
    {
        var assets = SourceOf(APage(total: 4_000));
        var screen = Showing(assets);
        screen.Pane = AssetsPane.Laps;

        screen.LapsSearchText = "WS01";
        Assert.Equal("WS01", Assert.Single(screen.VisibleLapsComputers).Name);
        Assert.Equal(4_000, screen.LapsTotal);
        Assert.Equal(Enum.GetValues<LapsManagement>().Length, screen.LapsCounts.Count);

        screen.LapsStateFilter = "Not managed";
        Assert.Empty(screen.VisibleLapsComputers);
        screen.LapsSearchText = "";
        Assert.Equal(2, screen.VisibleLapsComputers.Count);
    }

    [Fact]
    public void P248SavedLapsClearsAnEarlierRefusal()
    {
        var assets = SourceOf(APage());
        assets.LapsListingFails = AuditError.Create(ErrorCategory.Evidence, "Unavailable", ErrorSeverity.Failed,
            "This run has no saved LAPS inventory.", null);
        var screen = Showing(assets);
        screen.Pane = AssetsPane.Laps;
        assets.LapsListingFails = null;

        screen.ShowsBase = true;

        Assert.False(screen.HasLapsRefusal);
    }

    private static AssetsViewModel Showing(FakeAssetSource assets)
    {
        var screen = new AssetsViewModel(assets);
        screen.Show(BundlePath, aCaptureIsRunning: false);

        return screen;
    }

    private static FakeAssetSource SourceOf(LapsPage page) => new()
    {
        Tree = TreeOfOneDomain(),
        Page = new ObjectPage(
            [new ListedObject(DomainDn, "contoso", Guid.NewGuid(), "domainDNS", null)],
            1,
            true,
            null),
        LapsPage = page,
    };

    private static LapsPage APage(int? total = null)
    {
        IReadOnlyList<LapsComputer> computers =
        [
            Computer("FS01", LapsManagement.NotManaged, LapsAttributes.AccountState.Enabled),
            Computer("WS01", LapsManagement.Migrated, LapsAttributes.AccountState.Enabled),
            Computer("OLD1", LapsManagement.WindowsLaps, LapsAttributes.AccountState.Disabled),
            Computer("DC01", LapsManagement.NotManaged, LapsAttributes.AccountState.Enabled, controller: true),
        ];

        var counts = computers.CountBy(computer => computer.Management).ToDictionary();

        return new LapsPage(computers, total ?? computers.Count, counts, true, null);
    }

    private const string Timestamp = "133700000000000000";

    private static LapsComputer Computer(
        string name, LapsManagement management, LapsAttributes.AccountState account, bool controller = false) =>
        new(
            $"CN={name},{DomainDn}",
            name,
            Guid.NewGuid(),
            "contoso.com",
            TimestampFor(management is LapsManagement.WindowsLaps or LapsManagement.Migrated),
            TimestampFor(management is LapsManagement.Migrated),
            "Windows Server 2022 Datacenter",
            "10.0 (20348)",
            controller ? "532480" : account is LapsAttributes.AccountState.Disabled ? "4098" : "4096",
            controller ? "516" : null,
            new(LapsCapabilityKind.WindowsLapsCapable, LapsCapabilityBasis.OperatingSystemVersion, "Windows Server 2022 Datacenter", "10.0 (20348)"),
            new(controller, controller, false), account, management);

    private static StoredLapsTimestamp TimestampFor(bool present) => present
        ? new(Timestamp, LapsTimestampReading.Present, DateTimeOffset.FromFileTime(long.Parse(Timestamp)).ToUniversalTime())
        : new(null, LapsTimestampReading.Absent, null);

    private static DirectoryTree TreeOfOneDomain() => new(
        [
            new TreeNode(
                DomainDn,
                "contoso",
                Guid.Parse("11111111-2222-3333-4444-555555555555"),
                TreeNodeOrigin.Partition,
                [
                    new TreeNode(
                        "OU=Servers," + DomainDn,
                        "Servers",
                        null,
                        TreeNodeOrigin.Captured,
                        []),
                ]),
        ],
        []);
}
