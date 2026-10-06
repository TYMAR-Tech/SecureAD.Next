using SecureAD.Evidence;
using SecureAD.Kernel;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class ObjectNavigationTests
{
    private const string Bundle = @"C:\synthetic-runs\object-search";
    private const string Domain = "DC=contoso,DC=com";
    private const string OtherDomain = "DC=other,DC=example";
    private const string ObjectDn = "CN=Alice," + OtherDomain;

    [Fact]
    public async Task EditingSearchTextDoesNotRelabelOrRerunTheSubmittedQuestion()
    {
        var (screen, source) = Model();
        screen.ObjectSearchText = "Alice";
        screen.SearchObjectsCommand.Execute(null);
        await screen.ReadCompletion;

        screen.ObjectSearchText = "Bob";

        Assert.Single(source.ObjectSearchQueries);
        Assert.Contains("Alice", screen.ObjectSearchHeading);
        Assert.DoesNotContain("Bob", screen.ObjectSearchHeading);
        Assert.True(screen.HasListingResult);
    }

    [Fact]
    public async Task SearchDoesNotRequireASelectedTreeContainer()
    {
        var (screen, source) = Model();
        screen.Selected = null;
        screen.ObjectSearchText = "Alice";

        screen.SearchObjectsCommand.Execute(null);
        await screen.ReadCompletion;

        Assert.Single(source.ObjectSearchQueries);
        Assert.Single(screen.Objects);
        Assert.True(screen.IsObjectSearch);
    }

    [Fact]
    public async Task TypingDoesNotSearchAndSubmittingUsesTheWholeCapture()
    {
        var (screen, source) = Model();
        screen.ObjectSearchText = "Alice";
        Assert.Empty(source.ObjectSearchQueries);
        screen.SearchObjectsCommand.Execute(null);
        await screen.ReadCompletion;

        Assert.Equal("Alice", Assert.Single(source.ObjectSearchQueries).Search);
        Assert.True(screen.IsObjectSearch);
        Assert.Equal("other.example", Assert.Single(screen.Objects).Domain);
        Assert.Equal(OtherDomain, screen.Objects[0].Location);
        Assert.Equal(Domain, screen.Selected!.DistinguishedName);
        Assert.Contains("Entire selected capture", screen.ObjectSearchHeading);
        Assert.False(screen.CanChangeBrowsingScope);
        Assert.False(screen.ParentIsWorthShowing);
        Assert.Equal(1, source.ObjectListings);
    }

    [Fact]
    public async Task SearchPagesAndObjectReturnKeepTheirOriginalQuestion()
    {
        var (screen, source) = Model();
        var mark = new ObjectSearchMark(new string('a', 64), "Alice", 100);
        source.ObjectSearch = (_, after) => new ObjectSearchPage([Match()], after is null ? mark : null, new(true, null));
        source.Attributes = FakeAssetSource.CapturedObject(ObjectDn, "user");
        source.Permissions = Judgement.ControlEdgeDeriverTests.Permissions() with { DistinguishedName = ObjectDn };
        screen.ObjectSearchText = "Alice";
        screen.SearchObjectsCommand.Execute(null);
        await screen.ReadCompletion;
        screen.NextPage();
        await screen.ReadCompletion;
        Assert.Equal(mark, source.ObjectSearchQueries[1].After);
        Assert.Contains("Page 2", screen.PageDescription);
        screen.OpenObject(screen.Objects[0]);
        await screen.ReadCompletion;
        screen.CloseObject();

        Assert.Equal(2, source.ObjectSearchQueries.Count);
        Assert.True(screen.IsObjectSearch);
        Assert.Contains("Page 2", screen.PageDescription);
        screen.PreviousPage();
        await screen.ReadCompletion;
        Assert.Null(source.ObjectSearchQueries[2].After);
    }

    [Theory]
    [InlineData(ListingScope.Base)]
    [InlineData(ListingScope.OneLevel)]
    [InlineData(ListingScope.Subtree)]
    public async Task ClearSearchReturnsToTheSelectedContainerWithoutChangingTheScope(ListingScope scope)
    {
        var (screen, source) = Model();
        screen.Scope = scope;
        var listings = source.ObjectListings;
        screen.ObjectSearchText = "Alice";
        screen.SearchObjectsCommand.Execute(null);
        await screen.ReadCompletion;
        screen.ClearObjectSearchCommand.Execute(null);
        await screen.ReadCompletion;

        Assert.False(screen.IsObjectSearch);
        Assert.Equal("", screen.ObjectSearchText);
        Assert.Equal(scope, source.ListedScope);
        Assert.Equal(Domain, source.ListedContainer);
        Assert.Equal(listings + 1, source.ObjectListings);
        Assert.True(screen.CanChangeBrowsingScope);
    }

    [Theory]
    [InlineData("clear")]
    [InlineData("tree")]
    [InlineData("run")]
    [InlineData("pane")]
    public async Task ACancelledOrSupersededSearchCannotPublishLateMatches(string change)
    {
        var (screen, source) = Model();
        var delayed = new TaskCompletionSource<object>(TaskCreationOptions.RunContinuationsAsynchronously);
        object? answer = null;
        source.CompleteRead = (value, _) => { answer = value; return delayed.Task; };
        screen.ObjectSearchText = "Alice";
        screen.SearchObjectsCommand.Execute(null);
        var work = screen.ReadCompletion;
        source.CompleteRead = null;
        switch (change)
        {
            case "clear": screen.ClearObjectSearchCommand.Execute(null); break;
            case "tree": screen.Selected = screen.Roots[0].Children[0]; break;
            case "run": screen.Show(@"C:\synthetic-runs\another", false); break;
            case "pane": screen.Pane = AssetsPane.Findings; break;
        }
        delayed.SetResult(answer!);
        await work;

        Assert.False(screen.IsObjectSearch);
        Assert.DoesNotContain(screen.Objects, row => row.DistinguishedName == ObjectDn);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task EmptyAndRefusedSearchesDoNotClaimTheContainerIsEmpty(bool complete)
    {
        var (screen, source) = Model();
        source.ObjectSearch = (_, _) => new ObjectSearchPage([], null, new(complete, complete ? null : "Unread domain"));
        screen.ObjectSearchText = "Alice";
        screen.SearchObjectsCommand.Execute(null);
        await screen.ReadCompletion;
        Assert.True(screen.HasEmptyObjectSearch);
        Assert.False(screen.IsEmpty);
        Assert.Equal(complete ? null : "Unread domain", screen.Shortfall);
        source.ObjectSearch = (_, _) => Result<ObjectSearchPage>.Failure(AuditError.Create(
            ErrorCategory.Evidence, "SyntheticRefusal", ErrorSeverity.Failed, "Synthetic read failure", Bundle));
        screen.SearchObjectsCommand.Execute(null);
        await screen.ReadCompletion;

        Assert.True(screen.HasViewRefusal);
        Assert.False(screen.HasEmptyObjectSearch);
        Assert.False(screen.IsEmpty);
        Assert.Contains("Synthetic read failure", screen.ViewRefusal!.Detail);
    }

    [Fact]
    public void CompactCoverageSeparatesProductExclusionsFromRealRunGaps()
    {
        var (screen, source) = Model();
        source.Tree = source.Tree with { Gaps =
        [
            new("DC=DomainDnsZones," + Domain, TreeGapReason.PartitionNotRead, "Not collected by this product."),
            new("missing.example", TreeGapReason.DomainNotFullyRead, "Controller unavailable."),
            new("OU=Uncaptured," + Domain, TreeGapReason.ContainerNeverCaptured, "Parent not captured."),
        ] };
        screen.Read();

        Assert.False(screen.ShowsCaptureCoverageDetails);
        Assert.True(screen.HasCaptureGaps);
        Assert.Equal(2, screen.CaptureGaps.Count);
        Assert.Single(screen.ScopeNotes);
        screen.ToggleCaptureCoverageCommand.Execute(null);
        Assert.True(screen.ShowsCaptureCoverageDetails);
        Assert.Equal("Hide details", screen.CaptureCoverageAction);
        screen.Show(@"C:\synthetic-runs\another", false);
        Assert.False(screen.ShowsCaptureCoverageDetails);
    }

    [Fact]
    public void GeneralExclusionsAloneDoNotSayTheCaptureFailed()
    {
        var (screen, source) = Model();
        source.Tree = source.Tree with { Gaps = [new("DC=DomainDnsZones," + Domain, TreeGapReason.PartitionNotRead, "Not collected by this product.")] };
        screen.Read();

        Assert.False(screen.HasCaptureGaps);
        Assert.True(screen.HasScopeNotes);
        Assert.False(screen.HasNoTreeGaps);
    }

    internal static (AssetsViewModel Screen, FakeAssetSource Source) Model()
    {
        var source = new FakeAssetSource
        {
            Tree = new([new(Domain, "contoso", null, TreeNodeOrigin.Partition,
                [new("OU=People," + Domain, "People", null, TreeNodeOrigin.Captured, [])])], []),
            Page = new([new(Domain, "contoso", null, "domainDNS", null)], 1, true, null),
            ObjectSearch = (_, _) => new ObjectSearchPage([Match()], null, new(true, null)),
        };
        var screen = new AssetsViewModel(source);
        screen.Show(Bundle, false);
        return (screen, source);
    }

    private static ListedObject Match() => new(ObjectDn, "Alice", Guid.NewGuid(), "user", OtherDomain)
    { DomainFqdn = "other.example" };
}
