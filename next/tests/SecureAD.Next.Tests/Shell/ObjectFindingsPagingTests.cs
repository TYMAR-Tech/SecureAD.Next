using System.Windows;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Shell.ObjectNavigationViewTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class ObjectFindingsPagingTests
{
    private const string Dn = "CN=Recorded object,DC=contoso,DC=com";
    private static readonly Guid Generation = Guid.Parse("11111111-2222-3333-4444-555555555555");
    private static ObjectSectionDefinition Definition => new(ObjectSectionCatalog.Findings, "Findings", []);

    [Fact]
    public async Task ObjectFindingPagerRequestsOnlySelectedContinuationsAndKeepsCoverageIndependent()
    {
        var calls = new List<FindingsPageMark?>();
        var section = new FindingsSectionViewModel(Definition, new(),
            (after, _) =>
            {
                calls.Add(after);
                return Task.FromResult(Result<FindingListPage>.Success(Page(121, after)));
            }, () => true);
        await section.ReadCompletion;
        Assert.Single(calls);
        Assert.Null(calls[0]);
        Assert.Equal(50, section.Findings.Count);
        Assert.Equal(1, section.PageNumber);
        Assert.All(section.Findings, finding => Assert.Equal("Complete", finding.Coverage));
        Assert.False(section.PreviousCommand.CanExecute(null));
        Assert.True(section.NextCommand.CanExecute(null));
        section.NextCommand.Execute(null);
        await section.ReadCompletion;
        Assert.Equal(Mark(50), calls[1]);
        Assert.Equal("Recorded finding 050", section.Findings[0].Detail);
        section.NextCommand.Execute(null);
        await section.ReadCompletion;
        Assert.Equal(Mark(100), calls[2]);
        Assert.Equal(21, section.Findings.Count);
        Assert.False(section.NextCommand.CanExecute(null));
        section.PreviousCommand.Execute(null);
        await section.ReadCompletion;
        Assert.Equal(Mark(50), calls[3]);
        Assert.Equal("Recorded finding 050", section.Findings[0].Detail);
        Assert.Equal(2, section.PageNumber);
        section.PreviousCommand.Execute(null);
        await section.ReadCompletion;
        Assert.Null(calls[4]);
        Assert.Equal("Recorded finding 000", section.Findings[0].Detail);
        Assert.Equal(1, section.PageNumber);
        Assert.False(section.PreviousCommand.CanExecute(null));
    }

    [Theory]
    [InlineData("refused")]
    [InlineData("empty")]
    [InlineData("oversized")]
    [InlineData("nonadvancing")]
    public async Task ObjectFindingPageFailuresAreNotReportedAsNoFindingsAndCanReturn(string defect)
    {
        var section = new FindingsSectionViewModel(Definition, new(),
            (after, _) => Task.FromResult(after is null
                ? Result<FindingListPage>.Success(Page(51, null))
                : defect switch
                {
                    "refused" => Result<FindingListPage>.Failure(Failures.Any("The requested saved page is unavailable.")),
                    "empty" => Result<FindingListPage>.Success(new([], null, 1)),
                    "oversized" => Result<FindingListPage>.Success(new(Enumerable.Range(50, 51).Select(Item).ToArray(), null, 1)),
                    "nonadvancing" => Result<FindingListPage>.Success(new([Item(50)], after, 1)),
                    _ => throw new ArgumentOutOfRangeException(nameof(defect)),
                }), () => true);
        await section.ReadCompletion;
        section.NextCommand.Execute(null);
        await section.ReadCompletion;
        Assert.Empty(section.Findings);
        Assert.NotNull(section.Refusal);
        Assert.Equal(section.Refusal, section.Verdict);
        Assert.NotEqual(FindingsSectionViewModel.NothingFound, section.Verdict);
        Assert.NotEqual(FindingsSectionViewModel.NobodyLooked, section.Verdict);
        Assert.False(section.NextCommand.CanExecute(null));
        Assert.True(section.PreviousCommand.CanExecute(null));
        section.PreviousCommand.Execute(null);
        await section.ReadCompletion;
        Assert.Null(section.Refusal);
        Assert.Equal(50, section.Findings.Count);
        Assert.Equal(1, section.PageNumber);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SuspendedObjectFindingPagesRejectLateResultsAndFailures(bool failure)
    {
        var release = new TaskCompletionSource<Result<FindingListPage>>(TaskCreationOptions.RunContinuationsAsynchronously);
        CancellationToken observed = default;
        var section = new FindingsSectionViewModel(Definition, new(),
            (after, token) =>
            {
                if (after is null) return Task.FromResult(Result<FindingListPage>.Success(Page(51, null)));
                observed = token;
                return release.Task;
            }, () => true);
        await section.ReadCompletion;
        section.NextCommand.Execute(null);
        var pending = section.ReadCompletion;
        Assert.True(section.IsLoading);
        Assert.Empty(section.Findings);
        Assert.Null(section.Verdict);
        Assert.False(section.PreviousCommand.CanExecute(null));
        Assert.False(section.NextCommand.CanExecute(null));
        section.Suspend();
        var cancelled = observed.IsCancellationRequested;
        if (failure) release.SetException(new InvalidOperationException("A late saved page failure."));
        else release.SetResult(Result<FindingListPage>.Success(Page(51, Mark(50))));
        await pending;
        Assert.True(cancelled);
        Assert.Empty(section.Findings);
        Assert.Null(section.Refusal);
        Assert.Null(section.Verdict);
        Assert.False(section.ShowsPaging);
        Assert.False(section.PreviousCommand.CanExecute(null));
        Assert.False(section.NextCommand.CanExecute(null));
    }

    [Fact]
    public async Task ObjectFindingPagesRecheckTheSelectedLifetimeAfterReading()
    {
        var current = true;
        var release = new TaskCompletionSource<Result<FindingListPage>>(TaskCreationOptions.RunContinuationsAsynchronously);
        var section = new FindingsSectionViewModel(Definition, new(),
            (after, _) => after is null
                ? Task.FromResult(Result<FindingListPage>.Success(Page(51, null))) : release.Task, () => current);
        await section.ReadCompletion;
        section.NextCommand.Execute(null);
        current = false;
        release.SetResult(Result<FindingListPage>.Success(Page(51, Mark(50))));
        await section.ReadCompletion;
        Assert.Empty(section.Findings);
        Assert.Equal(SavedPathText.Get("GenerationChanged"), section.Refusal);
        Assert.False(section.NextCommand.CanExecute(null));
    }

    [Fact]
    public async Task StaleObjectFindingLifetimePreventsRequestingAnotherPage()
    {
        var current = true;
        var reads = 0;
        var section = new FindingsSectionViewModel(Definition, new(),
            (after, _) =>
            {
                reads++;
                return Task.FromResult(Result<FindingListPage>.Success(Page(51, after)));
            }, () => current);
        await section.ReadCompletion;
        current = false;
        section.NextCommand.Execute(null);
        await section.ReadCompletion;
        Assert.Equal(1, reads);
        Assert.Empty(section.Findings);
        Assert.Equal(SavedPathText.Get("GenerationChanged"), section.Refusal);
    }

    [Fact]
    public async Task DisabledObjectFindingPagerActionsDoNotRead()
    {
        var reads = 0;
        var section = new FindingsSectionViewModel(Definition, new(),
            (_, _) =>
            {
                reads++;
                return Task.FromResult(Result<FindingListPage>.Success(Page(50, null)));
            }, () => true);
        await section.ReadCompletion;
        section.NextCommand.Execute(null);
        section.PreviousCommand.Execute(null);
        Assert.Equal(1, reads);
        Assert.False(section.NextCommand.CanExecute(null));
        Assert.False(section.PreviousCommand.CanExecute(null));
        Assert.Equal(50, section.Findings.Count);
    }

    [Fact]
    public async Task ClosingTheObjectCancelsItsPendingFindingPage()
    {
        var (screen, source) = FakeOpened();
        screen.Opened!.Show(ObjectSectionCatalog.Findings);
        await screen.Opened.ReadCompletion;
        var section = Assert.IsType<FindingsSectionViewModel>(screen.Opened.Content);
        source.FindingsPage = new([Finding(50)], null, 1);
        var release = new TaskCompletionSource<object>(TaskCreationOptions.RunContinuationsAsynchronously);
        object? captured = null;
        CancellationToken observed = default;
        source.CompleteRead = (value, token) =>
        {
            if (value is not Result<FindingListPage>) return Task.FromResult(value);
            captured = value;
            observed = token;
            return release.Task;
        };
        section.NextCommand.Execute(null);
        var pending = section.ReadCompletion;
        Assert.NotNull(captured);
        screen.CloseObject();
        var cancelled = observed.IsCancellationRequested;
        release.SetResult(captured);
        await pending;
        Assert.True(cancelled);
        Assert.False(screen.HasOpenObject);
        Assert.Empty(section.Findings);
        Assert.Null(section.Refusal);
        Assert.False(section.NextCommand.CanExecute(null));
        screen.Suspend();
    }

    [Fact]
    public async Task ClosingTheObjectCancelsTheInitialFindingPageBeforeItIsPublished()
    {
        var (screen, source) = FakeOpened();
        var opened = Assert.IsType<ObjectViewModel>(screen.Opened);
        var release = new TaskCompletionSource<object>(TaskCreationOptions.RunContinuationsAsynchronously);
        object? captured = null;
        CancellationToken observed = default;
        source.CompleteRead = (value, token) =>
        {
            if (value is not Result<FindingListPage>) return Task.FromResult(value);
            captured = value;
            observed = token;
            return release.Task;
        };
        opened.Show(ObjectSectionCatalog.Findings);
        var pending = opened.ReadCompletion;
        Assert.NotNull(captured);
        screen.CloseObject();
        var cancelled = observed.IsCancellationRequested;
        release.SetResult(captured);
        await pending;
        Assert.True(cancelled);
        Assert.False(screen.HasOpenObject);
        Assert.Null(opened.Content);
        screen.Suspend();
    }

    [Theory]
    [InlineData(900, 430)]
    [InlineData(1300, 650)]
    public void ObjectFindingPagerRendersAndOperatesWithoutHidingScrollableCards(int width, int height) => OnSta(() =>
    {
        var section = new FindingsSectionViewModel(Definition, new(),
            (after, _) => Task.FromResult(Result<FindingListPage>.Success(Page(51, after))), () => true);
        Assert.True(section.ReadCompletion.IsCompletedSuccessfully);
        var (host, _, _) = AssetCardViewTests.Present(section);
        Layout(host, width, height);
        var previous = Assert.Single(Descendants<Button>(host), button => Equals(button.Content, "Previous"));
        var next = Assert.Single(Descendants<Button>(host), button => Equals(button.Content, "Next"));
        Assert.Same(section.PreviousCommand, previous.Command);
        Assert.Same(section.NextCommand, next.Command);
        Assert.False(previous.IsEnabled);
        Assert.True(next.IsEnabled);
        var scroll = Assert.Single(Descendants<ScrollViewer>(host), viewer => viewer.Content is ItemsControl);
        Assert.True(scroll.ViewportHeight > 0);
        Assert.True(scroll.ScrollableHeight > 0);
        var initialBounds = next.TransformToAncestor(host).TransformBounds(new Rect(0, 0, next.ActualWidth, next.ActualHeight));
        Assert.True(initialBounds.Top >= 0 && initialBounds.Bottom <= height && next.ActualHeight > 0);
        scroll.ScrollToEnd();
        Layout(host, width, height);
        var bounds = next.TransformToAncestor(host).TransformBounds(new Rect(0, 0, next.ActualWidth, next.ActualHeight));
        Assert.True(bounds.Top >= 0 && bounds.Bottom <= height && next.ActualHeight > 0);
        Assert.Contains(Descendants<TextBlock>(host), text => text.Text == "Page 1");
        ((IInvokeProvider)new ButtonAutomationPeer(next).GetPattern(PatternInterface.Invoke)!).Invoke();
        Layout(host, width, height);
        Assert.Equal(2, section.PageNumber);
        Assert.Single(section.Findings);
        Assert.True(previous.IsEnabled);
        Assert.False(next.IsEnabled);
        Assert.Contains(Descendants<TextBlock>(host), text => text.Text == "Page 2");
        ((IInvokeProvider)new ButtonAutomationPeer(previous).GetPattern(PatternInterface.Invoke)!).Invoke();
        Layout(host, width, height);
        Assert.Equal(50, section.Findings.Count);
        Assert.Equal(1, section.PageNumber);
        section.Suspend();
    });

    private static (AssetsViewModel Screen, FakeAssetSource Source) FakeOpened()
    {
        var (screen, source) = ObjectNavigationTests.Model();
        source.Attributes = FakeAssetSource.CapturedObject("DC=contoso,DC=com", "user");
        source.Permissions = Judgement.ControlEdgeDeriverTests.Permissions("DC=contoso,DC=com");
        source.FindingsPage = new(Enumerable.Range(0, 50).Select(Finding).ToArray(), Mark(50), 1);
        screen.OpenObject(screen.Objects[0]);
        Assert.True(screen.ObjectReadCompletion.IsCompletedSuccessfully);
        return (screen, source);
    }

    internal static Finding Finding(int index) => new("SEC-022", 1, Severity.High,
        new(FindingSubjectKind.DirectoryObject, "recorded subject " + index),
        Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"), Dn, "contoso.com", "user",
        $"Recorded finding {index:D3}", EvidenceCompleteness.Complete, new UserAccountControlEvidence(0x400200))
    { PrincipalName = "Recorded principal " + index };

    private static FindingListItem Item(int index) => FindingListItem.FromFinding(Finding(index));
    private static FindingsPageMark Mark(int position) =>
        new((int)Severity.High, "SEC-022", Dn, position) { GenerationId = Generation };
    private static FindingListPage Page(int count, FindingsPageMark? after)
    {
        var start = checked((int)(after?.FindingId ?? 0));
        var take = Math.Min(FindingsQuery.DefaultPageSize, count - start);
        return new(Enumerable.Range(start, take).Select(Item).ToArray(),
            start + take < count ? Mark(start + take) : null, 1);
    }
}
