using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    private const string PagingOtherDn = "CN=0,DC=ad,DC=lab";

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(49)]
    [InlineData(50)]
    [InlineData(51)]
    [InlineData(121)]
    public async Task ObjectFindingsReachEverySavedPageWithoutReadingOtherObjects(int count)
    {
        var directory = ObjectFindingPagingRun(count, out _);
        using var source = new BundleAssetSource();
        using var locks = new FindingsHeavyLocks(directory);
        var (screen, section) = await OpenObjectFindingPages(source, directory, FirstDn);
        var found = new List<string>();
        var offset = 0;
        do
        {
            Assert.Null(section.Refusal);
            Assert.Equal(offset / 50 + 1, section.PageNumber);
            Assert.Equal(Math.Min(50, count - offset), section.Findings.Count);
            Assert.All(section.Findings, finding =>
            {
                Assert.Equal(FirstDn, finding.DistinguishedName);
                Assert.Equal("Complete", finding.Coverage);
            });
            found.AddRange(section.Findings.Select(finding => finding.Detail));
            var more = offset + 50 < count;
            Assert.Equal(more, section.NextCommand.CanExecute(null));
            Assert.Equal(offset > 0, section.PreviousCommand.CanExecute(null));
            if (!more) break;
            section.NextCommand.Execute(null);
            await section.ReadCompletion;
            offset += 50;
        } while (true);
        Assert.Equal(Enumerable.Range(0, count).Select(index => $"Recorded object finding {index:D3}"), found);
        while (section.PreviousCommand.CanExecute(null))
        {
            section.PreviousCommand.Execute(null);
            await section.ReadCompletion;
            offset -= 50;
            Assert.Equal($"Recorded object finding {offset:D3}", section.Findings[0].Detail);
        }
        Assert.Equal(1, section.PageNumber);
        if (count == 0) Assert.Equal(FindingsSectionViewModel.NothingFound, section.Verdict);
        else Assert.Null(section.Verdict);
        screen.Suspend();
    }

    [Fact]
    public async Task ObjectFindingPagePositionSurvivesSectionChangesAndResume()
    {
        var directory = ObjectFindingPagingRun(121, out _);
        using var source = new BundleAssetSource();
        var (screen, section) = await OpenObjectFindingPages(source, directory, FirstDn);
        for (var index = 0; index < 2; index++)
        {
            section.NextCommand.Execute(null);
            await section.ReadCompletion;
        }
        Assert.Equal(3, section.PageNumber);
        var opened = Assert.IsType<ObjectViewModel>(screen.Opened);
        opened.Show(ObjectSectionCatalog.Help);
        await opened.ReadCompletion;
        Assert.Empty(section.Findings);
        Assert.False(section.NextCommand.CanExecute(null));
        Assert.False(section.PreviousCommand.CanExecute(null));
        opened.Show(ObjectSectionCatalog.Findings);
        await opened.ReadCompletion;
        section = Assert.IsType<FindingsSectionViewModel>(opened.Content);
        Assert.Equal(3, section.PageNumber);
        Assert.Equal("Recorded object finding 100", section.Findings[0].Detail);
        Assert.Equal(21, section.Findings.Count);
        opened.Suspend();
        Assert.Null(opened.Content);
        opened.Resume();
        await opened.ReadCompletion;
        section = Assert.IsType<FindingsSectionViewModel>(opened.Content);
        Assert.Equal(3, section.PageNumber);
        Assert.Equal("Recorded object finding 100", section.Findings[0].Detail);
        Assert.Equal(FirstDn, opened.DistinguishedName);
        Assert.Equal(ObjectSectionCatalog.Findings, opened.SelectedKey);
        screen.Suspend();
    }

    [Fact]
    public async Task AnotherObjectCannotInheritThePreviousObjectsFindingContinuation()
    {
        var directory = ObjectFindingPagingRun(51, out _);
        using var source = new BundleAssetSource();
        var (screen, section) = await OpenObjectFindingPages(source, directory, FirstDn);
        section.NextCommand.Execute(null);
        await section.ReadCompletion;
        Assert.Equal(2, section.PageNumber);
        screen.OpenObject(new ListedObjectViewModel(new(PagingOtherDn, "Other recorded object", null, "computer", "ad.lab")));
        await screen.ObjectReadCompletion;
        screen.Opened!.Show(ObjectSectionCatalog.Findings);
        await screen.Opened.ReadCompletion;
        section = Assert.IsType<FindingsSectionViewModel>(screen.Opened.Content);
        Assert.Equal(1, section.PageNumber);
        Assert.Equal(PagingOtherDn, Assert.Single(section.Findings).DistinguishedName);
        Assert.Equal("Other object's saved finding", section.Findings[0].Detail);
        Assert.False(section.PreviousCommand.CanExecute(null));
        Assert.False(section.NextCommand.CanExecute(null));
        screen.Suspend();
    }

    [Fact]
    public async Task ClosingPagedObjectFindingsPreservesTheMainListQuestionAndSelection()
    {
        var directory = ObjectFindingPagingRun(51, out _);
        using var source = new BundleAssetSource();
        var screen = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        screen.Show(directory, aCaptureIsRunning: false);
        await screen.ReadCompletion;
        screen.SeverityFilter = "High";
        screen.RuleFilter = "SEC-022";
        await screen.ReadCompletion;
        var before = screen.Findings.Select(FindingDisplaySnapshot).ToArray();
        var row = screen.Findings.First(finding => finding.DistinguishedName == FirstDn);
        screen.SelectedFinding = row;
        screen.OpenFinding(row);
        await screen.ObjectReadCompletion;
        var section = Assert.IsType<FindingsSectionViewModel>(screen.Opened!.Content);
        Assert.True(section.NextCommand.CanExecute(null));
        section.NextCommand.Execute(null);
        await section.ReadCompletion;
        Assert.Single(section.Findings);
        screen.CloseObject();
        await screen.ReadCompletion;
        Assert.Equal(AssetsPane.Findings, screen.Pane);
        Assert.Equal(1, screen.FindingsPageNumber);
        Assert.Equal("High", screen.SeverityFilter);
        Assert.Equal("SEC-022", screen.RuleFilter);
        Assert.Equal(before, screen.Findings.Select(FindingDisplaySnapshot));
        Assert.NotNull(screen.SelectedFinding);
        Assert.Equal(row.Detail, screen.SelectedFinding.Detail);
        screen.Suspend();
    }

    [Fact]
    public async Task ReplacedSavedResultsRefuseTheOldObjectFindingContinuation()
    {
        var directory = ObjectFindingPagingRun(51, out var saved);
        using var source = new BundleAssetSource();
        var (screen, section) = await OpenObjectFindingPages(source, directory, FirstDn);
        Assert.True(section.NextCommand.CanExecute(null));
        WriteFindingsFixture(directory, saved);
        section.NextCommand.Execute(null);
        await section.ReadCompletion;
        Assert.Empty(section.Findings);
        Assert.NotNull(section.Refusal);
        Assert.NotEqual(FindingsSectionViewModel.NothingFound, section.Verdict);
        Assert.False(section.NextCommand.CanExecute(null));
        screen.Suspend();
    }

    private static async Task<(AssetsViewModel Screen, FindingsSectionViewModel Section)> OpenObjectFindingPages(
        BundleAssetSource source, string directory, string distinguishedName)
    {
        var screen = new AssetsViewModel(source);
        screen.Show(directory, aCaptureIsRunning: false);
        await screen.ReadCompletion;
        screen.OpenObject(new ListedObjectViewModel(new(distinguishedName, "Recorded object", null, "computer", "ad.lab")));
        await screen.ObjectReadCompletion;
        Assert.Null(screen.ObjectRefusal);
        screen.Opened!.Show(ObjectSectionCatalog.Findings);
        await screen.Opened.ReadCompletion;
        Assert.Null(screen.Opened.Refusal);
        return (screen, Assert.IsType<FindingsSectionViewModel>(screen.Opened.Content));
    }

    private static string ObjectFindingPagingRun(int count, out Finding[] saved)
    {
        var directory = LapsBundle.BuildMany(
            [(FirstDn, null, null, null, null, 512), (PagingOtherDn, null, null, null, null, 512)], DateTimeOffset.UnixEpoch);
        using (var captured = BundleReader.Open(directory).Value)
        {
            var first = Assert.IsType<Guid>(captured.ReadObjectAttributes(FirstDn)!.ObjectGuid);
            var second = Assert.IsType<Guid>(captured.ReadObjectAttributes(PagingOtherDn)!.ObjectGuid);
            saved = Enumerable.Range(0, count).Select(index => ObjectFindingsPagingTests.Finding(index) with
            {
                ObjectGuid = first, DistinguishedName = FirstDn, DomainFqdn = "ad.lab", ObjectClass = "computer",
                Detail = $"Recorded object finding {index:D3}",
            }).Append(ObjectFindingsPagingTests.Finding(count) with
            {
                Subject = new(FindingSubjectKind.DirectoryObject, "other object's recorded subject"),
                ObjectGuid = second, DistinguishedName = PagingOtherDn, DomainFqdn = "ad.lab", ObjectClass = "computer",
                Detail = "Other object's saved finding",
            }).ToArray();
        }
        WriteFindingsFixture(directory, saved);
        return directory;
    }
}
