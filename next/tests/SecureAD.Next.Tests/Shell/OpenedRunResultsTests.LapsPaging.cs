using Microsoft.Data.Sqlite;
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
    [Fact]
    public async Task Arch04LapsScreenFiltersPastPageOneWithoutOpeningUnrelatedStores()
    {
        var directory = LapsScopePagingTests.FilterRun();
        using var locks = new LapsUnrelatedStoreLocks(directory);
        using var counts = new ReadbackCounts(directory);
        using var source = new BundleAssetSource();
        var screen = new AssetsViewModel(source) { Pane = AssetsPane.Laps };
        screen.Show(directory, aCaptureIsRunning: false);
        await screen.ReadCompletion;
        Assert.Null(screen.ViewRefusal);
        Assert.Equal((100, 205, 1, true), (screen.LapsComputers.Count, screen.LapsTotal, screen.LapsPageNumber, screen.HasMoreLaps));
        screen.NextLapsCommand.Execute(null);
        await screen.ReadCompletion;
        Assert.Equal((100, 205, 2, true), (screen.LapsComputers.Count, screen.LapsTotal, screen.LapsPageNumber, screen.HasMoreLaps));
        screen.NextLapsCommand.Execute(null);
        await screen.ReadCompletion;
        Assert.Equal((5, 205, 3, false), (screen.LapsComputers.Count, screen.LapsTotal, screen.LapsPageNumber, screen.HasMoreLaps));
        screen.PreviousLapsCommand.Execute(null);
        await screen.ReadCompletion;
        Assert.Equal((100, 2), (screen.LapsComputers.Count, screen.LapsPageNumber));
        screen.LapsSearchText = "nEeDlE";
        await screen.ReadCompletion;
        Assert.Equal((5, 205, 1, false), (screen.VisibleLapsComputers.Count, screen.LapsTotal, screen.LapsPageNumber, screen.HasMoreLaps));
        screen.LapsStateFilter = "Legacy LAPS";
        await screen.ReadCompletion;
        var row = Assert.Single(screen.VisibleLapsComputers);
        Assert.Equal("ZZ-Needle-LegacyLaps", row.Name);
        Assert.Equal("Legacy LAPS", row.Management);
        Assert.Same(row, screen.SelectedLapsComputer);
        Assert.Equal(205, screen.LapsTotal);
        Assert.Equal(201, screen.LapsCounts.Single(count => count.State == LapsManagement.WindowsLaps).Count);
        Assert.Equal((0L, 0L, 0L, 0L), (counts.EvidenceVerifications, counts.DerivationVerifications,
            counts.PermissionProofVerifications, counts.PathProofVerifications));
        Assert.Equal((1L, 1L, 1L), (counts.NavigationVerifications, counts.JudgementVerifications, counts.FactsVerifications));
        FindingsViewTests.VerifySavedLapsRowsRender(screen);
    }

    [Fact]
    public async Task Arch04LapsScopeAndFilterChangesResetOnlyThePageAndPreserveWholeScopeCounts()
    {
        var directory = LapsScopePagingTests.FilterRun();
        using var source = new BundleAssetSource();
        var screen = new AssetsViewModel(source) { Pane = AssetsPane.Laps };
        screen.Show(directory, aCaptureIsRunning: false);
        await screen.ReadCompletion;
        screen.NextLapsCommand.Execute(null);
        await screen.ReadCompletion;
        Assert.Equal(2, screen.LapsPageNumber);
        screen.Scope = ListingScope.OneLevel;
        await screen.ReadCompletion;
        Assert.Equal(1, screen.LapsPageNumber);
        Assert.False(screen.HasEarlierLaps);
        screen.LapsSearchText = "does-not-exist";
        await screen.ReadCompletion;
        Assert.Empty(screen.LapsComputers);
        Assert.Equal(205, screen.LapsTotal);
        Assert.Null(screen.ViewRefusal);
        Assert.Null(screen.LapsRefusal);
        screen.Suspend();
    }

    [Fact]
    public async Task Arch04LapsRefusesSelectedCorruptionInsteadOfCallingItNoMatches()
    {
        var directory = LapsScopePagingTests.FilterRun();
        var root = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value;
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        { DataSource = Path.Combine(directory, root.Segment(StoreSegmentRole.JudgementFacts).FileName), Pooling = false }.ToString()))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE laps_inventory SET result='broken' WHERE name='ZZ-Needle-Unexpected'";
            Assert.Equal(1, command.ExecuteNonQuery());
        }
        TestSealing.ResealAnalysis(directory, new(AnalysisStoreKind.Judgement, root.GenerationId));
        using var source = new BundleAssetSource();
        var screen = new AssetsViewModel(source) { Pane = AssetsPane.Laps };
        screen.Show(directory, aCaptureIsRunning: false);
        await screen.ReadCompletion;
        Assert.Null(screen.ViewRefusal);
        screen.LapsSearchText = "ZZ-Needle-Unexpected";
        await screen.ReadCompletion;
        Assert.NotNull(screen.ViewRefusal);
        Assert.Empty(screen.LapsComputers);
        Assert.False(screen.HasMoreLaps);
        screen.Suspend();
    }

    [Fact]
    public void Arch04LapsServiceRejectsAContinuationAfterGenerationReplacement()
    {
        var directory = LapsScopePagingTests.FilterRun();
        using var source = new BundleAssetSource();
        var query = new LapsQuery(LapsRoot, ListingScope.Subtree, "", null);
        var mark = Assert.IsType<LapsPageMark>(source.ListLapsComputers(directory, query, null).Value.Next);
        SavedLapsTestRun.Judge(directory);
        source.CloseRun();
        source.SelectRun(directory);
        var page = source.ListLapsComputers(directory, query, mark);
        Assert.False(page.IsSuccess);
        Assert.NotNull(page.Error);
    }

    private sealed class LapsUnrelatedStoreLocks : IDisposable
    {
        private readonly List<FileStream> _files = [];
        internal LapsUnrelatedStoreLocks(string directory)
        {
            var root = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value;
            var paths = root.Segments.Where(segment => segment.Role is StoreSegmentRole.PermissionProof or StoreSegmentRole.PathProof)
                .Select(segment => Path.Combine(directory, segment.FileName)).Append(Path.Combine(directory, BundleLayout.EvidenceFileName));
            foreach (var path in paths) _files.Add(new(path, FileMode.Open, FileAccess.Read, FileShare.None));
            var derivation = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Derivation);
            if (derivation.IsSuccess)
                _files.Add(new(Path.Combine(directory, derivation.Value.Segment(StoreSegmentRole.Derivation).FileName),
                    FileMode.Open, FileAccess.Read, FileShare.None));
        }
        public void Dispose()
        {
            foreach (var file in _files) file.Dispose();
        }
    }
}
