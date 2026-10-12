using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using System.Windows.Controls;
using System.Windows;
using System.Windows.Markup;
using System.Xml.Linq;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class SavedTier0PathSectionTests
{
    private static SavedTier0Path Connected()
    {
        var saved = Saved();
        var step = saved.Page.Questions[0].Steps[0];
        var middle = step.To with { DistinguishedName = "CN=Intermediate,DC=contoso,DC=com" };
        var grade = new SupportedRouteGrade(RouteEvidenceClass.Definite, RouteFeasibility.Direct, [], RouteConfidence.High, 2, "signature");
        return saved with { Routes = new(saved.Description.GenerationId, saved.Description.DerivationGenerationId,
            saved.Description.EvidenceSeal, saved.Page.Coverage.CalculationFingerprint, step.From,
            new(Tier0DistanceVerdict.SupportedRoute, Tier0State.Unknown, 1, false, true), grade, 2, 0, [],
            [step with { To = middle }, step with { From = middle }], [step], [], saved.Page.Coverage.PathCoverage) };
    }

    private static Tier0OverviewPage Overview(SavedTier0Path saved, bool anotherPage)
    {
        var route = saved.Routes!;
        var summary = new Tier0RunSummary(1, route.GenerationId, route.DerivationGenerationId, route.EvidenceSeal,
            route.CalculationFingerprint, PathInputAvailability.Recorded, route.Coverage, true, true,
            1200, 28, 5, 76, 48, 1124, 0, 64);
        return new(summary, [new(route.Subject, route.Distance, route.BestGrade)],
            anotherPage ? new(route.GenerationId, route.CalculationFingerprint, Tier0OverviewScope.Supported,
                route.Subject.DistinguishedName) : null);
    }

    [Fact]
    public void ConnectedPathSeparatesBestFromShortestWithoutRemovingExistingQuestions()
    {
        var section = Read(Connected());
        Assert.True(section.HasRoutes);
        Assert.Equal("1 steps", section.Routes!.Distance);
        Assert.Contains("2 steps", section.Routes.Best);
        Assert.Contains("not established", section.Routes.Minimum);
        Assert.Equal(2, section.SelectedSteps.Count);
        section.ShowShortest = true;
        Assert.Single(section.SelectedSteps);
        Assert.Single(Questions(section));
        Assert.Equal("High", section.Severity);
    }

    [Fact]
    public void ConnectedPathRejectsMixedGenerationSummaryBeforeShowingRoutes()
    {
        var saved = Connected();
        var section = Read(saved with { Routes = saved.Routes! with { GenerationId = Guid.NewGuid() } });
        Assert.False(section.HasRoutes);
        Assert.Empty(section.SelectedSteps);
        Assert.Empty(Questions(section));
        Assert.Contains("generation", section.Result + section.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ConnectedOverviewReadsOnSelectionAndKeepsWholeRunCountsAcrossPagesAndReturn()
    {
        var saved = Connected();
        var source = Source();
        source.SavedPath = Result<SavedTier0Path?>.Success(saved);
        source.Tree = new([new("DC=contoso,DC=com", "contoso", Guid.NewGuid(), TreeNodeOrigin.Partition, [])], []);
        source.Tier0Overview = Result<Tier0OverviewPage?>.Success(Overview(saved, true));
        var model = new AssetsViewModel(source);
        model.Show(Bundle, false);
        Assert.Empty(source.Tier0OverviewQueries);
        model.ShowTier0OverviewCommand.Execute(null);
        await model.ReadCompletion;
        Assert.Single(source.Tier0OverviewQueries);
        Assert.Equal(Tier0OverviewScope.Supported, source.Tier0OverviewQueries[0].Scope);
        Assert.Contains("1,200", model.Tier0OverviewStatus);
        Assert.Contains("1,124", model.Tier0OverviewStatus);
        Assert.Single(model.Tier0Objects);
        model.NextTier0PageCommand.Execute(null);
        await model.ReadCompletion;
        Assert.NotNull(source.Tier0OverviewQueries[^1].After);
        var calls = source.Tier0OverviewQueries.Count;
        var selected = model.SelectedTier0Object;
        model.OpenTier0PathCommand.Execute(null);
        await model.ReadCompletion;
        Assert.Equal(ObjectSectionCatalog.SavedTier0Path, model.Opened!.SelectedKey);
        var path = Assert.IsType<SavedTier0PathSectionViewModel>(model.Opened.Content);
        path.ShowShortest = true;
        model.ShowObjectFindingsCommand.Execute(null);
        await model.Opened.ReadCompletion;
        Assert.Equal(ObjectSectionCatalog.Findings, model.Opened.SelectedKey);
        model.ShowObjectPathCommand.Execute(null);
        await model.Opened.ReadCompletion;
        Assert.True(Assert.IsType<SavedTier0PathSectionViewModel>(model.Opened.Content).ShowShortest);
        model.CloseObject();
        Assert.Equal(calls, source.Tier0OverviewQueries.Count);
        Assert.Same(selected, model.SelectedTier0Object);
        Assert.StartsWith("Page 2", model.Tier0PageDescription);
    }

    [Fact]
    public async Task ConnectedOverviewStartsSupportedAndAllIdentitiesRestartsBoundedPaging()
    {
        var saved = Connected();
        var source = Source();
        source.Tree = new([new("DC=contoso,DC=com", "contoso", Guid.NewGuid(), TreeNodeOrigin.Partition, [])], []);
        source.Tier0Overview = Result<Tier0OverviewPage?>.Success(Overview(saved, true));
        var model = new AssetsViewModel(source);
        model.Show(Bundle, false);
        model.Pane = AssetsPane.Tier0;
        await model.ReadCompletion;

        Assert.True(model.Tier0SupportedOnly);
        Assert.False(model.Tier0AllIdentities);
        Assert.Equal((Tier0OverviewScope.Supported, null), source.Tier0OverviewQueries[0]);

        model.Tier0AllIdentities = true;
        await model.ReadCompletion;

        Assert.False(model.Tier0SupportedOnly);
        Assert.True(model.Tier0AllIdentities);
        Assert.Equal((Tier0OverviewScope.All, null), source.Tier0OverviewQueries[^1]);
        Assert.StartsWith("Page 1", model.Tier0PageDescription);
    }

    [Fact]
    public async Task ConnectedOverviewMissingCapturedObjectShowsLimitationNotInventedDetails()
    {
        var saved = Connected();
        var source = Source();
        source.Attributes = null;
        source.Tree = new([new("DC=contoso,DC=com", "contoso", Guid.NewGuid(), TreeNodeOrigin.Partition, [])], []);
        source.Tier0Overview = Result<Tier0OverviewPage?>.Success(Overview(saved, false));
        var model = new AssetsViewModel(source);
        model.Show(Bundle, false);
        model.Pane = AssetsPane.Tier0;
        await model.ReadCompletion;
        model.OpenTier0PathCommand.Execute(null);
        await model.ReadCompletion;
        Assert.Null(model.Opened);
        Assert.Contains("no captured object", model.Tier0ObjectLimitation);
        Assert.Empty(source.PathQueries);
    }

    [Fact]
    public async Task ConnectedOverviewRefusalNeverBecomesZeroResults()
    {
        var source = Source();
        source.Tree = new([new("DC=contoso,DC=com", "contoso", Guid.NewGuid(), TreeNodeOrigin.Partition, [])], []);
        source.Tier0Overview = Result<Tier0OverviewPage?>.Failure(Failure());
        var model = new AssetsViewModel(source);
        model.Show(Bundle, false);
        model.Pane = AssetsPane.Tier0;
        await model.ReadCompletion;
        Assert.True(model.HasViewRefusal);
        Assert.False(model.HasListingResult);
        Assert.Equal("", model.Tier0OverviewStatus);
        Assert.False(model.OpenTier0PathCommand.CanExecute(null));
    }

    [Theory]
    [InlineData(600, 430)]
    [InlineData(1200, 650)]
    public void ConnectedPathCompiledTemplateShowsBothDistancesAndReadableSteps(int width, int height) => OnPathSta(() =>
    {
        var section = Read(Connected());
        var (_, pane, _) = PathPane(section);
        LayoutPath(pane, width, height);
        Assert.Contains(PathDescendants<TextBlock>(pane), text => text.Text == "1 steps");
        Assert.Contains(PathDescendants<TextBlock>(pane), text => text.Text.StartsWith("2 steps", StringComparison.Ordinal));
        Assert.Contains(PathDescendants<TextBlock>(pane), text => text.Text.Contains("Recorded membership", StringComparison.Ordinal));
        Assert.DoesNotContain(PathDescendants<TextBlock>(pane), text => text.Text.Contains("SavedPathStepViewModel", StringComparison.Ordinal));
        Assert.All(PathDescendants<TextBlock>(pane), text => Assert.True(text.ActualWidth <= width && text.TextWrapping == System.Windows.TextWrapping.Wrap));
    });

    [Theory]
    [InlineData(780, 520)]
    [InlineData(1200, 700)]
    public void ConnectedOverviewViewShowsSavedCountsAndOpensTheExistingTab(int width, int height) => OnPathSta(() =>
    {
        var saved = Connected();
        var source = Source();
        source.SavedPath = Result<SavedTier0Path?>.Success(saved);
        source.Tree = new([new("DC=contoso,DC=com", "contoso", Guid.NewGuid(), TreeNodeOrigin.Partition, [])], []);
        source.Tier0Overview = Result<Tier0OverviewPage?>.Success(Overview(saved, false));
        var model = new AssetsViewModel(source);
        model.Show(Bundle, false);
        model.Pane = AssetsPane.Tier0;
        XNamespace wpf = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        XNamespace xaml = "http://schemas.microsoft.com/winfx/2006/xaml";
        var shell = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell");
        var root = XDocument.Load(Path.Combine(shell, "Views", "Tier0OverviewView.xaml")).Root!;
        root.Attribute(xaml + "Class")!.Remove();
        root.Attribute(xaml + "ClassModifier")!.Remove();
        var sources = XDocument.Load(Path.Combine(shell, "App.xaml")).Descendants(wpf + "ResourceDictionary")
            .Attributes("Source").Select(attribute => attribute.Value);
        var originalResources = root.Element(wpf + "UserControl.Resources")!;
        var definitions = originalResources.Elements().ToArray();
        originalResources.Remove();
        root.AddFirst(new XElement(wpf + "UserControl.Resources", new XElement(wpf + "ResourceDictionary",
            new XElement(wpf + "ResourceDictionary.MergedDictionaries", sources.Select(path => new XElement(wpf + "ResourceDictionary",
                new XAttribute("Source", path.StartsWith("pack:", StringComparison.Ordinal) ? path : "/SecureAD;component/" + path)))), definitions)));
        var view = Assert.IsType<UserControl>(XamlReader.Parse(root.ToString()));
        view.DataContext = model;
        LayoutPath(view, width, height);
        Assert.Equal(6, Assert.Single(PathDescendants<DataGrid>(view)).Columns.Count);
        var header = Assert.Single(PathDescendants<TextBlock>(view), text => text.Text == "Object");
        Assert.Equal(view.FindResource("AttributeLabelBrush").ToString(), header.Foreground.ToString());
        Assert.Contains(PathDescendants<TextBox>(view), text => text.Text.Contains("1,200", StringComparison.Ordinal));
        var open = Assert.Single(PathDescendants<Button>(view), button => Equals(button.Content, "Open Path to Tier 0"));
        Assert.True(open.IsEnabled && open.ActualHeight > 0 && open.ActualWidth > 0);
        Assert.True(open.TranslatePoint(new Point(0, 0), view).Y + open.ActualHeight <= height);
        open.Command.Execute(open.CommandParameter);
        Assert.Equal(ObjectSectionCatalog.SavedTier0Path, model.Opened!.SelectedKey);
        if (Environment.GetEnvironmentVariable("SECUREAD_TIER0_RENDER") is { } directory)
        {
            var bitmap = new System.Windows.Media.Imaging.RenderTargetBitmap(width, height, 96, 96, System.Windows.Media.PixelFormats.Pbgra32);
            bitmap.Render(view);
            var encoder = new System.Windows.Media.Imaging.PngBitmapEncoder();
            encoder.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(bitmap));
            using var output = File.Create(Path.Combine(directory, $"overview-{width}.png"));
            encoder.Save(output);
        }
    });
}
