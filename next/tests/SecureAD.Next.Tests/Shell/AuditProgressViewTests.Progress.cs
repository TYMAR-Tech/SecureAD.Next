using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;
using SecureAD.Derivation;
using SecureAD.Judgement;
using SecureAD.Kernel.Capture;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class AuditProgressViewTests
{
    [Fact]
    public void DetailsCommandBringsTheActualRecordedReasonsIntoTheVisibleViewport() => OnSta(() =>
    {
        var model = CompletedProgressExample(false);
        var view = Assert.IsAssignableFrom<UserControl>(LoadView());
        view.DataContext = model;
        DashboardRedesignTests.InWindow(view, 900, 650, () =>
        {
            Assert.False(model.ShowsRunDetails);
            model.ShowRunDetailsCommand.Execute(null);
            view.UpdateLayout();
            Dispatcher.CurrentDispatcher.Invoke(DispatcherPriority.Background, new Action(() => { }));
            view.UpdateLayout();
            var details = Assert.IsType<Border>(view.FindName("RunDetailsPanel"));
            var bounds = details.TransformToAncestor(view).TransformBounds(new Rect(details.RenderSize));
            Assert.True(details.IsVisible && bounds.Top >= 0 && bounds.Bottom <= 600,
                $"Recorded details were not brought into the available viewport: {bounds}.");
            model.ToggleRunDetailsCommand.Execute(null);
            view.UpdateLayout();
            Assert.Equal(Visibility.Collapsed, details.Visibility);
        });
    });

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void IncompleteDerivedCountsKeepTheirLowerBoundRatherThanBecomingAuthoritativeTotals(bool incomplete) => OnSta(() =>
    {
        var model = CompletedProgressExample(false, incomplete);
        var view = LoadView();
        view.DataContext = model;
        Arrange(view, 900, 650);
        Assert.Equal(incomplete ? "At least 4,332" : "4,332", BoundText(view, "ResultPrincipalsText").Text);
        Assert.Equal(incomplete ? "At least 2,136" : "2,136", BoundText(view, "ResultRelationshipsText").Text);
        Assert.Equal(incomplete ? AuditOutputState.SavedWithLimitations : AuditOutputState.Saved, model.DerivationOutput);
    });

    [Theory]
    [InlineData(900, 650)]
    [InlineData(1300, 768)]
    public void NineDomainActivityScrollsWithoutHidingAuthoritativeCountsOrTheStopAction(int width, int height) => OnSta(() =>
    {
        var (model, _) = ReviewExample();
        model.CaptureOutput = AuditOutputState.Active;
        model.IsCapturing = true;
        model.Progress.Begin("Capture");
        var scopes = Enumerable.Range(1, 9).Select(index => new CaptureScopeProgress(
            $"DC=d{index}," + Forests.Root, $"d{index}.ad.lab", true, index * 1_000, CaptureReadState.Reading)).ToList();
        scopes.Add(new("CN=Configuration," + Forests.Root, "Configuration", false, 3, CaptureReadState.ReadComplete));
        model.ApplyCaptureProgress(new(1, CaptureWorkPhase.DirectoryRead, scopes, null));
        var view = LoadView();
        view.DataContext = model;
        Arrange(view, width, height);
        Assert.Equal(10, model.CaptureRows.Count);
        Assert.Equal(("45,003", "0 / 9", "9 domains"), (model.CapturedObjectsText, model.DomainReadsText, model.RunScopeLabel));
        var scrolling = Assert.IsType<ScrollViewer>(view.FindName("CaptureScopeScroll"));
        Assert.True(scrolling.ExtentHeight > scrolling.ViewportHeight);
        var total = Assert.Single(VisibleText(view, "Progress.WorkCountText"));
        Assert.Equal("45,003", total.Text);
        Assert.True(total.TransformToAncestor(view).TransformBounds(new Rect(total.RenderSize)).Bottom <= height);
        var stop = ButtonFor(view, "RequestAuditStopCommand");
        Assert.True(stop.TransformToAncestor(view).TransformBounds(new Rect(stop.RenderSize)).Bottom <= height);
        Render(view, width, height, "progress-nine-domains");
    });

    [Theory]
    [InlineData(900, 650)]
    [InlineData(1300, 768)]
    public void LiveCaptureShowsExactScopeCountsAndNeverTreatsCompletedReadsAsASeal(int width, int height) => OnSta(() =>
    {
        var (model, _) = ReviewExample();
        model.CaptureOutput = AuditOutputState.Active;
        model.IsCapturing = true;
        model.Progress.Begin("Capturing evidence");
        model.ApplyCaptureProgress(CaptureSnapshot(1, false));
        var view = LoadView();
        view.DataContext = model;
        Arrange(view, width, height);
        Assert.Equal("Audit in progress", BoundText(view, "ScreenHeading").Text);
        var table = Assert.Single(Descendants<ItemsControl>(view), item =>
            BindingOperations.GetBinding(item, ItemsControl.ItemsSourceProperty)?.Path.Path == "CaptureRows");
        var names = Descendants<TextBlock>(table).Where(item =>
            BindingOperations.GetBinding(item, TextBlock.TextProperty)?.Path.Path == "Name").ToArray();
        Assert.Equal(["ad.lab", "ba.ad.lab", "ph.ad.lab", "Forest data"], names.Select(item => item.Text));
        Assert.Equal(["1,248", "4,139", "1,591", "1,142"], Descendants<TextBlock>(table).Where(item =>
            BindingOperations.GetBinding(item, TextBlock.TextProperty)?.Path.Path == "ObjectsText").Select(item => item.Text));
        Assert.All(names, item => Assert.True(item.ActualWidth >= 150 && item.ActualHeight > 0));
        Assert.Equal(("8,120", "2 / 3"), (model.CapturedObjectsText, model.DomainReadsText));
        Assert.Contains(VisibleText(view, "Progress.WorkCountText"), item => item.Text == "8,120");
        Assert.True(ButtonFor(view, "RequestAuditStopCommand").TransformToAncestor(view)
            .TransformBounds(new Rect(ButtonFor(view, "RequestAuditStopCommand").RenderSize)).Bottom <= height);
        model.ApplyCaptureProgress(CaptureSnapshot(2, true) with { Phase = CaptureWorkPhase.Sealing });
        view.UpdateLayout();
        Assert.Equal(("8,444", "3 / 3", AuditOutputState.Active, "Sealing", "\u2022"),
            (model.CapturedObjectsText, model.DomainReadsText, model.CaptureOutput, model.CaptureStepText, model.CaptureMark));
        Assert.False(model.HasSealedEvidence);
        Assert.True(Assert.Single(Descendants<ProgressBar>(view).Where(IsShown)).IsIndeterminate);
        Render(view, width, height, "live-capture");
    });

    [Theory]
    [InlineData(900, 650, false)]
    [InlineData(1300, 768, false)]
    [InlineData(900, 650, true)]
    [InlineData(1300, 768, true)]
    public void ResultsKeepSavedCountsLimitationsCoverageAndUnrequestedWorkDistinct(int width, int height, bool captureOnly) => OnSta(() =>
    {
        var model = CompletedProgressExample(captureOnly);
        var view = LoadView();
        view.DataContext = model;
        Arrange(view, width, height);
        Assert.Equal("Results", BoundText(view, "ScreenHeading").Text);
        Assert.Empty(Descendants<ProgressBar>(view).Where(IsShown));
        Assert.Equal("8,444", BoundText(view, "ResultObjectsText").Text);
        Assert.Single(Descendants<TextBox>(view).Where(item =>
            BindingOperations.GetBinding(item, TextBox.TextProperty)?.Path.Path == "BundleDirectory" && IsShown(item)));
        if (captureOnly)
        {
            Assert.Equal((AuditOutputState.NotRequested, AuditOutputState.NotRequested), (model.DerivationOutput, model.JudgementOutput));
            Assert.Equal("Evidence sealed", model.ResultsSummary);
            Assert.False(model.HasSavedDerivation || model.HasRuleLimitations || model.HasCoverage);
            Assert.Empty(VisibleText(view, "ResultPrincipalsText"));
        }
        else
        {
            Assert.Equal("Results saved with limitations", BoundText(view, "ResultsSummary").Text);
            Assert.Equal(("4,332", "2,136"), (BoundText(view, "ResultPrincipalsText").Text, BoundText(view, "ResultRelationshipsText").Text));
            Assert.Equal("Some rules could not reach a verdict.", BoundText(view, "RuleLimitationsText").Text);
            Assert.Equal("Self-Membership scan: No result reported", BoundText(view, "CoverageText").Text);
            Assert.DoesNotContain(Descendants<TextBlock>(view).Where(IsShown), item => item.Text == "Original reason A.");
            model.ShowRunDetailsCommand.Execute(null);
            view.UpdateLayout();
            Assert.Contains(Descendants<TextBlock>(view).Where(IsShown), item => item.Text == "Original reason A.");
            Assert.Contains(Descendants<TextBlock>(view).Where(IsShown), item => item.Text == "Original reason B.");
        }
        Assert.Equal("View results", Assert.IsType<TextBlock>(ButtonFor(view, "LeaveCommand").Content).Text);
        model.ShowsRunDetails = false;
        view.UpdateLayout();
        Render(view, width, height, captureOnly ? "progress-capture-only" : "progress-results");
    });

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void StoppedAndFailedCaptureHaveNoCompletedEvidenceOrResultsAction(bool stopped) => OnSta(() =>
    {
        var (model, _) = ReviewExample();
        model.CaptureOutput = stopped ? AuditOutputState.Stopped : AuditOutputState.Failed;
        model.DerivationOutput = model.JudgementOutput = AuditOutputState.NotStarted;
        model.HasFinished = true;
        var view = LoadView();
        view.DataContext = model;
        Arrange(view, 900, 650);
        Assert.Equal("Results", BoundText(view, "ScreenHeading").Text);
        Assert.False(model.HasSealedEvidence || model.HasResultMetrics);
        Assert.Equal(stopped ? "Stopped without a confirmed seal" : "No sealed evidence", BoundText(view, "ResultsSummary").Text);
        Assert.Equal("Done", Assert.IsType<TextBlock>(ButtonFor(view, "LeaveCommand").Content).Text);
        Assert.Empty(Descendants<ProgressBar>(view).Where(IsShown));
    });

    [Fact]
    public void RunProgressUsesTheActualSelectedScopesAndRejectsOldOrChangedInventories()
    {
        var (model, _) = ReviewExample();
        model.ApplyCaptureProgress(CaptureSnapshot(3, false));
        var before = model.CapturedObjectsText;
        model.ApplyCaptureProgress(CaptureSnapshot(2, true));
        Assert.Equal(before, model.CapturedObjectsText);
        var changed = CaptureSnapshot(4, true) with
        {
            Scopes = [new("DC=other,DC=lab", "other.lab", true, 999, CaptureReadState.ReadComplete)],
        };
        Assert.Throws<ArgumentException>(() => model.ApplyCaptureProgress(changed));
        Assert.Equal(before, model.CapturedObjectsText);
        var retry = CaptureSnapshot(4, false);
        retry = retry with { Scopes = retry.Scopes.Select(scope => scope.DisplayName == "ba.ad.lab"
            ? scope with { ObjectsRead = 0 } : scope).ToArray() };
        model.ApplyCaptureProgress(retry);
        Assert.Equal("3,981", model.CapturedObjectsText);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void StopAndResultActionsKeepTheirExplicitThemeContrast(bool result) => OnSta(() =>
    {
        var model = result ? CompletedProgressExample(false) : ReviewExample().Model;
        if (!result) { model.CaptureOutput = AuditOutputState.Active; model.IsCapturing = true; }
        var view = LoadView();
        view.DataContext = model;
        Arrange(view, 900, 650);
        var button = ButtonFor(view, result ? "LeaveCommand" : "RequestAuditStopCommand");
        button.SetCurrentValue(Control.ForegroundProperty, Brushes.White);
        view.UpdateLayout();
        var text = Assert.IsType<TextBlock>(button.Content);
        var foreground = Assert.IsType<SolidColorBrush>(text.Foreground).Color;
        var background = Assert.IsType<SolidColorBrush>(button.Background).Color;
        Assert.Equal(((SolidColorBrush)view.FindResource("OnAccentTextBrush")).Color, foreground);
        ApplicationThemeTests.AssertContrast(new Dictionary<string, Color> { ["text"] = foreground, ["button"] = background }, "text", "button");
    });

    private static bool IsShown(DependencyObject item) => item is UIElement element && element.Visibility == Visibility.Visible
        && Ancestors(item).OfType<UIElement>().All(parent => parent.Visibility == Visibility.Visible);

    private static IEnumerable<TextBlock> VisibleText(DependencyObject view, string path) => Descendants<TextBlock>(view).Where(item =>
        BindingOperations.GetBinding(item, TextBlock.TextProperty)?.Path.Path == path && IsShown(item));

    private static CaptureProgress CaptureSnapshot(long sequence, bool completed) => new(sequence, CaptureWorkPhase.DirectoryRead,
    [
        new("CN=Configuration,"+Forests.Root,"Configuration",false,1_000,CaptureReadState.ReadComplete),
        new("CN=Schema,CN=Configuration,"+Forests.Root,"Schema",false,142,CaptureReadState.ReadComplete),
        new(Forests.Root,"ad.lab",true,1_248,CaptureReadState.ReadComplete),
        new("DC=ba,"+Forests.Root,"ba.ad.lab",true,completed?4_463:4_139,
            completed?CaptureReadState.ReadComplete:CaptureReadState.Reading),
        new("DC=ph,"+Forests.Root,"ph.ad.lab",true,1_591,CaptureReadState.ReadComplete),
    ], null);

    private static NewAuditViewModel CompletedProgressExample(bool captureOnly, bool incompleteDerivation = false)
    {
        var capture = ReviewCapture();
        capture.Outcome = new(true, @"C:\synthetic-runs\progress") { Progress = CaptureSnapshot(2, true) };
        var deriving = new FakeDerivationLauncher
        {
            Outcome = new(incompleteDerivation ? DerivationRunState.CompletedDegraded : DerivationRunState.Completed,
                4_332, 2_136, !incompleteDerivation),
        };
        var judging = new FakeJudgingLauncher
        {
            Outcome = new(JudgementRunState.CompletedDegraded, 8_444,
                new Dictionary<SecureAD.Evidence.Findings.Severity, int>(), [new("Original reason A.", 1), new("Original reason B.", 2)]),
        };
        var model = AuditProgressTests.Model(deriving, judging, capture);
        model.OpenAsync().GetAwaiter().GetResult();
        model.Screen = AuditScreen.Review;
        model.CaptureOnly = captureOnly;
        model.StartAsync().GetAwaiter().GetResult();
        return model;
    }
}
