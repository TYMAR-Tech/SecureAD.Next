using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using SecureAD.Shell.Services;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class AuditProgressViewTests
{
    [Theory]
    [InlineData(900, 650)]
    [InlineData(1300, 768)]
    public void ReviewRunChoicesRenderTheirLabelsAndChangeOnlyTheIntent(int width, int height) => OnSta(() =>
    {
        var (model, capture) = ReviewExample();
        var view = LoadView();
        view.DataContext = model;
        Arrange(view, width, height);
        var checks = capture.TimesChecked;
        var plans = capture.TimesPlanned;
        foreach (var (path, title, description) in new[]
        {
            ("CaptureAndAnalyse", "Capture and analyse", "Capture evidence, then analyse it and save findings."),
            ("CaptureOnly", "Capture only", "Capture evidence now; analyse the saved run later."),
        })
        {
            var choice = Assert.Single(Descendants<RadioButton>(view), button =>
                BindingOperations.GetBinding(button, RadioButton.IsCheckedProperty)?.Path.Path == path);
            foreach (var text in new[] { title, description })
            {
                var label = Assert.Single(Descendants<TextBlock>(choice), item => item.Text == text);
                Assert.All(Ancestors(label).OfType<UIElement>(), parent => Assert.Equal(Visibility.Visible, parent.Visibility));
                var bounds = label.TransformToAncestor(view).TransformBounds(new Rect(label.RenderSize));
                Assert.True(bounds.Width > 0 && bounds.Height > 0 && bounds.Right <= width && bounds.Bottom <= height);
            }
        }
        var captureOnly = Assert.Single(Descendants<RadioButton>(view), button =>
            BindingOperations.GetBinding(button, RadioButton.IsCheckedProperty)?.Path.Path == "CaptureOnly");
        captureOnly.SetCurrentValue(RadioButton.IsCheckedProperty, true);
        view.UpdateLayout();
        Assert.True(model.CaptureOnly);
        Assert.False(model.CaptureAndAnalyse);
        Assert.Equal("Start capture", BoundText(view, "StartLabel").Text);
        Assert.Equal(checks, capture.TimesChecked);
        Assert.Equal(plans, capture.TimesPlanned);
        Assert.False(capture.WasRun);
        Render(view, width, height, "review-choices");
    });

    [Theory]
    [InlineData(900, 650, false)]
    [InlineData(1300, 768, false)]
    [InlineData(900, 650, true)]
    [InlineData(1300, 768, true)]
    public void ReviewDomainTableShowsOnlyIncludedDomainsAndKeepsExclusionAuthorization(int width, int height, bool exclude) => OnSta(() =>
    {
        var (model, _) = ReviewExample(exclude);
        var view = LoadView();
        view.DataContext = model;
        Arrange(view, width, height);
        var table = Assert.IsType<ItemsControl>(view.FindName("ReviewDomains"));
        var header = Assert.IsType<Grid>(view.FindName("ReviewDomainHeader"));
        var headings = Descendants<TextBlock>(header).ToArray();
        Assert.Equal(["Domain", "Domain controller"], headings.Select(item => item.Text));
        Assert.InRange(header.ActualHeight, 20, 40);
        Assert.All(headings, item => Assert.True(item.ActualWidth >= 150));
        Assert.Empty(Descendants<TextBox>(table));
        Assert.Empty(Descendants<System.Windows.Controls.Primitives.ToggleButton>(table));
        var expected = exclude
            ? new[] { ("ad.lab", "ADDC.ad.lab"), ("ph.ad.lab", "PHDC.ph.ad.lab") }
            : [("ad.lab", "ADDC.ad.lab"), ("ba.ad.lab", "BADC.ba.ad.lab"), ("ph.ad.lab", "PHDC.ph.ad.lab")];
        Assert.Equal(expected.Length, table.Items.Count);
        var domains = Descendants<TextBlock>(table).Where(item =>
            BindingOperations.GetBinding(item, TextBlock.TextProperty)?.Path.Path == "Domain").ToArray();
        var controllers = Descendants<TextBlock>(table).Where(item =>
            BindingOperations.GetBinding(item, TextBlock.TextProperty)?.Path.Path == "Controller").ToArray();
        Assert.Equal(expected.Select(item => item.Item1), domains.Select(item => item.Text));
        Assert.Equal(expected.Select(item => item.Item2), controllers.Select(item => item.Text));
        Assert.InRange(table.ActualHeight, expected.Length * 25, expected.Length * 40);
        for (var index = 0; index < expected.Length; index++)
        {
            Assert.True(domains[index].ActualWidth >= 150 && controllers[index].ActualWidth >= 190);
            foreach (var cell in new[] { domains[index], controllers[index] })
            {
                var bounds = cell.TransformToAncestor(view).TransformBounds(new Rect(cell.RenderSize));
                Assert.True(bounds.Width > 0 && bounds.Height > 0 && bounds.Right <= width && bounds.Bottom <= height);
                Assert.Equal((double)view.FindResource("BodyFontSize"), cell.FontSize);
            }
        }
        Assert.Equal($"{expected.Length} selected", BoundText(view, "Review.ReadCount").Text);
        Assert.True(table.TransformToAncestor(view).TransformBounds(new Rect(table.RenderSize)).Right <= width);
        var scope = Assert.IsType<StackPanel>(view.FindName("ReviewScope"));
        var text = Descendants<TextBlock>(scope).Select(item => item.Text).ToArray();
        Assert.Contains("Domains to audit", text);
        var options = Descendants<Expander>(scope).ToArray();
        Assert.Equal(["Object scope and optional inclusion", "Optional SYSVOL check"],
            options.Select(item => Assert.IsType<string>(item.Header)));
        Assert.All(options, item => Assert.False(item.IsExpanded));
        var optionBounds = options.Select(item => item.TransformToAncestor(view).TransformBounds(new Rect(item.RenderSize))).ToArray();
        Assert.InRange(Math.Abs(optionBounds[0].Top - optionBounds[1].Top), 0, 1);
        Assert.All(optionBounds, bounds => Assert.True(bounds.Width > 0 && bounds.Right <= width));
        if (exclude)
        {
            var excluded = Assert.Single(model.Exclusions);
            Assert.True(excluded.IsAttested);
            Assert.Contains(excluded.Domain, text);
            Assert.Contains(excluded.Why, text);
            Assert.Contains(excluded.Stated, text);
            Assert.Contains("Authorised by R. Zamus, as typed.", text);
            Assert.DoesNotContain("No domains excluded.", text);
            var background = Assert.IsType<SolidColorBrush>(Assert.IsType<Border>(scope.Parent).Background).Color;
            var exclusionLabels = Descendants<TextBlock>(scope).Where(item =>
                item.DataContext is ExclusionView && item.Visibility == Visibility.Visible).ToArray();
            Assert.Equal(4, exclusionLabels.Length);
            foreach (var label in exclusionLabels)
            {
                Assert.Equal((double)view.FindResource("BodyFontSize"), label.FontSize);
                ApplicationThemeTests.AssertContrast(new Dictionary<string, Color>
                {
                    ["label"] = Assert.IsType<SolidColorBrush>(label.Foreground).Color,
                    ["card"] = background,
                }, "label", "card");
            }
        }
        else
        {
            Assert.Empty(model.Exclusions);
            Assert.Contains("No domains excluded.", text);
        }
        Render(view, width, height, exclude ? "review-exclusion" : "review-domains");
    });

    [Theory]
    [InlineData("Dark", false)]
    [InlineData("Dark", true)]
    [InlineData("Light", false)]
    [InlineData("Light", true)]
    public void ReviewStartActionUsesThePrimaryTextColorForBothIntentsAndThemes(string theme, bool captureOnly) => OnSta(() =>
    {
        var (model, _) = ReviewExample();
        model.CaptureOnly = captureOnly;
        var view = LoadView();
        view.DataContext = model;
        new WpfThemeApplier(view.Resources).Apply(theme == "Dark" ? ThemeVariant.Dark : ThemeVariant.Light);
        Arrange(view, 900, 650);
        var button = ButtonFor(view, "StartCommand");
        Assert.True(button.IsEnabled);
        button.SetCurrentValue(Control.ForegroundProperty, Brushes.Magenta);
        view.UpdateLayout();
        var label = Assert.IsType<TextBlock>(button.Content);
        Assert.Equal(captureOnly ? "Start capture" : "Start audit", label.Text);
        Assert.Same(model.StartCommand, button.Command);
        var foreground = Assert.IsType<SolidColorBrush>(label.Foreground).Color;
        var background = Assert.IsType<SolidColorBrush>(button.Background).Color;
        Assert.Equal(((SolidColorBrush)view.FindResource("OnAccentTextBrush")).Color, foreground);
        Assert.Equal(((SolidColorBrush)view.FindResource("AccentBrush")).Color, background);
        ApplicationThemeTests.AssertContrast(new Dictionary<string, Color>
        {
            ["label"] = foreground,
            ["button"] = background,
        }, "label", "button");
        var bounds = button.TransformToAncestor(view).TransformBounds(new Rect(button.RenderSize));
        Assert.True(bounds.Width > 0 && bounds.Height > 0 && bounds.Right <= 900 && bounds.Bottom <= 650);
        Render(view, 900, 650, $"review-start-{theme}-{captureOnly}");
    });

    [Fact]
    public void ReviewPreparationOmitsInstructionalBlocksWithoutErasingTheRecordedWarnings() => OnSta(() =>
    {
        var (model, _) = ReviewExample();
        Assert.NotEmpty(model.Review.Warnings);
        var view = LoadView();
        view.DataContext = model;
        Arrange(view, 900, 650);
        Assert.Equal("New audit", BoundText(view, "ScreenHeading").Text);
        var text = Descendants<TextBlock>(view).Select(item => item.Text).ToArray();
        Assert.DoesNotContain("Scope you are authorizing", text);
        Assert.DoesNotContain("Worth knowing before you start", text);
        foreach (var path in new[] { "Review.ConcurrencyStatement", "Review.ConcurrencyCaveat", "UnestablishedFactSummary" })
            Assert.DoesNotContain(Descendants<TextBlock>(view), item =>
                BindingOperations.GetBinding(item, TextBlock.TextProperty)?.Path.Path == path);
        Assert.DoesNotContain(Descendants<ItemsControl>(view), item =>
            BindingOperations.GetBinding(item, ItemsControl.ItemsSourceProperty)?.Path.Path == "Review.Warnings");
        Assert.NotEmpty(model.Review.Warnings);
    });

    [Fact]
    public void ReviewHeadingRemainsVisibleForRunningAndCompletedOutputsOnly() => OnSta(() =>
    {
        var model = AuditProgressTests.Model(new FakeDerivationLauncher(), new FakeJudgingLauncher());
        var view = LoadView();
        view.DataContext = model;
        Arrange(view, 900, 650);
        var heading = BoundText(view, "ScreenHeading");
        Assert.Equal("New audit", heading.Text);
        model.CaptureOutput = AuditOutputState.Active;
        model.IsCapturing = true;
        view.UpdateLayout();
        Assert.Equal(Visibility.Visible, heading.Visibility);
        Assert.Equal("Audit in progress", heading.Text);
        model.IsCapturing = false;
        model.CaptureOutput = AuditOutputState.Saved;
        model.HasFinished = true;
        view.UpdateLayout();
        Assert.Equal(Visibility.Visible, heading.Visibility);
        Assert.Equal("Results", heading.Text);
        model.Screen = AuditScreen.Domains;
        view.UpdateLayout();
        Assert.Equal("New audit", heading.Text);
    });

    private static (NewAuditViewModel Model, FakeCaptureLauncher Capture) ReviewExample(bool exclude = false)
    {
        var capture = ReviewCapture();
        var model = AuditProgressTests.Model(new FakeDerivationLauncher(), new FakeJudgingLauncher(), capture);
        model.OpenAsync().GetAwaiter().GetResult();
        if (exclude) model.Domains[1].IsIncluded = false;
        model.Screen = AuditScreen.Review;
        return (model, capture);
    }

    private static FakeCaptureLauncher ReviewCapture() => new()
        {
            Plan = Forests.OneDomain() with
            {
                Domains =
                [
                    AuditReadinessTests.GoodPlan(Forests.Root, "ADDC.ad.lab", "ad.lab") with { Alternatives = [] },
                    AuditReadinessTests.GoodPlan("DC=ba," + Forests.Root, "BADC.ba.ad.lab", "ba.ad.lab"),
                    AuditReadinessTests.GoodPlan("DC=ph," + Forests.Root, "PHDC.ph.ad.lab", "ph.ad.lab"),
                ],
            },
            Check = new(true, []),
        };
}
