using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class AuditProgressViewTests
{
    [Fact]
    public void NextReviewLabelKeepsContrastWhenTheButtonInheritsWhiteText() => OnSta(() =>
    {
        var model = AuditProgressTests.Model(new FakeDerivationLauncher(), new FakeJudgingLauncher());
        model.Screen = AuditScreen.Domains;
        var view = LoadView();
        view.DataContext = model;
        Arrange(view, 900, 430);
        var button = ButtonFor(view, "ReviewCommand");
        button.SetCurrentValue(Control.ForegroundProperty, Brushes.White);
        view.UpdateLayout();
        var label = Assert.IsType<TextBlock>(button.Content);
        Assert.Equal("Next: review run", label.Text);
        Assert.Same(model.ReviewCommand, button.Command);
        var foreground = Assert.IsType<SolidColorBrush>(label.Foreground).Color;
        var background = Assert.IsType<SolidColorBrush>(button.Background).Color;
        Assert.Equal(((SolidColorBrush)view.FindResource("OnAccentTextBrush")).Color, foreground);
        Assert.NotEqual(Colors.White, foreground);
        ApplicationThemeTests.AssertContrast(new Dictionary<string, Color>
        {
            ["label"] = foreground,
            ["button"] = background,
        }, "label", "button");
        Render(view, 900, 430, "next-contrast");
    });

    [Theory]
    [InlineData(900, 650)]
    [InlineData(1300, 768)]
    public void ReadinessControlsHaveTheSameSizeAndOpenOnlyTheirOwnDomain(int width, int height) => OnSta(() =>
    {
        var (model, capture) = AuditReadinessTests.Example().GetAwaiter().GetResult();
        var view = LoadView();
        view.DataContext = model;
        Arrange(view, width, height);
        var include = Assert.Single(Descendants<DataGridColumnHeader>(view), header => Equals(header.Content, "Include"));
        Assert.True(include.ActualWidth >= 72);
        Assert.True(include.ActualHeight < 50, "The Include header must not wrap into a column of letters.");
        var controls = Descendants<Button>(view).Where(button =>
            BindingOperations.GetBinding(button, Button.CommandProperty)?.Path.Path == "DataContext.ShowRowDetailsCommand").ToArray();
        Assert.Equal(model.Rows.Count, controls.Length);
        var visible = controls.Where(button => button.Visibility == Visibility.Visible).ToArray();
        Assert.Equal(3, visible.Length);
        Assert.All(visible, button =>
        {
            Assert.Equal(170, button.ActualWidth);
            Assert.Equal(34, button.ActualHeight);
            var cell = Assert.Single(Ancestors(button).OfType<DataGridCell>());
            var rectangle = button.TransformToAncestor(cell).TransformBounds(new Rect(button.RenderSize));
            Assert.True(rectangle.Left >= 0 && rectangle.Right <= cell.ActualWidth,
                $"The readiness action is clipped by its cell: {rectangle}; cell width {cell.ActualWidth}.");
            Assert.Same(button.DataContext, button.CommandParameter);
            Assert.True(button.Command.CanExecute(button.CommandParameter));
        });
        var ready = Assert.Single(Descendants<System.Windows.Shapes.Path>(view), path =>
            path.Name == "ReadyToReadMark" && path.Visibility == Visibility.Visible);
        Assert.Equal(AuditReadinessStatus.Ready, Assert.IsAssignableFrom<AuditRowViewModel>(ready.DataContext).ReadinessStatus);
        var blocked = Assert.Single(visible, button => ((AuditRowViewModel)button.DataContext).ReadinessStatus == AuditReadinessStatus.Blocked);
        var checks = capture.TimesChecked;
        blocked.Command.Execute(blocked.CommandParameter);
        Assert.Same(blocked.DataContext, Assert.Single(model.Details!.Domains));
        Assert.Equal(checks, capture.TimesChecked);
        Assert.False(capture.WasRun);
        model.Details.CloseCommand.Execute(null);
        view.UpdateLayout();
        Assert.False(model.HasDetails);
        Render(view, width, height, "readiness-domains");
    });

    [Fact]
    public void SelectedDomainDetailsRenderTheOriginalRefusalAndFaultText() => OnSta(() =>
    {
        var row = new DomainRowViewModel(AuditReadinessTests.GoodPlan(Forests.Root, Forests.Controller, "ad.lab")
            with { Faults = ["Original preflight fault without shortening."] }, _ => Task.CompletedTask, (_, _) => { })
        { Problem = "Original controller refusal without shortening." };
        var model = new DomainDetailsViewModel([row], [], () => { });
        var view = LoadView("DomainDetailsView.xaml");
        view.DataContext = model;
        Arrange(view, 900, 650);
        Assert.Equal(row.Domain, BoundText(view, "Heading").Text);
        Assert.Equal(row.Problem, BoundReport(view, "Problem").Text);
        Assert.Contains(Descendants<TextBox>(view), text => text.Text == row.Faults[0]);
        Assert.Equal(Visibility.Visible, BoundReport(view, "Problem").Visibility);
        Render(view, 900, 650, "readiness-details");
    });

    [Theory]
    [InlineData(900, 430)]
    [InlineData(1300, 650)]
    public void WizardCompactReadinessAndRetryRemainVisibleAtBothWindowSizes(int width, int height) => OnSta(() =>
    {
        var model = AuditProgressTests.Model(new FakeDerivationLauncher(), new FakeJudgingLauncher());
        model.Screen = AuditScreen.Domains;
        model.Problem = "The selected controller name could not be resolved. This is a synthetic failure.";
        var view = LoadView();
        view.DataContext = model;
        Arrange(view, width, height);
        Assert.DoesNotContain(Descendants<Border>(view), border => border.Name == "WizardPreparationAttention");
        Assert.DoesNotContain(Descendants<TextBlock>(view), text => text.Text is "1  Domains & readiness" or "2  Review & run");
        Assert.Equal("New audit", BoundText(view, "ScreenHeading").Text);
        Assert.Contains("synthetic failure", BoundReport(view, "FooterStatus").Text);
        var active = Assert.Single(Descendants<Border>(view), border => border.Name == "DomainsStep");
        var inactive = Assert.Single(Descendants<Border>(view), border => border.Name == "ReviewStep");
        Assert.Equal(3, active.BorderThickness.Bottom);
        Assert.Equal(((SolidColorBrush)view.FindResource("AccentBrush")).Color, ((SolidColorBrush)active.BorderBrush).Color);
        Assert.Equal(Colors.Transparent, ((SolidColorBrush)inactive.BorderBrush).Color);
        var next = ButtonFor(view, "ReviewCommand");
        Assert.True(next.IsEnabled);
        Assert.True(next.ActualHeight > 0 && next.TransformToAncestor(view).Transform(new Point()).Y + next.ActualHeight <= height);
        model.Screen = AuditScreen.Review;
        view.UpdateLayout();
        Assert.Equal(((SolidColorBrush)view.FindResource("AccentBrush")).Color, ((SolidColorBrush)inactive.BorderBrush).Color);
        Assert.Equal(Colors.Transparent, ((SolidColorBrush)active.BorderBrush).Color);
        Assert.Equal("New audit", BoundText(view, "ScreenHeading").Text);
        Render(view, width, height, "compact-readiness");
    });

    [Theory]
    [InlineData(900, 430)]
    [InlineData(1300, 650)]
    public void WizardCompletedCardsDistinguishSealedEvidenceFromIncompleteJudgement(int width, int height) => OnSta(() =>
    {
        var model = AuditProgressTests.Model(new FakeDerivationLauncher(), new FakeJudgingLauncher());
        model.CaptureOutput = AuditOutputState.Saved;
        model.DerivationOutput = AuditOutputState.Saved;
        model.JudgementOutput = AuditOutputState.SavedWithLimitations;
        model.HasFinished = true;
        model.BundleDirectory = @"C:\synthetic-runs\wizard";
        var view = LoadView();
        view.DataContext = model;
        Arrange(view, width, height);
        Assert.Equal("Sealed", BoundText(view, "CaptureStepText").Text);
        Assert.Equal("Saved with limitations", BoundText(view, "JudgementOutputText").Text);
        Assert.All(Ancestors(BoundText(view, "JudgementOutputText")).OfType<UIElement>(),
            parent => Assert.Equal(Visibility.Visible, parent.Visibility));
        Assert.Equal(Visibility.Collapsed, ButtonFor(view, "StartCommand").Visibility);
        Assert.Equal(Visibility.Visible, ButtonFor(view, "LeaveCommand").Visibility);
        Assert.Equal("View results", Assert.IsType<TextBlock>(ButtonFor(view, "LeaveCommand").Content).Text);
        Render(view, width, height, "outcome");
    });

    [Fact]
    public void WizardStopOverlayBindsConfirmationAndKeepsTheOriginalStopSeparate() => OnSta(() =>
    {
        var model = AuditProgressTests.Model(new FakeDerivationLauncher(), new FakeJudgingLauncher());
        model.CaptureOutput = AuditOutputState.Saved;
        model.DerivationOutput = AuditOutputState.Active;
        model.IsCapturing = true;
        model.BundleDirectory = @"C:\synthetic-runs\wizard";
        var view = LoadView();
        view.DataContext = model;
        Arrange(view, 900, 500);
        ButtonFor(view, "RequestAuditStopCommand").Command.Execute(null);
        view.UpdateLayout();
        Assert.True(model.StopConfirmationRequested);
        Assert.Contains("will be kept", BoundText(view, "StopExplanation").Text);
        var keep = ButtonFor(view, "KeepAuditRunningCommand");
        Assert.All(Ancestors(keep).OfType<UIElement>(), parent => Assert.Equal(Visibility.Visible, parent.Visibility));
        keep.Command.Execute(null);
        Assert.False(model.StopConfirmationRequested);
        Assert.True(model.IsCapturing);
    });

    private static Button ButtonFor(DependencyObject view, string command) => Assert.Single(Descendants<Button>(view),
        button => BindingOperations.GetBinding(button, Button.CommandProperty)?.Path.Path == command);

    private static void Arrange(FrameworkElement view, int width, int height)
    {
        view.Measure(new Size(width, height));
        view.Arrange(new Rect(0, 0, width, height));
        view.UpdateLayout();
    }

    private static void Render(FrameworkElement view, int width, int height, string name)
    {
        if (Environment.GetEnvironmentVariable("SECUREAD_WIZARD_RENDER") is not { } directory) return;
        var image = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        image.Render(view);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(image));
        using var output = File.Create(Path.Combine(directory, $"{name}-{width}.png"));
        encoder.Save(output);
    }
}
