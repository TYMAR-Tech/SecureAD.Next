using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class AuditProgressViewTests
{
    [Theory]
    [InlineData(900, 430)]
    [InlineData(1300, 650)]
    public void WizardWarningAndRetryRemainVisibleAtBothWindowSizes(int width, int height) => OnSta(() =>
    {
        var model = AuditProgressTests.Model(new FakeDerivationLauncher(), new FakeJudgingLauncher());
        model.Screen = AuditScreen.Domains;
        model.Problem = "The selected controller name could not be resolved. This is a synthetic failure.";
        var view = LoadView();
        view.DataContext = model;
        Arrange(view, width, height);
        var warning = Assert.Single(Descendants<Border>(view), border => border.Name == "WizardPreparationAttention");
        Assert.Equal(Visibility.Visible, warning.Visibility);
        Assert.All(Ancestors(warning).OfType<UIElement>(), parent => Assert.Equal(Visibility.Visible, parent.Visibility));
        Assert.DoesNotContain(Ancestors(warning), parent => parent is ScrollViewer);
        Assert.Contains("synthetic failure", BoundReport(view, "PreparationAttentionDetail").Text);
        var next = ButtonFor(view, "ReviewCommand");
        Assert.True(next.IsEnabled);
        Assert.True(next.ActualHeight > 0 && next.TransformToAncestor(view).Transform(new Point()).Y + next.ActualHeight <= height);
        Assert.True(warning.ActualHeight > 0 && warning.TransformToAncestor(view).Transform(new Point()).Y + warning.ActualHeight <= height);
        Render(view, width, height, "warning");
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
        Assert.Equal("Sealed", BoundText(view, "CaptureOutputText").Text);
        Assert.Equal("Saved with limitations", BoundText(view, "JudgementOutputText").Text);
        Assert.All(Ancestors(BoundText(view, "JudgementOutputText")).OfType<UIElement>(),
            parent => Assert.Equal(Visibility.Visible, parent.Visibility));
        Assert.Equal(Visibility.Collapsed, ButtonFor(view, "StartCommand").Visibility);
        Assert.Equal(Visibility.Visible, ButtonFor(view, "LeaveCommand").Visibility);
        Assert.Equal("View results", ButtonFor(view, "LeaveCommand").Content);
        Render(view, width, height, "outcome");
    });

    [Fact]
    public void WizardStopOverlayBindsConfirmationAndKeepsTheOriginalStopSeparate() => OnSta(() =>
    {
        var model = AuditProgressTests.Model(new FakeDerivationLauncher(), new FakeJudgingLauncher());
        model.IsCapturing = true;
        model.BundleDirectory = @"C:\synthetic-runs\wizard";
        var view = LoadView();
        view.DataContext = model;
        Arrange(view, 900, 500);
        ButtonFor(view, "RequestAuditStopCommand").Command.Execute(null);
        view.UpdateLayout();
        Assert.True(model.StopConfirmationRequested);
        Assert.Contains("already sealed", BoundText(view, "StopExplanation").Text);
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
