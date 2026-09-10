using System.Runtime.ExceptionServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Markup;
using System.Windows.Media;
using System.Xml.Linq;
using SecureAD.Shell.ViewModels;
using Xunit;
using Xunit.Sdk;

namespace SecureAD.Next.Tests.Shell;

public sealed class AuditProgressViewTests
{
    [Theory]
    [InlineData(900, 430)]
    [InlineData(1300, 650)]
    [InlineData(1600, 900)]
    public void PhaseCounterAndSeparateOutcomesBindInTheRealView(int width, int height) => OnSta(() => Verify(width, height, false));

    [Fact]
    public void TheViewCheckRejectsAnUnboundPhaseLabel() =>
        OnSta(() => Assert.ThrowsAny<XunitException>(() => Verify(900, 430, true)));

    private static void Verify(int width, int height, bool unbind)
    {
        var model = AuditProgressTests.Model(new FakeDerivationLauncher(), new FakeJudgingLauncher());
        model.IsCapturing = model.IsJudging = true;
        model.Report = "Sealed evidence; the audit is still running.";
        model.DerivationReport = "Derived facts completed.";
        model.JudgingReport = "Judging is in progress.";
        model.Progress.Begin(AuditProgressViewModel.Text("EvaluatingObjects"));
        model.Progress.Report(AuditProgressViewModel.Text("EvaluatingObjects"), AuditProgressViewModel.Text("ObjectsProcessed", 5000));
        var view = LoadView();
        view.DataContext = model;
        view.Measure(new Size(width, height));
        view.Arrange(new Rect(0, 0, width, height));
        view.UpdateLayout();
        var panel = Assert.Single(Descendants<Border>(view).Where(border => border.Name == "AuditPhaseProgress"));
        var phase = BoundText(view, "Progress.Status");
        if (unbind) BindingOperations.ClearBinding(phase, TextBlock.TextProperty);
        Assert.Equal(model.Progress.Status, phase.Text);
        Assert.Equal(model.Progress.Counter, BoundText(view, "Progress.Counter").Text);
        Assert.Equal(Visibility.Visible, panel.Visibility);
        Assert.All(Ancestors(panel).OfType<UIElement>(), ancestor => Assert.Equal(Visibility.Visible, ancestor.Visibility));
        Assert.True(panel.ActualHeight > 0);
        Assert.Equal(Dock.Top, DockPanel.GetDock(panel));
        Assert.DoesNotContain(Ancestors(panel), parent => parent is ScrollViewer);
        Assert.True(panel.TransformToAncestor(view).Transform(new Point()).Y + panel.ActualHeight <= height);
        Assert.Equal(model.DerivationReport, BoundReport(view, "DerivationReport").Text);
        Assert.Equal(model.JudgingReport, BoundReport(view, "JudgingReport").Text);
        Assert.True(Assert.Single(Descendants<ProgressBar>(panel)).IsIndeterminate);
        model.Progress.End("Audit ended with gaps");
        view.UpdateLayout();
        Assert.False(Assert.Single(Descendants<ProgressBar>(panel)).IsIndeterminate);
    }

    private static FrameworkElement LoadView()
    {
        XNamespace wpf = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        XNamespace xaml = "http://schemas.microsoft.com/winfx/2006/xaml";
        var shell = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell");
        var root = XDocument.Load(Path.Combine(shell, "Views", "NewAuditView.xaml")).Root!;
        root.Attribute(xaml + "Class")!.Remove();
        root.Attribute(xaml + "ClassModifier")!.Remove();
        // The unused details dialog template requires compiled internal types. The audit surface
        // and all its progress/outcome bindings are loaded from the unmodified production XAML.
        root.Element(wpf + "UserControl.Resources")!.Remove();
        var assembly = typeof(NewAuditViewModel).Assembly.GetName().Name;
        root.SetAttributeValue(XNamespace.Xmlns + "vm", "clr-namespace:SecureAD.Shell.ViewModels;assembly=" + assembly);
        var sources = XDocument.Load(Path.Combine(shell, "App.xaml")).Descendants(wpf + "ResourceDictionary")
            .Attributes("Source").Select(attribute => attribute.Value).Where(source => !source.StartsWith("Views/", StringComparison.Ordinal));
        root.AddFirst(new XElement(wpf + "UserControl.Resources", new XElement(wpf + "ResourceDictionary",
            new XElement(wpf + "ResourceDictionary.MergedDictionaries", sources.Select(source => new XElement(wpf + "ResourceDictionary",
                new XAttribute("Source", source.StartsWith("pack:", StringComparison.Ordinal) ? source : $"pack://application:,,,/{assembly};component/" + source)))))));
        return (FrameworkElement)XamlReader.Parse(root.ToString());
    }

    private static TextBlock BoundText(DependencyObject root, string path) => Assert.Single(Descendants<TextBlock>(root)
        .Where(text => BindingOperations.GetBinding(text, TextBlock.TextProperty)?.Path.Path == path));
    private static TextBox BoundReport(DependencyObject root, string path) => Assert.Single(Descendants<TextBox>(root)
        .Where(text => BindingOperations.GetBinding(text, TextBox.TextProperty)?.Path.Path == path));
    private static IEnumerable<DependencyObject> Ancestors(DependencyObject element)
    {
        for (var parent = VisualTreeHelper.GetParent(element); parent is not null; parent = VisualTreeHelper.GetParent(parent)) yield return parent;
    }
    private static IEnumerable<T> Descendants<T>(DependencyObject root) where T : DependencyObject
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is T value) yield return value;
            foreach (var descendant in Descendants<T>(child)) yield return descendant;
        }
    }
    private static void OnSta(Action action)
    {
        Exception? failure = null;
        var thread = new Thread(() => { try { action(); } catch (Exception error) { failure = error; } });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
    }
}
