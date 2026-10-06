using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class SavedTier0PathSectionTests
{
    [Theory]
    [InlineData("SavedPathResult", "SEC-071 — Unexpected route to Tier 0")]
    [InlineData("SavedPathChecks", "Supported questions evaluated")]
    public void SavedPathCompiledTemplateBindsItsSavedStates(string name, string expected) => OnPathSta(() =>
    {
        var section = Read(Saved());
        var (template, pane, presenter) = PathPane(section);
        LayoutPath(pane, 600, 430);
        var text = Assert.IsType<TextBlock>(template.FindName(name, presenter));

        Assert.Equal(expected, text.Text);
    });

    [Fact]
    public void SavedPathCompiledTemplateDisplaysTheSavedSteps() => OnPathSta(() =>
    {
        var section = Read(Saved());
        var (template, pane, presenter) = PathPane(section);
        LayoutPath(pane, 600, 430);
        var rows = Assert.Single(PathDescendants<ItemsControl>(pane), value => value.Name == "SavedPathSteps");

        Assert.Same(Steps(section)[0], Assert.Single(rows.Items.Cast<object>()));
    });

    [Theory]
    [InlineData(600, 430)]
    [InlineData(1200, 650)]
    public void SavedPathCompiledTemplateWrapsAndKeepsExpandedEvidenceScrollable(int width, int height) => OnPathSta(() =>
    {
        var section = Read(Saved());
        var (template, pane, presenter) = PathPane(section);
        LayoutPath(pane, width, height);
        var scroll = Assert.IsType<ScrollViewer>(presenter.ContentTemplate.FindName("SavedPathResult", presenter) is TextBlock text
            ? AncestorScroll(text) : null);
        foreach (var expander in PathDescendants<Expander>(pane).ToArray()) expander.IsExpanded = true;
        LayoutPath(pane, width, height);
        scroll.ScrollToEnd();
        LayoutPath(pane, width, height);

        Assert.True(scroll.VerticalOffset > 0 && scroll.HorizontalScrollBarVisibility == ScrollBarVisibility.Disabled
            && PathDescendants<TextBlock>(pane).All(value => value.ActualWidth <= width && value.TextWrapping == TextWrapping.Wrap),
            $"Offset={scroll.VerticalOffset}; extent={scroll.ExtentHeight}; viewport={scroll.ViewportHeight}; "
            + string.Join("; ", PathDescendants<TextBlock>(pane).Where(value => value.ActualWidth > width || value.TextWrapping != TextWrapping.Wrap)
                .Select(value => $"{value.Name}: width={value.ActualWidth}, wrapping={value.TextWrapping}, text={value.Text}")));
    });

    private static (DataTemplate Template, Grid Pane, ContentPresenter Presenter) PathPane(SavedTier0PathSectionViewModel section)
    {
        var resources = (ResourceDictionary)Application.LoadComponent(new Uri("/SecureAD;component/Views/Sections/ObjectSectionTemplates.xaml", UriKind.Relative));
        var template = (DataTemplate)resources[new DataTemplateKey(typeof(SavedTier0PathSectionViewModel))];
        var presenter = new ContentPresenter { Content = section, ContentTemplate = template };
        var pane = new Grid();
        pane.Resources.MergedDictionaries.Add(resources);
        pane.Children.Add(presenter);
        return (template, pane, presenter);
    }

    private static void LayoutPath(FrameworkElement pane, int width, int height)
    {
        pane.Measure(new Size(width, height));
        pane.Arrange(new Rect(0, 0, width, height));
        pane.UpdateLayout();
        Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.ContextIdle);
    }

    private static ScrollViewer? AncestorScroll(DependencyObject value)
    {
        for (var parent = System.Windows.Media.VisualTreeHelper.GetParent(value); parent is not null;
            parent = System.Windows.Media.VisualTreeHelper.GetParent(parent))
            if (parent is ScrollViewer scroll) return scroll;
        return null;
    }

    private static IEnumerable<T> PathDescendants<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var index = 0; index < System.Windows.Media.VisualTreeHelper.GetChildrenCount(parent); index++)
        {
            var child = System.Windows.Media.VisualTreeHelper.GetChild(parent, index);
            if (child is T value) yield return value;
            foreach (var descendant in PathDescendants<T>(child)) yield return descendant;
        }
    }

    private static void OnPathSta(Action action)
    {
        var scheduled = new TaskCompletionSource<Task>(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            var dispatcher = Dispatcher.CurrentDispatcher;
            var operation = dispatcher.InvokeAsync(() =>
            {
                try { action(); }
                finally { dispatcher.BeginInvokeShutdown(DispatcherPriority.Background); }
            });
            scheduled.SetResult(operation.Task);
            Dispatcher.Run();
        }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(30)), "The no-window WPF layout check timed out.");
        scheduled.Task.Unwrap().GetAwaiter().GetResult();
    }
}
