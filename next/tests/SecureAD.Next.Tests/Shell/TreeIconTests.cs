using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Threading;
using SecureAD.Evidence;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class TreeIconTests
{
    [Theory]
    [InlineData("organizationalUnit", "OrganizationalUnit")]
    [InlineData("container", "Container")]
    [InlineData("builtinDomain", "Container")]
    [InlineData("domainDNS", "Domain")]
    [InlineData("configuration", "Configuration")]
    [InlineData("dMD", "Schema")]
    [InlineData(null, "Unknown")]
    [InlineData("customUnclassifiedClass", "Unknown")]
    public void IconsFollowCapturedClassesNotDistinguishedNamePrefixes(string? objectClass, string expected)
    {
        var node = new TreeNode("OU=Misleading,DC=example", "Example", null, TreeNodeOrigin.Captured, [])
        { ObjectClass = objectClass };

        Assert.Equal(expected, new TreeNodeViewModel(node, observe: null).IconKind.ToString());
    }

    [Theory]
    [InlineData(NamingContextKind.Domain, "Domain")]
    [InlineData(NamingContextKind.Configuration, "Configuration")]
    [InlineData(NamingContextKind.Schema, "Schema")]
    public void RecordedPartitionKindWinsOverNamesAndObjectClasses(NamingContextKind kind, string expected)
    {
        var node = new TreeNode("CN=UnrelatedName,DC=example", "UnrelatedName", null, TreeNodeOrigin.Partition, [])
        { PartitionKind = kind, ObjectClass = "container" };

        Assert.Equal(expected, new TreeNodeViewModel(node, observe: null).IconKind.ToString());
    }

    [Fact]
    public void AnUncapturedNodeKeepsItsGenericIconAndWarning()
    {
        var node = new TreeNode("OU=Missing,DC=example", "Missing", null, TreeNodeOrigin.NeverCaptured, [])
        { ObjectClass = "organizationalUnit" };
        var row = new TreeNodeViewModel(node, observe: null);

        Assert.Equal(TreeNodeIconKind.Unknown, row.IconKind);
        Assert.True(row.HasDetail);
        Assert.Equal(FactState.NotEstablished, row.State);
    }

    [Theory]
    [InlineData("domainDNS", "FluentTreeGlobe", false)]
    [InlineData("container", "FluentTreeFolder", false)]
    [InlineData("organizationalUnit", "FluentTreeFolder", true)]
    [InlineData("configuration", "FluentTreeSettings", false)]
    [InlineData("dMD", "FluentTreeLayer", false)]
    [InlineData(null, "FluentTreeFolder", false)]
    public void ActualIconTemplateRendersTheMappedVectorAndOuHierarchy(string? objectClass, string geometry, bool hierarchy) => OnSta(() =>
    {
        _ = XamlReader.Parse("<UserControl xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" />");
        var assembly = typeof(AssetsViewModel).Assembly.GetName().Name;
        var resources = new ResourceDictionary { Source = new Uri($"pack://application:,,,/{assembly};component/Themes/Tree.xaml") };
        var row = new TreeNodeViewModel(new("CN=Example,DC=example", "Example", null, TreeNodeOrigin.Captured, [])
        { ObjectClass = objectClass }, observe: null);
        var control = new ContentControl { Content = row, ContentTemplate = (DataTemplate)resources["TreeNodeIcon"] };
        control.Resources.MergedDictionaries.Add(new ResourceDictionary
        {
            Source = new Uri($"pack://application:,,,/{assembly};component/Themes/Palette.Dark.xaml"),
        });
        control.Resources.MergedDictionaries.Add(new ResourceDictionary
        {
            Source = new Uri($"pack://application:,,,/{assembly};component/Themes/Brushes.xaml"),
        });
        control.Resources.MergedDictionaries.Add(resources);
        control.Measure(new Size(22, 20));
        control.Arrange(new Rect(0, 0, 22, 20));
        control.UpdateLayout();
        var paths = Descendants<System.Windows.Shapes.Path>(control).ToArray();

        Assert.Equal(2, paths.Length);
        Assert.Same(resources[geometry], paths[0].Data);
        Assert.False(paths[0].Data.Bounds.IsEmpty);
        Assert.Equal(hierarchy ? Visibility.Visible : Visibility.Collapsed, paths[1].Visibility);
        var expected = Assert.IsType<SolidColorBrush>(control.FindResource(
            objectClass is null ? "SecondaryTextBrush" : "FocusBrush"));
        Assert.Equal(expected.Color, Assert.IsType<SolidColorBrush>(paths[0].Fill).Color);
        var viewbox = Assert.Single(Descendants<Viewbox>(control));
        Assert.Equal((16d, 16d, false), (viewbox.Width, viewbox.Height, viewbox.IsHitTestVisible));
    });

    private static IEnumerable<T> Descendants<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(parent); index++)
        {
            var child = VisualTreeHelper.GetChild(parent, index);
            if (child is T value) yield return value;
            foreach (var descendant in Descendants<T>(child)) yield return descendant;
        }
    }

    private static void OnSta(Action action)
    {
        var scheduled = new TaskCompletionSource<Task>(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            var dispatcher = Dispatcher.CurrentDispatcher;
            var work = dispatcher.InvokeAsync(() =>
            {
                try { action(); }
                finally { dispatcher.BeginInvokeShutdown(DispatcherPriority.Background); }
            });
            scheduled.SetResult(work.Task);
            Dispatcher.Run();
        }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(30)), "Tree icon rendering timed out.");
        scheduled.Task.Unwrap().GetAwaiter().GetResult();
    }
}
