using System.ComponentModel;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Threading;
using System.Xml.Linq;

namespace SecureAD.Gallery;

/// <summary>A synthetic comparison of the real section layout, never a reader of audit data.</summary>
internal sealed class RequesterSizingPreview : Window
{
    private static readonly XNamespace Wpf = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
    private static readonly XNamespace Xaml = "http://schemas.microsoft.com/winfx/2006/xaml";
    private static readonly string Inputs = Path.Combine(AppContext.BaseDirectory, "PreviewInputs");

    public RequesterSizingPreview()
    {
        var stamp = File.GetLastWriteTime(typeof(RequesterSizingPreview).Assembly.Location).ToString("yyyy-MM-dd HH:mm:ss");
        Title = $"R6 sizing preview — MADE-UP DATA — build {stamp}";
        Width = Math.Min(1500, SystemParameters.WorkArea.Width);
        Height = Math.Min(950, SystemParameters.WorkArea.Height);
        MinWidth = 850;
        MinHeight = 450;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        var root = new DockPanel { Margin = new Thickness(12) };
        Content = root;
        var instructions = new TextBlock
        {
            Text = "PREVIEW ONLY — all names, permissions and answers are made up. No AD or audit files are used.\n"
                + "Compare the two tabs at the same window size. Resize, scroll the tables, select a control row and expand its sample evidence.\n"
                + "Filters and paging are disabled. This synthetic preview does not establish real-product or forest acceptance.",
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 8)
        };
        DockPanel.SetDock(instructions, Dock.Top);
        root.Children.Add(instructions);
        var scenarios = new ComboBox
        {
            ItemsSource = new[] { "Many rows: 60 control permissions / 40 requester answers", "Few rows: 2 control permissions / 2 requester answers", "No requester requests: 2 control permissions / 0 requester answers" },
            SelectedIndex = 0,
            Margin = new Thickness(0, 0, 0, 8),
            HorizontalAlignment = HorizontalAlignment.Left
        };
        DockPanel.SetDock(scenarios, Dock.Top);
        root.Children.Add(scenarios);
        var tabs = new TabControl();
        root.Children.Add(tabs);
        void Refresh()
        {
            var selected = Math.Max(0, tabs.SelectedIndex);
            var controls = scenarios.SelectedIndex == 0 ? 60 : 2;
            var requesters = scenarios.SelectedIndex == 0 ? 40 : scenarios.SelectedIndex == 1 ? 2 : 0;
            tabs.Items.Clear();
            tabs.Items.Add(new TabItem { Header = "Before R6 — reconstructed sizing", Content = CreatePane(false, controls, requesters) });
            tabs.Items.Add(new TabItem { Header = "Implemented — capped tables + section scrolling", Content = CreatePane(true, controls, requesters) });
            tabs.SelectedIndex = selected;
        }
        scenarios.SelectionChanged += (_, _) => Refresh();
        Refresh();
    }

    private static FrameworkElement CreatePane(bool proposed, int controls, int requesters)
    {
        var section = new PreviewSection(controls, requesters);
        var source = XDocument.Load(Path.Combine(Inputs, "ObjectSectionTemplates.xaml"));
        var templateXml = new XElement(source.Root!.Elements(Wpf + "DataTemplate").Single(element =>
            (string?)element.Attribute("DataType") == "{x:Type vm:ControlEdgesSectionViewModel}"));
        templateXml.Attribute("DataType")!.Remove();
        templateXml.SetAttributeValue(XNamespace.Xmlns + "x", Xaml.NamespaceName);
        var template = (DataTemplate)XamlReader.Parse(templateXml.ToString());
        var sectionScroll = (ScrollViewer)template.LoadContent();
        var sectionGrid = (Grid)sectionScroll.Content;
        sectionGrid.DataContext = section;
        var controlGrid = sectionGrid.Children.OfType<DataGrid>().Single(grid => Grid.GetRow(grid) == 4);
        var toolbar = sectionGrid.Children.OfType<StackPanel>().Single();
        toolbar.IsEnabled = false;
        FrameworkElement sectionContent = sectionScroll;
        if (!proposed)
        {
            // Reconstruct only the three pre-R6 sizing choices, never write the product source.
            controlGrid.ClearValue(MaxHeightProperty);
            sectionGrid.RowDefinitions[6].Height = new GridLength(1, GridUnitType.Star);
            sectionScroll.Content = null;
            sectionContent = sectionGrid;
        }

        var objectXml = XDocument.Load(Path.Combine(Inputs, "ObjectView.xaml")).Root!;
        objectXml.Attribute(Xaml + "Class")!.Remove();
        objectXml.Attribute(Xaml + "ClassModifier")!.Remove();
        var objectView = (UserControl)XamlReader.Parse(objectXml.ToString());
        objectView.DataContext = new { Opened = new { DistinguishedName = "CN=Example group,OU=Demo,DC=example,DC=invalid", Selected = section } };
        var content = ((DockPanel)objectView.Content).Children.OfType<ContentControl>().Single();
        BindingOperations.ClearBinding(content, ContentControl.ContentProperty);
        content.Content = sectionContent;

        // Retain the real Assets screen padding and object-pane columns without loading its services.
        var assets = XDocument.Load(Path.Combine(Inputs, "AssetsView.xaml"));
        var dockXml = assets.Root!.Element(Wpf + "DockPanel")!;
        var gridXml = dockXml.Elements(Wpf + "Grid").Single();
        var columns = new XElement(gridXml.Element(Wpf + "Grid.ColumnDefinitions")!);
        var hostXml = new XElement(Wpf + "DockPanel", new XAttribute("Margin", dockXml.Attribute("Margin")!.Value),
            new XElement(Wpf + "Grid", columns));
        var host = (DockPanel)XamlReader.Parse(hostXml.ToString());
        var hostGrid = (Grid)host.Children[0];
        hostGrid.Children.Add(new TextBlock
        {
            Text = "SAMPLE OBJECT\nExample group\n\nSelected section:\nControl edges\n\nThis left area reserves the same width as the Assets screen. Navigation is not part of this preview.",
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 8, 12, 0)
        });
        Grid.SetColumn(objectView, 2);
        hostGrid.Children.Add(objectView);
        return new Border { Child = host, ClipToBounds = true };
    }

    internal static void Check(string reportPath)
    {
        var lines = new List<string>
        {
            "R6 gallery smoke check — no window shown; not visual acceptance.",
            "Template SHA-256: " + Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(Inputs, "ObjectSectionTemplates.xaml"))))
        };
        foreach (var proposed in new[] { false, true })
        {
            var pane = CreatePane(proposed, 60, 40);
            Layout(pane);
            var tables = Descendants<DataGrid>(pane).ToArray();
            if (tables.Length != 2 || tables[0].Items.Count != 60 || tables[1].Items.Count != 40)
                throw new InvalidOperationException("The preview did not bind both populated tables.");
            var requester = tables[1];
            var top = requester.TransformToAncestor(pane).Transform(new Point()).Y;
            lines.Add($"{(proposed ? "Implemented" : "Before R6 (reconstructed)")}: control height {tables[0].ActualHeight:F1}; requester height {requester.ActualHeight:F1}; requester top {top:F1}; pane height {pane.ActualHeight:F1}.");
            if (proposed)
            {
                var outer = Descendants<ScrollViewer>(pane).Single(view => view.Content is Grid grid && grid.Children.Contains(requester));
                outer.ScrollToEnd();
                Layout(pane);
                var inner = Descendants<ScrollViewer>(requester).First();
                inner.ScrollToEnd();
                Layout(pane);
                var last = requester.ItemContainerGenerator.ContainerFromIndex(39) as DataGridRow;
                var visibleTop = requester.TransformToAncestor(pane).Transform(new Point()).Y;
                if (tables[0].ActualHeight > 240.1 || requester.ActualHeight > 180.1 || requester.ActualHeight < 60
                    || outer.ScrollableHeight <= 0 || inner.ScrollableHeight <= 0 || last is null || last.ActualHeight <= 0
                    || visibleTop < 0 || visibleTop + requester.ActualHeight > pane.ActualHeight + 1)
                    throw new InvalidOperationException(string.Join(Environment.NewLine, lines)
                        + $"\nUnusable implemented layout: outer height={outer.ActualHeight}, outer scroll={outer.ScrollableHeight}, offset={outer.VerticalOffset}; "
                        + $"inner scroll={inner.ScrollableHeight}, last row height={last?.ActualHeight}, requester top={visibleTop}, pane height={pane.ActualHeight}.");
                lines.Add($"Implemented: section scroll {outer.ScrollableHeight:F1}; requester scroll {inner.ScrollableHeight:F1}; last row generated at height {last.ActualHeight:F1}; requester within pane after scrolling.");
            }
        }
        File.WriteAllLines(reportPath, lines);
    }

    private static void Layout(FrameworkElement pane)
    {
        pane.Measure(new Size(1300, 650));
        pane.Arrange(new Rect(0, 0, 1300, 650));
        pane.UpdateLayout();
        pane.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
        pane.UpdateLayout();
    }

    private static IEnumerable<T> Descendants<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T match) yield return match;
            foreach (var descendant in Descendants<T>(child)) yield return descendant;
        }
    }

    private sealed class PreviewSection : INotifyPropertyChanged
    {
        private PreviewControlRow? _selectedEdge;
        public string Title => "Control edges";
        public string SupportedScope => "Bounded control-edge slices: WRITE_DAC, WRITE_OWNER and group-membership rights. "
            + "General membership writes and own-account-only Self-Membership are separate; named-holder requester operations remain unknown, while explicit bounded requester assessments are separate uncounted detail. "
            + "Ownership-derived control, credentials, replication, full-control aggregation and effective member expansion are not yet derived. Counts are not totals for all control capabilities.";
        public string Coverage => "Capture coverage: all declared domains read. Objects with unanswered supported rights: 0. "
            + "This is a named-trustee view, not an expansion of rights inherited through group membership. Counts include unknown candidates; expectedness is not proof that a capability is established.";
        public string Counts => $"0 unexpected; {Rows.Length} expectedness unknown; 0 expected (hidden).";
        public string RequesterCoverage => RequesterAssessments.Length == 0
            ? "No concrete requester request was scheduled for this selection. This is not a refusal result."
            : $"{RequesterAssessments.Length} concrete requester assessments. These do not add to holder-edge counts. Synthetic answers for layout review only; no live operation was evaluated.";
        public bool ByHolder { get; set; }
        public bool IncludeExpected { get; set; }
        public bool HasPrincipal => true;
        public bool HasMore => false;
        public ICommand? FirstPageCommand => null;
        public ICommand? NextPageCommand => null;
        public PreviewControlRow[] Rows { get; }
        public object[] RequesterAssessments { get; }
        public PreviewControlRow? SelectedEdge
        {
            get => _selectedEdge;
            set { _selectedEdge = value; PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SelectedEdge))); }
        }
        public event PropertyChangedEventHandler? PropertyChanged;

        public PreviewSection(int controls, int requesters)
        {
            Rows = Enumerable.Range(1, controls).Select(i => new PreviewControlRow(i)).ToArray();
            _selectedEdge = Rows.FirstOrDefault();
            RequesterAssessments = Enumerable.Range(1, requesters).Select(i => (object)new
            {
                Requester = $"CN=Demo user {i:00},OU=Demo,DC=example,DC=invalid",
                Target = "CN=Example group,OU=Demo,DC=example,DC=invalid",
                Operation = i % 2 == 0 ? "Remove" : "Add",
                Authorization = i % 3 == 0 ? "Unknown" : "Established",
                OwnAccount = "Established",
                Readiness = "Unknown",
                Limits = "Synthetic example only. LiveOperationNotEvaluated; not a prediction of directory-operation success."
            }).ToArray();
        }
    }

    private sealed class PreviewControlRow(int number)
    {
        public string Holder => $"Demo holder {number:00}";
        public string Target => "CN=Example group,OU=Demo,DC=example,DC=invalid";
        public string Capability => "Self-Membership candidate — own account only; requester not verified";
        public string Evaluation => "Unknown";
        public string Expectedness => "Unknown";
        public string Evidence => $"MADE-UP EVIDENCE — row {number:00}. No stored audit data was opened.\nHolder: {Holder}\nTarget: {Target}\n"
            + string.Join("\n", Enumerable.Range(1, 16).Select(i => $"Sample evidence line {i:00}: own-account constraint; requester applicability not established by this holder row."));
    }
}
