using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;
using System.Xml.Linq;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Shell.ObjectNavigationViewTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class RulesPageTests
{
    private const string Bundle = @"C:\synthetic\rules";

    public static TheoryData<string> RuleIds() => new(RuleCatalogue.All.Select(rule => rule.Definition.Id));

    [Theory]
    [MemberData(nameof(RuleIds))]
    public void StructuredGuidanceKeepsEveryAuthoredParagraphAndDeclaredInput(string id)
    {
        var definition = RuleCatalogue.All.Single(rule => rule.Definition.Id == id).Definition;
        var row = new RuleRowViewModel(id, definition, null);
        Assert.NotEmpty(row.LooksFor);
        Assert.True(row.HasScopeNotes);
        Assert.Equal(WhiteSpace(row.About),
            WhiteSpace(string.Join(" ", new[] { row.LooksFor }.Concat(row.ScopeNotes.Select(note => note.Text)))));
        Assert.Equal(definition.RequiredAttributes, row.CapturedInputs.Select(input => input.Attribute));
        Assert.Equal(definition.RequiredDerivedFacts, row.RequiredDerivedFacts);
        Assert.All(row.CapturedInputs, input => Assert.EndsWith(":", input.Label));
        Assert.All(row.ScopeNotes, note => Assert.EndsWith(":", note.Heading));
        Assert.Equal(RuleGuidanceCatalogue.For(id)!.MicrosoftReference, row.MicrosoftReference);
    }

    [Fact]
    public void PrimaryRulesNavigationHasNoAssetsTabOrDirectoryRead()
    {
        var fixture = HomeRedesignTests.Model();
        var source = Source();
        var assets = new AssetsViewModel(source);
        var rules = new RulesViewModel(source);
        var shell = new ShellViewModel(fixture.Home, assets, new DashboardViewModel(source),
            new SettingsViewModel(new DomainConcurrency(new FakeSettingsStore())), rules);
        shell.Show(ShellSection.Rules);
        Assert.True(shell.IsRules);
        Assert.Same(rules, shell.Current);
        Assert.Empty(shell.Views);
        Assert.False(shell.HasViews);
        Assert.Equal(fixture.Home.Library.Selected!.Path, rules.BundlePath);
        Assert.Equal(1, source.RuleExecutionReads);
        Assert.Null(source.AskedFor);
        Assert.Equal(0, source.ObjectListings);
        shell.Show(ShellSection.Assets);
        Assert.DoesNotContain(shell.Views, view => view.Name == "Rules");
        Assert.Empty(rules.RuleRows);
        shell.ClearOpenedRun();
        Assert.True(rules.HasNoRun);
    }

    [Fact]
    public void ShellMarkupPlacesRulesBetweenDashboardAndAssetsWithoutNestedHosting()
    {
        var root = Architecture.RebuildTree.Root();
        var shell = XDocument.Load(Path.Combine(root, "src", "SecureAD.Shell", "Views", "ShellWindow.xaml"));
        var tabs = shell.Descendants().Where(element => element.Name.LocalName == "RadioButton"
            && (string?)element.Attribute("GroupName") == "Section").ToArray();
        Assert.Equal(new[] { "Home", "Dashboard", "Rules", "Assets", "Settings", "Audit" },
            tabs.Select(element => (string?)element.Attribute("Content")));
        var rules = Assert.Single(tabs, element => (string?)element.Attribute("Content") == "Rules");
        Assert.Equal("{x:Static vm:ShellSection.Rules}", (string?)rules.Attribute("CommandParameter"));
        var assets = XDocument.Load(Path.Combine(root, "src", "SecureAD.Shell", "Views", "AssetsView.xaml"));
        Assert.DoesNotContain(assets.Descendants(), element => element.Name.LocalName == "RulesView");
    }

    [Theory]
    [InlineData(900, 560)]
    [InlineData(1300, 800)]
    [InlineData(1920, 1080)]
    public void RulesPageRendersSelectedGuidanceWithoutMovingTheList(int width, int height) => OnSta(() =>
    {
        var source = Source();
        var model = new RulesViewModel(source);
        model.Show(Bundle);
        var view = View(model);
        DashboardRedesignTests.InWindow(view, width, height, () =>
        {
            Assert.Empty(Descendants<TreeView>(view));
            Assert.DoesNotContain(Descendants<TextBlock>(view), text => text.Text == "Rules and their results");
            var table = Assert.Single(Descendants<DataGrid>(view), grid => grid.Name == "RulesTable");
            Assert.Same(model.RuleRows[0], table.SelectedItem);
            Assert.Same(table.SelectedItem, model.SelectedRule);
            Assert.Equal(model.RuleRows.Count, table.Items.Count);
            var row = Assert.Single(model.RuleRows, item => item.Rule == "SEC-010");
            table.SelectedItem = row;
            Layout(view, width, height);
            var tableRow = Assert.IsType<DataGridRow>(table.ItemContainerGenerator.ContainerFromItem(row));
            Assert.Contains(Descendants<TextBlock>(tableRow), text => text.Text == row.Assessment && text.IsVisible);
            Assert.Contains(Descendants<TextBlock>(tableRow), text => text.Text == row.Severity && text.IsVisible);
            Assert.Contains(Descendants<TextBlock>(tableRow), text => text.Text == row.Findings.ToString() && text.IsVisible);
            var presenter = Assert.IsType<ContentControl>(view.FindName("RuleDetail"));
            Assert.Same(row, presenter.Content);
            Assert.NotEmpty(row.ScopeNotes);
            Assert.Empty(Descendants<Expander>(view));
            var tabs = Assert.Single(Descendants<TabControl>(presenter));
            Assert.Equal(new[] { "Summary", "Evidence used", "Scope & limitations", "Reference" },
                tabs.Items.Cast<TabItem>().Select(tab => tab.Header));
            var summary = Assert.Single(Descendants<TextBox>(presenter), box => box.Text == row.LooksFor);
            summary.SelectAll();
            Assert.Equal(row.LooksFor, summary.SelectedText);
            Assert.Contains(Descendants<TextBox>(presenter), box => box.Text == row.WhatToDo);
            tabs.SelectedIndex = 1;
            Layout(view, width, height);
            Assert.All(row.CapturedInputs,
                input => Assert.Contains(Descendants<TextBox>(presenter), box => box.Text == input.Attribute));
            Assert.Contains(Descendants<TextBox>(presenter), box => box.Text == row.Outcome);
            tabs.SelectedIndex = 2;
            Layout(view, width, height);
            Assert.All(row.ScopeNotes, note => Assert.Contains(Descendants<TextBox>(presenter), box => box.Text == note.Text));
            tabs.SelectedIndex = 3;
            Layout(view, width, height);
            Assert.Contains(Descendants<TextBox>(presenter), box => box.Text == row.MicrosoftReference);
            Assert.All(Descendants<TextBox>(presenter), box => Assert.Equal(TextWrapping.Wrap, box.TextWrapping));
            var detailScroll = Assert.Single(Descendants<ScrollViewer>(presenter), scroll => scroll.Name == "RuleExplanationScroll");
            var listScroll = Descendants<ScrollViewer>(table).First();
            var listOffset = listScroll.VerticalOffset;
            detailScroll.ScrollToEnd();
            Layout(view, width, height);
            Assert.Equal(listOffset, listScroll.VerticalOffset);
            var next = Assert.Single(model.RuleRows, item => item.Rule == "SEC-011");
            table.SelectedItem = next;
            tabs.SelectedIndex = 0;
            Layout(view, width, height);
            Assert.Same(next, presenter.Content);
            Assert.Contains(Descendants<TextBox>(presenter), box => box.Text == next.LooksFor);
            Assert.DoesNotContain(Descendants<TextBox>(presenter), box => box.Text == row.LooksFor);
            model.RuleSearchText = "SEC-011";
            Assert.Single(model.VisibleRuleRows);
            Assert.Equal(1, source.RuleExecutionReads);
            var splitter = Assert.Single(Descendants<GridSplitter>(view));
            var results = Assert.IsType<Grid>(splitter.Parent);
            var columns = results.ColumnDefinitions;
            var padding = Assert.IsType<Thickness>(view.FindResource("ScreenPadding"));
            Assert.Equal(
                padding.Top,
                results.TransformToAncestor(view).Transform(new Point()).Y,
                3);
            Assert.Equal(560, columns[0].ActualWidth, 3);
            splitter.RaiseEvent(new KeyEventArgs(Keyboard.PrimaryDevice, PresentationSource.FromVisual(view), 0, Key.Right)
                { RoutedEvent = Keyboard.KeyDownEvent });
            Layout(view, width, height);
            Assert.True(columns[0].ActualWidth > 560);
            Assert.True(presenter.ActualWidth >= 300);
        });
    });

    [Theory]
    [InlineData(900, 560, false)]
    [InlineData(900, 560, true)]
    [InlineData(1300, 800, false)]
    [InlineData(1300, 800, true)]
    [InlineData(1920, 1080, false)]
    [InlineData(1920, 1080, true)]
    public void InformationCardsKeepHeadingsBodyAndSelectedTabReadable(
        int width, int height, bool light) => OnSta(() =>
    {
        var model = new RulesViewModel(Source());
        model.Show(Bundle);
        var row = model.RuleRows.Single(rule => rule.Rule == "SEC-010");
        model.SelectedRule = row;
        var view = View(model);
        if (light) new WpfThemeApplier(view.Resources).Apply(ThemeVariant.Light);

        DashboardRedesignTests.InWindow(view, width, height, () =>
        {
            var presenter = Assert.IsType<ContentControl>(view.FindName("RuleDetail"));
            var tabs = Assert.Single(Descendants<TabControl>(presenter));
            var sectionStyle = Assert.IsType<Style>(view.FindResource("RuleInformationSection"));
            var titleStyle = Assert.IsType<Style>(view.FindResource("RuleInformationTitle"));
            var surface = ColorOf((Brush)view.FindResource("SurfaceRaisedBackground"));
            var text = ColorOf((Brush)view.FindResource("PrimaryTextBrush"));

            var summary = Assert.Single(Descendants<TextBox>(presenter),
                box => BindingOperations.GetBinding(box, TextBox.TextProperty)?.Path.Path == nameof(row.LooksFor));
            foreach (var (property, heading, answer) in new[]
            {
                (nameof(row.LooksFor), "What this rule detects:", row.LooksFor),
                (nameof(row.WhyItMatters), "Why it matters:", row.WhyItMatters),
                (nameof(row.WhatToDo), "What to do:", row.WhatToDo),
            })
            {
                var body = Assert.Single(Descendants<TextBox>(presenter),
                    box => BindingOperations.GetBinding(box, TextBox.TextProperty)?.Path.Path == property);
                var card = InformationCard(body, sectionStyle);
                Assert.Equal(answer, body.Text);
                Assert.Equal(FontWeights.Normal, body.FontWeight);
                Assert.Equal(text, ColorOf(body.Foreground));
                Assert.Equal(TextWrapping.Wrap, body.TextWrapping);
                Assert.True(body.IsReadOnly);
                body.SelectAll();
                Assert.Equal(answer, body.SelectedText);
                Assert.Equal(new CornerRadius(9), card.CornerRadius);
                Assert.Equal(surface, ColorOf(card.Background));
                var title = Assert.Single(Descendants<TextBlock>(card), item => ReferenceEquals(item.Style, titleStyle));
                Assert.Equal(heading, title.Text);
                Assert.Equal(FontWeights.SemiBold, title.FontWeight);
                Assert.True(title.FontSize > body.FontSize);
                Assert.True(body.TranslatePoint(new Point(), card).Y
                    >= title.TranslatePoint(new Point(), card).Y + title.ActualHeight + 5);
                Assert.True(body.ActualWidth <= card.ActualWidth);
                Assert.Equal(new Thickness(16, 13, 16, 16), Assert.IsType<Border>(body.Parent).Padding);
            }
            Assert.Equal(3, Descendants<Border>(tabs).Count(card => ReferenceEquals(card.Style, sectionStyle)));

            var selectedTab = Assert.IsType<TabItem>(tabs.SelectedItem);
            selectedTab.ApplyTemplate();
            var tabChrome = Assert.IsType<Border>(selectedTab.Template.FindName("RuleInformationTabChrome", selectedTab));
            Assert.Equal(new CornerRadius(20), tabChrome.CornerRadius);
            Assert.Equal(Colors.White, ColorOf(tabChrome.Background));
            var tabLabel = Assert.Single(Descendants<TextBlock>(selectedTab), item => item.Text == "Summary");
            Assert.Equal(Color.FromRgb(18, 22, 26), ColorOf(tabLabel.Foreground));
            Assert.True(summary.Focus());
            Assert.True(selectedTab.IsSelected);
            Assert.Equal(Colors.White, ColorOf(tabChrome.Background));

            tabs.SelectedIndex = 1;
            Layout(view, width, height);
            foreach (var input in row.CapturedInputs)
            {
                var label = Assert.Single(Descendants<TextBlock>(presenter), item => item.Text == input.Label);
                var value = Assert.Single(Descendants<TextBox>(presenter), item => item.Text == input.Attribute);
                Assert.True(value.TranslatePoint(new Point(), presenter).X
                    > label.TranslatePoint(new Point(), presenter).X);
                Assert.Equal(FontWeights.Normal, value.FontWeight);
                Assert.True(value.IsReadOnly);
                Assert.True(value.ActualWidth > 0);
                var inputRow = Assert.IsType<Border>(Assert.IsType<Grid>(value.Parent).Parent);
                Assert.Equal(new Thickness(0, 0, 0, 1), inputRow.BorderThickness);
                value.SelectAll();
                Assert.Equal(input.Attribute, value.SelectedText);
            }
            Assert.Contains(Descendants<TextBlock>(presenter), item => item.Text == "Captured attributes:");
            Assert.Contains(Descendants<TextBlock>(presenter), item => item.Text == "Saved execution result:");
            Assert.Contains(Descendants<TextBox>(presenter), item => item.Text == row.Outcome);

            tabs.SelectedIndex = 2;
            Layout(view, width, height);
            Assert.Equal(new[] { "Assessment boundary:", "Usage is not recorded:" },
                row.ScopeNotes.Select(note => note.Heading));
            foreach (var note in row.ScopeNotes)
            {
                var body = Assert.Single(Descendants<TextBox>(presenter), item => item.Text == note.Text);
                var card = InformationCard(body, sectionStyle);
                Assert.Equal(FontWeights.Normal, body.FontWeight);
                Assert.Contains(Descendants<TextBlock>(card), item => item.Text == note.Heading);
                Assert.Equal(new CornerRadius(9), card.CornerRadius);
            }
            Assert.Equal(row.ScopeNotes.Count,
                Descendants<Border>(tabs).Count(card => ReferenceEquals(card.Style, sectionStyle)));

            tabs.SelectedIndex = 3;
            Layout(view, width, height);
            Assert.Contains(Descendants<TextBlock>(presenter), item => item.Text == "Microsoft reference:");
            var reference = Assert.Single(Descendants<TextBox>(presenter), item => item.Text == row.MicrosoftReference);
            reference.SelectAll();
            Assert.Equal(row.MicrosoftReference, reference.SelectedText);
            Assert.Equal(FontWeights.Normal, reference.FontWeight);
        });
    });

    [Fact]
    public void EvidenceCardsIncludeEveryDeclaredDerivedInput() => OnSta(() =>
    {
        var model = new RulesViewModel(Source());
        model.Show(Bundle);
        var row = model.RuleRows.First(rule => rule.RequiredDerivedFacts.Count != 0);
        model.SelectedRule = row;
        var view = View(model);

        DashboardRedesignTests.InWindow(view, 1100, 700, () =>
        {
            var presenter = Assert.IsType<ContentControl>(view.FindName("RuleDetail"));
            var tabs = Assert.Single(Descendants<TabControl>(presenter));
            tabs.SelectedIndex = 1;
            Layout(view, 1100, 700);

            Assert.Contains(Descendants<TextBlock>(presenter), item => item.Text == "Required derived facts:");
            Assert.All(row.RequiredDerivedFacts, fact =>
                Assert.Contains(Descendants<TextBox>(presenter), item => item.Text == fact));
            Assert.Contains(Descendants<TextBox>(presenter), item => item.Text == row.Outcome);
        });
    });

    [Fact]
    public void UnknownRecordedRuleKeepsExplicitMissingGuidanceAndItsSavedOutcome() => OnSta(() =>
    {
        var source = Source();
        source.RuleExecutions = new(
            [new("SEC-999", 1, RuleExecutionOutcome.Error, 0, 0, 0, [], 0, "Recorded failure")],
            JudgementRunState.CompletedDegraded);
        var model = new RulesViewModel(source);
        model.Show(Bundle);
        var row = model.RuleRows.Single(rule => rule.Rule == "SEC-999");
        model.SelectedRule = row;
        var view = View(model);

        DashboardRedesignTests.InWindow(view, 1100, 700, () =>
        {
            var presenter = Assert.IsType<ContentControl>(view.FindName("RuleDetail"));
            var tabs = Assert.Single(Descendants<TabControl>(presenter));
            Assert.Contains(Descendants<TextBox>(presenter), item => item.Text == row.LooksFor && item.IsVisible);
            tabs.SelectedIndex = 1;
            Layout(view, 1100, 700);
            Assert.Contains(Descendants<TextBox>(presenter),
                item => item.Text == "This build has no input declaration for this recorded rule." && item.IsVisible);
            Assert.Contains(Descendants<TextBox>(presenter), item => item.Text == row.Outcome && item.IsVisible);
            Assert.Contains("Recorded failure", row.Outcome);
            tabs.SelectedIndex = 2;
            Layout(view, 1100, 700);
            Assert.Contains(Descendants<TextBox>(presenter),
                item => item.Text == "This build has no recorded scope or limitation guidance for this rule." && item.IsVisible);
            tabs.SelectedIndex = 3;
            Layout(view, 1100, 700);
            Assert.Contains(Descendants<TextBox>(presenter),
                item => item.Text == "This build has no recorded Microsoft reference for this rule." && item.IsVisible);
        });
    });

    [Fact]
    public void RenderedSeverityFilterDefaultsToAllWhenARunLoads() => OnSta(() =>
    {
        var source = Source();
        var model = new RulesViewModel(source);
        var view = View(model);

        DashboardRedesignTests.InWindow(view, 1100, 700, () =>
        {
            model.Show(Bundle);
            model.ReadCompletion.GetAwaiter().GetResult();
            Layout(view, 1100, 700);

            var severity = Assert.Single(Descendants<ComboBox>(view), item =>
                ReferenceEquals(item.ItemsSource, model.RuleSeverityChoices));
            Assert.Equal("All", severity.SelectedItem);
            Assert.Equal("All", model.RuleSeverityFilter);
            Assert.Equal(model.RuleRows.Count, model.VisibleRuleRows.Count);
            Assert.NotEmpty(model.VisibleRuleRows);

            model.RuleSeverityFilter = model.RuleSeverityChoices.First(choice => choice != "All");
            Assert.True(model.VisibleRuleRows.Count < model.RuleRows.Count);
            model.Show(@"C:\synthetic\rules-second");
            model.ReadCompletion.GetAwaiter().GetResult();
            Layout(view, 1100, 700);

            Assert.Equal("All", severity.SelectedItem);
            Assert.Equal("All", model.RuleSeverityFilter);
            Assert.Equal(model.RuleRows.Count, model.VisibleRuleRows.Count);
        });
    });

    [Fact]
    public async Task SelectedRuleIsClearedBeforeLoadingAnotherRunAndOnRefusal()
    {
        var source = Source();
        var model = new RulesViewModel(source);
        model.Show(Bundle);
        model.SelectedRule = model.RuleRows[^1];
        var old = model.SelectedRule;
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        source.CompleteRead = async (value, _) => { await completion.Task; return value; };
        model.Show(@"C:\synthetic\second");
        Assert.Null(model.SelectedRule);
        Assert.False(model.HasResults);
        completion.SetResult();
        await model.ReadCompletion;
        Assert.Same(model.RuleRows[0], model.SelectedRule);
        Assert.NotSame(old, model.SelectedRule);
        source.CompleteRead = null;
        source.RuleExecutionsFail = SecureAD.Kernel.AuditError.Create(SecureAD.Kernel.ErrorCategory.Shell,
            "SyntheticRefusal", SecureAD.Kernel.ErrorSeverity.Failed, "Saved rules could not be verified.", Bundle);
        model.Show(Bundle);
        Assert.True(model.HasRulesRefusal);
        Assert.Null(model.SelectedRule);
        Assert.Empty(model.RuleRows);
        model.Clear();
        Assert.Null(model.SelectedRule);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LeavingRulesCancelsAndWithholdsLateSuccessOrFailure(bool failure)
    {
        var source = Source();
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        CancellationToken tokenSeen = default;
        source.CompleteRead = async (value, token) =>
        {
            tokenSeen = token;
            await completion.Task;
            if (failure) throw new InvalidOperationException("late failure");
            return value;
        };
        var model = new RulesViewModel(source);
        model.Show(Bundle);
        Assert.True(model.IsLoading);
        Assert.False(model.HasResults);
        Assert.Empty(model.RuleRows);
        var pending = model.ReadCompletion;
        model.Suspend();
        completion.SetResult();
        await pending;
        Assert.True(tokenSeen.IsCancellationRequested);
        Assert.False(model.HasResults || model.HasRulesRefusal || model.IsLoading);
        Assert.Empty(model.RuleRows);
    }

    [Fact]
    public async Task ChangedGenerationIsRefusedAndNextRunDoesNotReuseRows()
    {
        var source = Source();
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        source.CompleteRead = async (value, _) => { await completion.Task; return value; };
        var model = new RulesViewModel(source);
        model.Show(Bundle);
        source.IsCurrent = false;
        completion.SetResult();
        await model.ReadCompletion;
        Assert.True(model.HasRulesRefusal);
        Assert.False(model.HasResults);
        Assert.Empty(model.RuleRows);
        source.CompleteRead = null;
        source.IsCurrent = true;
        model.Show(@"C:\synthetic\second");
        Assert.True(model.HasResults);
        Assert.False(model.HasRulesRefusal);
        Assert.Equal(2, source.RuleExecutionReads);
        model.Clear();
        Assert.Empty(model.RuleRows);
        Assert.True(model.HasNoRun);
    }

    private static string WhiteSpace(string text) => Regex.Replace(text, @"\s+", " ").Trim();
    private static Color ColorOf(Brush brush) => Assert.IsType<SolidColorBrush>(brush).Color;

    private static Border InformationCard(DependencyObject child, Style style)
    {
        for (var parent = VisualTreeHelper.GetParent(child); parent is not null; parent = VisualTreeHelper.GetParent(parent))
            if (parent is Border border && ReferenceEquals(border.Style, style))
                return border;
        throw new InvalidOperationException("The text has no separate information card.");
    }

    private static FakeAssetSource Source() => new()
    {
        RuleExecutions = new StoredRuleExecutions(
            [new("SEC-010", 1, RuleExecutionOutcome.Succeeded, 2101, 0, 0, [], 1, null)], JudgementRunState.Completed),
    };

    internal static UserControl View(RulesViewModel model)
    {
        XNamespace wpf = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        XNamespace xaml = "http://schemas.microsoft.com/winfx/2006/xaml";
        var shell = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell");
        var root = XDocument.Load(Path.Combine(shell, "Views", "RulesView.xaml")).Root!;
        root.Attribute(xaml + "Class")!.Remove();
        root.Attribute(xaml + "ClassModifier")!.Remove();
        var assembly = typeof(RulesViewModel).Assembly.GetName().Name;
        var originalResources = root.Element(wpf + "UserControl.Resources");
        var definitions = originalResources?.Elements().ToArray() ?? [];
        originalResources?.Remove();
        root.AddFirst(new XElement(wpf + "UserControl.Resources", new XElement(wpf + "ResourceDictionary",
            new XElement(wpf + "ResourceDictionary.MergedDictionaries",
                XDocument.Load(Path.Combine(shell, "App.xaml")).Descendants(wpf + "ResourceDictionary").Attributes("Source")
                    .Where(attribute => !attribute.Value.StartsWith("Views/", StringComparison.Ordinal))
                    .Select(attribute => new XElement(wpf + "ResourceDictionary", new XAttribute("Source",
                        attribute.Value.StartsWith("pack:", StringComparison.Ordinal) ? attribute.Value
                        : $"pack://application:,,,/{assembly};component/" + attribute.Value)))), definitions)));
        var view = (UserControl)XamlReader.Parse(root.ToString());
        view.DataContext = model;
        return view;
    }
}
