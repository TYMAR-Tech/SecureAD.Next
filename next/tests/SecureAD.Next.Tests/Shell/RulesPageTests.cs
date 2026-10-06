using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Markup;
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
        Assert.Equal(WhiteSpace(row.About), WhiteSpace(string.Join(" ", new[] { row.LooksFor }.Concat(row.ScopeNotes))));
        Assert.All(definition.RequiredAttributes, attribute => Assert.Contains(attribute, row.DeclaredEvidence));
        Assert.All(definition.RequiredDerivedFacts, fact => Assert.Contains(fact, row.DeclaredEvidence));
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
        Assert.Equal(fixture.Home.Library.Selected.Name, rules.RunName);
        Assert.Equal(1, source.RuleExecutionReads);
        Assert.Null(source.AskedFor);
        Assert.Equal(0, source.ObjectListings);
        shell.Show(ShellSection.Assets);
        Assert.DoesNotContain(shell.Views, view => view.Name == "Rules");
        Assert.Empty(rules.RuleRows);
        shell.ClearOpenedRun();
        Assert.True(rules.HasNoRun);
        Assert.Empty(rules.RunName);
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
        model.Show(Bundle, "Fictional run");
        var view = View(model);
        DashboardRedesignTests.InWindow(view, width, height, () =>
        {
            Assert.Empty(Descendants<TreeView>(view));
            Assert.Contains(Descendants<TextBlock>(view), text => text.Text == "Fictional run" && text.IsVisible);
            var list = Assert.Single(Descendants<ListBox>(view));
            Assert.Same(model.RuleRows[0], list.SelectedItem);
            Assert.Same(list.SelectedItem, model.SelectedRule);
            Assert.Equal(model.RuleRows.Count, list.Items.Count);
            var row = Assert.Single(model.RuleRows, item => item.Rule == "SEC-010");
            list.SelectedItem = row;
            Layout(view, width, height);
            var presenter = Assert.IsType<ContentControl>(view.FindName("RuleDetail"));
            Assert.Same(row, presenter.Content);
            Assert.NotEmpty(row.ScopeNotes);
            Assert.Empty(Descendants<Expander>(view));
            Assert.Contains(Descendants<TextBlock>(presenter), text => text.Text == row.Outcome && text.IsVisible);
            var summary = Assert.Single(Descendants<TextBox>(presenter), box => box.Text == row.LooksFor);
            summary.SelectAll();
            Assert.Equal(row.LooksFor, summary.SelectedText);
            Assert.All(row.ScopeNotes, note => Assert.Contains(Descendants<TextBox>(presenter), box => box.Text == note && box.ActualHeight > 0));
            Assert.Contains(Descendants<TextBox>(presenter), box => box.Text == row.DeclaredEvidence);
            Assert.Contains(Descendants<TextBox>(presenter), box => box.Text == row.MicrosoftReference);
            Assert.All(Descendants<TextBox>(presenter), box => Assert.Equal(TextWrapping.Wrap, box.TextWrapping));
            var detailScroll = Assert.Single(Descendants<ScrollViewer>(presenter), scroll => scroll.Name == "RuleExplanationScroll");
            var listScroll = Assert.Single(Descendants<ScrollViewer>(list));
            var listOffset = listScroll.VerticalOffset;
            detailScroll.ScrollToEnd();
            Layout(view, width, height);
            Assert.Equal(listOffset, listScroll.VerticalOffset);
            var next = Assert.Single(model.RuleRows, item => item.Rule == "SEC-011");
            list.SelectedItem = next;
            Layout(view, width, height);
            Assert.Same(next, presenter.Content);
            Assert.Contains(Descendants<TextBox>(presenter), box => box.Text == next.LooksFor);
            Assert.DoesNotContain(Descendants<TextBox>(presenter), box => box.Text == row.LooksFor);
            Assert.Equal(1, source.RuleExecutionReads);
            var splitter = Assert.Single(Descendants<GridSplitter>(view));
            var columns = Assert.IsType<Grid>(splitter.Parent).ColumnDefinitions;
            Assert.Equal(360, columns[0].ActualWidth, 3);
            splitter.RaiseEvent(new KeyEventArgs(Keyboard.PrimaryDevice, PresentationSource.FromVisual(view), 0, Key.Right)
                { RoutedEvent = Keyboard.KeyDownEvent });
            Layout(view, width, height);
            Assert.True(columns[0].ActualWidth > 360);
            Assert.True(presenter.ActualWidth >= 300);
        });
    });

    [Fact]
    public async Task SelectedRuleIsClearedBeforeLoadingAnotherRunAndOnRefusal()
    {
        var source = Source();
        var model = new RulesViewModel(source);
        model.Show(Bundle, "First");
        model.SelectedRule = model.RuleRows[^1];
        var old = model.SelectedRule;
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        source.CompleteRead = async (value, _) => { await completion.Task; return value; };
        model.Show(@"C:\synthetic\second", "Second");
        Assert.Null(model.SelectedRule);
        Assert.False(model.HasResults);
        completion.SetResult();
        await model.ReadCompletion;
        Assert.Same(model.RuleRows[0], model.SelectedRule);
        Assert.NotSame(old, model.SelectedRule);
        source.CompleteRead = null;
        source.RuleExecutionsFail = SecureAD.Kernel.AuditError.Create(SecureAD.Kernel.ErrorCategory.Shell,
            "SyntheticRefusal", SecureAD.Kernel.ErrorSeverity.Failed, "Saved rules could not be verified.", Bundle);
        model.Show(Bundle, "Refused");
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
        model.Show(Bundle, "First");
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
        model.Show(Bundle, "First");
        source.IsCurrent = false;
        completion.SetResult();
        await model.ReadCompletion;
        Assert.True(model.HasRulesRefusal);
        Assert.False(model.HasResults);
        Assert.Empty(model.RuleRows);
        source.CompleteRead = null;
        source.IsCurrent = true;
        model.Show(@"C:\synthetic\second", "Second");
        Assert.True(model.HasResults);
        Assert.False(model.HasRulesRefusal);
        Assert.Equal("Second", model.RunName);
        Assert.Equal(2, source.RuleExecutionReads);
        model.Clear();
        Assert.Empty(model.RuleRows);
        Assert.True(model.HasNoRun);
    }

    private static string WhiteSpace(string text) => Regex.Replace(text, @"\s+", " ").Trim();
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
