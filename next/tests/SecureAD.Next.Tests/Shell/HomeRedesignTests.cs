using System.Globalization;
using System.Windows;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Markup;
using System.Windows.Media;
using System.Xml.Linq;
using SecureAD.Evidence.Run;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Shell.ObjectNavigationViewTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class HomeRedesignTests
{
    [Theory]
    [InlineData(1280, 800)]
    [InlineData(1920, 1080)]
    [InlineData(900, 700)]
    public void HomeKeepsTheLibraryAndOpenActionReadableWithoutOpeningOnSelection(int width, int height) => OnSta(() =>
    {
        var fixture = Model();
        var home = fixture.Home;
        var view = View(home);
        DashboardRedesignTests.InWindow(view, width, height, () =>
        {
            var table = Assert.Single(Descendants<DataGrid>(view));
            Assert.Equal(new[] { "Run", "When (local time)", "Capture", "Analysis" }, table.Columns.Select(column => column.Header));
            Assert.All(table.Columns, column => Assert.False(column.Width.IsStar));
            Assert.True(table.ActualHeight >= 180);
            Assert.Equal(2, home.Library.RunsView.Groups!.Count);
            var scope = Assert.Single(Descendants<TextBlock>(table), text => text.Text == home.Library.Runs[0].GroupHeading);
            Assert.True(scope.IsVisible);
            Assert.Equal(((SolidColorBrush)view.FindResource("AttributeLabelBrush")).Color,
                Assert.IsType<SolidColorBrush>(scope.Foreground).Color);
            Assert.Contains(Descendants<TextBlock>(view), text => text.Text == "Capture once. Investigate offline." && text.IsVisible);
            Assert.Contains(Descendants<TextBlock>(table), text => text.Text == "Baseline");
            table.SelectedItem = home.Library.Runs[1];
            Layout(view, width, height);
            Assert.Equal(home.Library.Runs[1], home.Library.Selected);
            Assert.Null(fixture.Opener.Opened);
            var open = Button(view, home.Library.OpenRunCommand);
            Assert.True(open.IsVisible && open.IsEnabled);
            Assert.True(open.ActualWidth >= 180);
            Assert.All(Descendants<Expander>(view), expander => Assert.False(expander.IsExpanded));
            Assert.Null(Ancestor<Expander>(open));
            Invoke(open);
            Assert.Equal(home.Library.Selected!.Path, fixture.Opener.Opened);
            var names = Assert.Single(Descendants<TextBox>(view), box =>
                BindingOperations.GetBinding(box, TextBox.TextProperty)?.Path.Path == "Library.TypedName");
            Assert.Equal(home.Library.TypedName, names.Text);
            var right = Assert.IsType<ScrollViewer>(Ancestor<ScrollViewer>(open));
            Assert.True(right.ActualWidth >= 280);
            Assert.NotEqual(Colors.White, Assert.IsType<SolidColorBrush>(view.Background).Color);
        });
    });

    [Fact]
    public void RunDatesPreserveLocalTimeAndUnrecordedDateQualification() => OnSta(() =>
    {
        var fixture = Model();
        var model = fixture.Home;
        var view = View(model);
        DashboardRedesignTests.InWindow(view, 1280, 900, () =>
        {
            var row = model.Library.Runs[0];
            var moment = fixture.Catalog.Runs[0].Moment.Utc.ToLocalTime();
            Assert.Equal(moment.ToString("dd MMM yyyy", CultureInfo.CurrentCulture), row.WhenDate);
            Assert.Equal(moment.ToString("t", CultureInfo.CurrentCulture), row.WhenTime);
            Assert.Contains(Descendants<TextBlock>(view), text => text.Text == row.WhenDate);
            Assert.Contains(Descendants<TextBlock>(view), text => text.Text == row.WhenTime);
            Assert.Contains(Descendants<TextBlock>(view), text => text.Text == "folder date - the run recorded none" && text.IsVisible);
            var table = Assert.Single(Descendants<DataGrid>(view));
            table.SelectedItem = model.Library.Runs[^1];
            Layout(view, 1280, 900);
            Assert.False(Button(view, model.Library.OpenRunCommand).IsEnabled);
            Assert.Contains(Descendants<TextBlock>(view), text => text.Text == "Interrupted" && text.IsVisible);
            Assert.Contains(Descendants<TextBlock>(view), text => text.Text == "Not established" && text.IsVisible);
        });
    });

    [Fact]
    public void AnnotationAndDestructiveActionsKeepTheirExistingCommandsAndConfirmations() => OnSta(() =>
    {
        var fixture = Model();
        var model = fixture.Home;
        var view = View(model);
        DashboardRedesignTests.InWindow(view, 1280, 950, () =>
        {
            model.Library.Selected = model.Library.Runs[0];
            Layout(view, 1280, 950);
            var name = Assert.Single(Descendants<TextBox>(view), box =>
                BindingOperations.GetBinding(box, TextBox.TextProperty)?.Path.Path == "Library.TypedName");
            name.Text = "My renamed run";
            name.GetBindingExpression(TextBox.TextProperty)!.UpdateSource();
            var save = Button(view, model.Library.SaveAnnotationCommand);
            Invoke(save);
            Assert.Equal("My renamed run", fixture.Catalog.Annotated!.Value.Annotation.Name);
            Assert.Null(fixture.Catalog.Deleted);
            var actions = Assert.Single(Descendants<Expander>(view), item => Equals(item.Header, "Run actions"));
            actions.IsExpanded = true;
            Layout(view, 1280, 950);
            var delete = Button(view, model.Library.DeleteRunCommand);
            var rejudge = Button(view, model.Library.DiscardJudgementAndJudgeAgainCommand);
            Assert.Same(actions, Ancestor<Expander>(delete));
            Assert.Same(actions, Ancestor<Expander>(rejudge));
            Assert.Null(Ancestor<Expander>(save));
            Invoke(delete);
            Assert.NotNull(fixture.Confirmation.Asked);
            Assert.Null(fixture.Catalog.Deleted);
            Assert.NotNull(Button(view, model.Library.MarkAsBaselineCommand));
        });
    });

    [Fact]
    public void AnalysisStatusAndStopRemainOutsideSelectedRunAndCollapsedActions() => OnSta(() =>
    {
        var fixture = Model();
        var model = fixture.Home;
        var view = View(model);
        DashboardRedesignTests.InWindow(view, 1280, 850, () =>
        {
            model.Library.Selected = model.Library.Runs[1];
            var observed = false;
            var stopVisible = false;
            var stopEnabled = false;
            var stopOutsideDisclosure = false;
            var statusVisible = false;
            var statusText = "";
            fixture.Deriving.WhileRunning = () =>
            {
                model.Library.Selected = null;
                Layout(view, 1280, 850);
                var stop = Button(view, model.Library.StopAnalysisCommand);
                stopVisible = stop.IsVisible;
                stopEnabled = stop.IsEnabled;
                stopOutsideDisclosure = Ancestor<Expander>(stop) is null;
                var status = Assert.Single(Descendants<TextBox>(view), box =>
                    BindingOperations.GetBinding(box, TextBox.TextProperty)?.Path.Path == "Library.AnalysisStatus");
                statusVisible = status.IsVisible;
                statusText = status.Text;
                observed = true;
                Invoke(stop);
            };
            model.Library.DeriveFactsCommand.Execute(null);
            Layout(view, 1280, 850);
            Assert.True(observed && stopVisible && stopEnabled && stopOutsideDisclosure && statusVisible);
            Assert.Contains("Awaiting analysis", statusText);
            Assert.Contains("stopped", model.Library.AnalysisStatus, StringComparison.OrdinalIgnoreCase);
            Assert.True(fixture.Deriving.WasRun);
            Assert.False(model.Library.IsAnalysing);
            Assert.True(model.Library.HasAnalysisStatus);
        });
    });

    [Fact]
    public void LibraryFailureIsVisibleWithoutSelectionAndCannotLookEmpty() => OnSta(() =>
    {
        var fixture = Model();
        fixture.Catalog.Fails = Failures.Any("Library disk is unavailable.");
        fixture.Home.Library.Refresh();
        var view = View(fixture.Home);
        DashboardRedesignTests.InWindow(view, 1200, 800, () =>
        {
            Assert.Null(fixture.Home.Library.Selected);
            Assert.False(fixture.Home.Library.IsEmpty);
            Assert.True(fixture.Home.Library.HasProblem);
            Assert.Contains(Descendants<TextBox>(view), box => box.Text == "Library disk is unavailable." && box.IsVisible);
            fixture.Catalog.Fails = null;
            fixture.Catalog.Runs.Clear();
            fixture.Home.Library.Refresh();
            Layout(view, 1200, 800);
            Assert.False(fixture.Home.Library.HasProblem);
            Assert.True(fixture.Home.Library.IsEmpty);
            Assert.Contains(Descendants<TextBlock>(view), text => text.Text == "This run library holds no runs yet." && text.IsVisible);
        });
    });

    [Fact]
    public void UnconfiguredHomeKeepsNewAuditDisabledUntilLibraryChoice() => OnSta(() =>
    {
        var fixture = Model(chosen: false);
        var model = fixture.Home;
        var view = View(model);
        DashboardRedesignTests.InWindow(view, 1200, 800, () =>
        {
            Assert.False(Button(view, model.NewAuditCommand).IsEnabled);
            fixture.Picker.Answer = @"C:\synthetic-home";
            Invoke(Button(view, model.ChooseLibraryCommand));
            Layout(view, 1200, 800);
            Assert.True(fixture.Picker.WasAsked);
            Assert.True(Button(view, model.NewAuditCommand).IsEnabled);
            Assert.Equal(0, fixture.Audit.TimesOpened);
            Invoke(Button(view, model.NewAuditCommand));
            Assert.Equal(1, fixture.Audit.TimesOpened);
        });
    });

    [Fact]
    public void NewStatusVisibilityPropertiesNotifyWhenMessagesChange()
    {
        var model = Model().Home.Library;
        var notifications = new List<string?>();
        model.PropertyChanged += (_, args) => notifications.Add(args.PropertyName);
        model.Problem = "Problem";
        model.AnalysisStatus = "Run A is deriving";
        Assert.True(model.HasProblem && model.HasAnalysisStatus);
        Assert.Contains(nameof(model.HasProblem), notifications);
        Assert.Contains(nameof(model.HasAnalysisStatus), notifications);
        model.Problem = null;
        model.AnalysisStatus = "";
        Assert.False(model.HasProblem || model.HasAnalysisStatus);
    }

    internal sealed record Fixture(HomeViewModel Home, FakeRunCatalog Catalog, FakeConfirmation Confirmation,
        FakeRunOpener Opener, FakeFolderPicker Picker, FakeNewAuditDialog Audit, FakeDerivationLauncher Deriving);

    internal static Fixture Model(bool chosen = true)
    {
        var settings = new FakeSettingsStore { Stored = new ShellSettings(chosen ? @"C:\synthetic-home" : null, null) };
        var location = new RunLibraryLocation(settings);
        location.Load();
        var catalog = new FakeRunCatalog();
        var moment = new RunMoment(new DateTimeOffset(2026, 10, 5, 9, 33, 0, TimeSpan.Zero), true);
        var scope = RunScope.Of("synthetic-forest-scope", [DomainCoverage.Read("contoso.example"), DomainCoverage.Read("emea.contoso.example")]);
        catalog.Runs.Add(new("contoso-20261005-053318", @"C:\synthetic-home\judged", RunState.Sealed, null, moment,
            new("October review", "Fictional review notes.", true), scope, new(true, true)));
        catalog.Runs.Add(new("capture-only", @"C:\synthetic-home\capture-only", RunState.Sealed, null, moment,
            new("Awaiting analysis", null, false), scope, new(false, false)));
        catalog.Runs.Add(new("interrupted", @"C:\synthetic-home\interrupted", RunState.Interrupted, "Check the capture host.",
            moment with { Recorded = false }, RunAnnotation.None, null, new(false, false)));
        var confirmation = new FakeConfirmation();
        var opener = new FakeRunOpener();
        var picker = new FakeFolderPicker();
        var audit = new FakeNewAuditDialog();
        var deriving = new FakeDerivationLauncher();
        var library = new RunLibraryViewModel(location, catalog, confirmation, opener, deriving, new FakeJudgingLauncher());
        var home = new HomeViewModel(location, picker, audit, library);
        library.Refresh();
        if (library.Runs.Count != 0) library.Selected = library.Runs[0];
        return new(home, catalog, confirmation, opener, picker, audit, deriving);
    }

    internal static UserControl View(HomeViewModel model)
    {
        XNamespace wpf = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";
        XNamespace xaml = "http://schemas.microsoft.com/winfx/2006/xaml";
        var shell = Path.Combine(Architecture.RebuildTree.Root(), "src", "SecureAD.Shell");
        var root = XDocument.Load(Path.Combine(shell, "Views", "HomeView.xaml")).Root!;
        root.Attribute(xaml + "Class")!.Remove();
        root.Attribute(xaml + "ClassModifier")!.Remove();
        var assembly = typeof(HomeViewModel).Assembly.GetName().Name;
        root.AddFirst(new XElement(wpf + "UserControl.Resources", new XElement(wpf + "ResourceDictionary",
            new XElement(wpf + "ResourceDictionary.MergedDictionaries",
                XDocument.Load(Path.Combine(shell, "App.xaml")).Descendants(wpf + "ResourceDictionary").Attributes("Source")
                    .Where(attribute => !attribute.Value.StartsWith("Views/", StringComparison.Ordinal))
                    .Select(attribute => new XElement(wpf + "ResourceDictionary", new XAttribute("Source",
                        attribute.Value.StartsWith("pack:", StringComparison.Ordinal) ? attribute.Value
                        : $"pack://application:,,,/{assembly};component/" + attribute.Value)))))));
        var view = (UserControl)XamlReader.Parse(root.ToString());
        view.DataContext = model;
        return view;
    }

    private static Button Button(DependencyObject view, System.Windows.Input.ICommand command) =>
        Assert.Single(Descendants<Button>(view), button => ReferenceEquals(command, button.Command));

    private static T? Ancestor<T>(DependencyObject value) where T : DependencyObject
    {
        for (var parent = VisualTreeHelper.GetParent(value); parent is not null; parent = VisualTreeHelper.GetParent(parent))
            if (parent is T match) return match;
        return null;
    }

    private static void Invoke(Button button)
    {
        ((IInvokeProvider)new ButtonAutomationPeer(button).GetPattern(PatternInterface.Invoke)!).Invoke();
        System.Windows.Threading.Dispatcher.CurrentDispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.ContextIdle);
    }
}
