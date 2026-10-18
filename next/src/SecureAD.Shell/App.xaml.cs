using System.Windows;
using SecureAD.Audit.Sysvol;
using SecureAD.Judgement;
using SecureAD.Shell.Services;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using SecureAD.Shell.Views;

namespace SecureAD.Shell;

/// <summary>
/// The application, and the one place allowed to assemble it.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the composition root, and it is the only code-behind permitted to hold any.</b>
/// Every other <c>.xaml.cs</c> file under <c>Views/</c> contains nothing but
/// <c>InitializeComponent</c>, enforced by <c>CodeBehindGateTests</c>. The rule exists because the
/// predecessor accumulated logic in views where it could not be tested and could not be found.
/// </para>
/// <para>
/// Concrete services are constructed here and handed to view models as interfaces. A view model
/// that could reach the file system or a directory server directly would be a view model that
/// cannot be tested without one.
/// </para>
/// </remarks>
internal partial class App : Application
{
    private readonly Func<IShellSettingsStore> _settingsStore;
    private readonly Action<AppStartupPoint> _startup;
    private readonly Action<ShellWindow, ShellViewModel> _prepared;
    private readonly IRunCatalog _catalog;
    private readonly Func<RunProtectionSessions, ICaptureLauncher> _capture;

    public App() : this(
        static () => new JsonShellSettingsStore(JsonShellSettingsStore.DefaultPath),
        static _ => { }, static (_, _) => { })
    {
    }

    internal App(Func<IShellSettingsStore> settingsStore, Action<AppStartupPoint> startup,
        Action<ShellWindow, ShellViewModel> prepared)
        : this(settingsStore, startup, prepared, new RunCatalog())
    {
    }

    internal App(Func<IShellSettingsStore> settingsStore, Action<AppStartupPoint> startup,
        Action<ShellWindow, ShellViewModel> prepared, IRunCatalog catalog)
        : this(settingsStore, startup, prepared, catalog, static protections => new CaptureLauncher(protections))
    {
    }

    internal App(Func<IShellSettingsStore> settingsStore, Action<AppStartupPoint> startup,
        Action<ShellWindow, ShellViewModel> prepared, IRunCatalog catalog, ICaptureLauncher capture)
        : this(settingsStore, startup, prepared, catalog, _ => capture)
    {
        ArgumentNullException.ThrowIfNull(capture);
    }

    private App(Func<IShellSettingsStore> settingsStore, Action<AppStartupPoint> startup,
        Action<ShellWindow, ShellViewModel> prepared, IRunCatalog catalog,
        Func<RunProtectionSessions, ICaptureLauncher> capture)
    {
        ArgumentNullException.ThrowIfNull(settingsStore);
        ArgumentNullException.ThrowIfNull(startup);
        ArgumentNullException.ThrowIfNull(prepared);
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(capture);
        _settingsStore = settingsStore;
        _startup = startup;
        _prepared = prepared;
        _catalog = catalog;
        _capture = capture;
    }

    /// <summary>Assembles the product and shows its window.</summary>
    /// <param name="e">The startup arguments.</param>
    protected override async void OnStartup(StartupEventArgs e)
    {
        if (SysvolWorker.IsInvocation(e.Args))
        {
            Shutdown(await SysvolWorker.RunAsync(e.Args));
            return;
        }

        _startup(AppStartupPoint.Entered);
        base.OnStartup(e);

        // ONE STORE, THREE SETTINGS. Run location, appearance and concurrency each own one field
        // and read the current record before writing, so changing one cannot erase the others.
        var settingsStore = _settingsStore();

        var appearance = new ApplicationTheme(settingsStore, new WpfThemeApplier(Resources));
        var location = new RunLibraryLocation(settingsStore);
        var concurrency = new DomainConcurrency(settingsStore);

        appearance.Load();
        location.Load();
        concurrency.Load();
        _startup(AppStartupPoint.SettingsLoaded);

        // One launcher, shared by nothing else: the audit surface is the only place that plans,
        // checks or starts a run. Home chooses the library and starts an audit on it.
        //
        // The audit is handed to the service as a FACTORY rather than as an instance, so each
        // opening plans a fresh run and leaving discards it - 0057, kept by 0071 now that there is
        // no window closing to enforce it. A single shared instance would leave a half-planned run
        // to be found later in a state nobody remembers choosing.
        //
        // Both the service and the shell are referred to from inside lambdas that construct the
        // other. Neither lambda runs until an audit is started, by which time both variables are
        // assigned.
        NewAuditDialog newAudit = null!;
        ShellViewModel shell = null!;
        RunLibraryViewModel library = null!;

        // ONE STATEMENT OF WHAT AN ANALYSIS IS, shared by both doors onto it. The audit window
        // derives and judges straight after a capture; the run library does the same later, for a
        // run captured without them. Constructing a launcher at each door would be two policies
        // free to disagree - and the requester policy is what decides how far a judging looks, so
        // the same bundle would be judged differently depending on which screen asked.
        //
        // Sharing the instances is safe where sharing a NewAuditViewModel is not: a launcher holds
        // no half-planned run, only the decision about what a production analysis does.
        //
        // The shared requester policy does not activate the separate legacy membership scan.
        // That scan still needs its own measured and approved processing limit.
        var protections = new RunProtectionSessions();
        var capturing = _capture(protections);
        var deriving = new DerivationLauncher(protections);
        var judging = new JudgingLauncher(
            discoveryBudget: null, requesterPolicy: JudgingRun.ProductionPathRequesterPolicy, protections);

        var assets = new BundleAssetSource(protections, verifyOnSelect: true);
        Task CloseOpenedRun()
        {
            protections.ReleaseHandoff();
            var closed = assets.CloseRunAsync();
            shell.ClearOpenedRun();
            return closed;
        }

        // The wizard opens the run it has just captured, which the library has never listed - it
        // was written after the last read. So this opener adopts the run (read again, select that
        // path) before navigating, where the library's own opener below must not: refreshing there
        // would discard the selection the operator just made.
        newAudit = new NewAuditDialog(
            () => new NewAuditViewModel(
                location,
                capturing,
                newAudit,
                new RunOpener(path => shell.OpenCompletedRunAsync(path), CloseOpenedRun),
                deriving,
                judging,
                concurrency),
            audit => shell.Begin(audit),
            () => shell.Leave());

        // One library object. Home is the only screen that shows it.
        library = new RunLibraryViewModel(
            location,
            _catalog,
            new Confirmation(),
            // Moving to a section already opens whichever run is selected - ShellViewModel does it
            // on arrival, and it knows whether a capture is running, which this does not. So Open
            // navigates and lets that one path do the reading, rather than being a second door
            // onto it that would have to be kept in step.
            //
            // It lands wherever ShellViewModel.ShowOpenedRun says, which is where that product
            // decision is written down and tested. Restating it here would be a second answer.
            new RunOpener(_ =>
            {
                shell.ShowOpenedRun();
                return Task.CompletedTask;
            }, CloseOpenedRun),
            deriving,
            judging);

        // One asset source for both screens, not one each. It holds the opened bundle so the seal
        // is verified once when the operator arrives at a run; two of them would re-hash gigabytes
        // of evidence every time he moved between the dashboard and the tree.
        shell = new ShellViewModel(
            new HomeViewModel(location, new FolderPicker(), newAudit, library),
            new AssetsViewModel(assets),
            new DashboardViewModel(assets),
            new SettingsViewModel(concurrency, appearance),
            new RulesViewModel(assets));
        _startup(AppStartupPoint.ModelsComposed);

        var window = new ShellWindow { DataContext = shell };
        window.Closed += (_, _) =>
        {
            library.CancelRefresh();
            assets.Dispose();
            protections.Dispose();
        };
        _ = new ObjectDetailPresenter(shell.Assets, window);
        _prepared(window, shell);
        window.Show();
        _startup(AppStartupPoint.WindowShown);

        _startup(AppStartupPoint.LibraryRefreshStarting);
        await library.RefreshAsync();
        _startup(AppStartupPoint.LibraryRefreshCompleted);
    }
}
