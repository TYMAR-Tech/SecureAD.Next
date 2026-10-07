using System.Collections.ObjectModel;
using System.ComponentModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace SecureAD.Shell.ViewModels;

/// <summary>
/// The window's own state: which section is showing, and what is showing in it.
/// </summary>
/// <remarks>
/// <para>
/// The root of the view model tree. It owns the sections rather than creating them, so that the
/// composition root decides what each is given and a test can hand them whatever it needs to
/// examine.
/// </para>
/// <para>
/// <b>Navigation is state, not a stack.</b> There is no history and no back: the product has three
/// places to be, and an operator moving between them is not performing a journey that could be
/// retraced. The audit surface has steps of its own, and those are its business rather than the
/// shell's.
/// </para>
/// <para>
/// <b>The audit is a surface here rather than a window of its own</b> -
/// <c>docs/decisions/0071-the-audit-is-modal-in-effect-not-in-its-own-window.md</c>. While it is
/// being planned this window is modal in effect: the rail can be seen and not used, so a
/// half-planned run cannot be left behind a rail button. Once a capture is running the rail comes
/// back, because a three-hour read is the thing an operator should be able to walk away from.
/// </para>
/// </remarks>
internal sealed partial class ShellViewModel : ObservableObject
{
    [ObservableProperty]
    private ShellSection _section = ShellSection.Home;

    private NewAuditViewModel? _audit;

    /// <summary>Creates the window's state over the sections it will show.</summary>
    /// <param name="home">Where the run library is chosen and a run is started from.</param>
    /// <param name="runs">The runs the library holds.</param>
    /// <param name="assets">What the selected run captured.</param>
    /// <param name="dashboard">How much of the forest the selected run read, and what it held.</param>
    /// <param name="settings">What this installation has been told.</param>
    /// <remarks>
    /// <b>The audit is not passed in.</b> It is handed over by <see cref="Begin"/> when the
    /// operator starts one from Home, and dropped by <see cref="Leave"/> when he leaves it, so that
    /// each opening plans a fresh run and nothing half-planned survives to be inherited by the
    /// next - which <c>docs/decisions/0057-starting-an-audit-is-a-modal-act.md</c> required of the
    /// window this replaced. There is still no <i>New Audit</i> rail entry: an audit is started
    /// from Home.
    /// </remarks>
    public ShellViewModel(
        HomeViewModel home, AssetsViewModel assets, DashboardViewModel dashboard,
        SettingsViewModel settings, RulesViewModel rules)
    {
        ArgumentNullException.ThrowIfNull(home);
        ArgumentNullException.ThrowIfNull(assets);
        ArgumentNullException.ThrowIfNull(dashboard);
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(rules);

        Home = home;
        Assets = assets;
        Dashboard = dashboard;
        Settings = settings;
        Rules = rules;
        Assets.PropertyChanged += OnAssetsPaneChanged;
        Assets.Suspend();
    }

    /// <summary>Where the run library is chosen, and where a run is started from.</summary>
    public HomeViewModel Home { get; }

    /// <summary>
    /// The runs this library holds.
    /// </summary>
    /// <remarks>
    /// <b>Reached through Home, which is the only screen that shows it.</b> There was a Runs
    /// section carrying a second copy of this surface until 2026-08-21; it showed the same object,
    /// so the two could not disagree, but every capability the library gained had to be built on
    /// both - and the name and notes editor was built on only one, which is the complaint that
    /// started this work. Home is where the operator works, so Home is the library.
    /// </remarks>
    public RunLibraryViewModel Library => Home.Library;

    /// <summary>What the run selected in the library captured.</summary>
    public AssetsViewModel Assets { get; }

    /// <summary>
    /// How much of the forest the selected run read, and what it held.
    /// </summary>
    /// <remarks>
    /// <b>It reads the same selected run as <see cref="Assets"/>, and holds no selection of its
    /// own.</b> Two screens over one run with two ideas of which run that is would eventually show
    /// an operator a coverage statement from one capture beside a tree from another.
    /// </remarks>
    public DashboardViewModel Dashboard { get; }
    public RulesViewModel Rules { get; }

    /// <summary>
    /// What this installation has been told.
    /// </summary>
    /// <remarks>
    /// <b>It holds no run and reads nothing from the library.</b> Everything on it describes this
    /// machine rather than a capture, which is why arriving here does not refresh anything and why
    /// it is the one section that is just as meaningful with no runs taken yet.
    /// </remarks>
    public SettingsViewModel Settings { get; }

    /// <summary>Whether the home section is the one showing.</summary>
    public bool IsHome => Section == ShellSection.Home;

    /// <summary>Whether the runs section is the one showing.</summary>
    /// <summary>Whether the assets section is the one showing.</summary>
    public bool IsAssets => Section == ShellSection.Assets;

    /// <summary>Whether the dashboard section is the one showing.</summary>
    public bool IsDashboard => Section == ShellSection.Dashboard;
    public bool IsRules => Section == ShellSection.Rules;

    /// <summary>Whether the settings section is the one showing.</summary>
    public bool IsSettings => Section == ShellSection.Settings;

    /// <summary>
    /// The views the showing section offers - the second row of tabs.
    /// </summary>
    /// <remarks>
    /// <b>Held rather than computed</b>, because a selection has to live somewhere: a property that
    /// built a fresh list on every read would hand the tabs a new set of objects each time and lose
    /// which one was chosen.
    /// </remarks>
    public ObservableCollection<SectionView> Views { get; } = [];

    /// <summary>Whether the showing section offers more than one view.</summary>
    /// <remarks>
    /// The second row is absent for a section with one view, rather than carrying a single tab that
    /// switches to where the operator already is.
    /// </remarks>
    public bool HasViews => Views.Count > 1;

    /// <summary>The view showing, or null when the section has none.</summary>
    public SectionView? SelectedView => Views.FirstOrDefault(v => v.IsSelected);

    /// <summary>What stands in for a section that is not built.</summary>
    /// <remarks>
    /// <para>
    /// <b>Nothing is in this list, and both departures are worth naming.</b> The dashboard left it
    /// on 2026-09-05 when stage 2 was built. Settings left it on 2026-09-13, when the screen behind
    /// the tab became real: it had stood here saying <i>"There is no settings screen yet. The one
    /// setting this product has - where your runs are kept - is chosen on Home"</i>, and every
    /// clause of that became false at once.
    /// </para>
    /// <para>
    /// <b>Kept rather than deleted, because the mechanism is still the honest answer for the next
    /// section.</b> What it guarantees is that a section with nothing behind it never renders an
    /// empty result - a run whose coverage cannot be established refuses rather than drawing zeroes,
    /// which is the reasoning that put it here in the first place and does not expire with the last
    /// occupant.
    /// </para>
    /// </remarks>
    private SectionView? AbsentSection => Section switch
    {
        _ => null,
    };

    /// <summary>The audit being planned or captured, or null when there is none.</summary>
    public NewAuditViewModel? Audit
    {
        get => _audit;
        private set
        {
            if (ReferenceEquals(_audit, value))
            {
                return;
            }

            // Watched rather than read once, because whether the rail is live turns on how far the
            // audit has got, and nothing else tells this window when that changed.
            if (_audit is not null)
            {
                _audit.PropertyChanged -= OnAuditChanged;
            }

            _audit = value;

            if (_audit is not null)
            {
                _audit.PropertyChanged += OnAuditChanged;
            }

            OnPropertyChanged(nameof(Audit));
            OnPropertyChanged(nameof(HasAudit));
            OnPropertyChanged(nameof(IsAudit));
            OnPropertyChanged(nameof(RailIsLive));
            OnPropertyChanged(nameof(ShowingAudit));
            OnPropertyChanged(nameof(Current));
        }
    }

    /// <summary>Whether there is an audit on the audit surface at all.</summary>
    public bool HasAudit => Audit is not null;

    /// <summary>Whether the audit surface is the one showing.</summary>
    public bool IsAudit => Section == ShellSection.Audit;

    /// <summary>
    /// Whether the rail may be used.
    /// </summary>
    /// <remarks>
    /// False only while an audit is being <i>planned</i>. That is the whole of what
    /// <c>docs/decisions/0057-starting-an-audit-is-a-modal-act.md</c> asked for and
    /// <c>0071</c> kept: an operator part-way through deciding what a run will read cannot leave
    /// the decision half-made. Once the capture is running, or has finished, the decision is behind
    /// him and the rail is his again.
    /// </remarks>
    public bool RailIsLive =>
        Audit is null || Audit.IsCapturing || Audit.HasFinished;

    /// <summary>
    /// Whether the audit is on screen, as a card over whatever section is behind it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// True while a run is being planned - there is nowhere else to be until it is started or
    /// discarded - and true afterwards whenever the operator comes back to it from the rail.
    /// </para>
    /// <para>
    /// <b>The card is how this product says "a distinct act", now that it does not say it with a
    /// window.</b> <c>docs/decisions/0057-starting-an-audit-is-a-modal-act.md</c> asked for an act
    /// with a beginning and an end;
    /// <c>docs/decisions/0071-the-audit-is-modal-in-effect-not-in-its-own-window.md</c> took away
    /// the second title bar that used to carry that meaning. Drawn as a page it read as a fourth
    /// place to be, which is what <c>0057</c> refused. A card over a dimmed shell reads as
    /// something opened on top of the product rather than somewhere inside it.
    /// </para>
    /// </remarks>
    public bool ShowingAudit => Audit is not null && (IsAudit || !RailIsLive);

    /// <summary>
    /// The section currently showing. The window binds one content control to this and lets a
    /// template choose the view, so the window does not hold a list of screens to hide and reveal.
    /// </summary>
    /// <remarks>
    /// <b>The audit is not here.</b> It is drawn over this rather than instead of it, so whatever
    /// the operator was looking at stays behind the scrim where he left it.
    /// </remarks>
    public object Current
    {
        get
        {
            if (AbsentSection is { } absent)
                return absent;

            if (SelectedView is { IsBuilt: false } notBuilt)
                return notBuilt;

            return Section switch
            {
                ShellSection.Assets => Assets,
                ShellSection.Dashboard => Dashboard,
                ShellSection.Rules => Rules,
                ShellSection.Settings => Settings,
                _ => Home,
            };
        }
    }

    /// <summary>Puts <paramref name="audit"/> on the audit surface and shows it.</summary>    /// <summary>
    /// Shows the run the operator has just opened from the library.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>It lands on the dashboard</b>, the owner's decision of 2026-09-05. An operator opening a
    /// run is asking <i>what am I looking at</i>, and a tree of eight thousand objects does not
    /// answer that: it shows the forest's contents without its size, its coverage, or whether the
    /// capture was complete.
    /// </para>
    /// <para>
    /// <b>Named here rather than written at the call site.</b> The composition root is the one
    /// place in this product no test constructs, so a product decision spelled out there is a
    /// decision nothing can hold. This is the same statement, somewhere a test can reach it.
    /// </para>
    /// <para>
    /// A run that would not open never arrives here. It has no sealed evidence to land in, and the
    /// library states what became of it instead.
    /// </para>
    /// </remarks>
    public void ShowOpenedRun() => Show(ShellSection.Dashboard);

    /// <summary>Puts <paramref name="audit"/> on the audit surface and shows it.</summary>
    /// <param name="audit">The freshly planned run.</param>
    public void Begin(NewAuditViewModel audit)
    {
        ArgumentNullException.ThrowIfNull(audit);

        Audit = audit;
        Show(ShellSection.Audit);
    }

    /// <summary>Leaves the audit surface, discarding whatever was on it.</summary>
    /// <remarks>
    /// The plan is dropped rather than kept for a later visit. A half-planned run found again days
    /// afterwards, in a state nobody remembers choosing, is what
    /// <c>docs/decisions/0057-starting-an-audit-is-a-modal-act.md</c> refused, and it is refused
    /// here for the same reason now that there is no window closing to enforce it.
    /// </remarks>
    public void Leave()
    {
        Audit = null;
        Show(ShellSection.Home);
    }

    /// <summary>Shows <paramref name="section"/>.</summary>
    /// <param name="section">The section to show.</param>
    [RelayCommand]
    public void Show(ShellSection section) => Section = section;

    internal void ClearOpenedRun()
    {
        Dashboard.Clear();
        Rules.Clear();
        Assets.Clear();
    }

    /// <summary>
    /// Builds the second row of tabs for a section, and selects the first view that works.
    /// </summary>
    /// <remarks>
    /// <b>The first built view, not simply the first.</b> Landing on a tab that says "not built"
    /// would make a section look unfinished when its real view is one click away.
    /// </remarks>
    private void RebuildViews(ShellSection section)
    {
        foreach (var view in Views)
            view.PropertyChanged -= OnViewChanged;

        Views.Clear();

        if (section == ShellSection.Assets)
        {
            Views.Add(SectionView.Built("Objects"));
            Views.Add(SectionView.Built("Findings"));
            Views.Add(SectionView.Built("Groups"));
            Views.Add(SectionView.Built("Tier 0"));
            Views.Add(SectionView.Built("LAPS"));
            Views.Add(SectionView.Built("Delegations"));
        }

        foreach (var view in Views)
            view.PropertyChanged += OnViewChanged;

        if (Views.FirstOrDefault(v => v.IsBuilt) is { } first)
            first.IsSelected = true;
    }

    /// <summary>
    /// Takes a view reporting itself selected as the view showing, and deselects the rest.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The exclusivity is enforced here and not left to the tabs.</b> Radio buttons deselect one
    /// another on screen, so this looked unnecessary - and it is not: with the previous view still
    /// marked selected in the model, <see cref="SelectedView"/> returned whichever came first in
    /// the list. Selecting <i>Findings</i> went on showing the objects grid, which is the object
    /// list presented under a Findings heading. A test caught it; nothing on the screen would have.
    /// </para>
    /// <para>
    /// Only a view becoming selected is acted on. Deselection arrives as its own change and would
    /// otherwise read as "nothing is selected" for an instant on every click.
    /// </para>
    /// </remarks>
    private void OnAssetsPaneChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(AssetsViewModel.Pane) || Section != ShellSection.Assets) return;
        var selected = Views.FirstOrDefault(view => string.Equals(view.Name, Assets.Pane == AssetsPane.Tier0 ? "Tier 0" : Assets.Pane.ToString(), StringComparison.OrdinalIgnoreCase));
        if (selected is not null && !selected.IsSelected) selected.IsSelected = true;
    }

    private void OnViewChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(SectionView.IsSelected)
            || sender is not SectionView { IsSelected: true } selected)
        {
            return;
        }

        foreach (var other in Views.Where(v => !ReferenceEquals(v, selected)))
            other.IsSelected = false;

        // The three views are one screen, so the tabs cannot choose between view models the way the
        // rail does. The screen is told which of its views is showing.
        Assets.Pane = selected.Name switch
        {
            "Findings" => AssetsPane.Findings,
            "Groups" => AssetsPane.Groups,
            "Tier 0" => AssetsPane.Tier0,
            "LAPS" => AssetsPane.Laps,
            "Delegations" => AssetsPane.Delegations,
            _ => AssetsPane.Objects,
        };

        OnPropertyChanged(nameof(SelectedView));
        OnPropertyChanged(nameof(Current));
    }

    private void OnAuditChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is not (nameof(NewAuditViewModel.IsCapturing)
            or nameof(NewAuditViewModel.HasFinished)))
        {
            return;
        }

        OnPropertyChanged(nameof(RailIsLive));
        OnPropertyChanged(nameof(ShowingAudit));
        OnPropertyChanged(nameof(Current));
    }

    partial void OnSectionChanged(ShellSection value)
    {
        // Rebuilding tabs must not start a read against the previous Assets selection.
        Assets.Suspend();
        Rules.Suspend();
        RebuildViews(value);

        OnPropertyChanged(nameof(IsHome));
        OnPropertyChanged(nameof(IsAssets));
        OnPropertyChanged(nameof(IsDashboard));
        OnPropertyChanged(nameof(IsRules));
        OnPropertyChanged(nameof(IsSettings));
        OnPropertyChanged(nameof(IsAudit));
        OnPropertyChanged(nameof(HasViews));
        OnPropertyChanged(nameof(SelectedView));
        OnPropertyChanged(nameof(ShowingAudit));
        OnPropertyChanged(nameof(Current));

        // Assets shows the run selected in the library, so arriving here must not refresh it:
        // a refresh discards the selection, and the screen would report no run chosen the instant
        // the operator asked to see one.
        if (value == ShellSection.Assets)
        {
            ShowAssetsOfTheSelectedRun();
            return;
        }

        // The dashboard shows the run selected in the library, for the same reason and with the
        // same caveat as Assets above.
        if (value == ShellSection.Dashboard)
        {
            ShowDashboardOfTheSelectedRun();
            return;
        }
        if (value == ShellSection.Rules)
        {
            if (Library.Selected is { } selected) Rules.Show(selected.Path, selected.Name);
            else Rules.Clear();
            return;
        }

        // Settings describes this machine, not a capture. There is nothing on it that a run could
        // make stale, so arriving here re-reads no library - which said "a section with nothing
        // behind it" until 2026-09-13, when the screen became real and the reason changed even
        // though the behaviour did not.
        if (value is ShellSection.Settings)
            return;

        // Home shows the library, so arriving there reads it. A run started since the operator was
        // last here would otherwise be missing from a screen that looks current.
        Library.Refresh();
    }

    /// <summary>
    /// Points the assets screen at whichever run is selected, or at nothing.
    /// </summary>
    /// <remarks>
    /// <b>Whether a capture is running is answered here and passed in.</b>
    /// <c>docs/decisions/0072-analysis-and-capture-do-not-run-at-the-same-time.md</c> is a rule
    /// about the product rather than about one screen, and this window is the only thing that
    /// knows. The assets screen is told; it does not go looking, which would mean a view model
    /// reaching for the state of a capture it has no part in.
    /// </remarks>
    private void ShowAssetsOfTheSelectedRun()
    {
        var selected = Library.Selected;

        if (selected is null)
        {
            Assets.Clear();
            return;
        }

        Assets.Show(selected.Path, aCaptureIsRunning: Audit is not null && Audit.IsCapturing);
    }

    /// <summary>
    /// Points the dashboard at whichever run is selected, or at nothing.
    /// </summary>
    /// <remarks>
    /// <b>It is not told whether a capture is running, unlike <see cref="Assets"/>.</b> The assets
    /// screen refuses a run being written to because its tree would be a half-written directory
    /// presented as a whole one. This screen reads a sealed bundle's coverage, and a run still
    /// capturing has none to read - so the evidence layer's own refusal is the accurate answer and
    /// a second rule here would be a second account of one condition.
    /// </remarks>
    private void ShowDashboardOfTheSelectedRun()
    {
        var selected = Library.Selected;

        if (selected is null)
        {
            Dashboard.Clear();
            return;
        }

        Dashboard.Show(selected.Path);
    }
}
