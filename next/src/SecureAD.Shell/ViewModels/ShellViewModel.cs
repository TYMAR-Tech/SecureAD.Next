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
    /// <remarks>
    /// <b>The audit is not passed in.</b> It is handed over by <see cref="Begin"/> when the
    /// operator starts one from Home, and dropped by <see cref="Leave"/> when he leaves it, so that
    /// each opening plans a fresh run and nothing half-planned survives to be inherited by the
    /// next - which <c>docs/decisions/0057-starting-an-audit-is-a-modal-act.md</c> required of the
    /// window this replaced. There is still no <i>New Audit</i> rail entry: an audit is started
    /// from Home.
    /// </remarks>
    public ShellViewModel(HomeViewModel home, AssetsViewModel assets)
    {
        ArgumentNullException.ThrowIfNull(home);
        ArgumentNullException.ThrowIfNull(assets);

        Home = home;
        Assets = assets;
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

    /// <summary>Whether the home section is the one showing.</summary>
    public bool IsHome => Section == ShellSection.Home;

    /// <summary>Whether the runs section is the one showing.</summary>
    /// <summary>Whether the assets section is the one showing.</summary>
    public bool IsAssets => Section == ShellSection.Assets;

    /// <summary>Whether the dashboard section is the one showing.</summary>
    public bool IsDashboard => Section == ShellSection.Dashboard;

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
    private SectionView? AbsentSection => Section switch
    {
        ShellSection.Dashboard => SectionView.NotBuilt(
            "Dashboard",
            "Rules are evaluated, but only by a tool run by hand outside this application, so "
            + "there is no posture for this screen to report. This tab is here to settle where "
            + "the dashboard will live, and it reports nothing about your directory."),
        ShellSection.Settings => SectionView.NotBuilt(
            "Settings",
            "There is no settings screen yet. The one setting this product has - where your runs "
            + "are kept - is chosen on Home."),
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
                _ => Home,
            };
        }
    }

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
            Views.Add(SectionView.NotBuilt(
                "Findings",
                "Rules are evaluated, but only by a tool run by hand outside this application, "
                + "so this application has no findings to show. This tab is here to settle where "
                + "they will live, and it reports nothing about your directory."));
            Views.Add(SectionView.NotBuilt(
                "LAPS",
                "Local administrator password status is not assessed yet. This tab is here to "
                + "settle where it will live, and it reports nothing about your directory."));
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
    private void OnViewChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(SectionView.IsSelected)
            || sender is not SectionView { IsSelected: true } selected)
        {
            return;
        }

        foreach (var other in Views.Where(v => !ReferenceEquals(v, selected)))
            other.IsSelected = false;

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
        RebuildViews(value);

        OnPropertyChanged(nameof(IsHome));
        OnPropertyChanged(nameof(IsAssets));
        OnPropertyChanged(nameof(IsDashboard));
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

        // A section with nothing behind it reads no library. There is nothing to be current about,
        // and re-reading the disk to show a panel saying "not built" would be work for nobody.
        if (value is ShellSection.Dashboard or ShellSection.Settings)
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
}
