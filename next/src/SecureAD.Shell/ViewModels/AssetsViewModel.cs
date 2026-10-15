using System.IO;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Shell.Services;

namespace SecureAD.Shell.ViewModels;

/// <summary>
/// The assets of one run: the directory as its evidence can rebuild it, and the objects in
/// whichever part of it the operator selected.
/// </summary>
/// <remarks>
/// <para>
/// <b>Four silences are kept apart, because collapsing them would mislead.</b> No run chosen is a
/// question the operator has not answered. A capture running is a refusal with a remedy - wait. A
/// bundle that would not open is a failure they need to see, in the words the evidence layer used.
/// A container read that holds nothing is an empty container, which is a claim. Showing an empty
/// list for all four would say <i>there is nothing here</i> in three cases where that is not known
/// to be true, which is <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> exactly.
/// </para>
/// <para>
/// <b>The selected container and the level belong to the section, not to the grid.</b> The
/// predecessor scoped both its object list and its findings by the container selected in the tree,
/// and this product will do the same. Holding that state here means a findings list added later
/// reads the same selection rather than keeping a second one that can disagree with it.
/// </para>
/// <para>
/// <b>Nothing here reports a finding.</b> No risk, no severity, no verdict about any object -
/// nothing in this product computes one yet, and a column an administrator reads as a security
/// judgement, filled by nothing, is the worst thing this screen could do
/// (<c>docs/decisions/0045</c>).
/// </para>
/// </remarks>
internal sealed partial class AssetsViewModel : ObservableObject
{
    private readonly IAssetSource _assets;
    private CancellationTokenSource? _pending;
    private long _revision;
    private bool _active = true;
    private bool _resetting;
    private bool _listingReady;
    private Func<bool>? _filterValidity;
    private DirectoryTree? _retainedTree;
    private Func<bool>? _treeCurrent;

    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private string _loadingText = "";
    [ObservableProperty] private Notice? _viewRefusal;

    /// <summary>The current navigation read, including its publication on the screen.</summary>
    public Task ReadCompletion { get; private set; } = Task.CompletedTask;

    /// <summary>Whether the content area explains why the requested view could not be read.</summary>
    public bool HasViewRefusal => ViewRefusal is not null;

    /// <summary>Whether the visible listing has an answer, rather than a pending or refused read.</summary>
    public bool HasListingResult => _listingReady && !IsLoading && !HasViewRefusal;

    /// <summary>Whether the first captured tree is still being read.</summary>
    public bool IsOpeningTree => IsLoading && !HasLooked;

    [ObservableProperty]
    private string? _bundlePath;

    [ObservableProperty]
    private bool _hasLooked;

    [ObservableProperty]
    private Notice? _refusal;

    [ObservableProperty]
    private TreeNodeViewModel? _selected;

    /// <summary>
    /// The finding whose explanation and guidance the screen is showing.
    /// </summary>
    /// <remarks>
    /// <b>A property rather than the collection's current item.</b> A view binding through the
    /// current-item path is a binding <c>ViewBindingGateTests</c> cannot resolve, and an unheld
    /// binding is how this shell once crashed with the build green. This is the same shape the run
    /// library and the object sections already use for a selected row.
    /// </remarks>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelectedFinding))]
    private FindingRowViewModel? _selectedFinding;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasTier0Summary))]
    private string _tier0SummaryText = "";

    public string Tier0SummaryHeading { get; } = SavedPathText.Get("SummaryHeading");
    public bool HasTier0Summary => !string.IsNullOrEmpty(Tier0SummaryText);

    [ObservableProperty]
    private ListingScope _scope = ListingScope.Subtree;

    [ObservableProperty]
    private int _pageNumber = 1;

    [ObservableProperty]
    private int _total;

    [ObservableProperty]
    private string? _shortfall;

    /// <summary>
    /// Why there are no findings to show, or null when there are or when none were expected.
    /// </summary>
    /// <remarks>
    /// <b>Held apart from <see cref="Refusal"/>, which is about the evidence.</b> A bundle can be
    /// read perfectly and have no judgement beside it, and telling an operator his evidence could
    /// not be opened when the truth is that nobody has judged it would send him to fix the wrong
    /// thing.
    /// </remarks>
    [ObservableProperty]
    private Notice? _findingsRefusal;

    /// <summary>
    /// Whether the rules ran over this bundle and found nothing.
    /// </summary>
    /// <remarks>
    /// <b>Not the same as an empty grid, and the difference is the product.</b> No findings because
    /// every rule ran and matched nothing is a clean forest. No findings because nobody judged the
    /// bundle is silence. Both draw an empty table, so the screen must say which it is in words.
    /// </remarks>
    [ObservableProperty]
    private bool _nothingWasFound;

    /// <summary>
    /// Which of this screen's views is showing.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Told by the window rather than discovered here.</b> All three views are this one screen,
    /// and which of them is showing is a fact about the tabs - which belong to the shell. A view
    /// model that reached for the shell's selected tab would be a screen deciding the application's
    /// navigation, which is what <c>IRunOpener</c> exists to avoid one level up.
    /// </para>
    /// <para>
    /// <b>An enum where there were two booleans, because there are now three views.</b> The pair
    /// worked while one was the negation of the other; a third would have made the two flags able
    /// to describe a state that is not a view - both false, or both true - and nothing would have
    /// said which was on screen.
    /// </para>
    /// </remarks>
    [ObservableProperty]
    private AssetsPane _pane;

    /// <summary>Whether the findings are the view showing.</summary>
    public bool ShowsFindings => Pane is AssetsPane.Findings;

    /// <summary>Whether the object listing is the view showing.</summary>
    /// <remarks>
    /// Its own answer rather than the negation of anything, for the reason
    /// <see cref="HasNoRun"/> gives: a view cannot negate a binding without a converter.
    /// </remarks>
    public bool ShowsObjects => Pane is AssetsPane.Objects;

    /// <summary>Whether the LAPS inventory is the view showing.</summary>
    public bool ShowsLaps => Pane is AssetsPane.Laps;

    /// <summary>
    /// Whether the object grid should be on screen: the objects tab, and no object opened from it.
    /// </summary>
    /// <remarks>
    /// Both conditions together here rather than two bindings in the view, because a view that
    /// combines them is a view holding a rule about what is visible when - and the day a third
    /// condition arrives it is edited in a place no test reads.
    /// </remarks>
    public bool ShowsObjectListing => ShowsObjects && ShowsListing && HasListingResult;

    /// <summary>Whether the findings grid should be on screen.</summary>
    public bool ShowsFindingsListing => ShowsFindings && ShowsListing && HasListingResult;

    /// <summary>Whether the LAPS inventory grid should be on screen.</summary>
    public bool ShowsLapsListing => ShowsLaps && ShowsListing && HasListingResult;

    /// <summary>The severities a finding on this run actually has, worst first.</summary>
    /// <remarks>
    /// <b>Read from the judgement rather than listed here.</b> A fixed list offers Critical whether
    /// or not anything is critical, and an operator who picks it and gets an empty grid has learned
    /// only to distrust the control.
    /// </remarks>
    public ObservableCollection<string> Severities { get; } = [];

    /// <summary>The rules that found something on this run.</summary>
    public ObservableCollection<string> Rules { get; } = [];

    /// <summary>
    /// What every filter reads when nothing is chosen.
    /// </summary>
    /// <remarks>
    /// A word rather than an empty entry, because a blank first row in a list reads as a missing
    /// value rather than as a deliberate choice not to narrow anything.
    /// </remarks>
    public const string Any = "Any";

    /// <summary>The severity the grid is narrowed to, or <see cref="Any"/>.</summary>
    /// <remarks>
    /// Named for the filter rather than for the thing, because a property called
    /// <c>Severity</c> on this screen would shadow the type of the same name and force every use
    /// of it to be spelled out.
    /// </remarks>
    [ObservableProperty]
    private string _severityFilter = Any;

    /// <summary>The rule the grid is narrowed to, or <see cref="Any"/>.</summary>
    [ObservableProperty]
    private string _ruleFilter = Any;

    /// <summary>Whether any filter is narrowing the grid.</summary>
    public bool IsFiltered => SeverityFilter != Any || RuleFilter != Any;

    /// <summary>
    /// Why the findings grid is empty when the rules ran and matched nothing.
    /// </summary>
    /// <remarks>
    /// <b>A filtered grid and an unfiltered one are making different claims.</b> Empty with no
    /// filter says the rules found nothing here, which is about the directory. Empty with a filter
    /// says nothing matched what was asked for, which is about the question - and stating the first
    /// while the second is true would tell an operator his container is clean when he has narrowed
    /// to one severity that happens to be absent.
    /// </remarks>
    public string NothingFoundReason => IsFiltered
        ? "Nothing here matches the filters. The rules ran; what they found is outside what you "
          + "have asked for."
        : "The rules ran over this container and none of them found anything.";

    /// <summary>Where the findings page being shown ended, so the next can start after it.</summary>
    private FindingsPageMark? _findingsFrom;

    /// <summary>Where each page shown so far began, so the operator can go back.</summary>
    /// <remarks>
    /// <b>Keyset paging goes forward.</b> A page knows where it ended, not where the one before it
    /// began, so stepping back means remembering. The alternative is an offset, which is the cost
    /// this paging exists to avoid.
    /// </remarks>
    private readonly Stack<FindingsPageMark?> _findingsBack = new();

    /// <summary>
    /// The object the operator opened from the listing, or null while the listing is showing.
    /// </summary>
    /// <remarks>
    /// The detached presentation shares this run's protected source, but not the listing's
    /// cancellation or selection. Main-window navigation must not replace the object being read.
    /// </remarks>
    [ObservableProperty]
    private ObjectViewModel? _opened;

    private bool _captureIsRunning;

    /// <summary>Creates the assets screen's state.</summary>
    /// <param name="assets">How a bundle's tree and objects are read.</param>
    public AssetsViewModel(IAssetSource assets)
    {
        ArgumentNullException.ThrowIfNull(assets);

        _assets = assets;
    }

    /// <summary>The containers at the top of the tree - the partitions the run read.</summary>
    public ObservableCollection<TreeNodeViewModel> Roots { get; } = [];

    /// <summary>Everything the tree does not show, and why.</summary>
    public ObservableCollection<TreeGapViewModel> Gaps { get; } = [];

    /// <summary>The objects on the page being shown.</summary>
    public ObservableCollection<ListedObjectViewModel> Objects { get; } = [];

    /// <summary>The findings on the page being shown.</summary>
    public ObservableCollection<FindingRowViewModel> Findings { get; } = [];

    /// <summary>The computers on the page of the LAPS inventory being shown.</summary>
    public ObservableCollection<LapsComputerViewModel> LapsComputers { get; } = [];

    /// <summary>
    /// How many computers are in each LAPS state across the whole listing, not this page.
    /// </summary>
    /// <remarks>
    /// <b>The counts are what an operator watching a rollout actually reads.</b> A page of a
    /// hundred rows says little about an estate; <i>412 not managed against 1,908 managed</i> says
    /// whether the deployment is working.
    /// </remarks>
    public ObservableCollection<LapsCountViewModel> LapsCounts { get; } = [];

    /// <summary>How many computers the whole LAPS listing holds.</summary>
    [ObservableProperty]
    private int _lapsTotal;

    /// <summary>What the LAPS listing could not cover, or null when it is whole.</summary>
    [ObservableProperty]
    private string? _lapsShortfall;

    /// <summary>Why the computers could not be read, or null when they were.</summary>
    [ObservableProperty]
    private Notice? _lapsRefusal;

    /// <summary>Whether the LAPS listing has something to say about why it is empty.</summary>
    public bool HasLapsRefusal => LapsRefusal is not null;

    /// <summary>Whether the LAPS listing is short by an unknown number of machines.</summary>
    public bool HasLapsShortfall => LapsShortfall is not null;

    /// <summary>
    /// Whether a finding is selected, so there is an explanation to show beneath the grid.
    /// </summary>
    /// <remarks>
    /// Its own answer rather than a negation at the point of use, for the reason
    /// <see cref="HasNoRun"/> gives.
    /// </remarks>
    public bool HasSelectedFinding => SelectedFinding is not null;

    /// <summary>Whether a run has been chosen to look at.</summary>
    public bool HasRun => BundlePath is not null;

    /// <summary>
    /// Whether no run has been chosen. Its own answer rather than the negation of
    /// <see cref="HasRun"/> at the point of use, because a view cannot negate a binding without a
    /// converter and a converter that inverts is a place for presentation logic to accumulate.
    /// </summary>
    public bool HasNoRun => BundlePath is null;

    /// <summary>Whether the bundle was not read, and the screen is saying why.</summary>
    public bool HasRefusal => Refusal is not null;

    /// <summary>Whether the tree was read and shown.</summary>
    public bool HasTree => HasLooked && Refusal is null;

    /// <summary>Whether there is anything the tree does not show.</summary>
    public bool HasGaps => Gaps.Count > 0;

    /// <summary>Whether a container is selected, and so whether there are objects to list.</summary>
    public bool HasSelection => Selected is not null;

    /// <summary>Whether detached details are open for an object.</summary>
    public bool HasOpenObject => Opened is not null;

    /// <summary>
    /// Whether the main listing is showing. Detached object details do not replace it.
    /// </summary>
    public bool ShowsListing => _active && HasTree;

    /// <summary>
    /// Whether the listing was read and the selected part of the directory genuinely holds no
    /// objects. False while nothing is selected and false while the listing is short, so
    /// "nothing here" is only ever said when it was established.
    /// </summary>
    public bool IsEmpty => HasListingResult && ShowsObjects && !IsObjectSearch && HasTree && HasSelection && Objects.Count == 0 && Shortfall is null;

    /// <summary>
    /// Whether this listing is short by an unknown number of objects, because part of the
    /// directory it covers was not read.
    /// </summary>
    public bool IsShort => Shortfall is not null;

    /// <summary>
    /// Whether each object's container is worth a column. Only at
    /// <see cref="ListingScope.Subtree"/>, where objects genuinely come from different containers;
    /// at the narrower levels the column would repeat the container just selected on every row,
    /// which is what the predecessor's grid did.
    /// </summary>
    public bool ParentIsWorthShowing => !IsObjectSearch && Scope == ListingScope.Subtree;

    /// <summary>
    /// Whether the listing shows the selected object alone.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The three levels are offered as three plain answers rather than as one value a view has to
    /// convert. A converter that turns an enumeration into a tick is a place presentation logic
    /// accumulates, and it would sit outside the one layer that has tests.
    /// </para>
    /// <para>
    /// <b>Named as the directory names them</b>, on the owner's instruction of 2026-09-03. They read
    /// <i>this object</i>, <i>one level</i> and <i>everything beneath</i> until the LAPS inventory
    /// gave the same control a second grid to govern: an administrator already knows base, one
    /// level and subtree from every search he runs, and a screen that renames them makes him
    /// translate.
    /// </para>
    /// </remarks>
    public bool ShowsBase
    {
        get => Scope == ListingScope.Base;
        set
        {
            if (value)
                Scope = ListingScope.Base;
        }
    }

    /// <summary>Whether the listing shows the selected object and what is directly inside it.</summary>
    public bool ShowsOneLevel
    {
        get => Scope == ListingScope.OneLevel;
        set
        {
            if (value)
                Scope = ListingScope.OneLevel;
        }
    }

    /// <summary>Whether the listing shows the selected object and everything beneath it.</summary>
    public bool ShowsSubtree
    {
        get => Scope == ListingScope.Subtree;
        set
        {
            if (value)
                Scope = ListingScope.Subtree;
        }
    }

    /// <summary>Which objects of the listing this page holds, in words.</summary>
    /// <remarks>
    /// Empty when there is nothing to page through, rather than "0-0 of 0".
    /// </remarks>
    public string PageDescription
    {
        get
        {
            if (IsObjectSearch && HasListingResult)
                return ObjectNavigationText.Format("SearchPage", _objectSearchBack.Count + 1, Objects.Count,
                    _objectSearchNext is null ? "" : ObjectNavigationText.Get("MoreResults"));
            if (!HasListingResult || Total == 0)
                return string.Empty;

            var first = ((PageNumber - 1) * ObjectPaging.PageSize) + 1;
            var last = Math.Min(first + Objects.Count - 1, Total);

            return $"{first}-{last} of {Total}";
        }
    }

    /// <summary>Whether there is a page before this one.</summary>
    public bool HasPreviousPage => HasListingResult && (IsObjectSearch ? _objectSearchBack.Count > 0 : PageNumber > 1);

    /// <summary>Whether there is a page after this one.</summary>
    public bool HasNextPage => HasListingResult && (IsObjectSearch ? _objectSearchNext is not null : PageNumber * ObjectPaging.PageSize < Total);

    /// <summary>
    /// Shows the assets of the run in <paramref name="bundleDirectory"/>.
    /// </summary>
    /// <param name="bundleDirectory">The run's bundle directory.</param>
    /// <param name="aCaptureIsRunning">
    /// Whether a capture is running in this product. Passed in rather than discovered, because the
    /// window knows and this screen has no business reaching for it.
    /// </param>
    public void Show(string bundleDirectory, bool aCaptureIsRunning)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        var canReuseTree = !aCaptureIsRunning
            && _retainedTree is not null
            && _treeCurrent?.Invoke() == true
            && BundlePath is not null
            && string.Equals(Path.GetFullPath(BundlePath), Path.GetFullPath(bundleDirectory),
                StringComparison.OrdinalIgnoreCase);
        CancelRead();
        if (!string.Equals(BundlePath, bundleDirectory, StringComparison.OrdinalIgnoreCase))
        {
            ClearObjectPresentation();
            _resetting = true;
            ClearGroups();
            _resetting = false;
        }
        _assets.SelectRun(bundleDirectory);
        _active = true;
        BundlePath = bundleDirectory;
        _captureIsRunning = aCaptureIsRunning;
        if (canReuseTree && _treeCurrent?.Invoke() == true)
        {
            ResetTreePresentation();
            DisplayTree(_retainedTree!);
            ReadCompletion = LoadVisibleAsync();
            return;
        }
        Read();
    }

    /// <summary>Forgets the run being shown, so nothing describes a run no longer chosen.</summary>
    public void Clear()
    {
        ClearObjectPresentation();
        CancelRead();
        _resetting = true;
        _assets.CloseRun();
        ClearGroups();
        ResetObjectSearch();
        ShowsCaptureCoverageDetails = false;
        BundlePath = null;
        Refusal = null;
        HasLooked = false;
        _retainedTree = null;
        _treeCurrent = null;
        Selected = null;
        Roots.Clear();
        Gaps.Clear();
        Objects.Clear();
        Findings.Clear();
        FindingsRefusal = null;
        NothingWasFound = false;
        Severities.Clear();
        Rules.Clear();
        SeverityFilter = Any;
        RuleFilter = Any;
        _findingsBack.Clear();
        _findingsFrom = null;
        Total = 0;
        Shortfall = null;
        LapsComputers.Clear();
        LapsCounts.Clear();
        ResetLapsFilters();
        SelectedLapsComputer = null;
        LapsTotal = 0;
        LapsShortfall = null;
        LapsRefusal = null;
        SelectedFinding = null;
        ClearDelegationSearch();
        DelegationPrincipalSearch = "";
        _filterValidity = null;
        _listingReady = false;
        ViewRefusal = null;
        _resetting = false;
        Announce();
        AnnounceFindings();
    }

    /// <summary>Reads the chosen bundle again.</summary>
    [RelayCommand]
    public void Read()
    {
        ClearObjectPresentation();
        CancelRead();
        _retainedTree = null;
        _treeCurrent = null;
        ResetTreePresentation();

        if (BundlePath is null || !_active)
        {
            Announce();
            return;
        }

        // docs/decisions/0072: analysis does not run while a capture does. Said in words, with the
        // remedy in them, rather than by greying a control an operator would be left guessing at.
        if (_captureIsRunning)
        {
            Refusal = new Notice(
                "A capture is running",
                "This product does not read evidence while it is writing it. The assets of this "
                + "run can be read once the capture has finished.");
            Announce();
            return;
        }

        ReadCompletion = ReadTreeAsync(BundlePath);
    }

    private void ResetTreePresentation()
    {
        _resetting = true;
        ResetLapsFilters();
        ResetGroupPaging();
        ResetTier0Paging();
        ResetObjectSearch();
        ShowsCaptureCoverageDetails = false;
        Roots.Clear();
        Gaps.Clear();
        ClearListings();
        Selected = null;
        PageNumber = 1;
        _findingsBack.Clear();
        _findingsFrom = null;
        Severities.Clear();
        Rules.Clear();
        SeverityFilter = RuleFilter = Any;
        _filterValidity = null;
        HasLooked = false;
        Refusal = null;
        _resetting = false;
    }

    private async Task ReadTreeAsync(string bundle)
    {
        var revision = _revision + 1;
        await ReadViewAsync(bundle, reader => reader.ReadTree(bundle), (tree, current) =>
        {
            _retainedTree = tree;
            _treeCurrent = current;
            DisplayTree(tree);
        }, saved: false, tree: true);
        if (revision == _revision && _active && HasLooked && BundlePath == bundle)
            await LoadVisibleAsync();
    }

    private void DisplayTree(DirectoryTree tree)
    {
        foreach (var root in tree.Roots) Roots.Add(new TreeNodeViewModel(root));
        foreach (var node in Roots.SelectMany(root => root.ThisAndBelow()))
            node.PropertyChanged += OnNodeChanged;
        foreach (var gap in tree.Gaps) Gaps.Add(new TreeGapViewModel(gap));

        var automaticSelection = tree.ForestRootDistinguishedName is null
            ? Roots.FirstOrDefault()
            : Roots.SingleOrDefault(root => string.Equals(
                root.DistinguishedName,
                tree.ForestRootDistinguishedName,
                StringComparison.OrdinalIgnoreCase));
        if (tree.ForestRootDistinguishedName is not null && automaticSelection is null)
        {
            throw new InvalidDataException(
                $"The captured forest root '{tree.ForestRootDistinguishedName}' is not in its directory tree.");
        }

        _resetting = true;
        Selected = automaticSelection;
        if (automaticSelection is not null) automaticSelection.IsSelected = true;
        _resetting = false;
        HasLooked = true;
    }

    /// <summary>Shows the page before the one showing.</summary>
    [RelayCommand]
    public void PreviousPage()
    {
        if (!HasPreviousPage)
            return;

        if (IsObjectSearch)
        {
            ReadCompletion = ReadObjectSearchPageAsync(_objectSearchBack.Peek(), -1);
            return;
        }
        PageNumber--;
        LoadVisible();
    }

    /// <summary>Shows the page after the one showing.</summary>
    [RelayCommand]
    public void NextPage()
    {
        if (!HasNextPage)
            return;

        if (IsObjectSearch)
        {
            ReadCompletion = ReadObjectSearchPageAsync(_objectSearchNext, 1);
            return;
        }
        PageNumber++;
        LoadVisible();
    }

    /// <summary>
    /// Opens the object a finding is about, and lands on that object's findings.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A finding carries a distinguished name and nothing else about the object.</b> It was
    /// written by a rule reading the evidence, not by the listing, so it has no class and no type
    /// to hand over - both are read back out of the bundle here. That is the whole reason this
    /// exists beside <see cref="OpenObject"/> rather than being folded into it.
    /// </para>
    /// <para>
    /// <b>An object a finding names may not be in the evidence at all.</b> A judgement is an
    /// ordinary file that can be moved beside another capture, and the reader refuses one whose
    /// fingerprint disagrees - but a bundle can also simply not hold what it once did. The
    /// predecessor fell back to a finding-detail window; there is none here, so the honest answer
    /// is to say so in words rather than to open nothing and look broken.
    /// </para>
    /// </remarks>
    /// <param name="finding">The row the operator chose.</param>
    [RelayCommand]
    public void OpenFinding(FindingRowViewModel? finding)
    {
        if (finding is null || BundlePath is null)
            return;

        Open(finding.DistinguishedName, ObjectSectionCatalog.Findings);
    }

    [RelayCommand]
    private void OpenSavedRoutes(FindingRowViewModel? finding)
    {
        if (finding?.HasTier0Routes != true || BundlePath is null) return;
        Open(finding.DistinguishedName, ObjectSectionCatalog.SavedTier0Path);
    }

    /// <summary>
    /// Opens one object from the listing and shows what its permissions say.
    /// </summary>
    /// <param name="listed">The row the operator chose.</param>
    [RelayCommand]
    public void OpenObject(ListedObjectViewModel? listed)
    {
        if (listed is null || BundlePath is null)
            return;

        Open(listed.DistinguishedName, ObjectSectionCatalog.Overview);
    }

    private void Open(string distinguishedName, string section)
    {
        if (BundlePath is null || _captureIsRunning || (!_active && !HasObjectPresentation)) return;
        CancelObjectRead();
        IsOpeningObject = true;
        ObjectRefusal = null;
        Opened = null;
        ReadCompletion = ObjectReadCompletion = OpenAsync(BundlePath, distinguishedName, section);
    }

    /// <summary>
    /// The object's most specific class, or null when it did not arrive.
    /// </summary>
    /// <remarks>
    /// <b>The last value, which is the most derived one.</b> A computer's <c>objectClass</c> is
    /// <c>top, person, organizationalPerson, user, computer</c>, and an operator calling it a user
    /// would be reading the fourth of five. The rules take the same value the same way.
    /// </remarks>
    private static string? ClassOf(ObjectAttributes? attributes) =>
        attributes?.Find("objectClass")?.Values is { Count: > 0 } values
            ? values[^1].Text
            : null;

    /// <summary>Goes back to the listing the object was opened from.</summary>
    /// <remarks>
    /// <b>The findings are left exactly as they were.</b> Closing an object is a return to what was
    /// already on screen rather than a new question, so neither the page nor the mark stack behind
    /// it is disturbed - an operator who opened a finding from page four is put back on page four.
    /// Keyset paging only goes forward, so a rebuilt stack would mean page one.
    /// </remarks>
    [RelayCommand]
    public void CloseObject()
    {
        if (Pane == AssetsPane.Groups && _groupObjectBack.TryPop(out var group))
        {
            Open(group, ObjectSectionCatalog.Membership);
            return;
        }
        DismissObjectDetails();
    }

    internal void DismissObjectDetails()
    {
        ClearObjectPresentation();
        if (_active && _pages.TryGetValue(Pane, out var page) && page.Question == Question() && page.IsCurrent())
        {
            ViewRefusal = null;
            _listingReady = true;
        }
        else if (_active)
            LoadVisible();
        Announce();
    }

    /// <summary>What the findings grid is asking for, as the screen currently stands.</summary>
    /// <remarks>
    /// <b>Every filter is read here and nowhere else.</b> A third one is a property, a line in this
    /// method, and a control - not a change to how the grid is loaded or paged.
    /// </remarks>
    private FindingsQuery FindingsAsked() =>
        new(
            Severity: Chosen(SeverityFilter) is { } severity
                ? Enum.Parse<Severity>(severity)
                : null,
            RuleId: Chosen(RuleFilter),
            DomainFqdn: null,
            Container: Selected?.DistinguishedName,
            Object: null,
            After: _findingsBack.Count == 0 ? null : _findingsBack.Peek(),
            PageSize: FindingsQuery.DefaultPageSize);

    /// <summary>The value a filter is set to, or null when it is not narrowing anything.</summary>
    private static string? Chosen(string filter) =>
        filter == Any || string.IsNullOrEmpty(filter) ? null : filter;

    /// <summary>
    /// A different filter is a different list, and it starts at its first page.
    /// </summary>
    /// <remarks>
    /// The mark from the previous list points into rows this one may not contain, so carrying it
    /// over would open the grid part way down a list that no longer exists.
    /// </remarks>
    partial void OnSeverityFilterChanged(string value) => RefilterFindings();

    /// <inheritdoc cref="OnSeverityFilterChanged"/>
    partial void OnRuleFilterChanged(string value) => RefilterFindings();

    private void RefilterFindings()
    {
        if (_resetting) return;
        _findingsBack.Clear();
        _findingsFrom = null;
        ClearListing(AssetsPane.Findings);
        OnPropertyChanged(nameof(IsFiltered));
        OnPropertyChanged(nameof(NothingFoundReason));
        if (Pane == AssetsPane.Findings)
        {
            LoadVisible();
        }
    }

    /// <summary>Clears every filter, so the grid shows the whole container again.</summary>
    [RelayCommand]
    public void ClearFindingsFilters()
    {
        SeverityFilter = Any;
        RuleFilter = Any;
    }

    /// <summary>Dismisses the explanation without changing the findings, filters or page.</summary>
    [RelayCommand]
    public void CloseFindingDetails() => SelectedFinding = null;

    /// <summary>Shows the next page of findings.</summary>
    [RelayCommand(CanExecute = nameof(HasMoreFindings))]
    public void NextFindings()
    {
        if (_findingsFrom is not { } mark)
            return;

        _findingsBack.Push(mark);
        LoadVisible();
    }

    /// <summary>Whether there is another page of findings after this one.</summary>
    public bool HasMoreFindings => HasListingResult && _findingsFrom is not null;

    /// <summary>Goes back to the previous page of findings.</summary>
    [RelayCommand(CanExecute = nameof(HasEarlierFindings))]
    public void PreviousFindings()
    {
        if (_findingsBack.Count == 0)
            return;

        _findingsBack.Pop();
        LoadVisible();
    }

    /// <summary>Whether there is a page of findings before this one.</summary>
    public bool HasEarlierFindings => HasListingResult && _findingsBack.Count > 0;

    /// <summary>Whether any finding is being shown.</summary>
    public bool HasFindings => Findings.Count > 0;

    /// <summary>Whether the screen is saying why there are no findings.</summary>
    public bool HasFindingsRefusal => FindingsRefusal is not null;

    /// <summary>
    /// Which page of findings is showing, counting from one, for an operator who needs to know
    /// where he is.
    /// </summary>
    public int FindingsPageNumber => _findingsBack.Count + 1;

    private void AnnounceFindings()
    {
        OnPropertyChanged(nameof(HasFindings));
        OnPropertyChanged(nameof(HasFindingsRefusal));
        OnPropertyChanged(nameof(HasMoreFindings));
        OnPropertyChanged(nameof(HasEarlierFindings));
        OnPropertyChanged(nameof(FindingsPageNumber));
        NextFindingsCommand.NotifyCanExecuteChanged();
        PreviousFindingsCommand.NotifyCanExecuteChanged();
    }

    partial void OnOpenedChanging(ObjectViewModel? oldValue, ObjectViewModel? newValue)
    {
        oldValue?.Suspend();
    }

    /// <summary>Keeps the three views of the screen from both claiming to be showing.</summary>
    /// <remarks>
    /// The inventory is listed on arrival rather than with the objects, because a listing nobody is
    /// looking at is a scan of every computer in the forest paid for on every container click.
    /// </remarks>
    partial void OnPaneChanged(AssetsPane value)
    {
        CancelRead();
        if (value != AssetsPane.Objects) ResetObjectSearch();
        ViewRefusal = null;
        if (!_active || _resetting) return;
        if (!HasLooked && BundlePath is not null && !_captureIsRunning)
        {
            Read();
            return;
        }
        LoadVisible();
        OnPropertyChanged(nameof(ShowsObjects));
        OnPropertyChanged(nameof(ShowsFindings));
        OnPropertyChanged(nameof(ShowsLaps));
        OnPropertyChanged(nameof(ShowsObjectListing));
        OnPropertyChanged(nameof(ShowsFindingsListing));
        OnPropertyChanged(nameof(ShowsLapsListing));

        Announce();
    }

    /// <summary>
    /// Takes a node reporting itself selected as the selection.
    /// </summary>
    /// <remarks>
    /// Only a node becoming selected is acted on. A tree deselects the previous item as it selects
    /// the next, and treating that as "nothing is selected" would empty the grid for an instant
    /// on every click.
    /// </remarks>
    private void OnNodeChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(TreeNodeViewModel.IsSelected)
            && sender is TreeNodeViewModel { IsSelected: true } node)
        {
            Selected = node;
        }
    }

    /// <summary>
    /// A different container is a different listing, and it starts at its first page. Keeping the
    /// page number would open a container at page seven of a listing that has two.
    /// </summary>
    /// <remarks>
    /// The findings restart with it, and for the same reason: they are scoped by this selection, so
    /// a mark from the previous container points into a page of a list that no longer exists.
    /// </remarks>
    partial void OnSelectedChanged(TreeNodeViewModel? value)
    {
        if (_resetting) return;
        UseSelectedGroupLocation();
        ResetObjectSearch();
        PageNumber = 1;
        _findingsBack.Clear();
        _findingsFrom = null;
        ResetLapsPaging();
        ClearListing(AssetsPane.Objects);
        ClearListing(AssetsPane.Findings);
        ClearListing(AssetsPane.Laps);
        ClearListing(AssetsPane.Groups);
        if (Pane != AssetsPane.Delegations) LoadVisible();
        Announce();
    }

    /// <summary>Changing the level changes the listing, and it starts again at its first page.</summary>
    /// <remarks>
    /// <b>The level belongs to the tree, not to one grid.</b> It sits beside the tree on screen and
    /// governs whichever view is showing, so an operator narrowing to an organisational unit during
    /// a LAPS rollout does not have to go back to the objects tab to change it and then return.
    /// Until 2026-09-03 the control lived in the object listing and only re-listed the objects,
    /// which is exactly what that cost.
    /// </remarks>
    partial void OnScopeChanged(ListingScope value)
    {
        if (_resetting) return;
        if (IsObjectSearch)
        {
            OnPropertyChanged(nameof(ShowsBase));
            OnPropertyChanged(nameof(ShowsOneLevel));
            OnPropertyChanged(nameof(ShowsSubtree));
            return;
        }
        PageNumber = 1;
        ResetLapsPaging();
        OnPropertyChanged(nameof(ParentIsWorthShowing));
        OnPropertyChanged(nameof(ShowsBase));
        OnPropertyChanged(nameof(ShowsOneLevel));
        OnPropertyChanged(nameof(ShowsSubtree));
        ClearListing(AssetsPane.Objects);
        ClearListing(AssetsPane.Laps);
        ResetGroupPaging();
        ResetTier0Paging();
        ClearListing(AssetsPane.Groups);
        if (Pane is AssetsPane.Objects or AssetsPane.Laps or AssetsPane.Groups)
        {
            LoadVisible();
        }
        Announce();
    }

    /// <summary>
    /// Tells the screen that the answers derived from the collections have changed. The
    /// collections raise their own changes; these read from them and would otherwise go stale.
    /// </summary>
    private void Announce()
    {
        AnnounceObjectNavigation();
        AnnounceDelegations();
        AnnounceGroups();
        AnnounceTier0();
        AnnounceScopeTree();
        OnPropertyChanged(nameof(HasViewRefusal));
        OnPropertyChanged(nameof(IsOpeningTree));
        OnPropertyChanged(nameof(HasListingResult));
        OnPropertyChanged(nameof(HasLapsRefusal));
        OnPropertyChanged(nameof(HasLapsShortfall));
        OnPropertyChanged(nameof(HasRun));
        OnPropertyChanged(nameof(HasNoRun));
        OnPropertyChanged(nameof(HasRefusal));
        OnPropertyChanged(nameof(HasGaps));
        OnPropertyChanged(nameof(HasTree));
        OnPropertyChanged(nameof(HasSelection));
        OnPropertyChanged(nameof(HasOpenObject));
        OnPropertyChanged(nameof(ShowsListing));

        OnPropertyChanged(nameof(ShowsObjectListing));
        OnPropertyChanged(nameof(ShowsFindingsListing));
        OnPropertyChanged(nameof(ShowsLapsListing));

        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(IsShort));
        OnPropertyChanged(nameof(PageDescription));
        OnPropertyChanged(nameof(HasPreviousPage));
        OnPropertyChanged(nameof(HasNextPage));
    }
}
