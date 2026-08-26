using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Evidence;
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

    /// <summary>
    /// The words and verdicts for the run on screen, read on first use and dropped with the run.
    /// </summary>
    /// <remarks>
    /// <b>Tied to the run, and cleared whenever it changes.</b> A catalogue is a fact about one
    /// forest on one day, so a stale one would label this run's permissions with another forest's
    /// schema - and the names would look perfectly reasonable while being about the wrong
    /// directory.
    /// </remarks>
    private PermissionVocabulary? _vocabulary;

    [ObservableProperty]
    private string? _bundlePath;

    [ObservableProperty]
    private bool _hasLooked;

    [ObservableProperty]
    private Notice? _refusal;

    [ObservableProperty]
    private TreeNodeViewModel? _selected;

    [ObservableProperty]
    private ListingScope _scope = ListingScope.OneLevel;

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
    /// Whether the findings are the view showing, rather than the objects.
    /// </summary>
    /// <remarks>
    /// <b>Told by the window rather than discovered here.</b> Both views are this one screen, and
    /// which of them is showing is a fact about the tabs - which belong to the shell. A view model
    /// that reached for the shell's selected tab would be a screen deciding the application's
    /// navigation, which is what <c>IRunOpener</c> exists to avoid one level up.
    /// </remarks>
    [ObservableProperty]
    private bool _showsFindings;

    /// <summary>Whether the object listing is the view showing.</summary>
    /// <remarks>
    /// Its own answer rather than the negation of <see cref="ShowsFindings"/>, for the reason
    /// <see cref="HasNoRun"/> gives: a view cannot negate a binding without a converter.
    /// </remarks>
    public bool ShowsObjects => !ShowsFindings;

    /// <summary>
    /// Whether the object grid should be on screen: the objects tab, and no object opened from it.
    /// </summary>
    /// <remarks>
    /// Both conditions together here rather than two bindings in the view, because a view that
    /// combines them is a view holding a rule about what is visible when - and the day a third
    /// condition arrives it is edited in a place no test reads.
    /// </remarks>
    public bool ShowsObjectListing => ShowsObjects && ShowsListing;

    /// <summary>Whether the findings grid should be on screen.</summary>
    public bool ShowsFindingsListing => ShowsFindings && ShowsListing;

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
    /// <b>It replaces the grid rather than opening beside it or in a window of its own.</b> The
    /// predecessor had a left pane and a pop-out window, and both existed because two panes left no
    /// room for an entry table on a laptop. The tree stays, because an operator reading one
    /// object's permissions is still somewhere in the directory and will move to a neighbour next.
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

    /// <summary>Whether an object is open and its permissions are showing.</summary>
    public bool HasOpenObject => Opened is not null;

    /// <summary>
    /// Whether the listing is showing. Its own answer rather than the negation of
    /// <see cref="HasOpenObject"/>, for the reason <see cref="HasNoRun"/> gives.
    /// </summary>
    public bool ShowsListing => Opened is null;

    /// <summary>
    /// Whether the listing was read and the selected part of the directory genuinely holds no
    /// objects. False while nothing is selected and false while the listing is short, so
    /// "nothing here" is only ever said when it was established.
    /// </summary>
    public bool IsEmpty => HasTree && HasSelection && Objects.Count == 0 && Shortfall is null;

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
    public bool ParentIsWorthShowing => Scope == ListingScope.Subtree;

    /// <summary>
    /// Whether the listing shows the selected object alone.
    /// </summary>
    /// <remarks>
    /// The three levels are offered as three plain answers rather than as one value a view has to
    /// convert. A converter that turns an enumeration into a tick is a place presentation logic
    /// accumulates, and it would sit outside the one layer that has tests.
    /// </remarks>
    public bool ShowsThisObject
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

    /// <summary>Whether the listing shows everything beneath the selected object.</summary>
    public bool ShowsEverythingBeneath
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
            if (Total == 0)
                return string.Empty;

            var first = ((PageNumber - 1) * ObjectPaging.PageSize) + 1;
            var last = Math.Min(first + Objects.Count - 1, Total);

            return $"{first}-{last} of {Total}";
        }
    }

    /// <summary>Whether there is a page before this one.</summary>
    public bool HasPreviousPage => PageNumber > 1;

    /// <summary>Whether there is a page after this one.</summary>
    public bool HasNextPage => PageNumber * ObjectPaging.PageSize < Total;

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

        BundlePath = bundleDirectory;
        _captureIsRunning = aCaptureIsRunning;
        _vocabulary = null;
        Read();
    }

    /// <summary>Forgets the run being shown, so nothing describes a run no longer chosen.</summary>
    public void Clear()
    {
        BundlePath = null;
        Refusal = null;
        HasLooked = false;
        Selected = null;
        Opened = null;
        _vocabulary = null;
        Roots.Clear();
        Gaps.Clear();
        Objects.Clear();
        Findings.Clear();
        FindingsRefusal = null;
        NothingWasFound = false;
        _findingsBack.Clear();
        _findingsFrom = null;
        Total = 0;
        Shortfall = null;
        Announce();
        AnnounceFindings();
    }

    /// <summary>Reads the chosen bundle again.</summary>
    [RelayCommand]
    public void Read()
    {
        Roots.Clear();
        Gaps.Clear();
        Objects.Clear();
        Selected = null;
        Total = 0;
        Shortfall = null;
        HasLooked = false;
        Refusal = null;

        if (BundlePath is null)
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

        var read = _assets.ReadTree(BundlePath);

        if (!read.IsSuccess)
        {
            Refusal = new Notice("This run's evidence was not opened", read.Error.Description);
            Announce();
            return;
        }

        foreach (var root in read.Value.Roots)
            Roots.Add(new TreeNodeViewModel(root));

        // Every node, not only the roots: a tree reports a selection on whichever item was
        // clicked, however deep.
        foreach (var node in Roots.SelectMany(r => r.ThisAndBelow()))
            node.PropertyChanged += OnNodeChanged;

        foreach (var gap in read.Value.Gaps)
            Gaps.Add(new TreeGapViewModel(gap));

        HasLooked = true;

        // Rooted at the forest, so the screen arrives showing something rather than an empty half
        // and an instruction to click.
        Selected = Roots.FirstOrDefault();

        // Setting the selection lists the findings through OnSelectedChanged, but only when it
        // changed. A bundle whose tree has no roots leaves it null, and the findings would never be
        // asked for at all.
        if (Selected is null)
            ListFindings();

        Announce();
    }

    /// <summary>Shows the page before the one showing.</summary>
    [RelayCommand]
    public void PreviousPage()
    {
        if (!HasPreviousPage)
            return;

        PageNumber--;
        ListObjects();
    }

    /// <summary>Shows the page after the one showing.</summary>
    [RelayCommand]
    public void NextPage()
    {
        if (!HasNextPage)
            return;

        PageNumber++;
        ListObjects();
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

        var read = _assets.ReadPermissions(BundlePath, listed.DistinguishedName);

        if (!read.IsSuccess)
        {
            Refusal = new Notice(
                "This object's permissions were not read", read.Error.Description);
            Announce();
            return;
        }

        // The bundle was read and does not hold the object. That is not a failure of this build,
        // and it is not an object with no permissions - it is a listing and an evidence file that
        // disagree, which an operator needs told rather than shown as an empty table.
        if (read.Value is null)
        {
            Refusal = new Notice(
                "This object is not in this run's evidence",
                $"'{listed.DistinguishedName}' was listed but no object of that name was found in "
                + "the bundle.");
            Announce();
            return;
        }

        // Attribute values are read separately and are allowed to be absent. A failure to read
        // them is not a reason to refuse the object: the permissions are the reason this screen
        // exists, and each section says for itself when it has nothing.
        var attributes = _assets.ReadObjectAttributes(BundlePath, listed.DistinguishedName);

        Opened = new ObjectViewModel(
            read.Value,
            attributes.IsSuccess ? attributes.Value : null,
            listed.ObjectType,
            listed.ObjectClass,
            Vocabulary());
        Announce();
    }

    /// <summary>
    /// The words and verdicts permissions are read with for the run on screen.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The forest's own schema, where the run captured it.</b> Until this was wired up, every
    /// GUID on the permissions screen was resolved against the table shipped with the product, so a
    /// stock class missing from that table - and every attribute a customer had ever added - showed
    /// as a bare GUID. The bundle held the answer all along.
    /// </para>
    /// <para>
    /// <b>A failure to read it is not a reason to refuse the object.</b> The shipped table still
    /// resolves what Microsoft publishes, which is most of what an operator is reading, and the
    /// screen says which of the two kinds of answer it is giving. Refusing the whole object because
    /// its schema could not be read would hide the permissions over a question about their labels.
    /// </para>
    /// </remarks>
    private PermissionVocabulary Vocabulary()
    {
        if (_vocabulary is not null)
            return _vocabulary;

        var schema = _assets.ReadSchemaGuids(BundlePath!);

        _vocabulary = schema.IsSuccess
            ? new PermissionVocabulary(schema.Value)
            : PermissionVocabulary.Shipped;

        return _vocabulary;
    }

    /// <summary>Goes back to the listing the object was opened from.</summary>
    [RelayCommand]
    public void CloseObject()
    {
        Opened = null;
        Announce();
    }

    /// <summary>Lists the objects of the selected container at the chosen level.</summary>
    private void ListObjects()
    {
        Objects.Clear();
        Shortfall = null;

        // A new listing is a different question from the one the open object answered. Leaving it
        // up would show one container's object over another container's list.
        Opened = null;

        if (BundlePath is null || Selected is null)
        {
            Total = 0;
            Announce();
            return;
        }

        var listed = _assets.ListObjects(
            BundlePath, Selected.DistinguishedName, Scope, PageNumber);

        if (!listed.IsSuccess)
        {
            Total = 0;
            Refusal = new Notice("This run's objects were not read", listed.Error.Description);
            Announce();
            return;
        }

        foreach (var listedObject in listed.Value.Objects)
            Objects.Add(new ListedObjectViewModel(listedObject));

        Total = listed.Value.Total;
        Shortfall = listed.Value.ObjectsAreComplete ? null : listed.Value.Shortfall;
        Announce();
    }

    /// <summary>
    /// Lists the findings of the selected container, or of the whole run when nothing is selected.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Scoped by the same selection the object listing uses.</b> An operator who has selected
    /// <c>OU=Servers</c> and switches to findings is still asking about servers, and a grid that
    /// silently widened to the forest would answer a question he did not ask.
    /// </para>
    /// <para>
    /// <b>Four silences, kept apart.</b> No run chosen, a capture running, a judgement that cannot
    /// be read, a bundle nobody judged, and a judging that found nothing are different facts, and
    /// only the last of them means the forest is clean.
    /// </para>
    /// </remarks>
    private void ListFindings()
    {
        Findings.Clear();
        FindingsRefusal = null;
        NothingWasFound = false;

        if (BundlePath is null || _captureIsRunning)
        {
            AnnounceFindings();
            return;
        }

        var read = _assets.ReadFindings(BundlePath, FindingsAsked());

        if (!read.IsSuccess)
        {
            FindingsRefusal = new Notice("There are no findings to show", read.Error.Description);
            AnnounceFindings();
            return;
        }

        foreach (var finding in read.Value.Findings)
            Findings.Add(new FindingRowViewModel(finding));

        _findingsFrom = read.Value.Next;
        NothingWasFound = read.Value.NothingWasFound;
        AnnounceFindings();
    }

    /// <summary>What the findings grid is asking for, as the screen currently stands.</summary>
    private FindingsQuery FindingsAsked() =>
        new(
            Severity: null,
            RuleId: null,
            DomainFqdn: null,
            Container: Selected?.DistinguishedName,
            After: _findingsBack.Count == 0 ? null : _findingsBack.Peek(),
            PageSize: FindingsQuery.DefaultPageSize);

    /// <summary>Shows the next page of findings.</summary>
    [RelayCommand(CanExecute = nameof(HasMoreFindings))]
    public void NextFindings()
    {
        if (_findingsFrom is not { } mark)
            return;

        _findingsBack.Push(mark);
        ListFindings();
    }

    /// <summary>Whether there is another page of findings after this one.</summary>
    public bool HasMoreFindings => _findingsFrom is not null;

    /// <summary>Goes back to the previous page of findings.</summary>
    [RelayCommand(CanExecute = nameof(HasEarlierFindings))]
    public void PreviousFindings()
    {
        if (_findingsBack.Count == 0)
            return;

        _findingsBack.Pop();
        ListFindings();
    }

    /// <summary>Whether there is a page of findings before this one.</summary>
    public bool HasEarlierFindings => _findingsBack.Count > 0;

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

    /// <summary>Keeps the two halves of the screen from both claiming to be showing.</summary>
    partial void OnShowsFindingsChanged(bool value)
    {
        OnPropertyChanged(nameof(ShowsObjects));
        OnPropertyChanged(nameof(ShowsObjectListing));
        OnPropertyChanged(nameof(ShowsFindingsListing));
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
        PageNumber = 1;
        _findingsBack.Clear();
        _findingsFrom = null;
        ListObjects();
        ListFindings();
    }

    /// <summary>Changing the level changes the listing, and it starts again at its first page.</summary>
    partial void OnScopeChanged(ListingScope value)
    {
        PageNumber = 1;
        OnPropertyChanged(nameof(ParentIsWorthShowing));
        OnPropertyChanged(nameof(ShowsThisObject));
        OnPropertyChanged(nameof(ShowsOneLevel));
        OnPropertyChanged(nameof(ShowsEverythingBeneath));
        ListObjects();
    }

    /// <summary>
    /// Tells the screen that the answers derived from the collections have changed. The
    /// collections raise their own changes; these read from them and would otherwise go stale.
    /// </summary>
    private void Announce()
    {
        OnPropertyChanged(nameof(HasRun));
        OnPropertyChanged(nameof(HasNoRun));
        OnPropertyChanged(nameof(HasRefusal));
        OnPropertyChanged(nameof(HasGaps));
        OnPropertyChanged(nameof(HasTree));
        OnPropertyChanged(nameof(HasSelection));
        OnPropertyChanged(nameof(HasOpenObject));
        OnPropertyChanged(nameof(ShowsListing));

        // The two halves derive from ShowsListing, so opening or closing an object changes them
        // without either of them being assigned. Left out, the grid draws once and never moves,
        // which reads as a tab that does nothing. Held by
        // AssetsViewModelTests.OpeningAnObjectTakesTheFindingsGridOffTheScreen.
        OnPropertyChanged(nameof(ShowsObjectListing));
        OnPropertyChanged(nameof(ShowsFindingsListing));

        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(IsShort));
        OnPropertyChanged(nameof(PageDescription));
        OnPropertyChanged(nameof(HasPreviousPage));
        OnPropertyChanged(nameof(HasNextPage));
    }
}
