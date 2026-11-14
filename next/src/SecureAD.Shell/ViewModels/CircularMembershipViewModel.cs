using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Naming;

namespace SecureAD.Shell.ViewModels;

internal sealed record CircularMembershipReads(
    Func<CircularMembershipLoopMark?, CancellationToken, Task<Result<SavedCircularMembershipLoop>>> Loop,
    Func<CircularMembershipGroupMark?, CancellationToken, Task<Result<SavedCircularMembershipGroups>>> Groups,
    Func<CircularMembershipLinkMark?, CancellationToken, Task<Result<SavedCircularMembershipLinks>>> Links,
    Func<Guid, Guid, CircularMembershipWitnessMark?, CancellationToken, Task<Result<SavedCircularMembershipWitnesses>>> Witnesses,
    Action<CircularMembershipGroup> OpenGroup,
    Action<SavedCircularMembershipLink> ReviewMembership);

internal sealed class CircularMembershipLoopRow(SavedCircularMembershipLoopStep saved,
    Action<SavedCircularMembershipLink> review, Func<SavedCircularMembershipLink, bool> current)
{
    internal SavedCircularMembershipLoopStep Saved { get; } = saved;
    internal static string Name(CircularMembershipGroup group) => DnHelper.ExtractFirstRdn(group.DistinguishedName) + " (" + group.DomainFqdn + ")";
    public string ContainingGroup => Name(saved.Link.ContainingGroup);
    public string Member => Name(saved.Link.Member);
    public IRelayCommand ReviewCommand { get; } = new RelayCommand(() => review(saved.Link), () => current(saved.Link));
}

internal sealed class CircularMembershipGroupRow(SavedCircularMembershipGroup saved,
    Action<SavedCircularMembershipGroup> open, Func<SavedCircularMembershipGroup, bool> current)
{
    internal SavedCircularMembershipGroup Saved { get; } = saved;
    public string Group => DnHelper.ExtractFirstRdn(saved.Group.DistinguishedName);
    public string Sid => saved.Group.Sid;
    public string Domain => saved.Group.DomainFqdn;
    public string Location => saved.Group.DistinguishedName;
    public IRelayCommand OpenCommand { get; } = new RelayCommand(() => open(saved), () => current(saved));
}
internal sealed class CircularMembershipLinkRow(SavedCircularMembershipLink saved,
    Action<SavedCircularMembershipLink> select, Func<SavedCircularMembershipLink, bool> current)
{
    internal SavedCircularMembershipLink Saved { get; } = saved;
    public string Direction => Describe(saved);
    internal static string Describe(SavedCircularMembershipLink link) => DnHelper.ExtractFirstRdn(link.Member.DistinguishedName) + " (" + link.Member.DomainFqdn
        + ") is a member of " + DnHelper.ExtractFirstRdn(link.ContainingGroup.DistinguishedName) + " (" + link.ContainingGroup.DomainFqdn + ").";
    public string MemberLocation => saved.Member.DistinguishedName;
    public string ContainingGroupLocation => saved.ContainingGroup.DistinguishedName;
    public bool IsSelfMembership => saved.IsSelfMembership;
    public string SelfMembershipNote => "This group is recorded as a member of itself.";
    public IRelayCommand ViewCommand { get; } = new RelayCommand(() => select(saved), () => current(saved));
}
internal sealed record CircularMembershipWitnessRow(SavedCircularMembershipWitness Saved)
{
    public string Source => Saved.Source.DistinguishedName;
    public string Attribute => Saved.Attribute;
    public string Value => Saved.Value;
}

internal sealed class CircularMembershipPageViewModel<TPage, TMark, TRow> : SavedFindingPageViewModel<TPage, TMark>
    where TPage : class where TMark : struct
{
    private readonly Func<TPage, TMark?> _next;
    private readonly Func<TPage, TMark?, bool> _valid;
    private readonly Func<TPage, IReadOnlyList<TRow>> _rows;
    private readonly Action? _changed;
    private TPage _published;
    internal CircularMembershipPageViewModel(TPage first, Func<TMark?, CancellationToken, Task<Result<TPage>>> read,
        Func<bool> current, Func<TPage, TMark?> next, Func<TPage, TMark?, bool> valid,
        Func<TPage, IReadOnlyList<TRow>> rows, Action? changed) : base(first, read, current)
    {
        (_next, _valid, _rows, _changed, _published) = (next, valid, rows, changed, first);
        Rows = rows(first);
    }
    public IReadOnlyList<TRow> Rows { get; private set; }
    internal TPage SavedPage => Page;
    protected override TMark? NextFor(TPage page) => _next(page);
    protected override bool Accepts(TPage page, TMark? after) => _valid(page, after);
    protected override string InvalidDetails => SavedCircularMembershipContext.InvalidDetails;
    protected override void AnnouncePage()
    {
        var changed = !ReferenceEquals(_published, Page);
        _published = Page;
        Rows = IsActive ? _rows(Page) : [];
        OnPropertyChanged(nameof(Rows));
        if (changed || !IsActive) _changed?.Invoke();
    }
}

internal sealed partial class CircularMembershipViewModel : ObservableObject
{
    private readonly SavedCircularMembershipContext _context;
    private readonly CircularMembershipReads _reads;
    private readonly Func<bool> _current;
    private bool _active = true;
    private CancellationTokenSource? _pending;
    private long _revision;
    private SavedCircularMembershipLink? _selectedLink;
    internal CircularMembershipViewModel(SavedCircularMembershipLoop first, CircularMembershipReads reads, Func<bool> current)
    {
        (_context, _reads, _current) = (first.Context, reads, current);
        Loop = new(first, reads.Loop, IsCurrent, page => page.Next,
            (page, after) => page.Context == _context && page.LoopKey == first.LoopKey && page.StepCount == first.StepCount
                && page.StartGroupGuid == first.StartGroupGuid && page.IsExpectedPage(after),
            page => page.Steps.Select(value => new CircularMembershipLoopRow(value, Review, ContainsLoopLink)).ToArray(), Announce);
    }
    public string Chain => Loop.Rows.Count == 0 ? "" : string.Join(" \u2192 ",
        new[] { Loop.Rows[0].ContainingGroup }.Concat(Loop.Rows.Select(row => row.Member)));
    public string ArrowNote => IsPagedLoop ? "Arrow means contains." : "Arrow means contains. The last link returns to the first group.";
    public string BreakNote => "If one of these memberships is unintended, removing it breaks the loop shown. Choose a membership after checking its other uses.";
    public string ReviewNote => "Review membership opens the containing group's captured membership. It does not remove a member or contact Active Directory.";
    public string OtherLoopsNote => "Other loops are recorded in this group set. Breaking the loop shown may leave another loop.";
    public bool HasOtherLoops => Loop.SavedPage.HasOtherLoops;
    public bool IsPagedLoop => Loop.SavedPage.StepCount > SavedCircularMembershipContext.PageSize;
    public string GroupNote => "This finding covers the listed group set. The display order is not a membership path.";
    public string AffectedObjectNote => "Open affected object opens " + DnHelper.ExtractFirstRdn(_context.Anchor.DistinguishedName)
        + " (" + _context.Anchor.DomainFqdn + "). This finding applies to all listed groups.";
    public string InventoryLabel => "Saved cycle inventory: " + (_context.InventoryComplete ? "Complete" : "Incomplete");
    public bool IsIncomplete => !_context.InventoryComplete;
    public string IncompleteNote => "The captured evidence is incomplete. This loop is recorded, but additional groups, links or loops may be missing.";
    public string LinksNote => "These are direct membership links, not one ordered path or a minimum set of changes.";
    public string WitnessesNote => "These values support the selected direct relationship; they are not a complete membership list.";
    public string MemberOfNote => "memberOf records the same relationship from the member side.";
    public string SelectedRelationship => _selectedLink is null ? "" : CircularMembershipLinkRow.Describe(_selectedLink);
    public CircularMembershipPageViewModel<SavedCircularMembershipLoop, CircularMembershipLoopMark, CircularMembershipLoopRow> Loop { get; }
    public CircularMembershipPageViewModel<SavedCircularMembershipGroups, CircularMembershipGroupMark, CircularMembershipGroupRow>? Groups { get; private set; }
    public bool HasDetails => Groups is not null;
    public CircularMembershipPageViewModel<SavedCircularMembershipLinks, CircularMembershipLinkMark, CircularMembershipLinkRow>? Links { get; private set; }
    public CircularMembershipPageViewModel<SavedCircularMembershipWitnesses, CircularMembershipWitnessMark, CircularMembershipWitnessRow>? Witnesses { get; private set; }
    public bool HasLinks => Links is not null;
    public bool HasWitnesses => Witnesses is not null;
    public bool HasMemberOf => Witnesses?.Rows.Any(value => value.Attribute == "memberOf") == true;
    public bool IsLoading { get; private set; }
    public string LoadingText => NavigationText.Get("SavedLoading");
    public string? Refusal { get; private set; }
    public bool HasRefusal => Refusal is not null;
    public Task ReadCompletion { get; private set; } = Task.CompletedTask;
    private bool IsCurrent() => _active && _current();
    internal bool ContainsGroup(CircularMembershipGroup group) => IsCurrent()
        && (Groups?.Rows.Any(value => value.Saved.Group == group) == true
            || Loop.Rows.Any(value => value.Saved.Link.ContainingGroup == group || value.Saved.Link.Member == group));
    internal bool ContainsLoopLink(SavedCircularMembershipLink link) => IsCurrent() && Loop.Rows.Any(value => value.Saved.Link == link);
    private void Review(SavedCircularMembershipLink link) { if (ContainsLoopLink(link)) _reads.ReviewMembership(link); }
    private bool CanOpen(SavedCircularMembershipGroup group) => ContainsGroup(group.Group);
    private void Open(SavedCircularMembershipGroup group) { if (CanOpen(group)) _reads.OpenGroup(group.Group); }
    private bool CanViewDetails() => IsCurrent() && !IsLoading && Groups is null;
    [RelayCommand(CanExecute = nameof(CanViewDetails))]
    private void ViewDetails() { if (CanViewDetails()) ReadCompletion = Load(null, true); }
    private bool CanViewLinks() => IsCurrent() && !IsLoading && Links is null;
    [RelayCommand(CanExecute = nameof(CanViewLinks))]
    private void ViewLinks() { if (CanViewLinks()) ReadCompletion = Load(null); }
    private bool CanSelect(SavedCircularMembershipLink link) => IsCurrent() && !IsLoading
        && Links?.Rows.Any(value => value.Saved == link) == true;
    private void Select(SavedCircularMembershipLink link) { if (CanSelect(link)) ReadCompletion = Load(link); }
    private async Task Load(SavedCircularMembershipLink? selected, bool details = false)
    {
        _pending?.Cancel();
        Witnesses?.Suspend(); Witnesses = null; _selectedLink = selected;
        using var pending = new CancellationTokenSource();
        _pending = pending; var revision = ++_revision;
        IsLoading = true; Refusal = null; Announce();
        try
        {
            if (!IsCurrent()) return;
            if (details)
            {
                var answer = await _reads.Groups(null, pending.Token);
                if (!IsCurrent() || pending.IsCancellationRequested || revision != _revision) return;
                if (!answer.IsSuccess) throw new InvalidDataException(answer.Error.Description);
                if (answer.Value.Context != _context || !answer.Value.IsExpectedPage(null)) throw Invalid();
                Groups = new(answer.Value, _reads.Groups, IsCurrent, page => page.Next,
                    (page, after) => page.Context == _context && page.IsExpectedPage(after),
                    page => page.Groups.Select(value => new CircularMembershipGroupRow(value, Open, CanOpen)).ToArray(), changed: null);
            }
            else if (selected is null)
            {
                var answer = await _reads.Links(null, pending.Token);
                if (!IsCurrent() || pending.IsCancellationRequested || revision != _revision) return;
                if (!answer.IsSuccess) throw new InvalidDataException(answer.Error.Description);
                if (answer.Value.Context != _context || !answer.Value.IsExpectedPage(null)) throw Invalid();
                Links = new(answer.Value, _reads.Links, IsCurrent, page => page.Next,
                    (page, after) => page.Context == _context && page.IsExpectedPage(after),
                    page => page.Links.Select(value => new CircularMembershipLinkRow(value, Select, CanSelect)).ToArray(), ClearWitnesses);
            }
            else
            {
                var answer = await _reads.Witnesses(selected.ContainingGroup.ObjectGuid, selected.Member.ObjectGuid, null, pending.Token);
                if (!IsCurrent() || pending.IsCancellationRequested || revision != _revision) return;
                if (!answer.IsSuccess) throw new InvalidDataException(answer.Error.Description);
                if (answer.Value.Context != _context || answer.Value.Link != selected || !answer.Value.IsExpectedPage(null)) throw Invalid();
                Witnesses = new(answer.Value,
                    (after, token) => _reads.Witnesses(selected.ContainingGroup.ObjectGuid, selected.Member.ObjectGuid, after, token),
                    IsCurrent, page => page.Next,
                    (page, after) => page.Context == _context && page.Link == selected && page.IsExpectedPage(after),
                    page => page.Witnesses.Select(value => new CircularMembershipWitnessRow(value)).ToArray(), Announce);
            }
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested) { }
        catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException or InvalidOperationException
            or ArgumentException or Microsoft.Data.Sqlite.SqliteException)
        { if (IsCurrent() && !pending.IsCancellationRequested && revision == _revision) Refusal = error.Message; }
        finally
        {
            if (ReferenceEquals(_pending, pending)) { _pending = null; IsLoading = false; Announce(); }
        }
    }
    private void ClearWitnesses()
    {
        _revision++; _pending?.Cancel(); Witnesses?.Suspend(); Witnesses = null; _selectedLink = null; Announce();
    }
    internal void Suspend()
    {
        _active = false; _revision++; _pending?.Cancel(); Loop.Suspend(); Groups?.Suspend(); Links?.Suspend(); Witnesses?.Suspend(); Announce();
    }
    private void Announce()
    {
        OnPropertyChanged(nameof(Chain)); OnPropertyChanged(nameof(HasOtherLoops)); OnPropertyChanged(nameof(IsPagedLoop));
        OnPropertyChanged(nameof(Groups)); OnPropertyChanged(nameof(HasDetails));
        OnPropertyChanged(nameof(Links)); OnPropertyChanged(nameof(HasLinks)); OnPropertyChanged(nameof(Witnesses));
        OnPropertyChanged(nameof(HasWitnesses)); OnPropertyChanged(nameof(SelectedRelationship));
        OnPropertyChanged(nameof(HasMemberOf));
        OnPropertyChanged(nameof(IsLoading)); OnPropertyChanged(nameof(Refusal)); OnPropertyChanged(nameof(HasRefusal));
        ViewLinksCommand.NotifyCanExecuteChanged();
        ViewDetailsCommand.NotifyCanExecuteChanged();
    }
    private static InvalidDataException Invalid() => new(SavedCircularMembershipContext.InvalidDetails);
}
