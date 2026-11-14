using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Naming;

namespace SecureAD.Shell.ViewModels;

internal sealed record BroadMembershipReads(
    Func<BroadMembershipMark?, CancellationToken, Task<Result<SavedBroadMembershipPage<SavedBroadIdentity>>>> Sources,
    Func<BroadMembershipMark?, CancellationToken, Task<Result<SavedBroadMembershipPage<SavedBroadMembershipLink>>>> Links,
    Func<long, BroadMembershipMark?, CancellationToken, Task<Result<SavedBroadMembershipPage<SavedBroadMembershipWitness>>>> Values,
    Func<BroadMembershipMark?, CancellationToken, Task<Result<SavedBroadMembershipPage<AdministrativeMembershipLimitation>>>> Limitations);
internal sealed record BroadIdentityRow(SavedBroadIdentity Saved)
{
    public string Name => Saved.Name;
    public string Sid => Saved.Sid;
    public string? SidScope => Saved.SidScope;
    public bool HasSidScope => Saved.SidScope is not null;
}
internal sealed record BroadMembershipValueRow(SavedBroadMembershipWitness Saved)
{
    public string Source => Saved.Source.DistinguishedName;
    public string Attribute => Saved.Attribute;
    public string Value => Saved.Value;
}
internal sealed record BroadMembershipLimitationRow(AdministrativeMembershipLimitation Saved)
{
    public string Reason => SavedBroadMembershipContext.DescribeLimitation(Saved.Reason);
    public string Location => Saved.DistinguishedName;
}
internal sealed class BroadMembershipLinkRow(SavedBroadMembershipLink saved, Action<SavedBroadMembershipLink> select,
    Func<SavedBroadMembershipLink, bool> current)
{
    internal SavedBroadMembershipLink Saved { get; } = saved;
    internal static string Name(SavedBroadMembershipIdentity identity) => DnHelper.ExtractFirstRdn(identity.DistinguishedName);
    internal static string Describe(SavedBroadMembershipLink link) => Name(link.Member) + " is a member of " + Name(link.ContainingGroup) + ".";
    public string Direction => Describe(saved);
    public SavedBroadMembershipIdentity Member => saved.Member;
    public SavedBroadMembershipIdentity ContainingGroup => saved.ContainingGroup;
    public SavedBroadMembershipIdentity RecordedThrough => saved.RecordedThrough;
    public bool HasForeignReference => saved.Member.ObjectGuid != saved.RecordedThrough.ObjectGuid;
    public bool HasMemberDomain => saved.Member.DomainFqdn is not null;
    public bool HasReferenceDomain => saved.RecordedThrough.DomainFqdn is not null;
    public string ForeignReferenceNote => "This relationship uses a captured foreign-security-principal reference.";
    public IRelayCommand ViewCommand { get; } = new RelayCommand(() => select(saved), () => current(saved));
}
internal sealed class BroadMembershipPageViewModel<T, TRow> : SavedFindingPageViewModel<SavedBroadMembershipPage<T>, BroadMembershipMark>
{
    private readonly SavedBroadMembershipContext _context;
    private readonly SavedBroadMembershipLink? _link;
    private readonly Func<T, TRow> _row;
    private readonly Action? _changed;
    private SavedBroadMembershipPage<T> _published;
    internal BroadMembershipPageViewModel(SavedBroadMembershipPage<T> first,
        Func<BroadMembershipMark?, CancellationToken, Task<Result<SavedBroadMembershipPage<T>>>> read,
        Func<bool> current, Func<T, TRow> row, Action? changed) : base(first, read, current)
    {
        (_context, _link, _row, _changed, _published) = (first.Context, first.SelectedLink, row, changed, first);
        Rows = first.Rows.Select(value => row(value.Value)).ToArray();
    }
    public IReadOnlyList<TRow> Rows { get; private set; }
    protected override BroadMembershipMark? NextFor(SavedBroadMembershipPage<T> page) => page.Next;
    protected override bool Accepts(SavedBroadMembershipPage<T> page, BroadMembershipMark? after) =>
        page.Context == _context && page.SelectedLink == _link && page.IsExpectedPage(after);
    protected override string InvalidDetails => SavedBroadMembershipContext.InvalidDetails;
    protected override void AnnouncePage()
    {
        var changed = !ReferenceEquals(_published, Page); _published = Page;
        Rows = IsActive ? Page.Rows.Select(value => _row(value.Value)).ToArray() : [];
        OnPropertyChanged(nameof(Rows));
        if (changed || !IsActive) _changed?.Invoke();
    }
}
internal sealed partial class BroadMembershipViewModel : ObservableObject
{
    private readonly SavedBroadMembershipContext _context;
    private readonly BroadMembershipReads _reads;
    private readonly Func<bool> _current;
    private bool _active = true;
    private CancellationTokenSource? _pending;
    private long _revision;
    private SavedBroadMembershipLink? _selected;
    internal BroadMembershipViewModel(SavedBroadMembershipPage<SavedBroadIdentity> first,
        SavedBroadMembershipPage<AdministrativeMembershipLimitation>? limitations, BroadMembershipReads reads, Func<bool> current)
    {
        (_context, _reads, _current) = (first.Context, reads, current);
        Sources = new(first, reads.Sources, IsCurrent, value => new(value), changed: null);
        if (limitations is not null) Limitations = new(limitations, reads.Limitations, IsCurrent, value => new(value), changed: null);
    }
    public string Group => DnHelper.ExtractFirstRdn(_context.Target.DistinguishedName);
    public string Sid => _context.Target.Sid;
    public string? Domain => _context.Target.DomainFqdn;
    public string Location => _context.Target.DistinguishedName;
    public string SourcesNote => "These are the broad identities recorded by this finding. Their members are not expanded into accounts here.";
    public string GroupingNote => "This is one finding for the affected group, not one finding per account or recorded link.";
    public string LinksNote => "These are saved direct links supporting this broad-membership finding. Alternative links are retained; this is not a count of every possible route or a minimum set of changes.";
    public string ValuesNote => "These values support the selected direct relationship; they are not a complete membership list.";
    public string MemberOfNote => "memberOf records the same relationship from the member side.";
    public string LimitationsNote => "Recorded positive links remain findings. Other membership may not have been fully assessed.";
    public bool HasLimitations => _context.LimitationCount > 0;
    public bool HasLinks => Links is not null;
    public bool HasValues => Values is not null;
    public bool HasMemberOf => Values?.Rows.Any(value => value.Attribute == "memberOf") == true;
    public string SelectedRelationship => _selected is null ? "" : BroadMembershipLinkRow.Describe(_selected);
    public BroadMembershipPageViewModel<SavedBroadIdentity, BroadIdentityRow> Sources { get; }
    public BroadMembershipPageViewModel<AdministrativeMembershipLimitation, BroadMembershipLimitationRow>? Limitations { get; }
    public BroadMembershipPageViewModel<SavedBroadMembershipLink, BroadMembershipLinkRow>? Links { get; private set; }
    public BroadMembershipPageViewModel<SavedBroadMembershipWitness, BroadMembershipValueRow>? Values { get; private set; }
    public bool IsLoading { get; private set; }
    public string LoadingText => NavigationText.Get("SavedLoading");
    public string? Refusal { get; private set; }
    public bool HasRefusal => Refusal is not null;
    public Task ReadCompletion { get; private set; } = Task.CompletedTask;
    private bool IsCurrent() => _active && _current();
    private bool CanViewLinks() => IsCurrent() && !IsLoading && Links is null;
    [RelayCommand(CanExecute = nameof(CanViewLinks))]
    private void ViewLinks() { if (CanViewLinks()) ReadCompletion = Load(null); }
    private bool CanSelect(SavedBroadMembershipLink link) => IsCurrent() && !IsLoading && Links?.Rows.Any(row => row.Saved == link) == true;
    private void Select(SavedBroadMembershipLink link) { if (CanSelect(link)) ReadCompletion = Load(link); }
    private async Task Load(SavedBroadMembershipLink? link)
    {
        _pending?.Cancel(); Values?.Suspend(); Values = null; _selected = link;
        using var pending = new CancellationTokenSource(); _pending = pending; var revision = ++_revision;
        IsLoading = true; Refusal = null; Announce();
        try
        {
            if (!IsCurrent()) return;
            if (link is null)
            {
                var answer = await _reads.Links(null, pending.Token);
                if (!IsCurrent() || pending.IsCancellationRequested || revision != _revision) return;
                if (!answer.IsSuccess) throw new InvalidDataException(answer.Error.Description);
                if (answer.Value.Context != _context || !answer.Value.IsExpectedPage(null)) throw Invalid();
                Links = new(answer.Value, _reads.Links, IsCurrent, value => new(value, Select, CanSelect), ClearValues);
            }
            else
            {
                var answer = await _reads.Values(link.Position, null, pending.Token);
                if (!IsCurrent() || pending.IsCancellationRequested || revision != _revision) return;
                if (!answer.IsSuccess) throw new InvalidDataException(answer.Error.Description);
                if (answer.Value.Context != _context || answer.Value.SelectedLink != link || !answer.Value.IsExpectedPage(null)) throw Invalid();
                Values = new(answer.Value, (after, token) => _reads.Values(link.Position, after, token), IsCurrent, value => new(value), Announce);
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
    private void ClearValues() { _revision++; _pending?.Cancel(); Values?.Suspend(); Values = null; _selected = null; Announce(); }
    internal void Suspend()
    { _active = false; _revision++; _pending?.Cancel(); Sources.Suspend(); Limitations?.Suspend(); Links?.Suspend(); Values?.Suspend(); Announce(); }
    private void Announce()
    {
        OnPropertyChanged(nameof(Links)); OnPropertyChanged(nameof(HasLinks)); OnPropertyChanged(nameof(Values)); OnPropertyChanged(nameof(HasValues));
        OnPropertyChanged(nameof(SelectedRelationship)); OnPropertyChanged(nameof(HasMemberOf)); OnPropertyChanged(nameof(IsLoading));
        OnPropertyChanged(nameof(Refusal)); OnPropertyChanged(nameof(HasRefusal)); ViewLinksCommand.NotifyCanExecuteChanged();
    }
    private static InvalidDataException Invalid() => new(SavedBroadMembershipContext.InvalidDetails);
}
