using System.Globalization;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Naming;

namespace SecureAD.Shell.ViewModels;

internal sealed record ServiceAccountReads(
    Func<ServiceAccountMark?, CancellationToken, Task<Result<SavedServiceAccountPage<SavedServiceAccountName>>>> Names,
    Func<ServiceAccountMark?, CancellationToken, Task<Result<SavedServiceAccountPage<SavedServiceAccountLink>>>> Entries,
    Func<ServiceAccountMark?, CancellationToken, Task<Result<SavedServiceAccountPage<SavedServiceAccountLink>>>> Links,
    Func<long, ServiceAccountMark?, CancellationToken, Task<Result<SavedServiceAccountPage<SavedServiceAccountWitness>>>> Values,
    Func<ServiceAccountMark?, CancellationToken, Task<Result<SavedServiceAccountPage<AdministrativeMembershipLimitation>>>> Limitations);
internal sealed record ServiceAccountNameRow(SavedServiceAccountName Saved)
{
    public string Value => string.IsNullOrWhiteSpace(Saved.Text) ? "Unreadable captured value." : Saved.Text;
    public bool IsUnreadable => !Saved.IsReadable;
}
internal sealed record ServiceAccountValueRow(SavedServiceAccountWitness Saved)
{
    public string Source => Saved.Source.DistinguishedName;
    public string Attribute => Saved.Attribute;
    public string Value => Saved.Value;
}
internal sealed record ServiceAccountLimitationRow(AdministrativeMembershipLimitation Saved)
{
    public string Category => Saved.Reason is AdministrativeMembershipReason.CaptureIncomplete or AdministrativeMembershipReason.SourceIncomplete
        or AdministrativeMembershipReason.MembershipValuesUnavailable or AdministrativeMembershipReason.MembershipValuesMalformed
        or AdministrativeMembershipReason.MemberUncaptured or AdministrativeMembershipReason.PrimaryGroupUnavailable
        ? "Captured evidence gaps" : "Unsupported or unresolved membership";
    public string Reason => SavedBroadMembershipContext.DescribeLimitation(Saved.Reason);
    public string Location => Saved.DistinguishedName;
}
internal sealed record ServiceAccountRouteLimitRow(MembershipRouteIncompleteReason Saved)
{
    public string Category => Saved is MembershipRouteIncompleteReason.NodeBudgetReached or MembershipRouteIncompleteReason.EdgeBudgetReached
        or MembershipRouteIncompleteReason.StorageBudgetReached or MembershipRouteIncompleteReason.TimeBudgetReached
        ? "Saved processing limits" : Saved == MembershipRouteIncompleteReason.MembershipEvidenceIncomplete
            ? "Captured evidence gaps" : "Unsupported or unresolved membership";
    public string Reason => Saved switch
    {
        MembershipRouteIncompleteReason.NotDerived => "Routes were not derived.",
        MembershipRouteIncompleteReason.MembershipEvidenceIncomplete => "Membership evidence or capture coverage is incomplete.",
        MembershipRouteIncompleteReason.ForestIdentityUnknown => "The forest-root identity is unknown.",
        MembershipRouteIncompleteReason.NodeBudgetReached => "The visited-principal limit was reached.",
        MembershipRouteIncompleteReason.EdgeBudgetReached => "The examined-membership limit was reached.",
        MembershipRouteIncompleteReason.StorageBudgetReached => "The stored-evidence size limit was reached.",
        MembershipRouteIncompleteReason.TimeBudgetReached => "The expansion time limit was reached.",
        MembershipRouteIncompleteReason.CycleBoundary => "A membership cycle prevents a complete simple-route summary.",
        _ => throw new InvalidDataException(SavedServiceAccountContext.InvalidDetails),
    };
}
internal sealed class ServiceAccountLinkRow(SavedServiceAccountLink saved, bool isEntry,
    Action<SavedServiceAccountLink> select, Func<SavedServiceAccountLink, bool> current)
{
    internal SavedServiceAccountLink Saved { get; } = saved;
    internal static string Describe(SavedServiceAccountLink link) =>
        DnHelper.ExtractFirstRdn(link.Member.DistinguishedName) + " is a member of " + DnHelper.ExtractFirstRdn(link.ContainingGroup.DistinguishedName) + ".";
    public string Direction => Describe(saved);
    public SavedServiceAccountIdentity Member => saved.Member;
    public SavedServiceAccountIdentity ContainingGroup => saved.ContainingGroup;
    public SavedServiceAccountIdentity RecordedThrough => saved.RecordedThrough;
    public bool ShowsMember => !isEntry;
    public bool IsPrimaryGroup => saved.IsPrimaryGroup;
    public bool HasForeignReference => saved.Member.ObjectGuid != saved.RecordedThrough.ObjectGuid;
    public IRelayCommand ViewCommand { get; } = new RelayCommand(() => select(saved), () => current(saved));
}
internal sealed class ServiceAccountPageViewModel<T, TRow> : SavedFindingPageViewModel<SavedServiceAccountPage<T>, ServiceAccountMark>
{
    private readonly SavedServiceAccountContext _context;
    private readonly ServiceAccountPageKind _kind;
    private readonly SavedServiceAccountLink? _link;
    private readonly Func<T, TRow> _row;
    private readonly Action? _changed;
    private SavedServiceAccountPage<T> _published;
    internal ServiceAccountPageViewModel(SavedServiceAccountPage<T> first,
        Func<ServiceAccountMark?, CancellationToken, Task<Result<SavedServiceAccountPage<T>>>> read,
        Func<bool> current, Func<T, TRow> row, Action? changed) : base(first, read, current)
    {
        (_context, _kind, _link, _row, _changed, _published) = (first.Context, first.Kind, first.SelectedLink, row, changed, first);
        Rows = first.Rows.Select(value => row(value.Value)).ToArray();
    }
    public IReadOnlyList<TRow> Rows { get; private set; }
    protected override ServiceAccountMark? NextFor(SavedServiceAccountPage<T> page) => page.Next;
    protected override bool Accepts(SavedServiceAccountPage<T> page, ServiceAccountMark? after) =>
        page.Context == _context && page.Kind == _kind && page.SelectedLink == _link && page.IsExpectedPage(after);
    protected override string InvalidDetails => SavedServiceAccountContext.InvalidDetails;
    protected override void AnnouncePage()
    {
        var changed = !ReferenceEquals(_published, Page); _published = Page;
        Rows = IsActive ? Page.Rows.Select(value => _row(value.Value)).ToArray() : [];
        OnPropertyChanged(nameof(Rows));
        if (changed || !IsActive) _changed?.Invoke();
    }
}
internal sealed partial class ServiceAccountViewModel : ObservableObject
{
    private readonly SavedServiceAccountContext _context;
    private readonly ServiceAccountReads _reads;
    private readonly Func<bool> _current;
    private bool _active = true;
    private CancellationTokenSource? _pending;
    private long _revision;
    private SavedServiceAccountLink? _selected;
    private ServiceAccountPageKind? _selectedKind;

    internal ServiceAccountViewModel(SavedServiceAccountDetails first, ServiceAccountReads reads, Func<bool> current)
    {
        (_context, _reads, _current) = (first.Context, reads, current);
        if (first.EntryMemberships is { } entries)
            Entries = new(entries, reads.Entries, IsCurrent,
                value => LinkRow(value, ServiceAccountPageKind.EntryMemberships), () => PageChanged(ServiceAccountPageKind.EntryMemberships));
    }
    public bool IsAdministrative => _context.IsAdministrative;
    public bool IsPasswordSetting => !IsAdministrative;
    public string Heading => IsAdministrative ? "Saved administrative membership" : "Captured password setting";
    public string Statement => SavedServiceAccountContext.Statement(_context.RuleId);
    public SavedServiceAccountFacts Account => _context.Account;
    public string CapturedAt => Account.CapturedUtc.ToString("u", CultureInfo.InvariantCulture);
    public string AccountState => Account.UserAccountControl is not { } control ? "Not established from captured evidence."
        : (control & 2) != 0 ? "Disabled" : "Enabled";
    public string Association => Account.Kind switch
    {
        ServiceAccountKind.SpnBearingUser => "Ordinary user with captured service principal names",
        ServiceAccountKind.StandaloneManagedServiceAccount => "Standalone managed service account (sMSA)",
        ServiceAccountKind.GroupManagedServiceAccount => "Group managed service account (gMSA)",
        _ => throw new InvalidDataException(SavedServiceAccountContext.InvalidDetails),
    };
    public string AssociationNote => SavedServiceAccountContext.AssociationNote;
    public SavedServiceAccountIdentity? Target => _context.Target;
    public string TargetName => Target is null ? "" : DnHelper.ExtractFirstRdn(Target.DistinguishedName);
    public bool HasMissingInputs => Account.MissingInputs.Length > 0;
    public bool HasCaptureWarning => Account.Coverage != EvidenceCompleteness.Complete;
    public bool HasMembershipLimitations => IsAdministrative
        && (!_context.InputsComplete || _context.RouteIncompleteReasons != MembershipRouteIncompleteReason.None || _context.LimitationCount > 0);
    public bool HasLimitations => HasMissingInputs || HasCaptureWarning || HasMembershipLimitations;
    public bool HasRecordedLimitations => _context.LimitationCount > 0;
    public string LimitationsNote => SavedServiceAccountContext.LimitationsNote;
    public IReadOnlyList<ServiceAccountRouteLimitRow> RouteLimitations => Enum.GetValues<MembershipRouteIncompleteReason>()
        .Where(value => value != MembershipRouteIncompleteReason.None && _context.RouteIncompleteReasons.HasFlag(value))
        .Select(value => new ServiceAccountRouteLimitRow(value)).ToArray();
    public bool HasNames => Names is not null;
    public bool HasNoNames => Names is not null && Account.ServiceNameCount == 0;
    public bool HasLinks => Links is not null;
    public bool HasValues => Values is not null;
    public bool HasSavedLimitations => Limitations is not null;
    public string SelectedRelationship => _selected is null ? "" : ServiceAccountLinkRow.Describe(_selected);
    public ServiceAccountPageViewModel<SavedServiceAccountLink, ServiceAccountLinkRow>? Entries { get; }
    public ServiceAccountPageViewModel<SavedServiceAccountName, ServiceAccountNameRow>? Names { get; private set; }
    public ServiceAccountPageViewModel<SavedServiceAccountLink, ServiceAccountLinkRow>? Links { get; private set; }
    public ServiceAccountPageViewModel<SavedServiceAccountWitness, ServiceAccountValueRow>? Values { get; private set; }
    public ServiceAccountPageViewModel<AdministrativeMembershipLimitation, ServiceAccountLimitationRow>? Limitations { get; private set; }
    public bool IsLoading { get; private set; }
    public string LoadingText => NavigationText.Get("SavedLoading");
    public string? Refusal { get; private set; }
    public bool HasRefusal => Refusal is not null;
    public Task ReadCompletion { get; private set; } = Task.CompletedTask;

    private bool IsCurrent() => _active && _current();
    private bool CanViewNames() => IsCurrent() && !IsLoading && Names is null;
    [RelayCommand(CanExecute = nameof(CanViewNames))]
    private void ViewNames()
    {
        if (CanViewNames()) ReadCompletion = Load(ServiceAccountPageKind.Names, _reads.Names,
            page => Names = new(page, _reads.Names, IsCurrent, value => new(value), changed: null), link: null);
    }
    private bool CanViewLinks() => IsAdministrative && IsCurrent() && !IsLoading && Links is null;
    [RelayCommand(CanExecute = nameof(CanViewLinks))]
    private void ViewLinks()
    {
        if (CanViewLinks()) ReadCompletion = Load(ServiceAccountPageKind.Links, _reads.Links,
            page => Links = new(page, _reads.Links, IsCurrent,
                value => LinkRow(value, ServiceAccountPageKind.Links), () => PageChanged(ServiceAccountPageKind.Links)), link: null);
    }
    private bool CanViewLimitations() => IsAdministrative && HasRecordedLimitations && IsCurrent() && !IsLoading && Limitations is null;
    [RelayCommand(CanExecute = nameof(CanViewLimitations))]
    private void ViewLimitations()
    {
        if (CanViewLimitations()) ReadCompletion = Load(ServiceAccountPageKind.Limitations, _reads.Limitations,
            page => Limitations = new(page, _reads.Limitations, IsCurrent, value => new(value), changed: null), link: null);
    }
    private ServiceAccountLinkRow LinkRow(SavedServiceAccountLink link, ServiceAccountPageKind kind) =>
        new(link, kind == ServiceAccountPageKind.EntryMemberships, value => Select(value, kind), value => CanSelect(value, kind));
    private bool CanSelect(SavedServiceAccountLink link, ServiceAccountPageKind kind) => IsCurrent() && !IsLoading
        && (kind == ServiceAccountPageKind.EntryMemberships ? Entries : Links)?.Rows.Any(row => row.Saved == link) == true;
    private void Select(SavedServiceAccountLink link, ServiceAccountPageKind kind)
    {
        if (!CanSelect(link, kind)) return;
        ClearValues(); _selected = link; _selectedKind = kind;
        ReadCompletion = Load(ServiceAccountPageKind.Values, (after, token) => _reads.Values(link.Position, after, token),
            page => Values = new(page, (after, token) => _reads.Values(link.Position, after, token), IsCurrent, value => new(value), changed: null), link);
    }
    private async Task Load<T>(ServiceAccountPageKind kind,
        Func<ServiceAccountMark?, CancellationToken, Task<Result<SavedServiceAccountPage<T>>>> read,
        Action<SavedServiceAccountPage<T>> publish, SavedServiceAccountLink? link)
    {
        _pending?.Cancel();
        using var pending = new CancellationTokenSource(); _pending = pending; var revision = ++_revision;
        IsLoading = true; Refusal = null; Announce();
        try
        {
            if (!IsCurrent()) return;
            var answer = await read(null, pending.Token);
            if (!IsCurrent() || pending.IsCancellationRequested || revision != _revision) return;
            if (!answer.IsSuccess) throw new InvalidDataException(answer.Error.Description);
            if (answer.Value.Context != _context || answer.Value.Kind != kind || answer.Value.SelectedLink != link
                || !answer.Value.IsExpectedPage(null)) throw new InvalidDataException(SavedServiceAccountContext.InvalidDetails);
            publish(answer.Value);
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
    private void PageChanged(ServiceAccountPageKind kind) { if (_selectedKind == kind) ClearValues(); }
    private void ClearValues()
    { _revision++; _pending?.Cancel(); Values?.Suspend(); Values = null; _selected = null; _selectedKind = null; Announce(); }
    internal void Suspend()
    {
        _active = false; _revision++; _pending?.Cancel();
        Names?.Suspend(); Entries?.Suspend(); Links?.Suspend(); Values?.Suspend(); Limitations?.Suspend();
        Announce();
    }
    private void Announce()
    {
        OnPropertyChanged(nameof(Names)); OnPropertyChanged(nameof(HasNames)); OnPropertyChanged(nameof(HasNoNames));
        OnPropertyChanged(nameof(Links)); OnPropertyChanged(nameof(HasLinks)); OnPropertyChanged(nameof(Values)); OnPropertyChanged(nameof(HasValues));
        OnPropertyChanged(nameof(Limitations)); OnPropertyChanged(nameof(HasSavedLimitations)); OnPropertyChanged(nameof(SelectedRelationship));
        OnPropertyChanged(nameof(IsLoading)); OnPropertyChanged(nameof(Refusal)); OnPropertyChanged(nameof(HasRefusal));
        ViewNamesCommand.NotifyCanExecuteChanged(); ViewLinksCommand.NotifyCanExecuteChanged(); ViewLimitationsCommand.NotifyCanExecuteChanged();
    }
}
