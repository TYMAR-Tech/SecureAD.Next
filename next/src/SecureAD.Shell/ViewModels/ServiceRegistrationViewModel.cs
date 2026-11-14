using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Shell.ViewModels;

internal sealed record ServiceRegistrationReads(
    Func<ServiceNameMark?, CancellationToken, Task<Result<SavedServiceRegistrations>>> Names,
    Func<InitialMembershipMark?, CancellationToken, Task<Result<SavedInitialMemberships>>> Memberships,
    Func<int, MembershipRouteMark?, CancellationToken, Task<Result<SavedMembershipRoutes>>> Routes,
    Func<int, int, MembershipStepMark?, CancellationToken, Task<Result<SavedMembershipSteps>>> Steps);

internal sealed record ServiceNameViewModel(string Value);
internal sealed record ServiceMembershipViewModel(SavedInitialMembership Saved, IRelayCommand ViewCommand)
{
    public string Identity => ServiceRegistrationViewModel.Identity(Saved.Principal);
    public string ExactIdentity => Saved.Principal.DistinguishedName ?? Saved.Principal.Sid;
    public bool IsPrimaryGroup => Saved.IsPrimaryGroup;
    public string PrimaryNote => "Primary-group membership; not an ordinary member entry.";
}
internal sealed record ServiceRouteViewModel(SavedMembershipRoute Saved, IRelayCommand ViewCommand)
{
    public string Root => Saved.RootName + (Saved.RootPrincipal is { } principal
        ? " (" + (principal.Scope ?? (principal.DistinguishedName is { } dn ? DnHelper.DnToFqdn(dn) : principal.Sid)) + ")" : "");
    public string Authorization => Saved.Authorization switch
    {
        MembershipRouteAuthorization.SecurityEnabled => "Security-enabled membership chain; this is not an effective-access calculation.",
        MembershipRouteAuthorization.DistributionGroup => "Contains a distribution group: this chain does not confer membership-based authorization.",
        MembershipRouteAuthorization.UnknownGroupType => "Group type was not captured: membership-based authorization is unknown.",
        _ => throw new InvalidDataException(SavedServiceRegistrations.InvalidDetails),
    };
    public string Protection => Saved.EstablishesProtection ? "Protection established by this chain." : "Protection not established by this chain.";
}
internal sealed record ServiceStepViewModel(SavedMembershipStep Saved)
{
    public string Identity => (Saved.Ordinal == 0 ? "" : Saved.IsPrimaryGroup ? "--primary group--> " : "--member of--> ")
        + ServiceRegistrationViewModel.Identity(Saved.Principal);
    public string ExactIdentity => Saved.Principal.DistinguishedName ?? Saved.Principal.Sid;
    public bool IsPrimaryGroup => Saved.IsPrimaryGroup;
    public string PrimaryNote => "Primary-group membership; not an ordinary member entry.";
}

internal sealed class ServicePageViewModel<TPage, TMark, TRow> : SavedFindingPageViewModel<TPage, TMark> where TMark : struct
{
    private readonly Func<TPage, IReadOnlyList<TRow>> _rows;
    private readonly Func<TPage, TMark?> _next;
    private readonly Func<TPage, TMark?, bool> _accepts;
    private readonly Action? _changed;
    internal ServicePageViewModel(TPage first, Func<TMark?, CancellationToken, Task<Result<TPage>>> read, Func<bool> current,
        Func<TPage, IReadOnlyList<TRow>> rows, Func<TPage, TMark?> next, Func<TPage, TMark?, bool> accepts, Action? changed)
        : base(first, read, current)
    {
        (_rows, _next, _accepts, _changed) = (rows, next, accepts, changed);
        Rows = rows(first);
    }
    public IReadOnlyList<TRow> Rows { get; private set; }
    public bool IsContinuation => PageLabel != "Page 1";
    protected override TMark? NextFor(TPage page) => _next(page);
    protected override bool Accepts(TPage page, TMark? after) => _accepts(page, after);
    protected override string InvalidDetails => SavedServiceRegistrations.InvalidDetails;
    protected override void AnnouncePage()
    {
        Rows = IsActive ? _rows(Page) : [];
        _changed?.Invoke();
        OnPropertyChanged(nameof(Rows));
        OnPropertyChanged(nameof(IsContinuation));
    }
}

internal sealed partial class ServiceRegistrationViewModel : ObservableObject
{
    private readonly ServiceRegistrationContext _context;
    private readonly ServiceRegistrationReads _reads;
    private readonly Func<bool> _current;
    private CancellationTokenSource? _pending;
    private bool _active = true;
    internal ServiceRegistrationViewModel(SavedServiceRegistrations first, ServiceRegistrationReads reads, Func<bool> current)
    {
        (_context, _reads, _current) = (first.Context, reads, current);
        Names = new(first, reads.Names, current, page => page.Names.Select(value => new ServiceNameViewModel(value.Value)).ToArray(),
            page => page.Next, (page, after) => ValidNames(page, _context, after), changed: null);
    }
    public string Account => _context.Name;
    public string Sid => _context.Sid;
    public string Domain => _context.Account.DomainFqdn;
    public string Location => _context.Account.DistinguishedName;
    public string SavedProtection => "AdminSDHolder-protected";
    public string AccountState => _context.SavedAccountControl == 0 ? "Not established by this finding."
        : (_context.SavedAccountControl & 2) != 0 ? "Disabled" : "Enabled";
    public bool HasDirectProtection => _context.DirectProtectionName is not null;
    public string DirectProtection => $"Protected in its own right: {_context.DirectProtectionName}. Membership changes do not remove this direct protection basis.";
    public bool HasUnreadableNames => _context.UnreadableServiceNames > 0;
    public string UnreadableNames => $"{_context.UnreadableServiceNames} additional service-name values could not be read; the displayed values are not a complete list.";
    public string MembershipNote => ServiceRegistrationPresentation.MembershipNote;
    public string MembershipCount => "Recorded initial memberships: " + _context.InitialMembershipCount;
    public string MembershipCompleteness => new MembershipRouteSummary([], _context.MembershipLimits).CompletenessDescription;
    public bool HasMemberships => Memberships is not null;
    public bool MembershipNotOpened => Memberships is null;
    public bool HasNoMemberships => Memberships is not null && _context.InitialMembershipCount == 0;
    public string EmptyMemberships => "No initial-membership chains were saved for this finding.";
    public bool HasPartialEmpty => HasNoMemberships && _context.MembershipLimits != MembershipRouteIncompleteReason.None;
    public string PartialEmpty => "This is not proof that no additional memberships exist.";
    public bool HasRoutes => Routes is not null;
    public bool HasSteps => Steps is not null;
    public string? SelectedMembership { get; private set; }
    public string? SelectedRoot { get; private set; }
    public string ContinuedSteps => "Continued saved chain; earlier steps are on previous pages.";
    public bool IsLoading { get; private set; }
    public string LoadingText => NavigationText.Get("SavedLoading");
    public string? Refusal { get; private set; }
    public bool HasRefusal => Refusal is not null;
    public Task ReadCompletion { get; private set; } = Task.CompletedTask;
    public ServicePageViewModel<SavedServiceRegistrations, ServiceNameMark, ServiceNameViewModel> Names { get; }
    public ServicePageViewModel<SavedInitialMemberships, InitialMembershipMark, ServiceMembershipViewModel>? Memberships { get; private set; }
    public ServicePageViewModel<SavedMembershipRoutes, MembershipRouteMark, ServiceRouteViewModel>? Routes { get; private set; }
    public ServicePageViewModel<SavedMembershipSteps, MembershipStepMark, ServiceStepViewModel>? Steps { get; private set; }

    private bool CanViewMembership() => _active && !IsLoading && Memberships is null;
    [RelayCommand(CanExecute = nameof(CanViewMembership))]
    private void ViewMembership()
    {
        if (!_active || IsLoading || Memberships is not null || !_current()) return;
        ReadCompletion = Load(_reads.Memberships(null, Token()), page =>
        {
            if (!ValidGroups(page, null)) throw new InvalidDataException(SavedServiceRegistrations.InvalidDetails);
            Memberships = new(page, _reads.Memberships, _current, value => value.Memberships.Select(group =>
                new ServiceMembershipViewModel(group, new RelayCommand(() => ViewRoutes(group)))).ToArray(), value => value.Next, ValidGroups, ClearRoutes);
        });
    }
    private void ViewRoutes(SavedInitialMembership group)
    {
        if (!_active || IsLoading || !_current()) return;
        ClearRoutes(); SelectedMembership = Identity(group.Principal);
        ReadCompletion = Load(_reads.Routes(group.Ordinal, null, Token()), page =>
        {
            if (!ValidRoutes(page, group, null)) throw new InvalidDataException(SavedServiceRegistrations.InvalidDetails);
            Routes = new(page, (after, token) => _reads.Routes(group.Ordinal, after, token), _current,
                value => value.Routes.Select(route => new ServiceRouteViewModel(route, new RelayCommand(() => ViewSteps(group, route)))).ToArray(),
                value => value.Next, (value, after) => ValidRoutes(value, group, after), ClearSteps);
        });
    }
    private void ViewSteps(SavedInitialMembership group, SavedMembershipRoute route)
    {
        if (!_active || IsLoading || !_current()) return;
        ClearSteps(); SelectedRoot = new ServiceRouteViewModel(route, new RelayCommand(() => { })).Root;
        ReadCompletion = Load(_reads.Steps(group.Ordinal, route.Ordinal, null, Token()), page =>
        {
            if (!ValidSteps(page, group, route, null)) throw new InvalidDataException(SavedServiceRegistrations.InvalidDetails);
            Steps = new(page, (after, token) => _reads.Steps(group.Ordinal, route.Ordinal, after, token), _current,
                value => value.Steps.Select(step => new ServiceStepViewModel(step)).ToArray(), value => value.Next,
                (value, after) => ValidSteps(value, group, route, after), changed: null);
        });
    }
    private CancellationToken Token()
    {
        _pending?.Cancel(); _pending?.Dispose(); _pending = new();
        return _pending.Token;
    }
    private async Task Load<T>(Task<Result<T>> read, Action<T> publish)
    {
        var pending = _pending!;
        IsLoading = true; Refusal = null; Announce();
        try
        {
            if (!_current()) return;
            var answer = await read;
            if (!_active || pending.IsCancellationRequested || !ReferenceEquals(_pending, pending) || !_current()) return;
            if (!answer.IsSuccess) throw new InvalidDataException(answer.Error.Description);
            publish(answer.Value);
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested) { }
        catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException
            or InvalidOperationException or ArgumentException or Microsoft.Data.Sqlite.SqliteException)
        {
            if (_active && !pending.IsCancellationRequested && ReferenceEquals(_pending, pending) && _current()) Refusal = error.Message;
        }
        finally { if (ReferenceEquals(_pending, pending)) { IsLoading = false; Announce(); } }
    }
    private void ClearRoutes()
    {
        Routes?.Suspend(); Routes = null; SelectedMembership = null; ClearSteps();
        Announce();
    }
    private void ClearSteps()
    {
        Steps?.Suspend(); Steps = null; SelectedRoot = null;
        OnPropertyChanged(nameof(Steps)); OnPropertyChanged(nameof(HasSteps)); OnPropertyChanged(nameof(SelectedRoot));
    }
    internal void Suspend()
    {
        _active = false; _pending?.Cancel(); Names.Suspend(); Memberships?.Suspend(); ClearRoutes(); Announce();
    }
    private void Announce()
    {
        ViewMembershipCommand.NotifyCanExecuteChanged();
        foreach (var name in new[] { nameof(Memberships), nameof(HasMemberships), nameof(MembershipNotOpened), nameof(HasNoMemberships),
            nameof(HasPartialEmpty), nameof(Routes), nameof(HasRoutes), nameof(Steps), nameof(HasSteps), nameof(SelectedMembership),
            nameof(SelectedRoot), nameof(IsLoading), nameof(Refusal), nameof(HasRefusal) }) OnPropertyChanged(name);
    }
    internal static string Identity(MembershipRoutePrincipal principal) => principal.DistinguishedName is { } dn
        ? DnHelper.ExtractFirstRdn(dn) + " (" + (principal.Scope ?? DnHelper.DnToFqdn(dn)) + ")" : principal.Sid + (principal.Scope is { } scope ? " (" + scope + ")" : "");
    private static bool Slice(IEnumerable<int> ordinals, long total, int after, bool next)
    {
        var values = ordinals.ToArray(); var start = after + 1;
        return after >= -1 && total >= 0 && start <= total && values.Length == Math.Min(SavedServiceRegistrations.PageSize, total - start)
            && values.Select((value, index) => value == start + index).All(value => value)
            && next == (start + values.Length < total);
    }
    private static bool Mark(ServiceRegistrationContext context, Guid generation, long finding, Guid account) =>
        generation == context.Reference.GenerationId && finding == context.Reference.FindingId && account == context.Account.ObjectGuid;
    internal static bool ValidNames(SavedServiceRegistrations page, ServiceRegistrationContext context, ServiceNameMark? after) =>
        page is { Context: not null, Names: not null } && page.Context == context
        && page.Names.All(value => value is not null && !string.IsNullOrWhiteSpace(value.Value))
        && Slice(page.Names.Select(value => value.Ordinal), context.ServiceNameCount, after?.Ordinal ?? -1, page.Next is not null)
        && (page.Next is not { } mark || Mark(context, mark.GenerationId, mark.FindingId, mark.AccountGuid) && mark.Ordinal == page.Names[^1].Ordinal);
    private bool ValidGroups(SavedInitialMemberships page, InitialMembershipMark? after) =>
        page is { Context: not null, Memberships: not null } && page.Context == _context
        && page.Memberships.All(value => value is not null && value.Principal is not null && SecureAD.Kernel.Security.Sid.ToBytes(value.Principal.Sid) is not null && value.RouteCount > 0)
        && Slice(page.Memberships.Select(value => value.Ordinal), _context.InitialMembershipCount, after?.Ordinal ?? -1, page.Next is not null)
        && (page.Next is not { } mark || Mark(_context, mark.GenerationId, mark.FindingId, mark.AccountGuid) && mark.Ordinal == page.Memberships[^1].Ordinal);
    private bool ValidRoutes(SavedMembershipRoutes page, SavedInitialMembership group, MembershipRouteMark? after) =>
        page is { Context: not null, Routes: not null } && page.Context == _context && page.Membership == group
        && page.Routes.All(value => value is not null && value.RootPrincipal is not null
            && SecureAD.Kernel.Security.Sid.ToBytes(value.RootPrincipal.Sid) is not null
            && value.StepCount >= 2 && !string.IsNullOrWhiteSpace(value.RootName)
            && Enum.IsDefined(value.Authorization) && !(value.EstablishesProtection && group.IsPrimaryGroup))
        && Slice(page.Routes.Select(value => value.Ordinal), group.RouteCount, after?.Ordinal ?? -1, page.Next is not null)
        && (page.Next is not { } mark || Mark(_context, mark.GenerationId, mark.FindingId, mark.AccountGuid)
            && mark.MembershipOrdinal == group.Ordinal && mark.Ordinal == page.Routes[^1].Ordinal);
    private bool ValidSteps(SavedMembershipSteps page, SavedInitialMembership group, SavedMembershipRoute route, MembershipStepMark? after) =>
        page is { Context: not null, Steps: not null } && page.Context == _context && page.Membership == group && page.Route == route
        && page.Steps.All(value => value is not null && value.Principal is not null && SecureAD.Kernel.Security.Sid.ToBytes(value.Principal.Sid) is not null
            && !(value.IsPrimaryGroup && (value.Ordinal == 0 || route.EstablishesProtection))
            && (value.Ordinal != 0 || value.Principal.Sid == _context.Sid)
            && (value.Ordinal != 1 || value.Principal == group.Principal && value.IsPrimaryGroup == group.IsPrimaryGroup)
            && (value.Ordinal != route.StepCount - 1 || value.Principal == route.RootPrincipal))
        && Slice(page.Steps.Select(value => value.Ordinal), route.StepCount, after?.Ordinal ?? -1, page.Next is not null)
        && (page.Next is not { } mark || Mark(_context, mark.GenerationId, mark.FindingId, mark.AccountGuid)
            && mark.MembershipOrdinal == group.Ordinal && mark.RouteOrdinal == route.Ordinal && mark.Ordinal == page.Steps[^1].Ordinal);
}
