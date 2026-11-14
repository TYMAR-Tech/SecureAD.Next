using System.Globalization;
using System.IO;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Shell.ViewModels;

internal sealed class SpnOwnerRowViewModel(DuplicateSpnOwner owner, Guid subject)
{
    public string RegisteredObject => owner.AccountName ?? owner.DistinguishedName;
    public string ObjectType => owner.ObjectClass;
    public string Domain => owner.DomainFqdn;
    public string Location => owner.DistinguishedName;
    public bool IsSubject => owner.ObjectGuid == subject;
    public string SubjectNote => "This finding's object";
}

internal sealed class SpnRegistrationRowViewModel(SavedSpnRegistration saved)
{
    public string RegisteredObject => (saved.Owner.AccountName ?? saved.Owner.DistinguishedName)
        + " [" + saved.Owner.DomainFqdn + "] " + saved.Owner.DistinguishedName;
    public string CapturedSpn => saved.Value;
}

internal sealed class DuplicateSpnRowsViewModel : SavedFindingPageViewModel<SavedDuplicateSpn, DuplicateSpnMark>
{
    private readonly SavedDuplicateSpn _first;
    internal DuplicateSpnRowsViewModel(SavedDuplicateSpn first,
        Func<DuplicateSpnMark?, CancellationToken, Task<Result<SavedDuplicateSpn>>> read, Func<bool> current)
        : base(first, (position, token) => read(position ?? first.Position, token), current) => _first = first;
    public IReadOnlyList<SpnOwnerRowViewModel> Owners => IsActive
        ? Page.Owners.Select(owner => new SpnOwnerRowViewModel(owner, Page.Context.AffectedObject.ObjectGuid)).ToArray() : [];
    public IReadOnlyList<SpnRegistrationRowViewModel> Registrations => IsActive
        ? Page.Registrations.Select(value => new SpnRegistrationRowViewModel(value)).ToArray() : [];
    protected override DuplicateSpnMark? NextFor(SavedDuplicateSpn page) => page.Next;
    protected override bool Accepts(SavedDuplicateSpn page, DuplicateSpnMark? requested) =>
        page is { Context: not null } && page.Context.SameAs(_first.Context) && page.SpnIndex == _first.SpnIndex && page.MatchKey == _first.MatchKey
        && page.Kind == _first.Kind && page.SpnCount == _first.SpnCount && page.TotalRows == _first.TotalRows
        && page.IsExpectedPage(requested ?? _first.Position);
    protected override string InvalidDetails => SavedDuplicateSpn.InvalidDetails;
    protected override void AnnouncePage()
    {
        OnPropertyChanged(nameof(Owners));
        OnPropertyChanged(nameof(Registrations));
    }
}

internal sealed partial class DuplicateSpnViewModel : SavedFindingPageViewModel<SavedDuplicateSpn, DuplicateSpnMark>
{
    private readonly Func<DuplicateSpnMark?, CancellationToken, Task<Result<SavedDuplicateSpn>>> _read;
    private readonly Func<bool> _current;
    private readonly DuplicateSpnContext _context;
    private SavedDuplicateSpn _displayed;
    private CancellationTokenSource? _pendingRegistrations;

    internal DuplicateSpnViewModel(SavedDuplicateSpn first,
        Func<DuplicateSpnMark?, CancellationToken, Task<Result<SavedDuplicateSpn>>> read, Func<bool> current)
        : base(first, read, current)
    {
        (_read, _current, _context, _displayed) = (read, current, first.Context, first);
        Owners = new(first, read, current);
    }

    public string AffectedObject => _context.AffectedObject.AccountName ?? _context.AffectedObject.DistinguishedName;
    public string ObjectType => _context.AffectedObject.ObjectClass;
    public string Domain => _context.AffectedObject.DomainFqdn;
    public string Location => _context.AffectedObject.DistinguishedName;
    public string Forest => _context.ForestFqdn;
    public string Statement => SavedDuplicateSpn.Statement;
    public string ScopeNote => SavedDuplicateSpn.ScopeNote;
    public string LimitationsNote => SavedDuplicateSpn.LimitationsNote;
    public IReadOnlyList<string> Limitations => _context.Limitations;
    public bool HasLimitations => Limitations.Count > 0;
    public string MatchKey => Page.MatchKey;
    public string SpnLabel => "SPN " + (Page.SpnIndex + 1).ToString(CultureInfo.InvariantCulture);
    public DuplicateSpnRowsViewModel Owners { get; private set; }
    public DuplicateSpnRowsViewModel? Registrations { get; private set; }
    public bool HasRegistrations => Registrations is not null;
    public bool IsLoadingRegistrations { get; private set; }
    public string? RegistrationRefusal { get; private set; }
    public bool HasRegistrationRefusal => RegistrationRefusal is not null;
    public Task RegistrationReadCompletion { get; private set; } = Task.CompletedTask;
    private bool CanLoadRegistrations() => IsActive && !IsLoading && !IsLoadingRegistrations && Registrations is null;

    [RelayCommand(CanExecute = nameof(CanLoadRegistrations))]
    private void LoadRegistrations()
    {
        if (CanLoadRegistrations()) RegistrationReadCompletion = ReadRegistrationsAsync();
    }

    private async Task ReadRegistrationsAsync()
    {
        using var pending = new CancellationTokenSource();
        _pendingRegistrations = pending;
        var selected = Page;
        var request = selected.Position with { Kind = DuplicateSpnPageKind.CapturedRegistrations, Offset = 0 };
        IsLoadingRegistrations = true;
        RegistrationRefusal = null;
        AnnounceRegistrations();
        try
        {
            if (!_current()) return;
            var answer = await _read(request, pending.Token);
            if (!IsActive || pending.IsCancellationRequested || !ReferenceEquals(selected, Page) || !_current()) return;
            if (!answer.IsSuccess) throw new InvalidDataException(answer.Error.Description);
            if (answer.Value is not { Context: not null } || !answer.Value.Context.SameAs(_context) || answer.Value.MatchKey != selected.MatchKey
                || answer.Value.SpnCount != selected.SpnCount
                || !answer.Value.IsExpectedPage(request)) throw new InvalidDataException(SavedDuplicateSpn.InvalidDetails);
            Registrations = new(answer.Value, _read, _current);
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested) { }
        catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException
            or InvalidOperationException or ArgumentException or Microsoft.Data.Sqlite.SqliteException)
        {
            if (IsActive && !pending.IsCancellationRequested && ReferenceEquals(selected, Page) && _current())
                RegistrationRefusal = error.Message;
        }
        finally
        {
            if (ReferenceEquals(_pendingRegistrations, pending))
            {
                _pendingRegistrations = null;
                IsLoadingRegistrations = false;
                AnnounceRegistrations();
            }
        }
    }

    protected override DuplicateSpnMark? NextFor(SavedDuplicateSpn page) => page.NextSpn;
    protected override bool Accepts(SavedDuplicateSpn page, DuplicateSpnMark? requested) =>
        page is { Context: not null } && page.Context.SameAs(_context) && page.Kind == DuplicateSpnPageKind.RegisteredObjects && page.Offset == 0
        && page.SpnCount == _displayed.SpnCount && page.IsExpectedPage(requested);
    protected override string InvalidDetails => SavedDuplicateSpn.InvalidDetails;
    protected override void AnnouncePage()
    {
        if (!IsActive || !ReferenceEquals(_displayed, Page))
        {
            Owners.Suspend();
            Registrations?.Suspend();
            _pendingRegistrations?.Cancel();
            _pendingRegistrations = null;
            IsLoadingRegistrations = false;
            Registrations = null;
            RegistrationRefusal = null;
            _displayed = Page;
            if (IsActive) Owners = new(Page, _read, _current);
        }
        OnPropertyChanged(nameof(MatchKey));
        OnPropertyChanged(nameof(SpnLabel));
        OnPropertyChanged(nameof(Owners));
        AnnounceRegistrations();
    }

    private void AnnounceRegistrations()
    {
        OnPropertyChanged(nameof(Registrations));
        OnPropertyChanged(nameof(HasRegistrations));
        OnPropertyChanged(nameof(IsLoadingRegistrations));
        OnPropertyChanged(nameof(RegistrationRefusal));
        OnPropertyChanged(nameof(HasRegistrationRefusal));
        LoadRegistrationsCommand.NotifyCanExecuteChanged();
    }
}
