using System.IO;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Shell.ViewModels;

/// <summary>One object's saved findings, with bounded continuation and explicit unread states.</summary>
internal sealed partial class FindingsSectionViewModel : ObjectSectionViewModel
{
    internal sealed class PagingState
    {
        internal FindingsPageMark? Position { get; set; }
        internal Stack<FindingsPageMark?> Back { get; } = [];
    }

    public const string NothingFound =
        "The rules ran over this object and none of them found anything.";

    public const string NobodyLooked =
        "No rule has been run over this bundle, so nothing is known about this object. What is "
        + "shown here is silence rather than a clean result.";

    private readonly PagingState _paging;
    private readonly Func<FindingsPageMark?, CancellationToken, Task<Result<FindingListPage>>>? _read;
    private readonly Func<bool>? _current;
    private CancellationTokenSource? _pending;
    private FindingsPageMark? _next;
    private bool _active = true;

    public FindingsSectionViewModel(ObjectSectionDefinition definition, FindingListPage? findings,
        string? refusal) : base(definition)
    {
        _paging = new();
        Apply(findings, refusal);
    }

    internal FindingsSectionViewModel(ObjectSectionDefinition definition, PagingState paging,
        Func<FindingsPageMark?, CancellationToken, Task<Result<FindingListPage>>> read,
        Func<bool> current) : base(definition)
    {
        ArgumentNullException.ThrowIfNull(paging);
        ArgumentNullException.ThrowIfNull(read);
        ArgumentNullException.ThrowIfNull(current);
        (_paging, _read, _current) = (paging, read, current);
        Start();
    }

    public IReadOnlyList<FindingRowViewModel> Findings { get; private set; } = [];
    public string? Refusal { get; private set; }
    public bool NobodyHasLooked { get; private set; }
    public bool HasFindings => Findings.Count > 0;
    public bool IsLoading { get; private set; }
    public string LoadingText => NavigationText.Get("SavedLoading");
    public int PageNumber => _paging.Back.Count + 1;
    public bool ShowsPaging => _read is not null && _active && (IsLoading || HasFindings || PageNumber > 1);
    public Task ReadCompletion { get; private set; } = Task.CompletedTask;

    public string? Verdict => !_active || IsLoading ? null
        : Refusal ?? (NobodyHasLooked ? NobodyLooked : HasFindings ? null : NothingFound);
    public bool HasVerdict => Verdict is not null;

    private void Apply(FindingListPage? page, string? refusal)
    {
        Refusal = refusal;
        Findings = page is null ? [] : [.. page.Findings.Select(finding => new FindingRowViewModel(finding))];
        NobodyHasLooked = page?.DidNotRun ?? false;
        _next = page?.Next;
    }

    private void Start() => ReadCompletion = LoadAsync();

    private async Task LoadAsync()
    {
        var read = _read ?? throw new InvalidOperationException("The finding page reader is not configured.");
        var current = _current ?? throw new InvalidOperationException("The finding page lifetime is not configured.");
        _pending?.Cancel();
        using var pending = new CancellationTokenSource();
        _pending = pending;
        IsLoading = true;
        Apply(null, null);
        Announce();
        try
        {
            if (!_active || !current()) throw new InvalidOperationException(SavedPathText.Get("GenerationChanged"));
            var answer = await read(_paging.Position, pending.Token);
            if (!_active || pending.IsCancellationRequested || !ReferenceEquals(_pending, pending)) return;
            if (!current()) throw new InvalidOperationException(SavedPathText.Get("GenerationChanged"));
            if (!answer.IsSuccess) Refusal = answer.Error.Description;
            else
            {
                var page = answer.Value;
                if (page.Findings.Count > FindingsQuery.DefaultPageSize
                    || page.Findings.Count == 0 && (_paging.Position is not null || page.Next is not null)
                    || page.Next is { } next && _paging.Position == next)
                    throw new InvalidDataException("The saved finding page does not match its bounded continuation.");
                Apply(page, null);
            }
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested) { }
        catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException
            or InvalidOperationException or ArgumentException or Microsoft.Data.Sqlite.SqliteException)
        {
            if (_active && !pending.IsCancellationRequested && ReferenceEquals(_pending, pending))
                Refusal = error.Message;
        }
        finally
        {
            if (ReferenceEquals(_pending, pending))
            {
                _pending = null;
                IsLoading = false;
                Announce();
            }
        }
    }

    internal void Suspend()
    {
        _active = false;
        _pending?.Cancel();
        Findings = [];
        _next = null;
        IsLoading = false;
        Announce();
    }

    private bool CanPrevious() => _read is not null && _active && !IsLoading && _paging.Back.Count > 0;
    private bool CanNext() => _read is not null && _active && !IsLoading && _next is not null;

    [RelayCommand(CanExecute = nameof(CanPrevious))]
    private void Previous()
    {
        if (!CanPrevious()) return;
        _paging.Position = _paging.Back.Pop();
        Start();
    }

    [RelayCommand(CanExecute = nameof(CanNext))]
    private void Next()
    {
        if (!CanNext()) return;
        _paging.Back.Push(_paging.Position);
        _paging.Position = _next;
        Start();
    }

    private void Announce()
    {
        OnPropertyChanged(nameof(Findings));
        OnPropertyChanged(nameof(Refusal));
        OnPropertyChanged(nameof(NobodyHasLooked));
        OnPropertyChanged(nameof(HasFindings));
        OnPropertyChanged(nameof(IsLoading));
        OnPropertyChanged(nameof(Verdict));
        OnPropertyChanged(nameof(HasVerdict));
        OnPropertyChanged(nameof(PageNumber));
        OnPropertyChanged(nameof(ShowsPaging));
        PreviousCommand.NotifyCanExecuteChanged();
        NextCommand.NotifyCanExecuteChanged();
    }
}
