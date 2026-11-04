using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Shell.ViewModels;

internal sealed record HistoryValueViewModel(SavedHistoryValue saved)
{
    public int Ordinal => saved.Ordinal;
    public string Sid => saved.Sid;
    public string RecognisedType => saved.RecognisedType ?? "Not ranked by this rule.";
}

internal sealed class SidHistoryValuesViewModel : SavedFindingPageViewModel<SavedSidHistory, SidHistoryMark>
{
    private readonly SavedSidHistory _first;
    internal SidHistoryValuesViewModel(SavedSidHistory first,
        Func<SidHistoryMark?, CancellationToken, Task<Result<SavedSidHistory>>> read, Func<bool> current)
        : base(first, (position, token) => read(position ?? first.Start, token), current) => _first = first;
    public IReadOnlyList<HistoryValueViewModel> Values => IsActive
        ? Page.Values.Select(value => new HistoryValueViewModel(value)).ToArray() : [];
    protected override SidHistoryMark? NextFor(SavedSidHistory page) => page.Next;
    protected override bool Accepts(SavedSidHistory page, SidHistoryMark? after) => page is { Context: not null }
        && page.Context == _first.Context && page.Kind == _first.Kind && page.IsExpectedPage(after ?? _first.Start);
    protected override string InvalidDetails => SavedSidHistory.InvalidDetails;
    protected override void AnnouncePage() => OnPropertyChanged(nameof(Values));
}

internal sealed partial class SidHistoryViewModel : ObservableObject
{
    private readonly SavedSidHistory _first;
    private readonly Func<SidHistoryMark?, CancellationToken, Task<Result<SavedSidHistory>>> _read;
    private readonly Func<bool> _current;
    private CancellationTokenSource? _pending;
    private bool _active = true;
    internal SidHistoryViewModel(SavedSidHistory first,
        Func<SidHistoryMark?, CancellationToken, Task<Result<SavedSidHistory>>> read, Func<bool> current)
    {
        (_first, _read, _current) = (first, read, current);
        Flagged = new(first, read, current);
    }

    public string AffectedObject => _first.Context.Name;
    public string ObjectType => _first.Context.Object.ObjectClass;
    public string Domain => _first.Context.Object.DomainFqdn;
    public string Location => _first.Context.Object.DistinguishedName;
    public string ObjectSid => _first.Context.ObjectSid ?? "Not established from captured evidence.";
    public int UnreadableValues => _first.Context.UnreadableValues;
    public string Statement => SavedSidHistory.Statement;
    public string ScopeNote => SavedSidHistory.ScopeNote;
    public bool HasUnreadable => UnreadableValues > 0;
    public bool HasCaptureLimit => _first.Context.Coverage != EvidenceCompleteness.Complete;
    public bool HasLimitations => HasUnreadable || HasCaptureLimit;
    public string UnreadableNote => SavedSidHistory.UnreadableNote;
    public string CaptureNote => SavedSidHistory.CaptureNote;
    public SidHistoryValuesViewModel Flagged { get; }
    public SidHistoryValuesViewModel? Other { get; private set; }
    public bool HasOther => Other is not null;
    public bool HasNoOther => Other is { Values.Count: 0 };
    public bool IsLoading { get; private set; }
    public string LoadingText => NavigationText.Get("SavedLoading");
    public string? Refusal { get; private set; }
    public bool HasRefusal => Refusal is not null;
    public Task ReadCompletion { get; private set; } = Task.CompletedTask;
    private bool CanLoadOther() => _active && !IsLoading && Other is null;

    [RelayCommand(CanExecute = nameof(CanLoadOther))]
    private void LoadOther()
    {
        if (CanLoadOther()) ReadCompletion = LoadOtherAsync();
    }

    private async Task LoadOtherAsync()
    {
        using var pending = new CancellationTokenSource();
        _pending = pending;
        var request = _first.Start with { Kind = SidHistoryPageKind.Other };
        IsLoading = true;
        Refusal = null;
        Announce();
        try
        {
            if (!_current()) return;
            var answer = await _read(request, pending.Token);
            if (!_active || pending.IsCancellationRequested || !_current()) return;
            if (!answer.IsSuccess) throw new InvalidDataException(answer.Error.Description);
            if (answer.Value is not { Context: not null } || answer.Value.Context != _first.Context
                || !answer.Value.IsExpectedPage(request)) throw new InvalidDataException(SavedSidHistory.InvalidDetails);
            Other = new(answer.Value, _read, _current);
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested) { }
        catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException
            or InvalidOperationException or ArgumentException or Microsoft.Data.Sqlite.SqliteException)
        {
            if (_active && !pending.IsCancellationRequested && _current()) Refusal = error.Message;
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

    internal void Suspend() { _active = false; _pending?.Cancel(); Flagged.Suspend(); Other?.Suspend(); Other = null; Announce(); }
    private void Announce()
    {
        OnPropertyChanged(nameof(Other)); OnPropertyChanged(nameof(HasOther)); OnPropertyChanged(nameof(HasNoOther));
        OnPropertyChanged(nameof(IsLoading)); OnPropertyChanged(nameof(Refusal)); OnPropertyChanged(nameof(HasRefusal));
        LoadOtherCommand.NotifyCanExecuteChanged();
    }
}
