using System.Globalization;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Kernel;

namespace SecureAD.Shell.ViewModels;

internal abstract partial class SavedFindingPageViewModel<TPage, TMark> : ObservableObject where TMark : struct
{
    private readonly Func<TMark?, CancellationToken, Task<Result<TPage>>> _read;
    private readonly Func<bool> _current;
    private readonly List<TMark?> _history = [null];
    private CancellationTokenSource? _pending;
    private int _position;
    protected TPage Page { get; private set; }
    protected bool IsActive { get; private set; } = true;

    protected SavedFindingPageViewModel(TPage first, Func<TMark?, CancellationToken, Task<Result<TPage>>> read, Func<bool> current) =>
        (Page, _read, _current) = (first, read, current);

    public string PageLabel => "Page " + (_position + 1).ToString(CultureInfo.InvariantCulture);
    public bool IsLoading { get; private set; }
    public string LoadingText { get; } = NavigationText.Get("SavedLoading");
    public string? Refusal { get; private set; }
    public bool HasRefusal => Refusal is not null;
    public Task ReadCompletion { get; private set; } = Task.CompletedTask;
    protected abstract TMark? NextFor(TPage page);
    protected abstract bool Accepts(TPage page, TMark? after);
    protected abstract string InvalidDetails { get; }
    protected abstract void AnnouncePage();
    private bool CanNextPage() => IsActive && !IsLoading && NextFor(Page) is not null;
    private bool CanPreviousPage() => IsActive && !IsLoading && _position > 0;

    [RelayCommand(CanExecute = nameof(CanNextPage))]
    private void NextPage() { if (CanNextPage()) ReadCompletion = LoadAsync(NextFor(Page), _position + 1); }
    [RelayCommand(CanExecute = nameof(CanPreviousPage))]
    private void PreviousPage() { if (CanPreviousPage()) ReadCompletion = LoadAsync(_history[_position - 1], _position - 1); }

    private async Task LoadAsync(TMark? after, int position)
    {
        _pending?.Cancel();
        using var pending = new CancellationTokenSource();
        _pending = pending;
        IsLoading = true;
        Refusal = null;
        Announce();
        try
        {
            if (!_current()) return;
            var answer = await _read(after, pending.Token);
            if (!IsActive || pending.IsCancellationRequested || !ReferenceEquals(_pending, pending)) return;
            if (!_current()) return;
            if (!answer.IsSuccess) throw new InvalidDataException(answer.Error.Description);
            if (!Accepts(answer.Value, after)) throw new InvalidDataException(InvalidDetails);
            if (position == _history.Count) _history.Add(after);
            else if (!EqualityComparer<TMark?>.Default.Equals(_history[position], after)) throw new InvalidDataException(InvalidDetails);
            _position = position;
            Page = answer.Value;
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested) { }
        catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException
            or InvalidOperationException or ArgumentException or Microsoft.Data.Sqlite.SqliteException)
        {
            if (IsActive && !pending.IsCancellationRequested && ReferenceEquals(_pending, pending) && _current())
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

    internal void Suspend() { IsActive = false; _pending?.Cancel(); Announce(); }
    private void Announce()
    {
        AnnouncePage();
        OnPropertyChanged(nameof(PageLabel));
        OnPropertyChanged(nameof(IsLoading));
        OnPropertyChanged(nameof(Refusal));
        OnPropertyChanged(nameof(HasRefusal));
        NextPageCommand.NotifyCanExecuteChanged();
        PreviousPageCommand.NotifyCanExecuteChanged();
    }
}
