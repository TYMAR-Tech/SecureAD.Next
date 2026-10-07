using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Shell.ViewModels;

internal sealed class GroupMemberRowViewModel(CapturedMemberReference value)
{
    internal CapturedMemberReference Value { get; } = value;
    public string Name => value.Name ?? value.RecordedName;
    public string Domain => value.DomainFqdn ?? "Not established";
    public string Kind => value.ObjectClass ?? "Unresolved reference";
    public string RecordedName => value.RecordedName;
    public bool CanOpen => value.DistinguishedName is not null;
}

internal sealed partial class GroupMembershipSectionViewModel : ObjectSectionViewModel
{
    private readonly ObjectAttributes _attributes;
    private readonly Func<IReadOnlyList<string>, CancellationToken, Task<Result<CapturedMemberReferences>>> _read;
    private readonly Action<string> _open;
    private readonly Func<bool> _current;
    private CancellationTokenSource? _pending;
    private int _page;
    private bool _parents;
    private bool _active = true;
    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private string? _error;
    [ObservableProperty] private GroupMemberRowViewModel? _selectedMember;
    public ObservableCollection<GroupMemberRowViewModel> Members { get; } = [];
    public Task ReadCompletion { get; private set; } = Task.CompletedTask;
    public string[] Views { get; } = ["Direct members", "Member of"];
    public string SelectedView
    {
        get => _parents ? Views[1] : Views[0];
        set { _parents = value == Views[1]; _page = 0; Start(); OnPropertyChanged(); }
    }
    private IReadOnlyList<AttributeValue> Values => _attributes.Find(_parents ? "memberOf" : "member")?.Values ?? [];
    public string PageDescription => $"{Values.Count:N0} recorded values - page {_page + 1}";
    public string Qualification => "Original member/memberOf values only; no nested total or effective permission is inferred. "
        + "Unresolved references cannot be opened. Primary-group relationships remain separate.";
    public string PrimaryGroup => _attributes.Find("primaryGroupID")?.OnlyValue?.Text is { } primary
        ? "Captured primaryGroupID: " + primary : "No primary-group identifier was recorded for this object.";
    public bool HasError => Error is not null;

    public GroupMembershipSectionViewModel(ObjectSectionDefinition definition, ObjectAttributes attributes,
        Func<IReadOnlyList<string>, CancellationToken, Task<Result<CapturedMemberReferences>>> read,
        Action<string> open, Func<bool> current) : base(definition)
    {
        (_attributes, _read, _open, _current) = (attributes, read, open, current);
        Start();
    }

    private void Start() => ReadCompletion = LoadAsync();
    private async Task LoadAsync()
    {
        _pending?.Cancel();
        using var pending = new CancellationTokenSource();
        _pending = pending;
        IsLoading = true;
        Error = null;
        Members.Clear();
        SelectedMember = null;
        Announce();
        try
        {
            if (!_active || !_current()) throw new InvalidOperationException(SavedPathText.Get("GenerationChanged"));
            var values = Values.Skip(_page * 50).Take(50).Select(value => value.Stored).ToArray();
            var answer = await _read(values, pending.Token);
            if (!_active || pending.IsCancellationRequested || !ReferenceEquals(_pending, pending)) return;
            if (!_current()) throw new InvalidOperationException(SavedPathText.Get("GenerationChanged"));
            if (!answer.IsSuccess) Error = answer.Error.Description;
            else foreach (var member in answer.Value.References) Members.Add(new(member));
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested) { }
        catch (InvalidOperationException failure) { if (_active && ReferenceEquals(_pending, pending)) Error = failure.Message; }
        finally
        {
            if (ReferenceEquals(_pending, pending)) { _pending = null; IsLoading = false; Announce(); }
        }
    }

    internal void Suspend() { _active = false; _pending?.Cancel(); Announce(); }
    private bool CanPrevious() => _active && !IsLoading && _page > 0;
    private bool CanNext() => _active && !IsLoading && (_page + 1) * 50 < Values.Count;
    private bool CanOpen(GroupMemberRowViewModel? row) => _active && !IsLoading && row is { CanOpen: true } && Members.Contains(row);
    [RelayCommand(CanExecute = nameof(CanPrevious))] private void Previous() { _page--; Start(); }
    [RelayCommand(CanExecute = nameof(CanNext))] private void Next() { _page++; Start(); }
    [RelayCommand(CanExecute = nameof(CanOpen))]
    private void OpenMember(GroupMemberRowViewModel? row)
    {
        if (!_current()) { Error = SavedPathText.Get("GenerationChanged"); Announce(); return; }
        _open(row!.Value.DistinguishedName!);
    }

    partial void OnErrorChanged(string? value) => OnPropertyChanged(nameof(HasError));
    private void Announce()
    {
        OnPropertyChanged(nameof(PageDescription));
        PreviousCommand.NotifyCanExecuteChanged();
        NextCommand.NotifyCanExecuteChanged();
        OpenMemberCommand.NotifyCanExecuteChanged();
    }
}
