using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Naming;

namespace SecureAD.Shell.ViewModels;

internal sealed class PermissionControlChainViewModel : SavedFindingPageViewModel<SavedPermissionControlChain, PermissionControlMark>
{
    private readonly SavedPermissionControl _context;
    internal PermissionControlChainViewModel(SavedPermissionControlChain first,
        Func<PermissionControlMark?, CancellationToken, Task<Result<SavedPermissionControlChain>>> read, Func<bool> current)
        : base(first, read, current) { _context = first.Context; Steps = first.Steps; }
    public IReadOnlyList<SavedPermissionControlStep> Steps { get; private set; }
    protected override PermissionControlMark? NextFor(SavedPermissionControlChain page) => page.Next;
    protected override bool Accepts(SavedPermissionControlChain page, PermissionControlMark? after) =>
        page.Context == _context && page.IsExpectedPage(after);
    protected override string InvalidDetails => SavedPermissionControl.InvalidDetails;
    protected override void AnnouncePage() { Steps = IsActive ? Page.Steps : []; OnPropertyChanged(nameof(Steps)); }
}

internal sealed partial class PermissionControlViewModel(SavedPermissionControl saved,
    Func<PermissionControlMark?, CancellationToken, Task<Result<SavedPermissionControlChain>>> read, Func<bool> current) : ObservableObject
{
    private bool _active = true;
    private CancellationTokenSource? _pending;
    public string AffectedObject => DnHelper.ExtractFirstRdn(saved.Object.DistinguishedName);
    public SavedDelegationIdentity Object => saved.Object;
    public string Holder => saved.HolderName ?? "Name not resolved from saved evidence.";
    public string HolderSid => saved.HolderSid;
    public string BroadIdentity => saved.BroadName ?? "Name not resolved from saved evidence.";
    public string BroadSid => saved.BroadSid;
    public string Statement => SavedPermissionControl.Statement;
    public string CalculationLimits => SavedPermissionControl.CalculationLimits;
    public string EntryContext => saved.InheritedContext ? "Inherited" : "Explicit";
    public string EntryNote => SavedPermissionControl.EntryNote;
    public string Expansion => saved.ExpansionWasComplete ? "Complete" : "May be incomplete";
    public string ExpansionNote => SavedPermissionControl.ExpansionNote;
    public string ChainNote => SavedPermissionControl.ChainNote;
    public bool IsOwnership => saved.ReportedRight == ObjectTakeoverRight.WriteOwner;
    public bool IsFullControlCategory => saved.ReportedRight == ObjectTakeoverRight.GenericAll;
    public string OwnerNote => SavedPermissionControl.OwnerNote;
    public string FullControlNote => SavedPermissionControl.FullControlNote;
    public string ReportedRight => saved.ReportedRight switch
    {
        ObjectTakeoverRight.WriteDacl => "Modify permissions (WRITE_DAC)",
        ObjectTakeoverRight.WriteOwner => "Change owner (WRITE_OWNER)",
        ObjectTakeoverRight.GenericAll => "Full-control category reported by the legacy assessment",
        _ => throw new InvalidDataException(SavedPermissionControl.InvalidDetails),
    };
    public PermissionControlChainViewModel? Chain { get; private set; }
    public bool HasChain => Chain is not null;
    public bool IsLoading { get; private set; }
    public string LoadingText => NavigationText.Get("SavedLoading");
    public string? Refusal { get; private set; }
    public bool HasRefusal => Refusal is not null;
    public Task ReadCompletion { get; private set; } = Task.CompletedTask;
    private bool IsCurrent() => _active && current();
    private bool CanViewChain() => IsCurrent() && !IsLoading && Chain is null;
    [RelayCommand(CanExecute = nameof(CanViewChain))]
    private void ViewChain() { if (CanViewChain()) ReadCompletion = LoadAsync(); }
    private async Task LoadAsync()
    {
        _pending?.Cancel();
        using var pending = new CancellationTokenSource(); _pending = pending;
        IsLoading = true; Refusal = null; Announce();
        try
        {
            if (!IsCurrent()) return;
            var answer = await read(null, pending.Token);
            if (!IsCurrent() || pending.IsCancellationRequested || !ReferenceEquals(_pending, pending)) return;
            if (!answer.IsSuccess) throw new InvalidDataException(answer.Error.Description);
            if (answer.Value.Context != saved || !answer.Value.IsExpectedPage(null))
                throw new InvalidDataException(SavedPermissionControl.InvalidDetails);
            Chain = new(answer.Value, read, IsCurrent);
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested) { }
        catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException
            or InvalidOperationException or ArgumentException or Microsoft.Data.Sqlite.SqliteException)
        { if (IsCurrent() && !pending.IsCancellationRequested && ReferenceEquals(_pending, pending)) Refusal = error.Message; }
        finally
        { if (ReferenceEquals(_pending, pending)) { _pending = null; IsLoading = false; Announce(); } }
    }
    internal void Suspend() { _active = false; _pending?.Cancel(); Chain?.Suspend(); Announce(); }
    private void Announce()
    {
        OnPropertyChanged(nameof(Chain)); OnPropertyChanged(nameof(HasChain)); OnPropertyChanged(nameof(IsLoading));
        OnPropertyChanged(nameof(Refusal)); OnPropertyChanged(nameof(HasRefusal)); ViewChainCommand.NotifyCanExecuteChanged();
    }
}
