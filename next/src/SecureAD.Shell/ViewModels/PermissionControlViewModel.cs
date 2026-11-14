using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

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
    public string HolderType
    {
        get
        {
            var kind = saved.HolderObjectClass;
            if (string.IsNullOrWhiteSpace(kind))
                return saved.HolderIsWellKnownIdentity ? "Well-known identity" : "Type unavailable";
            return kind.ToLowerInvariant() switch
            {
                "group" => "Group",
                "user" => "User",
                "computer" => "Computer",
                "msds-managedserviceaccount" => "Managed service account",
                "msds-groupmanagedserviceaccount" => "Group managed service account",
                "foreignsecurityprincipal" => "Foreign principal reference",
                _ => kind,
            };
        }
    }
    public string BroadIdentity => saved.BroadName ?? "Name not resolved from saved evidence.";
    public string BroadSid => saved.BroadSid;
    public string Statement => SavedPermissionControl.Statement;
    public bool HasCurrentAssessment => saved.Assessment is not null;
    public bool HasLegacyAssessment => !HasCurrentAssessment;
    public string Heading => HasCurrentAssessment ? "Permission-changing rights" : "Saved permission-control assessment";
    public string ModifyPermissions => State(saved.Assessment?.ModifyPermissions);
    public string ChangeOwner => State(saved.Assessment?.ChangeOwner);
    public string FullControl => State(saved.Assessment?.FullControl);
    public string StateNote => SavedPermissionControl.CurrentStateNote;
    public string ScopeNote => SavedPermissionControl.CurrentScopeNote;
    public bool HasCalculationLimits => saved.Assessment?.IsComplete != true;
    public bool HasCaptureLimits => saved.Assessment is { DescriptorCompleteness: not DaclCompleteness.Complete };
    public bool HasMembershipLimits => !saved.ExpansionWasComplete;
    public string CalculationLimitsHeading => HasCurrentAssessment ? "Saved assessment limits" : "Known calculation limits";
    public string CalculationLimits => HasCurrentAssessment ? SavedPermissionControl.CurrentCalculationLimits : SavedPermissionControl.CalculationLimits;
    public bool HasNullDacl => saved.Assessment?.DescriptorState == DaclState.Null;
    public string CapturedPermissions => HasNullDacl ? "No permission list (NULL DACL)"
        : saved.Assessment?.DescriptorCompleteness == DaclCompleteness.Complete ? "Complete" : "May be incomplete";
    public string EntryContext => HasNullDacl ? "No entry (NULL DACL)" : saved.InheritedContext ? "Inherited" : "Explicit";
    public string EntryNote => HasNullDacl ? SavedPermissionControl.NullDaclNote
        : HasCurrentAssessment ? SavedPermissionControl.CurrentEntryNote : SavedPermissionControl.EntryNote;
    public string Expansion => saved.ExpansionWasComplete ? "Complete" : "May be incomplete";
    public string ExpansionNote => HasCurrentAssessment ? SavedPermissionControl.CurrentExpansionNote : SavedPermissionControl.ExpansionNote;
    public string ChainNote => SavedPermissionControl.ChainNote;
    public bool IsOwnership => saved.Assessment is { } current
        ? current.ChangeOwner != PermissionControlState.NotEstablished : saved.ReportedRight == ObjectTakeoverRight.WriteOwner;
    public bool IsFullControlCategory => !HasCurrentAssessment && saved.ReportedRight == ObjectTakeoverRight.GenericAll;
    public string OwnerRoute => SavedPermissionControl.CurrentOwnerRoute;
    public string OwnerSummary => HasCurrentAssessment
        ? "Change owner permission does not prove that becoming the owner will allow permission changes. Independently established Modify permissions remains separate."
        : SavedPermissionControl.OwnerNote;
    public string OwnerNote => HasCurrentAssessment ? SavedPermissionControl.CurrentOwnerNote : SavedPermissionControl.OwnerNote;
    public string FullControlNote => SavedPermissionControl.FullControlNote;
    public string ReportedRight => saved.ReportedRight switch
    {
        ObjectTakeoverRight.WriteDacl => "Modify permissions (WRITE_DAC)",
        ObjectTakeoverRight.WriteOwner => "Change owner (WRITE_OWNER)",
        ObjectTakeoverRight.GenericAll => HasCurrentAssessment ? "Full control" : "Full-control category reported by the legacy assessment",
        _ => throw new InvalidDataException(SavedPermissionControl.InvalidDetails),
    };
    private static string State(PermissionControlState? state) => state switch
    {
        PermissionControlState.Established => "Established",
        PermissionControlState.NotEstablished => "Not established",
        PermissionControlState.Unknown => "Unresolved",
        null => "",
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
