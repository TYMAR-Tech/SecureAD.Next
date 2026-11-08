using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Naming;

namespace SecureAD.Shell.ViewModels;

internal sealed record GroupReviewReferenceViewModel(SavedGroupReference Saved) { public string Value => Saved.Value; }
internal sealed class GroupReviewReferencesViewModel : SavedFindingPageViewModel<SavedGroupReferences, GroupReviewReferenceMark>
{
    private readonly SavedGroupReview _context;
    internal GroupReviewReferencesViewModel(SavedGroupReferences first,
        Func<GroupReviewReferenceMark?, CancellationToken, Task<Result<SavedGroupReferences>>> read, Func<bool> current) : base(first, read, current)
    { _context = first.Context; Rows = first.References.Select(value => new GroupReviewReferenceViewModel(value)).ToArray(); }
    public IReadOnlyList<GroupReviewReferenceViewModel> Rows { get; private set; }
    protected override GroupReviewReferenceMark? NextFor(SavedGroupReferences page) => page.Next;
    protected override bool Accepts(SavedGroupReferences page, GroupReviewReferenceMark? after) => page.Context == _context && page.IsExpectedPage(after);
    protected override string InvalidDetails => SavedGroupReview.InvalidDetails(_context.RuleId);
    protected override void AnnouncePage()
    {
        Rows = IsActive ? Page.References.Select(value => new GroupReviewReferenceViewModel(value)).ToArray() : [];
        OnPropertyChanged(nameof(Rows));
    }
}
internal sealed partial class GroupReviewViewModel(SavedGroupReview saved,
    Func<GroupReviewReferenceMark?, CancellationToken, Task<Result<SavedGroupReferences>>> read, Func<bool> current) : ObservableObject
{
    private CancellationTokenSource? _pending;
    private bool _active = true;
    public bool IsSize => saved.IsSizeReview;
    public bool IsNesting => !IsSize;
    public string PanelTitle => IsSize ? "Saved group-size review" : "Saved direct group nesting";
    public string Group => DnHelper.ExtractFirstRdn(saved.Affected.Identity.DistinguishedName);
    public string GroupDescription => (IsSize ? "Affected group: " : "Nested group: ") + Group;
    public string Sid => saved.Affected.Sid;
    public string Domain => saved.Affected.Identity.DomainFqdn;
    public string Location => saved.Affected.Identity.DistinguishedName;
    public string SidDescription => (IsSize ? "SID: " : "Nested-group SID: ") + Sid;
    public string DomainDescription => (IsSize ? "Domain: " : "Nested-group domain: ") + Domain;
    public string LocationDescription => (IsSize ? "Location: " : "Nested-group location: ") + Location;
    public int? DirectCount => saved.DirectCount;
    public int? ReviewThreshold => saved.ReviewThreshold;
    public int? KnownTotal => saved.KnownTotal;
    public int? UnresolvedReferences => saved.UnresolvedReferences;
    public int? UnreadableReferences => saved.UnreadableReferences;
    public string Destination => DnHelper.ExtractFirstRdn(saved.Destination.Identity.DistinguishedName);
    public string DestinationSid => saved.Destination.Sid;
    public string DestinationDomain => saved.Destination.Identity.DomainFqdn;
    public string DestinationLocation => saved.Destination.Identity.DistinguishedName;
    public string Direction => Group + " is a member of " + Destination + ".";
    public string NestedType => saved.Affected.GroupType is not { } type ? "Not established from saved evidence."
        : (type & 0x80000000L) != 0 ? "Security-enabled group" : "Distribution group";
    public bool HasForeignReference => saved.HasForeignReference;
    public string ForeignReferenceNote => "Some saved membership references identify the nested group through a foreign-security-principal object.";
    public string NestingScope => "This is a recorded direct membership relationship, not an effective-access calculation for the nested group's members or proof of a completed Tier 0 path.";
    public string DirectNote => "Direct count is the number of distinct recorded member references. A nested group counts once here; this is not a count of people.";
    public string TotalNote => "Known total counts distinct captured objects reached through recorded member links, including nested groups, and excludes the starting group. Primary-group relationships are separate.";
    public string ReferenceNote => "Unresolved and unreadable references are limitations, not additional resolved objects. Known total is not a count of people and can be lower than Direct count.";
    public string PolicyNote => "Review thresholds are product policy, not Microsoft limits, a safe group size or a processing cap. Being below a threshold does not establish safety.";
    public bool HasTotalLimits => saved.TotalLimitations != GroupMembershipLimitations.None;
    public string TotalLimits => string.Join("\n", Enum.GetValues<GroupMembershipLimitations>()
        .Where(value => value != GroupMembershipLimitations.None && saved.TotalLimitations.HasFlag(value)).Select(value => value switch
        {
            GroupMembershipLimitations.CaptureIncomplete => "The captured scope is incomplete.",
            GroupMembershipLimitations.UnresolvedReferences => "Some recorded references could not be resolved.",
            GroupMembershipLimitations.UnreadableReferences => "Some recorded references could not be read.",
            GroupMembershipLimitations.SourceLimited => "Some captured membership sources are incomplete.",
            GroupMembershipLimitations.ForeignPrincipal => "Foreign-principal references limit the captured-object total.",
            GroupMembershipLimitations.ObjectClassNotRecorded => "Some object classes were not recorded.",
            _ => throw new InvalidDataException(SavedGroupReview.InvalidDetails(saved.RuleId)),
        }));
    public bool HasInputLimits => !string.IsNullOrEmpty(saved.InputLimitations);
    public string InputLimits => saved.InputLimitations;
    public string ReferencesNote => IsSize
        ? "Repeated original values are retained. The Direct count is a saved distinct-reference count, not the number of rows on this page."
        : "These are original references supporting this one saved direct-nesting finding, not additional findings or a list of the nested group's members.";
    public GroupReviewReferencesViewModel? References { get; private set; }
    public bool HasReferences => References is not null;
    public bool IsLoading { get; private set; }
    public string LoadingText => NavigationText.Get("SavedLoading");
    public string? Refusal { get; private set; }
    public bool HasRefusal => Refusal is not null;
    public Task ReadCompletion { get; private set; } = Task.CompletedTask;
    private bool CanViewReferences() => _active && !IsLoading && References is null;
    [RelayCommand(CanExecute = nameof(CanViewReferences))]
    private void ViewReferences() => ReadCompletion = Load();
    private async Task Load()
    {
        if (!_active || !current()) return;
        using var pending = new CancellationTokenSource(); _pending = pending;
        IsLoading = true; Refusal = null; Announce();
        try
        {
            var answer = await read(null, pending.Token);
            if (!_active || pending.IsCancellationRequested || !current()) return;
            if (!answer.IsSuccess) throw new InvalidDataException(answer.Error.Description);
            if (answer.Value.Context != saved || !answer.Value.IsExpectedPage(null)) throw new InvalidDataException(SavedGroupReview.InvalidDetails(saved.RuleId));
            References = new(answer.Value, read, current);
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested) { }
        catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException
            or InvalidOperationException or ArgumentException or Microsoft.Data.Sqlite.SqliteException)
        { if (_active && !pending.IsCancellationRequested && current()) Refusal = error.Message; }
        finally { _pending = null; IsLoading = false; Announce(); }
    }
    internal void Suspend() { _active = false; _pending?.Cancel(); References?.Suspend(); Announce(); }
    private void Announce()
    {
        OnPropertyChanged(nameof(References)); OnPropertyChanged(nameof(HasReferences)); OnPropertyChanged(nameof(IsLoading));
        OnPropertyChanged(nameof(Refusal)); OnPropertyChanged(nameof(HasRefusal)); ViewReferencesCommand.NotifyCanExecuteChanged();
    }
}
