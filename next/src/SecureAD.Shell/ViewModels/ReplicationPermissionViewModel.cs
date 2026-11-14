using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Shell.ViewModels;

internal sealed record ReplicationEntryViewModel(SavedReplicationPermissionEntry Saved)
{
    public string EntryType => Saved.EntryType;
    public string Holder => Saved.Holder;
    public string Sid => Saved.Sid;
    public string Scope => Saved.Scope;
    public string Assignment => Saved.Assignment;
    public bool IsInherited => Saved.IsInherited;
    public string InheritanceNote => Saved.InheritanceNote;
}

internal sealed class ReplicationPermissionViewModel : SavedFindingPageViewModel<SavedReplicationPermission, ReplicationPermissionMark>
{
    private readonly ReplicationPermissionContext _context;
    internal ReplicationPermissionViewModel(SavedReplicationPermission first,
        Func<ReplicationPermissionMark?, CancellationToken, Task<Result<SavedReplicationPermission>>> read, Func<bool> current)
        : base(first, read, current)
    {
        _context = first.Context;
        Entries = first.Entries.Select(entry => new ReplicationEntryViewModel(entry)).ToArray();
    }
    public string Holder => _context.Holder;
    public string Sid => _context.HolderSid;
    public SavedDelegationIdentity Root => _context.Root;
    public string Changes => "Established";
    public string ChangesAll => "Established";
    public string Unexpectedness => _context.Unexpectedness;
    public string PolicyNote => SavedReplicationPermission.PolicyNote;
    public string EntryNote => SavedReplicationPermission.EntryNote;
    public string ScopeNote => SavedReplicationPermission.ScopeNote;
    public bool HasNullDacl => _context.HasNullDacl;
    public bool ShowsEntries => !HasNullDacl;
    public string NullDaclNote => SavedAttributeWritePermission.NullDaclNote;
    public bool HasLimitations => !_context.EvidenceIsComplete;
    public string Limitations => UnexpectedDomainSecretReplication.IncompleteExplanation;
    public IReadOnlyList<ReplicationEntryViewModel> Entries { get; private set; }
    protected override ReplicationPermissionMark? NextFor(SavedReplicationPermission page) => page.Next;
    protected override bool Accepts(SavedReplicationPermission page, ReplicationPermissionMark? after) =>
        page.Context == _context && page.IsExpectedPage(after?.Ordinal ?? -1);
    protected override string InvalidDetails => SavedReplicationPermission.InvalidDetails;
    protected override void AnnouncePage()
    {
        Entries = IsActive ? Page.Entries.Select(entry => new ReplicationEntryViewModel(entry)).ToArray() : [];
        OnPropertyChanged(nameof(Entries));
    }
}
