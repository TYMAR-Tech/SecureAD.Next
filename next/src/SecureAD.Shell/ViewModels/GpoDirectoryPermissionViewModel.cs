using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Shell.ViewModels;

internal sealed class GpoDirectoryPermissionViewModel : SavedFindingPageViewModel<SavedGpoDirectoryPermission, GpoDirectoryPermissionMark>
{
    private readonly GpoDirectoryPermissionContext _context;
    internal GpoDirectoryPermissionViewModel(SavedGpoDirectoryPermission first,
        Func<GpoDirectoryPermissionMark?, CancellationToken, Task<Result<SavedGpoDirectoryPermission>>> read, Func<bool> current)
        : base(first, read, current)
    {
        _context = first.Context;
        Entries = first.Entries;
        Operations = _context.Operations.Where(operation => operation.IsEstablished).Select(operation => operation.Permission).ToArray();
        Limitations = _context.Limitations.Select(SavedGpoDirectoryPermission.DescribeLimitation).ToArray();
    }
    public string Holder => _context.PermissionHolder;
    public string Sid => _context.HolderSid;
    public string TargetLabel => _context.TargetLabel;
    public string Target => _context.TargetName;
    public string TargetCaption => TargetLabel + ": " + Target;
    public string Domain => _context.Target.DomainFqdn;
    public string Location => _context.Target.DistinguishedName;
    public string WhyUnexpected => _context.WhyUnexpected;
    public string Caution => _context.Caution;
    public bool HasNullDacl => _context.HasNullDacl;
    public string NullDaclNote => SavedAttributeWritePermission.NullDaclNote;
    public bool HasLimitations => !_context.EvidenceIsComplete;
    public string IncompleteNote => _context.IncompleteNote;
    public IReadOnlyList<string> Operations { get; }
    public IReadOnlyList<string> Limitations { get; }
    public IReadOnlyList<SavedGpoDirectoryEntry> Entries { get; private set; }
    protected override GpoDirectoryPermissionMark? NextFor(SavedGpoDirectoryPermission page) => page.Next;
    protected override bool Accepts(SavedGpoDirectoryPermission page, GpoDirectoryPermissionMark? after) =>
        _context.SameQuestion(page.Context) && page.IsExpectedPage(after?.Ordinal ?? -1);
    protected override string InvalidDetails => SavedGpoDirectoryPermission.InvalidDetails;
    protected override void AnnouncePage()
    {
        Entries = IsActive ? Page.Entries : [];
        OnPropertyChanged(nameof(Entries));
    }
}
