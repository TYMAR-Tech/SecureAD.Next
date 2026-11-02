using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Naming;

namespace SecureAD.Shell.ViewModels;

internal sealed record PropertyWriteEntryViewModel(SavedPropertyWriteEntry saved)
{
    public int Ordinal => saved.Ordinal;
    public string EntryType => saved.EntryType;
    public string PermissionScope => saved.PermissionScope;
    public string Assignment => saved.Assignment;
    public bool IsInherited => saved.IsInherited;
    public string InheritanceNote => saved.InheritanceNote;
}

internal sealed class AttributeWritePermissionViewModel : SavedFindingPageViewModel<SavedAttributeWritePermission, AttributeWritePermissionMark>
{
    private readonly AttributeWritePermissionContext _context;
    internal AttributeWritePermissionViewModel(SavedAttributeWritePermission first,
        Func<AttributeWritePermissionMark?, CancellationToken, Task<Result<SavedAttributeWritePermission>>> read, Func<bool> current)
        : base(first, read, current)
    {
        _context = first.Context;
        Limitations = _context.DescribeLimitations();
        Entries = first.Entries.Select(entry => new PropertyWriteEntryViewModel(entry)).ToArray();
    }

    public string Holder => _context.PermissionHolder;
    public string Sid => _context.HolderSid;
    public SavedDelegationIdentity Target => _context.Target;
    public string TargetName => DnHelper.ExtractFirstRdn(Target.DistinguishedName);
    public string AccountState => _context.AccountState;
    public string Unexpectedness => _context.Unexpectedness;
    public string Attribute { get; } = SavedAttributeWritePermission.AttributeName;
    public bool HasNullDacl => _context.HasNullDacl;
    public bool ShowsEntries => !HasNullDacl;
    public string NullDaclNote { get; } = SavedAttributeWritePermission.NullDaclNote;
    public string ScopeNote { get; } = SavedAttributeWritePermission.ScopeNote;
    public IReadOnlyList<string> Limitations { get; }
    public bool HasLimitations => Limitations.Count > 0;
    public IReadOnlyList<PropertyWriteEntryViewModel> Entries { get; private set; } = [];
    protected override AttributeWritePermissionMark? NextFor(SavedAttributeWritePermission page) => page.Next;
    protected override bool Accepts(SavedAttributeWritePermission page, AttributeWritePermissionMark? after) =>
        page.Context == _context && page.IsExpectedPage(after?.Ordinal ?? -1);
    protected override string InvalidDetails => SavedAttributeWritePermission.InvalidDetails;
    protected override void AnnouncePage()
    {
        Entries = IsActive ? Page.Entries.Select(entry => new PropertyWriteEntryViewModel(entry)).ToArray() : [];
        OnPropertyChanged(nameof(Entries));
    }
}
