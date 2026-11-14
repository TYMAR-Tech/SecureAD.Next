using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Shell.ViewModels;

internal sealed class GmsaPasswordReadersViewModel : SavedFindingPageViewModel<SavedGmsaPasswordReaders, GmsaPasswordReaderMark>
{
    private readonly GmsaPasswordReaderContext _context;

    internal GmsaPasswordReadersViewModel(SavedGmsaPasswordReaders first,
        Func<GmsaPasswordReaderMark?, CancellationToken, Task<Result<SavedGmsaPasswordReaders>>> read, Func<bool> current)
        : base(first, read, current)
    {
        _context = first.Context;
        Holders = first.Holders;
        Limitations = _context.Limitations.Select(SavedGmsaPasswordReaders.DescribeLimitation).ToArray();
    }

    public string ServiceAccount => _context.ServiceAccount + " (" + _context.DomainFqdn + ")";
    public string BroadIdentity => _context.BroadName + " (" + _context.BroadSid + ")";
    public string AccountState => _context.AccountState;
    public string ScopeNote => _context.ScopeNote;
    public bool HasNullDacl => _context.HasNullDacl;
    public string NullDaclNote => _context.NullDaclNote;
    public bool HasLimitations => !_context.EvidenceIsComplete;
    public string IncompleteNote => _context.IncompleteNote;
    public IReadOnlyList<string> Limitations { get; }
    public IReadOnlyList<SavedGmsaPasswordReaderHolder> Holders { get; private set; }
    protected override GmsaPasswordReaderMark? NextFor(SavedGmsaPasswordReaders page) => page.Next;
    protected override bool Accepts(SavedGmsaPasswordReaders page, GmsaPasswordReaderMark? after) =>
        _context.SameQuestion(page.Context) && page.IsExpectedPage(after?.Ordinal ?? -1);
    protected override string InvalidDetails => SavedGmsaPasswordReaders.InvalidDetails;
    protected override void AnnouncePage()
    {
        Holders = IsActive ? Page.Holders : [];
        OnPropertyChanged(nameof(Holders));
    }
}
