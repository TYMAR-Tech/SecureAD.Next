using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Shell.ViewModels;

internal sealed class DelegationConfigurationViewModel : SavedFindingPageViewModel<SavedDelegationConfiguration, DelegationConfigurationMark>
{
    private readonly DelegationConfigurationContext _context;
    internal DelegationConfigurationViewModel(string principal, SavedDelegationConfiguration first,
        Func<DelegationConfigurationMark?, CancellationToken, Task<Result<SavedDelegationConfiguration>>> read, Func<bool> current)
        : base(first, read, current)
    {
        DelegatingAccount = principal;
        _context = first.Context;
        Limitations = _context.DescribeLimitations();
    }

    public string DelegatingAccount { get; }
    public string ResourceName => DelegatingAccount;
    public SavedDelegationIdentity Account => _context.Account;
    public SavedDelegationIdentity Resource => _context.Resource;
    public bool IsResourceBased => _context.IsResourceBased;
    public bool IsConstrained => !IsResourceBased;
    public bool HasNullDacl => _context.HasNullDacl;
    public bool ShowsHolders => IsResourceBased && !HasNullDacl;
    public bool ShowsPaging => !HasNullDacl;
    public string Heading => IsResourceBased ? "Captured RBCD configuration" : "Captured delegation";
    public string Statement => IsResourceBased ? SavedDelegationConfiguration.ResourceStatement : SavedDelegationConfiguration.ConstrainedStatement;
    public string ScopeNote => IsResourceBased ? SavedDelegationConfiguration.ResourceScopeNote : SavedDelegationConfiguration.ConstrainedScopeNote;
    public string NullDaclNote { get; } = SavedDelegationConfiguration.NullDaclNote;
    public string ResourceRelevance => _context.EstablishedTier0 ? "Established Tier 0 resource."
        : "Identified controller or dependency of Tier 0; not itself classified as Tier 0.";
    public IReadOnlyList<string> Services => IsActive ? Page.Services : [];
    public IReadOnlyList<SavedDelegationHolder> Holders => IsActive ? Page.Holders : [];
    public IReadOnlyList<string> Limitations { get; }
    public bool HasLimitations => Limitations.Count > 0;
    protected override DelegationConfigurationMark? NextFor(SavedDelegationConfiguration page) => page.Next;
    protected override bool Accepts(SavedDelegationConfiguration page, DelegationConfigurationMark? after) =>
        page.Context == _context && page.IsExpectedPage(after?.Offset ?? 0);
    protected override string InvalidDetails => IsResourceBased
        ? SavedDelegationConfiguration.ResourceInvalidDetails : SavedDelegationConfiguration.ConstrainedInvalidDetails;
    protected override void AnnouncePage()
    {
        OnPropertyChanged(nameof(Services));
        OnPropertyChanged(nameof(Holders));
    }
}
